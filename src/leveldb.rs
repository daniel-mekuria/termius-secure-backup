// SPDX-License-Identifier: Apache-2.0

//! Minimal read-only LevelDB reader, used to fingerprint the *logical*
//! contents of Termius's Chromium LevelDB stores (`IndexedDB`, `Local
//! Storage`) for two-way sync.
//!
//! LevelDB rewrites its files all the time without any logical change:
//! every open replays the write-ahead log into a fresh table, and
//! background compactions merge tables into new ones. A file-level
//! fingerprint (sizes, mtimes, even content hashes) therefore changes on
//! every Termius start — which two-way sync would mistake for a local edit
//! and push over the other devices' changes. Hashing the live key/value
//! pairs instead is immune to all of that.
//!
//! Only what fingerprinting needs is implemented: the log format (`*.log`,
//! write batches), the table format (`*.ldb` / `*.sst`: footer, index and
//! data blocks, raw or Snappy-compressed), CRC32C checks, and a Snappy
//! decompressor. The MANIFEST is not parsed: every table and log in the
//! directory is read and the newest entry per user key (highest sequence
//! number) wins. A table made obsolete by a compaction but not deleted yet
//! only contributes entries that a newer one shadows (at worst it shows up
//! transiently, until LevelDB deletes it a moment later).

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The newest version of every user key in a LevelDB directory: the
/// sequence number that wrote it and its value (`None` = deleted).
type KeyState = BTreeMap<Vec<u8>, (u64, Option<Vec<u8>>)>;

/// Whether `dir` looks like a LevelDB database (it has a `CURRENT` file).
pub fn is_leveldb_dir(dir: &Path) -> bool {
    dir.join("CURRENT").is_file()
}

/// The live (not deleted) key/value pairs of the LevelDB database in
/// `dir`, sorted by key bytes.
pub fn live_entries(dir: &Path) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(read_state(dir)?
        .into_iter()
        .filter_map(|(k, (_, v))| v.map(|v| (k, v)))
        .collect())
}

/// SHA-256 over the live key/value pairs of the LevelDB database in `dir`
/// — identical for two databases with the same logical contents,
/// regardless of how they are laid out in files.
pub fn logical_digest(dir: &Path) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    for (k, v) in live_entries(dir)? {
        h.update((k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(&v);
    }
    Ok(h.finalize().into())
}

fn read_state(dir: &Path) -> Result<KeyState> {
    let mut state = KeyState::new();
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    for name in names {
        let path = dir.join(&name);
        if name.ends_with(".ldb") || name.ends_with(".sst") {
            let data = std::fs::read(&path)?;
            read_table(&data, &mut state).map_err(|e| corrupt(&path, e))?;
        } else if name.ends_with(".log") {
            let data = std::fs::read(&path)?;
            read_log(&data, &mut state).map_err(|e| corrupt(&path, e))?;
        }
    }
    Ok(state)
}

fn corrupt(path: &Path, e: Error) -> Error {
    Error::Other(format!("cannot read LevelDB file {}: {e}", path.display()))
}

fn bad(msg: &str) -> Error {
    Error::Other(msg.to_string())
}

/// Record one entry, keeping only the newest version of each key.
fn put(state: &mut KeyState, key: &[u8], seq: u64, value: Option<&[u8]>) {
    match state.get(key) {
        Some((old, _)) if *old >= seq => {}
        _ => {
            state.insert(key.to_vec(), (seq, value.map(<[u8]>::to_vec)));
        }
    }
}

// --------------------------------------------------------------- varints

/// Decode a LevelDB varint (up to 64 bits) at `*pos`, advancing it.
fn varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *buf.get(*pos).ok_or_else(|| bad("truncated varint"))?;
        *pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(bad("varint too long"))
}

/// A `varint`-length-prefixed slice at `*pos`, advancing it.
fn length_prefixed<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = usize::try_from(varint(buf, pos)?).map_err(|_| bad("length overflow"))?;
    let end = pos
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| bad("truncated slice"))?;
    let s = &buf[*pos..end];
    *pos = end;
    Ok(s)
}

fn u32_le(buf: &[u8], at: usize) -> Result<u32> {
    let b = buf.get(at..at + 4).ok_or_else(|| bad("truncated u32"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_le(buf: &[u8], at: usize) -> Result<u64> {
    let b = buf.get(at..at + 8).ok_or_else(|| bad("truncated u64"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_le_bytes(a))
}

// ----------------------------------------------------------------- CRC32C

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32C_TABLE: [u32; 256] = crc32c_table();

/// CRC32C (Castagnoli) of the concatenation of `parts`.
fn crc32c(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    for part in parts {
        for &b in *part {
            crc = CRC32C_TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
        }
    }
    !crc
}

/// Undo LevelDB's CRC masking (`crc32c::Unmask`).
fn unmask_crc(masked: u32) -> u32 {
    let rot = masked.wrapping_sub(0xa282_ead8);
    rot.rotate_left(15)
}

// ------------------------------------------------------------------ Snappy

/// Decompress a raw (unframed) Snappy block.
fn snappy_decompress(src: &[u8]) -> Result<Vec<u8>> {
    let mut i = 0usize;
    let len = usize::try_from(varint(src, &mut i)?).map_err(|_| bad("snappy: length overflow"))?;
    // Guard against absurd sizes from a corrupt header (blocks are ~4 KiB).
    if len > 64 * 1024 * 1024 {
        return Err(bad("snappy: implausible uncompressed length"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while i < src.len() {
        let tag = src[i];
        i += 1;
        let (copy_len, offset) = match tag & 3 {
            0 => {
                let mut lit = usize::from(tag >> 2);
                if lit >= 60 {
                    let n = lit - 59;
                    let b = src
                        .get(i..i + n)
                        .ok_or_else(|| bad("snappy: truncated literal length"))?;
                    lit = b
                        .iter()
                        .rev()
                        .fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
                    i += n;
                }
                let lit = lit + 1;
                let b = src
                    .get(i..i + lit)
                    .ok_or_else(|| bad("snappy: truncated literal"))?;
                out.extend_from_slice(b);
                i += lit;
                continue;
            }
            1 => {
                let b = *src.get(i).ok_or_else(|| bad("snappy: truncated copy"))?;
                i += 1;
                (
                    usize::from((tag >> 2) & 7) + 4,
                    (usize::from(tag >> 5) << 8) | usize::from(b),
                )
            }
            2 => {
                let b = src
                    .get(i..i + 2)
                    .ok_or_else(|| bad("snappy: truncated copy"))?;
                i += 2;
                (
                    usize::from(tag >> 2) + 1,
                    usize::from(u16::from_le_bytes([b[0], b[1]])),
                )
            }
            _ => {
                let off = u32_le(src, i)?;
                i += 4;
                (
                    usize::from(tag >> 2) + 1,
                    usize::try_from(off).map_err(|_| bad("snappy: offset overflow"))?,
                )
            }
        };
        if offset == 0 || offset > out.len() {
            return Err(bad("snappy: copy offset out of range"));
        }
        let start = out.len() - offset;
        for k in 0..copy_len {
            let b = out[start + k];
            out.push(b);
        }
        if out.len() > len {
            return Err(bad("snappy: output longer than declared"));
        }
    }
    if out.len() != len {
        return Err(bad("snappy: output length mismatch"));
    }
    Ok(out)
}

// --------------------------------------------------------------- log files

const LOG_BLOCK: usize = 32 * 1024;
const LOG_HEADER: usize = 7;
const FULL: u8 = 1;
const FIRST: u8 = 2;
const MIDDLE: u8 = 3;
const LAST: u8 = 4;

/// Replay a write-ahead log (`NNNNNN.log`) into `state`. A torn or
/// corrupt tail — the live log of a running database is written while we
/// read it — ends the replay of that block, like LevelDB's own recovery.
fn read_log(data: &[u8], state: &mut KeyState) -> Result<()> {
    let mut record: Vec<u8> = Vec::new();
    let mut in_fragmented = false;
    let mut block_start = 0usize;
    while block_start < data.len() {
        let block = &data[block_start..data.len().min(block_start + LOG_BLOCK)];
        let mut p = 0usize;
        while p + LOG_HEADER <= block.len() {
            let crc = u32_le(block, p)?;
            let len = usize::from(u16::from_le_bytes([block[p + 4], block[p + 5]]));
            let kind = block[p + 6];
            if kind == 0 && len == 0 {
                break; // zero padding (preallocated space)
            }
            let start = p + LOG_HEADER;
            let Some(payload) = block.get(start..start + len) else {
                break; // torn tail
            };
            if unmask_crc(crc) != crc32c(&[&[kind], payload]) {
                break; // corrupt or half-written record
            }
            p = start + len;
            match kind {
                FULL => {
                    apply_batch(payload, state)?;
                    in_fragmented = false;
                }
                FIRST => {
                    record.clear();
                    record.extend_from_slice(payload);
                    in_fragmented = true;
                }
                MIDDLE if in_fragmented => record.extend_from_slice(payload),
                LAST if in_fragmented => {
                    record.extend_from_slice(payload);
                    apply_batch(&record, state)?;
                    in_fragmented = false;
                }
                _ => in_fragmented = false, // unexpected fragment: drop it
            }
        }
        block_start += LOG_BLOCK;
    }
    Ok(())
}

/// Apply one `WriteBatch` (sequence number, count, then put/delete
/// records) to `state`.
fn apply_batch(batch: &[u8], state: &mut KeyState) -> Result<()> {
    if batch.len() < 12 {
        return Err(bad("write batch too short"));
    }
    let seq = u64_le(batch, 0)?;
    let count = u32_le(batch, 8)?;
    let mut pos = 12usize;
    for i in 0..u64::from(count) {
        let kind = *batch.get(pos).ok_or_else(|| bad("write batch truncated"))?;
        pos += 1;
        let key = length_prefixed(batch, &mut pos)?;
        match kind {
            1 => {
                let value = length_prefixed(batch, &mut pos)?;
                put(state, key, seq + i, Some(value));
            }
            0 => put(state, key, seq + i, None),
            _ => return Err(bad("unknown write batch record type")),
        }
    }
    Ok(())
}

// ------------------------------------------------------------- table files

const TABLE_MAGIC: u64 = 0xdb47_7524_8b80_fb57;
const FOOTER_LEN: usize = 48;

/// Read every entry of an SSTable (`NNNNNN.ldb` / `.sst`) into `state`.
fn read_table(data: &[u8], state: &mut KeyState) -> Result<()> {
    if data.len() < FOOTER_LEN {
        return Err(bad("table too short"));
    }
    let footer = &data[data.len() - FOOTER_LEN..];
    if u64_le(footer, FOOTER_LEN - 8)? != TABLE_MAGIC {
        return Err(bad("bad table magic"));
    }
    let mut pos = 0usize;
    let _meta_off = varint(footer, &mut pos)?;
    let _meta_len = varint(footer, &mut pos)?;
    let index_off = varint(footer, &mut pos)?;
    let index_len = varint(footer, &mut pos)?;
    let index = read_block(data, index_off, index_len)?;
    for (_, handle) in block_entries(&index)? {
        let mut hp = 0usize;
        let off = varint(&handle, &mut hp)?;
        let len = varint(&handle, &mut hp)?;
        let block = read_block(data, off, len)?;
        for (ikey, value) in block_entries(&block)? {
            if ikey.len() < 8 {
                return Err(bad("internal key too short"));
            }
            let (user_key, trailer) = ikey.split_at(ikey.len() - 8);
            let tag = u64_le(trailer, 0)?;
            let (seq, kind) = (tag >> 8, (tag & 0xff) as u8);
            match kind {
                1 => put(state, user_key, seq, Some(value.as_slice())),
                0 => put(state, user_key, seq, None),
                _ => return Err(bad("unknown table entry type")),
            }
        }
    }
    Ok(())
}

/// Read and check one block (contents + 1-byte compression type + masked
/// CRC32C), decompressing it if needed.
fn read_block(data: &[u8], off: u64, len: u64) -> Result<Vec<u8>> {
    let off = usize::try_from(off).map_err(|_| bad("block offset overflow"))?;
    let len = usize::try_from(len).map_err(|_| bad("block length overflow"))?;
    let end = off
        .checked_add(len)
        .and_then(|e| e.checked_add(5))
        .filter(|&e| e <= data.len())
        .ok_or_else(|| bad("block out of range"))?;
    let contents = &data[off..off + len];
    let kind = data[off + len];
    let crc = u32_le(data, end - 4)?;
    if unmask_crc(crc) != crc32c(&[contents, &[kind]]) {
        return Err(bad("block checksum mismatch"));
    }
    match kind {
        0 => Ok(contents.to_vec()),
        1 => snappy_decompress(contents),
        _ => Err(bad("unsupported block compression")),
    }
}

/// All (key, value) entries of a block (prefix-compressed keys, restart
/// array at the end).
fn block_entries(block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if block.len() < 4 {
        return Err(bad("block too short"));
    }
    let restarts = u32_le(block, block.len() - 4)? as usize;
    let limit = block
        .len()
        .checked_sub(
            4 + restarts
                .checked_mul(4)
                .ok_or_else(|| bad("restart overflow"))?,
        )
        .ok_or_else(|| bad("bad restart count"))?;
    let mut out = Vec::new();
    let mut key: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while pos < limit {
        let shared = usize::try_from(varint(block, &mut pos)?).map_err(|_| bad("overflow"))?;
        let non_shared = usize::try_from(varint(block, &mut pos)?).map_err(|_| bad("overflow"))?;
        let value_len = usize::try_from(varint(block, &mut pos)?).map_err(|_| bad("overflow"))?;
        if shared > key.len() {
            return Err(bad("bad shared key prefix"));
        }
        let delta = block
            .get(pos..pos + non_shared)
            .ok_or_else(|| bad("truncated key"))?;
        pos += non_shared;
        let value = block
            .get(pos..pos + value_len)
            .ok_or_else(|| bad("truncated value"))?;
        pos += value_len;
        key.truncate(shared);
        key.extend_from_slice(delta);
        out.push((key.clone(), value.to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Writers for just enough of LevelDB's formats to build fixtures
    //! that the reader must understand.
    use super::*;

    pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    pub fn mask_crc(crc: u32) -> u32 {
        crc.rotate_right(15).wrapping_add(0xa282_ead8)
    }

    /// A write batch with puts (`Some`) and deletes (`None`).
    pub fn batch(seq: u64, ops: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&(ops.len() as u32).to_le_bytes());
        for (k, v) in ops {
            b.push(u8::from(v.is_some()));
            put_varint(&mut b, k.len() as u64);
            b.extend_from_slice(k);
            if let Some(v) = v {
                put_varint(&mut b, v.len() as u64);
                b.extend_from_slice(v);
            }
        }
        b
    }

    /// A log file holding `records`, fragmented across 32 KiB blocks the
    /// way LevelDB's log writer does it.
    pub fn log_file(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for rec in records {
            let mut left: &[u8] = rec;
            let mut begin = true;
            loop {
                let room = LOG_BLOCK - out.len() % LOG_BLOCK;
                if room < LOG_HEADER {
                    out.resize(out.len() + room, 0);
                    continue;
                }
                let avail = room - LOG_HEADER;
                let n = left.len().min(avail);
                let end = n == left.len();
                let kind = match (begin, end) {
                    (true, true) => FULL,
                    (true, false) => FIRST,
                    (false, true) => LAST,
                    (false, false) => MIDDLE,
                };
                let payload = &left[..n];
                out.extend_from_slice(&mask_crc(crc32c(&[&[kind], payload])).to_le_bytes());
                out.extend_from_slice(&(n as u16).to_le_bytes());
                out.push(kind);
                out.extend_from_slice(payload);
                left = &left[n..];
                begin = false;
                if end {
                    break;
                }
            }
        }
        out
    }

    pub fn block(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        let mut prev: Vec<u8> = Vec::new();
        for (k, v) in entries {
            let shared = prev.iter().zip(k).take_while(|(a, b)| a == b).count();
            put_varint(&mut b, shared as u64);
            put_varint(&mut b, (k.len() - shared) as u64);
            put_varint(&mut b, v.len() as u64);
            b.extend_from_slice(&k[shared..]);
            b.extend_from_slice(v);
            prev = k.clone();
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // one restart, at 0
        b.extend_from_slice(&1u32.to_le_bytes());
        b
    }

    /// A valid Snappy block that stores the input as literals only (good
    /// enough to exercise the reader's decompression path).
    pub fn snappy_literal(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, data.len() as u64);
        for chunk in data.chunks(60) {
            out.push(((chunk.len() - 1) as u8) << 2);
            out.extend_from_slice(chunk);
        }
        out
    }

    pub fn append_block(file: &mut Vec<u8>, contents: &[u8], kind: u8) -> Vec<u8> {
        let mut handle = Vec::new();
        put_varint(&mut handle, file.len() as u64);
        put_varint(&mut handle, contents.len() as u64);
        file.extend_from_slice(contents);
        file.push(kind);
        file.extend_from_slice(&mask_crc(crc32c(&[contents, &[kind]])).to_le_bytes());
        handle
    }

    /// A table entry: user key, sequence number, value (`None` = delete).
    pub type TableEntry<'a> = (&'a [u8], u64, Option<&'a [u8]>);

    /// An SSTable with one data block holding `entries` (internal keys).
    pub fn table(entries: &[TableEntry], compress: bool) -> Vec<u8> {
        let ikeys: Vec<(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|(k, seq, v)| {
                let mut ik = k.to_vec();
                let tag = (seq << 8) | u64::from(v.is_some());
                ik.extend_from_slice(&tag.to_le_bytes());
                (ik, v.unwrap_or_default().to_vec())
            })
            .collect();
        let mut file = Vec::new();
        let data = block(&ikeys);
        let data_handle = if compress {
            append_block(&mut file, &snappy_literal(&data), 1)
        } else {
            append_block(&mut file, &data, 0)
        };
        let meta_handle = append_block(&mut file, &block(&[]), 0);
        let last_key = ikeys.last().map(|(k, _)| k.clone()).unwrap_or_default();
        let index_handle = append_block(&mut file, &block(&[(last_key, data_handle)]), 0);
        let mut footer = Vec::new();
        footer.extend_from_slice(&meta_handle);
        footer.extend_from_slice(&index_handle);
        footer.resize(FOOTER_LEN - 8, 0);
        footer.extend_from_slice(&TABLE_MAGIC.to_le_bytes());
        file.extend_from_slice(&footer);
        file
    }

    pub fn db_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        d
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        // RFC 3720 B.4: 32 bytes of zeros.
        assert_eq!(crc32c(&[&[0u8; 32]]), 0x8a91_36aa);
        assert_eq!(crc32c(&[b"123456789"]), 0xe306_9283);
        assert_eq!(unmask_crc(mask_crc(0x1234_5678)), 0x1234_5678);
    }

    #[test]
    fn snappy_decodes_literals_and_copies() {
        // "abcd" + copy(offset 4, len 8) -> "abcdabcdabcd".
        let src = [12u8, 3 << 2, b'a', b'b', b'c', b'd', 0b0001_0001, 4];
        assert_eq!(snappy_decompress(&src).unwrap(), b"abcdabcdabcd");
        // Two-byte-offset copy.
        let src = [6u8, 1 << 2, b'x', b'y', (3 << 2) | 2, 2, 0];
        assert_eq!(snappy_decompress(&src).unwrap(), b"xyxyxy");
        // Length mismatch and bad offsets are rejected.
        assert!(snappy_decompress(&[5u8, 0, b'a']).is_err());
        assert!(snappy_decompress(&[4u8, 0b0001_0001, 9]).is_err());
    }

    #[test]
    fn log_replay_newest_wins_and_deletes() {
        let d = db_dir();
        let big = vec![7u8; 70_000]; // spans three log blocks
        let log = log_file(&[
            batch(1, &[(b"a", Some(b"1")), (b"b", Some(b"2"))]),
            batch(3, &[(b"a", Some(b"3")), (b"b", None)]),
            batch(5, &[(b"big", Some(big.as_slice()))]),
        ]);
        std::fs::write(d.path().join("000003.log"), &log).unwrap();
        let live = live_entries(d.path()).unwrap();
        assert_eq!(
            live,
            vec![
                (b"a".to_vec(), b"3".to_vec()),
                (b"big".to_vec(), big.clone())
            ]
        );
    }

    #[test]
    fn torn_log_tail_is_ignored() {
        let d = db_dir();
        let mut log = log_file(&[
            batch(1, &[(b"k", Some(b"v1"))]),
            batch(2, &[(b"k", Some(b"v2"))]),
        ]);
        log.truncate(log.len() - 3); // the second record is half-written
        std::fs::write(d.path().join("000003.log"), &log).unwrap();
        assert_eq!(
            live_entries(d.path()).unwrap(),
            vec![(b"k".to_vec(), b"v1".to_vec())]
        );
    }

    #[test]
    fn tables_raw_and_snappy_merge_with_logs() {
        let d = db_dir();
        std::fs::write(
            d.path().join("000005.ldb"),
            table(&[(b"a", 1, Some(b"old")), (b"b", 2, Some(b"bee"))], false),
        )
        .unwrap();
        std::fs::write(
            d.path().join("000006.ldb"),
            table(&[(b"c", 3, Some(b"sea")), (b"d", 4, Some(b"dee"))], true),
        )
        .unwrap();
        std::fs::write(
            d.path().join("000007.log"),
            log_file(&[batch(10, &[(b"a", Some(b"new")), (b"d", None)])]),
        )
        .unwrap();
        assert_eq!(
            live_entries(d.path()).unwrap(),
            vec![
                (b"a".to_vec(), b"new".to_vec()),
                (b"b".to_vec(), b"bee".to_vec()),
                (b"c".to_vec(), b"sea".to_vec()),
            ]
        );
    }

    #[test]
    fn digest_ignores_file_layout() {
        // The same logical contents as (a) one log, and (b) a compacted
        // table plus an empty log — what LevelDB does on every open.
        let a = db_dir();
        std::fs::write(
            a.path().join("000003.log"),
            log_file(&[
                batch(1, &[(b"host:1", Some(b"alpha"))]),
                batch(2, &[(b"host:2", Some(b"beta")), (b"tmp", Some(b"x"))]),
                batch(4, &[(b"tmp", None)]),
            ]),
        )
        .unwrap();
        let b = db_dir();
        std::fs::write(
            b.path().join("000009.ldb"),
            table(
                &[
                    (b"host:1", 1, Some(b"alpha")),
                    (b"host:2", 2, Some(b"beta")),
                ],
                true,
            ),
        )
        .unwrap();
        std::fs::write(b.path().join("000010.log"), b"").unwrap();
        std::fs::write(b.path().join("LOG"), b"some diagnostics").unwrap();
        assert_eq!(
            logical_digest(a.path()).unwrap(),
            logical_digest(b.path()).unwrap()
        );

        // A real change does change the digest.
        std::fs::write(
            b.path().join("000011.log"),
            log_file(&[batch(20, &[(b"host:3", Some(b"gamma"))])]),
        )
        .unwrap();
        assert_ne!(
            logical_digest(a.path()).unwrap(),
            logical_digest(b.path()).unwrap()
        );
    }

    #[test]
    fn corrupt_table_is_an_error() {
        let d = db_dir();
        let mut t = table(&[(b"a", 1, Some(b"1"))], false);
        t[3] ^= 0xff; // flip a byte inside the data block
        std::fs::write(d.path().join("000005.ldb"), &t).unwrap();
        assert!(live_entries(d.path()).is_err());
        assert!(is_leveldb_dir(d.path()));
    }

    /// Manual diagnostic: dump a summary of a real LevelDB directory.
    /// `LEVELDB_DIAG=<dir> cargo test --lib leveldb_diag -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn leveldb_diag() {
        let dir = std::env::var("LEVELDB_DIAG").expect("set LEVELDB_DIAG");
        let state = read_state(Path::new(&dir)).unwrap();
        let live = state.values().filter(|(_, v)| v.is_some()).count();
        let max_seq = state.values().map(|(s, _)| *s).max().unwrap_or(0);
        println!(
            "keys: {} (live {live}), max seq {max_seq}, digest {}",
            state.len(),
            crate::util::hex::encode_lower_owned(&logical_digest(Path::new(&dir)).unwrap())
        );
        let mut by_seq: Vec<_> = state.iter().collect();
        by_seq.sort_by_key(|(_, (s, _))| std::cmp::Reverse(*s));
        for (k, (s, v)) in by_seq.iter().take(40) {
            let shown: String = k
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!(
                "seq {s:>8}  {}  key[{}] {shown}",
                match v {
                    Some(v) => format!("put {:>7}B", v.len()),
                    None => "delete     ".into(),
                },
                k.len()
            );
        }
    }
}
