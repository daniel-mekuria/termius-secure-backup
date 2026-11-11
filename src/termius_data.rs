// SPDX-License-Identifier: Apache-2.0

//! What two-way sync carries between devices, how it notices that this
//! machine's Termius data changed, and how it swaps another device's data
//! in.
//!
//! **What is synced.** Termius keeps every synced entity type (hosts,
//! groups, keys, identities, snippets, port-forwarding rules, known hosts,
//! tags, settings, …) in its own IndexedDB database under `IndexedDB/`, so
//! sync carries exactly that directory. Everything else in the data
//! directory stays per-device on purpose: `Local Storage` holds this
//! device's Termius session and device tokens and analytics queues,
//! `Local State` holds Chromium's machine-bound cookie key, and the rest is
//! caches, logs, and window state.
//!
//! **Change detection.** LevelDB rewrites its files on every open and
//! compaction without any logical change, and Termius writes activity logs
//! and terminal command history in the background. So the fingerprint is
//! the hash of the *logical* key/value contents (see [`crate::leveldb`]) of
//! the user-data databases only — the background-written ones
//! ([`LOCAL_ONLY_DBS`]) and Chromium's own bookkeeping are left out, so
//! they never trigger an upload on their own (they still travel with one).
//!
//! **Applying.** Termius holds its LevelDB files open and caches their
//! contents while it runs, so another device's data is only swapped in
//! while Termius is closed ([`termius_running`]).

use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::leveldb;
use crate::util;

/// The part of the Termius data directory that two-way sync carries.
pub const SYNC_DIR: &str = "IndexedDB";

/// IndexedDB databases that Termius writes on its own (activity and sync
/// logs, terminal command history, last-connected times, in-app messages,
/// team caches) or that describe this particular device. Their changes do
/// not count as edits to sync.
pub const LOCAL_ONLY_DBS: &[&str] = &[
    "activities",
    "databaseMetadata",
    "history_commands",
    "host_latest_activities",
    "inAppMessages",
    "personalDeviceKeyPair",
    "sshid",
    "teamInvites",
    "teamMemberAvatars",
    "teamMembers",
];

/// LevelDB housekeeping files: recreated by LevelDB itself, never synced
/// and never fingerprinted.
const HOUSEKEEPING: &[&str] = &["LOCK", "LOG", "LOG.old"];

/// Whether the entry at `rel` (relative to the Termius data directory)
/// belongs in a sync upload: everything under [`SYNC_DIR`] except
/// LevelDB housekeeping files. Used as the archive filter.
pub fn in_sync_set(rel: &Path) -> bool {
    let mut comps = rel.components();
    match comps.next() {
        Some(c) if c.as_os_str() == SYNC_DIR => {}
        _ => return false,
    }
    match rel.file_name().and_then(|n| n.to_str()) {
        Some(name) => !HOUSEKEEPING.contains(&name),
        None => true,
    }
}

/// Fingerprint of this machine's synced Termius data (lowercase hex), or
/// an empty string when there is no [`SYNC_DIR`] at all. Two directories
/// with the same logical contents in their user-data databases have the
/// same fingerprint, however LevelDB happens to have laid them out.
pub fn fingerprint(termius_dir: &Path) -> Result<String> {
    let root = termius_dir.join(SYNC_DIR);
    if !root.is_dir() {
        return Ok(String::new());
    }
    let mut h = Sha256::new();
    hash_tree(&root, &root, &mut h)?;
    Ok(util::hex::encode_lower_owned(&h.finalize()))
}

fn hash_tree(root: &Path, dir: &Path, h: &mut Sha256) -> Result<()> {
    let rel = dir
        .strip_prefix(root)
        .unwrap_or(dir)
        .to_string_lossy()
        .replace('\\', "/");
    if leveldb::is_leveldb_dir(dir) {
        match idb_digest(dir) {
            Ok(d) => {
                h.update(b"leveldb\0");
                h.update(rel.as_bytes());
                h.update([0]);
                h.update(d);
                return Ok(());
            }
            Err(e) => {
                // Unreadable as LevelDB (a format this reader does not know,
                // or a table caught mid-write): fall back to hashing the
                // files, which is noisier but never misses a change.
                tracing::debug!("logical fingerprint of {} failed: {e}", dir.display());
            }
        }
    }
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(dir)?.collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            hash_tree(root, &path, h)?;
        } else if meta.is_file() && !HOUSEKEEPING.contains(&name.as_str()) {
            h.update(b"file\0");
            h.update(format!("{rel}/{name}").as_bytes());
            h.update([0]);
            h.update(util::sha256_file(&path)?.as_bytes());
        }
    }
    Ok(())
}

/// Logical digest of a Chromium IndexedDB LevelDB, restricted to the
/// user-data databases. A LevelDB that does not look like IndexedDB (no
/// database names found) is hashed whole.
fn idb_digest(dir: &Path) -> Result<[u8; 32]> {
    let entries = leveldb::live_entries(dir)?;
    let names = idb_database_names(&entries);
    let mut h = Sha256::new();
    for (k, v) in &entries {
        if !names.is_empty() {
            let Some((db, ..)) = idb_key_prefix(k) else {
                continue;
            };
            // Database 0 is Chromium's global bookkeeping (schema version,
            // transaction undo logs, sweep times) — never user data.
            match names.get(&db) {
                Some(name) if !LOCAL_ONLY_DBS.contains(&name.as_str()) => {}
                _ => continue,
            }
        }
        h.update((k.len() as u64).to_le_bytes());
        h.update(k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(v);
    }
    Ok(h.finalize().into())
}

/// Decode a Chromium IndexedDB key prefix: `(database id, object store
/// id, index id, prefix length)`. The first byte packs the byte lengths of
/// the three little-endian ids.
fn idb_key_prefix(k: &[u8]) -> Option<(u64, u64, u64, usize)> {
    let b0 = *k.first()?;
    let db_len = usize::from(b0 >> 5) + 1;
    let os_len = usize::from((b0 >> 2) & 7) + 1;
    let idx_len = usize::from(b0 & 3) + 1;
    let n = 1 + db_len + os_len + idx_len;
    if k.len() < n {
        return None;
    }
    let le = |s: &[u8]| s.iter().rev().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    Some((
        le(&k[1..1 + db_len]),
        le(&k[1 + db_len..1 + db_len + os_len]),
        le(&k[1 + db_len + os_len..n]),
        n,
    ))
}

/// Database id → name, from the global `DatabaseNameKey` entries: prefix
/// `(0, 0, 0)`, type byte 201, then the origin and the database name as
/// length-prefixed UTF-16BE strings; the value is the id (little-endian).
fn idb_database_names(entries: &[(Vec<u8>, Vec<u8>)]) -> HashMap<u64, String> {
    const DATABASE_NAME_TYPE: u8 = 201;
    let mut names = HashMap::new();
    for (k, v) in entries {
        let Some((0, 0, 0, n)) = idb_key_prefix(k) else {
            continue;
        };
        if k.get(n) != Some(&DATABASE_NAME_TYPE) {
            continue;
        }
        let mut pos = n + 1;
        let (Some(_origin), Some(name)) =
            (utf16_with_len(k, &mut pos), utf16_with_len(k, &mut pos))
        else {
            continue;
        };
        if v.is_empty() || v.len() > 8 {
            continue;
        }
        let id = v.iter().rev().fold(0u64, |a, &b| (a << 8) | u64::from(b));
        names.insert(id, name);
    }
    names
}

/// A varint length (in UTF-16 code units) followed by UTF-16BE data.
fn utf16_with_len(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut len = 0usize;
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        len |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    let bytes = buf.get(*pos..*pos + len * 2)?;
    *pos += len * 2;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Swap the synced part of another device's data in: replace
/// `termius_dir/IndexedDB` with `staging/IndexedDB` (an unpacked, verified
/// vault snapshot), by renames within the data directory. The caller must
/// have made sure Termius is not running. On failure the original
/// directory is put back.
pub fn apply(termius_dir: &Path, staging: &Path) -> Result<()> {
    let incoming = staging.join(SYNC_DIR);
    if !incoming.is_dir() {
        return Err(Error::Integrity(format!(
            "the vault snapshot carries no Termius {SYNC_DIR} data"
        )));
    }
    std::fs::create_dir_all(termius_dir)?;
    let live = termius_dir.join(SYNC_DIR);
    let old = termius_dir.join(format!(
        ".{SYNC_DIR}.sync-old-{}",
        util::local_timestamp_string(&util::current_time())
    ));
    let had_live = live.exists();
    if had_live {
        std::fs::rename(&live, &old).map_err(|e| {
            Error::Other(format!(
                "could not move {} aside (is Termius still running?): {e}",
                live.display()
            ))
        })?;
    }
    if let Err(e) = std::fs::rename(&incoming, &live) {
        if had_live {
            let _ = std::fs::rename(&old, &live);
        }
        return Err(Error::Other(format!(
            "could not move the synced data into {}: {e}",
            live.display()
        )));
    }
    if had_live {
        let _ = std::fs::remove_dir_all(&old);
    }
    Ok(())
}

/// Whether the Termius desktop app is running on this machine. When the
/// check itself fails, Termius is assumed to be running — applying data
/// under a running Termius could corrupt it, waiting cannot.
///
/// `TSBAK_TERMIUS_RUNNING=0|1` overrides the detection (tests, and
/// setups where the process name differs).
pub fn termius_running() -> bool {
    if let Ok(v) = std::env::var("TSBAK_TERMIUS_RUNNING") {
        match v.trim() {
            "0" => return false,
            "1" => return true,
            _ => {}
        }
    }
    match detect_running() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("could not check whether Termius is running: {e}");
            true
        }
    }
}

#[cfg(target_os = "windows")]
fn detect_running() -> std::io::Result<bool> {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq Termius.exe", "/FO", "CSV", "/NH"])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("tasklist failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .to_ascii_lowercase()
        .contains("\"termius.exe\""))
}

#[cfg(target_os = "macos")]
fn detect_running() -> std::io::Result<bool> {
    // Exit 0 = a process named exactly "Termius" exists, 1 = none.
    let st = std::process::Command::new("pgrep")
        .args(["-x", "Termius"])
        .stdout(std::process::Stdio::null())
        .status()?;
    match st.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(std::io::Error::other("pgrep failed")),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn detect_running() -> std::io::Result<bool> {
    // The Electron binary is `termius-app` (deb/rpm/AppImage/Snap) or
    // `termius`; never match this tool itself (`termius-backup`).
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let comm = comm.trim().to_ascii_lowercase();
        if comm == "termius" || comm == "termius-app" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Build IndexedDB-shaped LevelDB fixtures.
    use super::*;
    use crate::leveldb::testutil::{batch, log_file};

    /// `KeyPrefix(db, store, index)` with one-byte ids.
    pub fn prefix(db: u8, store: u8, index: u8) -> Vec<u8> {
        vec![0, db, store, index]
    }

    fn utf16_with_len(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = vec![units.len() as u8];
        for u in units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    }

    /// The global key mapping database `name` to id `db`.
    pub fn name_key(name: &str) -> Vec<u8> {
        let mut k = prefix(0, 0, 0);
        k.push(201);
        k.extend(utf16_with_len("file__0"));
        k.extend(utf16_with_len(name));
        k
    }

    /// The object-store record key `key` in database `db`.
    pub fn record_key(db: u8, key: &[u8]) -> Vec<u8> {
        let mut k = prefix(db, 1, 1);
        k.extend_from_slice(key);
        k
    }

    /// The LevelDB directory inside a Termius data directory.
    pub fn idb_dir(termius_dir: &Path) -> std::path::PathBuf {
        termius_dir.join(SYNC_DIR).join("file__0.indexeddb.leveldb")
    }

    /// Write a log file `NNNNNN.log` (number `file_no`) with one batch of
    /// puts/deletes starting at sequence `seq` into the IndexedDB LevelDB
    /// of `termius_dir` (creating it, with `CURRENT`, when missing).
    pub fn write_ops(
        termius_dir: &Path,
        file_no: u32,
        seq: u64,
        ops: &[(Vec<u8>, Option<Vec<u8>>)],
    ) {
        let dir = idb_dir(termius_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let current = dir.join("CURRENT");
        if !current.exists() {
            std::fs::write(current, b"MANIFEST-000001\n").unwrap();
        }
        let ops: Vec<(&[u8], Option<&[u8]>)> = ops
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_deref()))
            .collect();
        std::fs::write(
            dir.join(format!("{file_no:06}.log")),
            log_file(&[batch(seq, &ops)]),
        )
        .unwrap();
    }

    /// A fresh IndexedDB with the `hosts` (id 2) and `activities` (id 3)
    /// databases, each holding one record.
    pub fn seed(termius_dir: &Path) {
        write_ops(
            termius_dir,
            3,
            1,
            &[
                (name_key("hosts"), Some(vec![2])),
                (name_key("activities"), Some(vec![3])),
                (record_key(2, b"host-1"), Some(b"alpha".to_vec())),
                (record_key(3, b"log-1"), Some(b"connected".to_vec())),
            ],
        );
        std::fs::write(idb_dir(termius_dir).join("LOCK"), b"").unwrap();
        std::fs::write(idb_dir(termius_dir).join("LOG"), b"opened").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn sync_set_is_indexeddb_without_housekeeping() {
        assert!(in_sync_set(Path::new("IndexedDB")));
        assert!(in_sync_set(Path::new(
            "IndexedDB/file__0.indexeddb.leveldb/000003.log"
        )));
        assert!(in_sync_set(Path::new(
            "IndexedDB/file__0.indexeddb.leveldb/CURRENT"
        )));
        assert!(!in_sync_set(Path::new(
            "IndexedDB/file__0.indexeddb.leveldb/LOCK"
        )));
        assert!(!in_sync_set(Path::new(
            "IndexedDB/file__0.indexeddb.leveldb/LOG.old"
        )));
        assert!(!in_sync_set(Path::new("Local Storage/leveldb/000005.ldb")));
        assert!(!in_sync_set(Path::new("Local State")));
        assert!(!in_sync_set(Path::new("Cache/data_0")));
    }

    #[test]
    fn key_prefix_decodes_variable_width_ids() {
        assert_eq!(idb_key_prefix(&[0, 5, 1, 1, 9]), Some((5, 1, 1, 4)));
        // db id in 2 bytes (0x0102 LE), store 1 byte, index 1 byte.
        assert_eq!(
            idb_key_prefix(&[0b0010_0000, 0x02, 0x01, 7, 30]),
            Some((0x0102, 7, 30, 5))
        );
        assert_eq!(idb_key_prefix(&[0, 1]), None);
    }

    #[test]
    fn database_names_are_decoded() {
        let entries = vec![
            (name_key("hosts"), vec![2]),
            (name_key("activities"), vec![3]),
            (record_key(2, b"x"), b"y".to_vec()),
        ];
        let names = idb_database_names(&entries);
        assert_eq!(names.get(&2).map(String::as_str), Some("hosts"));
        assert_eq!(names.get(&3).map(String::as_str), Some("activities"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn fingerprint_is_empty_without_indexeddb() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(fingerprint(t.path()).unwrap(), "");
    }

    #[test]
    fn fingerprint_tracks_user_data_only() {
        let t = tempfile::tempdir().unwrap();
        seed(t.path());
        let base = fingerprint(t.path()).unwrap();
        assert_eq!(base.len(), 64);

        // Housekeeping files and other top-level data do not count.
        std::fs::write(idb_dir(t.path()).join("LOG"), b"reopened").unwrap();
        std::fs::write(t.path().join("Local State"), b"{}").unwrap();
        assert_eq!(fingerprint(t.path()).unwrap(), base);

        // Background writes to a local-only database do not count.
        write_ops(
            t.path(),
            4,
            10,
            &[(record_key(3, b"log-2"), Some(b"disconnected".to_vec()))],
        );
        assert_eq!(fingerprint(t.path()).unwrap(), base);

        // A host edit does.
        write_ops(
            t.path(),
            5,
            20,
            &[(record_key(2, b"host-2"), Some(b"beta".to_vec()))],
        );
        let edited = fingerprint(t.path()).unwrap();
        assert_ne!(edited, base);

        // Deleting it again restores the original fingerprint: it is a
        // function of the logical contents, not of the file history.
        write_ops(t.path(), 6, 30, &[(record_key(2, b"host-2"), None)]);
        assert_eq!(fingerprint(t.path()).unwrap(), base);
    }

    #[test]
    fn unreadable_leveldb_falls_back_to_file_hashes() {
        let t = tempfile::tempdir().unwrap();
        seed(t.path());
        let dir = idb_dir(t.path());
        std::fs::write(dir.join("000009.ldb"), b"not a table").unwrap();
        let a = fingerprint(t.path()).unwrap();
        std::fs::write(dir.join("000009.ldb"), b"still not a table").unwrap();
        let b = fingerprint(t.path()).unwrap();
        assert_ne!(a, b, "file-hash fallback must still see changes");
    }

    #[test]
    fn apply_swaps_only_indexeddb() {
        let live = tempfile::tempdir().unwrap();
        seed(live.path());
        std::fs::write(live.path().join("Local State"), b"mine").unwrap();
        let staging = tempfile::tempdir().unwrap();
        write_ops(
            staging.path(),
            3,
            1,
            &[
                (name_key("hosts"), Some(vec![2])),
                (record_key(2, b"host-9"), Some(b"remote".to_vec())),
            ],
        );
        std::fs::write(staging.path().join("Local State"), b"theirs").unwrap();
        let want = fingerprint(staging.path()).unwrap();

        apply(live.path(), staging.path()).unwrap();
        assert_eq!(fingerprint(live.path()).unwrap(), want);
        assert_eq!(
            std::fs::read(live.path().join("Local State")).unwrap(),
            b"mine"
        );
        // No leftovers from the swap.
        let leftovers: Vec<_> = std::fs::read_dir(live.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("sync-old"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn apply_without_incoming_data_fails_and_keeps_live() {
        let live = tempfile::tempdir().unwrap();
        seed(live.path());
        let before = fingerprint(live.path()).unwrap();
        let staging = tempfile::tempdir().unwrap();
        assert!(apply(live.path(), staging.path()).is_err());
        assert_eq!(fingerprint(live.path()).unwrap(), before);
    }

    #[test]
    fn running_override() {
        // Only the override is testable portably; detection itself is
        // platform plumbing.
        std::env::set_var("TSBAK_TERMIUS_RUNNING", "0");
        assert!(!termius_running());
        std::env::set_var("TSBAK_TERMIUS_RUNNING", "1");
        assert!(termius_running());
        std::env::remove_var("TSBAK_TERMIUS_RUNNING");
    }
}
