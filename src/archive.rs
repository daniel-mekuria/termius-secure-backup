// SPDX-License-Identifier: Apache-2.0

//! Archive (tar + zstd) packing/unpacking of the Termius data directory.
//!
//! The encrypted payload layout is:
//! `zstd( tar([__meta.json, <tree of the termius dir>]) )`
//!
//! `__meta.json` is the first entry and carries provenance metadata so a
//! restored tree can be verified. It lives *inside* the encrypted envelope,
//! so it leaks nothing without the password.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::util;

/// Inner-metadata entry name, stored as the first tar entry.
pub const META_ENTRY_NAME: &str = "__meta.json";

/// Zstandard compression level (1–19; 3 is a fast/balance default).
const ZSTD_LEVEL: i32 = 3;

/// Inner metadata describing the archived tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMeta {
    pub tool_version: String,
    pub source_dir: String,
    pub entry_count: u64,
    pub byte_size: u64,
    pub sha256_root: String,
    pub created_at: String,
}

/// Pack `root` (a directory) into a zstd-compressed tar held in `out`.
/// `created_at` is an ISO-8601 timestamp string.
pub fn pack(root: &Path, out: &mut Vec<u8>, created_at: &str) -> Result<ArchiveMeta> {
    if !root.is_dir() {
        return Err(Error::NotFound(format!(
            "source is not a directory: {}",
            root.display()
        )));
    }
    let (byte_size, entry_count) = util::dir_stats(root)?;
    let root_hash = tree_hash(root)?;
    let meta = ArchiveMeta {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source_dir: root.display().to_string(),
        entry_count,
        byte_size,
        sha256_root: root_hash,
        created_at: created_at.to_string(),
    };

    let meta_bytes = serde_json::to_vec(&meta)?;

    // Build the tar archive into a buffer, then zstd-compress it.
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        builder.mode(tar::HeaderMode::Deterministic);

        // First entry: __meta.json
        let mut hdr = tar::Header::new_gnu();
        hdr.set_path(META_ENTRY_NAME)?;
        hdr.set_size(meta_bytes.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_mtime(0);
        hdr.set_cksum();
        builder.append(&hdr, std::io::Cursor::new(&meta_bytes))?;

        append_dir_recursive(&mut builder, root, root)?;
        builder.finish()?;
    }

    // zstd-compress the tar.
    let mut encoder = zstd::stream::Encoder::new(out, ZSTD_LEVEL)?;
    encoder.write_all(&tar_buf)?;
    encoder.finish()?;
    Ok(meta)
}

/// Append a directory tree to the tar builder, preserving permissions,
/// mtimes, and symlinks. Paths are stored relative to `root`.
fn append_dir_recursive(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    root: &Path,
    current: &Path,
) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
    // Sort for deterministic archives.
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let meta = std::fs::symlink_metadata(&path)?;
        let mtime = meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if meta.is_symlink() {
            let target = std::fs::read_link(&path)?;
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_entry_type(tar::EntryType::Symlink);
            hdr.set_link_name(target.to_string_lossy().as_ref())?;
            hdr.set_size(0);
            hdr.set_mode(perm_mode(&meta, false));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, std::io::empty())?;
        } else if meta.is_dir() {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_entry_type(tar::EntryType::Directory);
            hdr.set_size(0);
            hdr.set_mode(perm_mode(&meta, true));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, std::io::empty())?;
            append_dir_recursive(builder, root, &path)?;
        } else if meta.is_file() {
            let mut f = std::fs::File::open(&path)?;
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_size(meta.len());
            hdr.set_mode(perm_mode(&meta, false));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, &mut f)?;
        }
        // Other types (sockets, fifos) are skipped.
    }
    Ok(())
}

/// Read the permission bits of a metadata entry. On non-Unix platforms
/// (which lack POSIX mode bits) return a sensible default.
fn perm_mode(meta: &std::fs::Metadata, is_dir: bool) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = is_dir;
        meta.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        if is_dir {
            0o755
        } else {
            0o644
        }
    }
}

/// Unpack an archive produced by [`pack`] into `dest`, returning the parsed
/// metadata. `dest` is created if missing. Existing contents are NOT cleared
/// by this function — callers manage overwrite semantics.
pub fn unpack(data: &[u8], dest: &Path) -> Result<ArchiveMeta> {
    std::fs::create_dir_all(dest)?;
    let mut decoder = zstd::stream::Decoder::new(data)?;
    let mut tar_buf = Vec::new();
    decoder.read_to_end(&mut tar_buf)?;

    let mut archive = tar::Archive::new(&tar_buf[..]);
    let mut meta: Option<ArchiveMeta> = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?;
        if name == std::path::Path::new(META_ENTRY_NAME) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            meta = Some(serde_json::from_slice(&buf)?);
            continue;
        }
        // Unpack entries relative to dest, preserving perms/symlinks.
        entry.set_preserve_permissions(true);
        entry.unpack_in(dest)?;
    }
    let meta = meta.ok_or_else(|| Error::BadFormat {
        detail: "archive is missing __meta.json".into(),
        offset: 0,
    })?;
    Ok(meta)
}

/// Compute a stable hash over a directory tree: a recursive Merkle-like
/// digest of (path, type, size, mtime, file-content-hash). Used to verify
/// round-trips.
fn tree_hash(root: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    tree_hash_into(root, root, &mut hasher)?;
    Ok(util::hex::encode_lower_owned(&hasher.finalize()))
}

fn tree_hash_into(root: &Path, current: &Path, hasher: &mut sha2::Sha256) -> Result<()> {
    use sha2::Digest;
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let meta = std::fs::symlink_metadata(&path)?;
        hasher.update(rel.as_bytes());
        hasher.update([entry_type_byte(&meta)]);
        hasher.update(meta.len().to_le_bytes());
        if meta.is_file() {
            let h = util::sha256_file(&path)?;
            hasher.update(h.as_bytes());
        } else if meta.is_symlink() {
            let t = std::fs::read_link(&path)?;
            hasher.update(t.to_string_lossy().as_bytes());
        } else if meta.is_dir() {
            tree_hash_into(root, &path, hasher)?;
        }
    }
    Ok(())
}

fn entry_type_byte(meta: &std::fs::Metadata) -> u8 {
    if meta.is_symlink() {
        b'l'
    } else if meta.is_dir() {
        b'd'
    } else if meta.is_file() {
        b'f'
    } else {
        b'?'
    }
}

/// Verify that a directory tree matches the recorded metadata (used after
/// restore). Returns Ok(()) if the root hash matches.
pub fn verify(dest: &Path, meta: &ArchiveMeta) -> Result<()> {
    let actual = tree_hash(dest)?;
    if !util::ct_eq(actual.as_bytes(), meta.sha256_root.as_bytes()) {
        return Err(Error::Integrity(format!(
            "restored tree hash mismatch: expected {}, got {}",
            meta.sha256_root, actual
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_tree(root: &Path) {
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        fs::write(root.join("hello.txt"), b"hello world").unwrap();
        fs::write(
            root.join("sub/deeper/unicode-名前.txt"),
            "名前 = name".as_bytes(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("hello.txt"), fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink("hello.txt", root.join("link-to-hello")).unwrap();
        }
    }

    #[test]
    fn round_trip_preserves_tree() {
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let mut buf = Vec::new();
        let meta = pack(src.path(), &mut buf, "2026-01-01T00:00:00Z").unwrap();
        assert!(meta.entry_count > 0);

        let dest = tempfile::tempdir().unwrap();
        let got = unpack(&buf, dest.path()).unwrap();
        assert_eq!(got.sha256_root, meta.sha256_root);
        verify(dest.path(), &got).unwrap();

        // contents
        let txt = fs::read_to_string(dest.path().join("hello.txt")).unwrap();
        assert_eq!(txt, "hello world");
        let uni = fs::read_to_string(dest.path().join("sub/deeper/unicode-名前.txt")).unwrap();
        assert_eq!(uni, "名前 = name");
    }

    #[test]
    fn empty_dir_round_trips() {
        let src = tempfile::tempdir().unwrap();
        let mut buf = Vec::new();
        let meta = pack(src.path(), &mut buf, "2026-01-01T00:00:00Z").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let got = unpack(&buf, dest.path()).unwrap();
        verify(dest.path(), &got).unwrap();
        assert_eq!(got.sha256_root, meta.sha256_root);
    }

    #[test]
    fn nested_dirs_and_spaces() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("a b/c d")).unwrap();
        fs::write(src.path().join("a b/c d/file with spaces.txt"), b"x").unwrap();
        let mut buf = Vec::new();
        pack(src.path(), &mut buf, "t").unwrap();
        let dest = tempfile::tempdir().unwrap();
        unpack(&buf, dest.path()).unwrap();
        assert!(dest.path().join("a b/c d/file with spaces.txt").exists());
    }

    #[test]
    fn archive_is_zstd_compressed() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f.txt"), b"AAAAAAAAAA").unwrap();
        let mut buf = Vec::new();
        pack(src.path(), &mut buf, "t").unwrap();
        // zstd magic: 0x28 0xB5 0x2F 0xFD
        assert_eq!(&buf[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    }

    #[test]
    fn single_file_trees_differ_by_content() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(a.path().join("f"), b"content-a").unwrap();
        fs::write(b.path().join("f"), b"content-b").unwrap();
        let mut ba = Vec::new();
        let mut bb = Vec::new();
        let ma = pack(a.path(), &mut ba, "t").unwrap();
        let mb = pack(b.path(), &mut bb, "t").unwrap();
        assert_ne!(ma.sha256_root, mb.sha256_root);
    }

    #[test]
    fn mismatched_dest_fails_verify() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f"), b"original").unwrap();
        let mut buf = Vec::new();
        let meta = pack(src.path(), &mut buf, "t").unwrap();
        let dest = tempfile::tempdir().unwrap();
        unpack(&buf, dest.path()).unwrap();
        fs::write(dest.path().join("f"), b"tampered").unwrap();
        assert!(verify(dest.path(), &meta).is_err());
    }
}
