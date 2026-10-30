// SPDX-License-Identifier: Apache-2.0

//! Archive (tar + zstd) packing/unpacking of the Termius data directory.
//!
//! The encrypted payload layout is:
//! `zstd( tar([<tree of the termius dir>, __meta.json]) )`
//!
//! `__meta.json` carries provenance metadata so a restored tree can be
//! verified. It lives *inside* the encrypted envelope, so it leaks nothing
//! without the password. [`unpack`] finds it by name, so its position in
//! the tar is not significant (archives made before the single-pass pack
//! store it first; new ones append it after the tree).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::util;

/// Inner-metadata entry name. Found by name at unpack time, so its position
/// in the tar is not significant.
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

/// Accumulators for the single pack walk.
#[derive(Default)]
struct PackStats {
    byte_size: u64,
    entry_count: u64,
}

/// One entry of an archived tree, recorded by [`unpack`] as it is written
/// to disk. The manifest is derived from the (AEAD-protected) tar itself,
/// so it is authoritative for what the archive contained — [`verify`]
/// uses it as a fallback when the recorded root hash was computed with a
/// platform-dependent scheme by an older release.
#[derive(Debug, Clone)]
pub struct TarEntry {
    /// Relative name with `/` separators.
    pub name: String,
    /// `b'd'` directory, `b'f'` file, `b'l'` symlink.
    pub kind: u8,
    /// File size in bytes (0 for directories and symlinks).
    pub size: u64,
    /// File: lowercase hex SHA-256 of the content. Symlink: link target.
    /// Directory: empty.
    pub digest: String,
}

/// Pack `root` (a directory) into a zstd-compressed tar held in `out`.
/// `created_at` is an ISO-8601 timestamp string.
///
/// The tree is walked exactly once: every entry is appended to the tar and
/// fed into the tree hash as it goes, and each file's content is streamed
/// into the tar and its content hash at the same time (each byte is read
/// exactly once). The recorded `sha256_root` therefore always describes
/// precisely what was packed — even when the source is a live directory
/// (a running Termius) that keeps changing during the pack.
pub fn pack(root: &Path, out: &mut Vec<u8>, created_at: &str) -> Result<ArchiveMeta> {
    if !root.is_dir() {
        return Err(Error::NotFound(format!(
            "source is not a directory: {}",
            root.display()
        )));
    }

    let mut root_hasher = Sha256::new();
    let mut stats = PackStats::default();
    let mut tar_buf: Vec<u8> = Vec::new();
    let meta;
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        builder.mode(tar::HeaderMode::Deterministic);
        append_dir_recursive(&mut builder, root, root, &mut root_hasher, &mut stats)?;

        // __meta.json rides along as a tar entry after the tree;
        // [`unpack`] finds it by name, so its position is not significant.
        meta = ArchiveMeta {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            source_dir: root.display().to_string(),
            entry_count: stats.entry_count,
            byte_size: stats.byte_size,
            sha256_root: util::hex::encode_lower_owned(&root_hasher.finalize()),
            created_at: created_at.to_string(),
        };
        let meta_bytes = serde_json::to_vec(&meta)?;
        let mut hdr = tar::Header::new_gnu();
        hdr.set_path(META_ENTRY_NAME)?;
        hdr.set_size(meta_bytes.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_mtime(0);
        hdr.set_cksum();
        builder.append(&hdr, std::io::Cursor::new(&meta_bytes))?;
        builder.finish()?;
    }

    // zstd-compress the tar.
    let mut encoder = zstd::stream::Encoder::new(out, ZSTD_LEVEL)?;
    encoder.write_all(&tar_buf)?;
    encoder.finish()?;
    Ok(meta)
}

/// A `Read` adapter that mirrors every byte it reads into a SHA-256
/// hasher, so a file's content is read exactly once and feeds both the
/// tar entry and the tree hash.
struct TeeRead<'a> {
    inner: &'a mut dyn Read,
    hasher: &'a mut Sha256,
}

impl Read for TeeRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Feed one tree entry into the hash: the relative path, a type byte
/// (`l`/`d`/`f`), the entry size, then a type-specific payload (a file's
/// content hash or a symlink's target; directories pass none — their
/// children are hashed by the caller's recursion). This must stay in
/// lockstep with what [`append_dir_recursive`] puts in the tar.
///
/// `rel` must be the path with `/` as separator: `Path::display()` uses
/// the native separator (`\` on Windows), which would make the tree hash
/// platform-dependent — a backup packed on Linux/macOS would never
/// verify on Windows (and vice versa). Tar member names are already
/// `/`-normalized by the tar crate, so this matches them.
fn hash_tree_entry(hasher: &mut Sha256, rel: &str, type_byte: u8, len: u64, payload: &[u8]) {
    hasher.update(rel.as_bytes());
    hasher.update([type_byte]);
    hasher.update(len.to_le_bytes());
    hasher.update(payload);
}

/// The `sep`-separated form of `path` relative to `root` — the name fed
/// into the tree hash (see [`hash_tree_entry`]). The canonical form uses
/// `sep = '/'`.
fn rel_name(root: &Path, path: &Path, sep: char) -> String {
    let sep = sep.to_string();
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(&sep)
}

/// Append a directory tree to the tar builder, preserving permissions,
/// mtimes, and symlinks. Paths are stored relative to `root`.
///
/// Every entry appended is also fed into `root_hasher` and counted in
/// `stats` in the same walk, and each file's content is streamed into
/// both the tar entry and its content hash via [`TeeRead`] — so the
/// recorded hash always describes exactly what was packed, even when the
/// source is a live directory (a running Termius) that changes while the
/// pack is underway. Sockets and fifos are skipped: the tar format cannot
/// carry them, so they are excluded from the hash as well (a restored
/// tree likewise never contains them).
fn append_dir_recursive(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    root: &Path,
    current: &Path,
    root_hasher: &mut Sha256,
    stats: &mut PackStats,
) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
    // Sort for deterministic archives (and hash order).
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let meta = std::fs::symlink_metadata(&path)?;
        if !(meta.is_file() || meta.is_symlink() || meta.is_dir()) {
            continue; // sockets, fifos: not representable in the tar
        }
        stats.entry_count += 1;
        let mtime = meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if meta.is_symlink() {
            let target = std::fs::read_link(&path)?;
            let target_lossy = target.to_string_lossy().into_owned();
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_entry_type(tar::EntryType::Symlink);
            hdr.set_link_name(target_lossy.as_str())?;
            hdr.set_size(0);
            hdr.set_mode(perm_mode(&meta, false));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, std::io::empty())?;
            // A symlink's st_size is platform-dependent (POSIX reports the
            // target length, Windows 0) — like directory sizes it is not
            // part of the tree's identity, so hash it as 0.
            hash_tree_entry(
                root_hasher,
                &rel_name(root, &path, '/'),
                b'l',
                0,
                target_lossy.as_bytes(),
            );
        } else if meta.is_dir() {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_entry_type(tar::EntryType::Directory);
            hdr.set_size(0);
            hdr.set_mode(perm_mode(&meta, true));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, std::io::empty())?;
            // Directory size is filesystem-dependent (ext4 reports a
            // non-zero st_size, Windows always 0) — not part of the
            // tree's identity, so hash it as 0.
            hash_tree_entry(root_hasher, &rel_name(root, &path, '/'), b'd', 0, &[]);
            append_dir_recursive(builder, root, &path, root_hasher, stats)?;
        } else {
            let mut f = std::fs::File::open(&path)?;
            let mut content_hash = Sha256::new();
            let mut tee = TeeRead {
                inner: &mut f,
                hasher: &mut content_hash,
            };
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path(rel)?;
            hdr.set_size(meta.len());
            hdr.set_mode(perm_mode(&meta, false));
            hdr.set_mtime(mtime);
            hdr.set_cksum();
            builder.append(&hdr, &mut tee)?;
            let digest = content_hash.finalize();
            hash_tree_entry(
                root_hasher,
                &rel_name(root, &path, '/'),
                b'f',
                meta.len(),
                util::hex::encode_lower_owned(&digest).as_bytes(),
            );
            stats.byte_size += meta.len();
        }
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

/// Unpack an archive produced by [`pack`] into `dest`, returning the
/// parsed metadata and a per-entry manifest of everything that was
/// written (see [`TarEntry`]). `dest` is created if missing. Existing
/// contents are NOT cleared by this function — callers manage overwrite
/// semantics.
pub fn unpack(data: &[u8], dest: &Path) -> Result<(ArchiveMeta, Vec<TarEntry>)> {
    std::fs::create_dir_all(dest)?;
    let mut decoder = zstd::stream::Decoder::new(data)?;
    let mut tar_buf = Vec::new();
    decoder.read_to_end(&mut tar_buf)?;

    let mut archive = tar::Archive::new(&tar_buf[..]);
    let mut meta: Option<ArchiveMeta> = None;
    let mut manifest: Vec<TarEntry> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        // Owned so the borrow on `entry` ends before the mutable
        // `set_preserve_permissions`/`unpack_in` calls below.
        let name = entry.path()?.to_path_buf();
        if name == std::path::Path::new(META_ENTRY_NAME) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            meta = Some(serde_json::from_slice(&buf)?);
            continue;
        }
        // Unpack entries relative to dest, preserving perms/symlinks.
        entry.set_preserve_permissions(true);
        entry.unpack_in(dest)?;
        let et = entry.header().entry_type();
        if et.is_file() {
            // Hash what actually landed on disk (the AEAD-protected tar is
            // the source of truth for the fallback check).
            let digest = util::sha256_file(&dest.join(&name))?;
            manifest.push(TarEntry {
                name: slash_name(&name),
                kind: b'f',
                size: entry.header().size()?,
                digest,
            });
        } else if et.is_dir() {
            manifest.push(TarEntry {
                name: slash_name(&name),
                kind: b'd',
                size: 0,
                digest: String::new(),
            });
        } else if et.is_symlink() {
            let target = entry
                .link_name()?
                .map(|t| t.to_string_lossy().into_owned())
                .unwrap_or_default();
            manifest.push(TarEntry {
                name: slash_name(&name),
                kind: b'l',
                size: 0,
                digest: target,
            });
        }
        // Other member types (hard links, char/block devices) are not
        // produced by [`pack`]; if one appears, it is restored but not
        // tracked by the manifest.
    }
    let meta = meta.ok_or_else(|| Error::BadFormat {
        detail: "archive is missing __meta.json".into(),
        offset: 0,
    })?;
    Ok((meta, manifest))
}

/// The `/`-separated form of a path whose components are joined with the
/// native separator (the tar crate converts member names to the native
/// separator when unpacking off-Unix).
fn slash_name(p: &Path) -> String {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Compute a stable hash over a directory tree: a recursive Merkle-like
/// digest of (path, type, size, file-content-hash / symlink-target). This
/// mirrors [`hash_tree_entry`] exactly, so it matches the hash recorded at
/// pack time. Sockets and fifos are skipped (a restored tree never contains
/// them). Used to verify round-trips.
fn tree_hash(root: &Path, sep: char) -> Result<String> {
    let mut hasher = Sha256::new();
    tree_hash_into(root, root, &mut hasher, sep)?;
    Ok(util::hex::encode_lower_owned(&hasher.finalize()))
}

fn tree_hash_into(root: &Path, current: &Path, hasher: &mut Sha256, sep: char) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            // Directory size is filesystem-dependent — hashed as 0 (see
            // the matching comment in [`append_dir_recursive`]).
            hash_tree_entry(hasher, &rel_name(root, &path, sep), b'd', 0, &[]);
            tree_hash_into(root, &path, hasher, sep)?;
        } else if meta.is_file() {
            let h = util::sha256_file(&path)?;
            hash_tree_entry(
                hasher,
                &rel_name(root, &path, sep),
                b'f',
                meta.len(),
                h.as_bytes(),
            );
        } else if meta.is_symlink() {
            let t = std::fs::read_link(&path)?;
            // Symlink st_size is platform-dependent — hashed as 0 (see the
            // matching comment in [`append_dir_recursive`]).
            hash_tree_entry(
                hasher,
                &rel_name(root, &path, sep),
                b'l',
                0,
                t.to_string_lossy().as_bytes(),
            );
        }
        // Sockets, fifos: skipped (not representable in the tar).
    }
    Ok(())
}

/// Verify that a directory tree matches the recorded metadata (used after
/// restore). Returns Ok(()) if the root hash matches.
pub fn verify(dest: &Path, meta: &ArchiveMeta, manifest: &[TarEntry]) -> Result<()> {
    let actual = tree_hash(dest, '/')?;
    if util::ct_eq(actual.as_bytes(), meta.sha256_root.as_bytes()) {
        return Ok(());
    }
    // A release before slash-normalization recorded the native separator
    // in the hash (on Windows, `\`). Re-check with it so such a backup
    // still verifies on the platform it was packed on.
    let native = std::path::MAIN_SEPARATOR;
    if native != '/' {
        let legacy = tree_hash(dest, native)?;
        if util::ct_eq(legacy.as_bytes(), meta.sha256_root.as_bytes()) {
            return Ok(());
        }
    }
    // The recorded root hash came from a release whose scheme embedded
    // platform-specific details (ext4 directory `st_size`, …). The tree
    // may still be intact — compare it entry-by-entry against the
    // manifest the unpack recorded from the AEAD-protected tar.
    verify_against_manifest(dest, manifest).map_err(|e| {
        Error::Integrity(format!(
            "restored tree does not match the archive: expected root hash {}, got {}, and per-entry check found: {e}",
            meta.sha256_root, actual
        ))
    })
}

/// Compare the tree under `dest` against the per-entry manifest recorded
/// by [`unpack`]. Every manifest entry must exist on disk with the same
/// type; files must match in size and content hash, symlinks in target,
/// directories are matched by name alone. Any entry on disk that is not
/// in the manifest is a failure (a restore stages into an empty dir).
fn verify_against_manifest(dest: &Path, manifest: &[TarEntry]) -> Result<()> {
    let mut expected: std::collections::BTreeMap<&str, &TarEntry> =
        std::collections::BTreeMap::new();
    for e in manifest {
        if expected.insert(e.name.as_str(), e).is_some() {
            return Err(Error::Integrity(format!(
                "archive lists entry {} more than once",
                e.name
            )));
        }
    }
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    walk_against_manifest(dest, dest, &mut expected, &mut seen)?;
    let missing: Vec<&str> = expected
        .keys()
        .copied()
        .filter(|n| !seen.contains(*n))
        .collect();
    if !missing.is_empty() {
        return Err(Error::Integrity(format!(
            "entries missing from restored tree: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn walk_against_manifest(
    root: &Path,
    current: &Path,
    expected: &mut std::collections::BTreeMap<&str, &TarEntry>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let name = rel_name(root, &path, '/');
        let exp = expected.remove(name.as_str()).ok_or_else(|| {
            Error::Integrity(format!("unexpected entry in restored tree: {name}"))
        })?;
        seen.insert(name);
        if meta.is_dir() {
            if exp.kind != b'd' {
                return Err(Error::Integrity(format!(
                    "entry {}: archive has a {}, tree has a directory",
                    path.display(),
                    kind_name(exp.kind)
                )));
            }
            walk_against_manifest(root, &path, expected, seen)?;
        } else if meta.is_file() {
            if exp.kind != b'f' {
                return Err(Error::Integrity(format!(
                    "entry {}: archive has a {}, tree has a file",
                    path.display(),
                    kind_name(exp.kind)
                )));
            }
            if meta.len() != exp.size {
                return Err(Error::Integrity(format!(
                    "entry {}: size {} does not match archive size {}",
                    path.display(),
                    meta.len(),
                    exp.size
                )));
            }
            let h = util::sha256_file(&path)?;
            if !util::ct_eq(h.as_bytes(), exp.digest.as_bytes()) {
                return Err(Error::Integrity(format!(
                    "entry {}: content hash {} does not match archive hash {}",
                    path.display(),
                    h,
                    exp.digest
                )));
            }
        } else if meta.is_symlink() {
            if exp.kind != b'l' {
                return Err(Error::Integrity(format!(
                    "entry {}: archive has a {}, tree has a symlink",
                    path.display(),
                    kind_name(exp.kind)
                )));
            }
            let t = std::fs::read_link(&path)?;
            if t.to_string_lossy() != exp.digest {
                return Err(Error::Integrity(format!(
                    "entry {}: symlink target {} does not match archive target {}",
                    path.display(),
                    t.display(),
                    exp.digest
                )));
            }
        } else {
            // Sockets, fifos: cannot come from the tar, so they are not
            // tracked by the manifest.
            return Err(Error::Integrity(format!(
                "entry {}: unsupported file type in restored tree",
                path.display()
            )));
        }
    }
    Ok(())
}

/// `b'd'`/`b'f'`/`b'l'` as a word, for error messages.
fn kind_name(kind: u8) -> &'static str {
    match kind {
        b'd' => "directory",
        b'f' => "file",
        b'l' => "symlink",
        _ => "unknown entry",
    }
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
        let (got, manifest) = unpack(&buf, dest.path()).unwrap();
        assert_eq!(got.sha256_root, meta.sha256_root);
        verify(dest.path(), &got, &manifest).unwrap();

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
        let (got, manifest) = unpack(&buf, dest.path()).unwrap();
        verify(dest.path(), &got, &manifest).unwrap();
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
        let (_, manifest) = unpack(&buf, dest.path()).unwrap();
        fs::write(dest.path().join("f"), b"tampered").unwrap();
        assert!(verify(dest.path(), &meta, &manifest).is_err());
    }

    /// A backup packed by an older release whose recorded root hash
    /// embedded platform-specific details (e.g. ext4 directory `st_size`)
    /// cannot match on any platform — but the tree is intact, and the
    /// per-entry manifest check (derived from the AEAD-protected tar)
    /// must accept it.
    #[test]
    fn verify_falls_back_to_manifest_for_legacy_root_hash() {
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let mut buf = Vec::new();
        pack(src.path(), &mut buf, "t").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let (mut got, manifest) = unpack(&buf, dest.path()).unwrap();
        // Simulate the older release's hash: non-empty, but unmatchable.
        got.sha256_root = "0".repeat(64);
        verify(dest.path(), &got, &manifest).unwrap();
    }

    /// The fallback must still catch real damage: a tree whose root hash
    /// mismatches AND whose entries diverge from the manifest fails.
    #[test]
    fn verify_fallback_rejects_tampered_tree() {
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let mut buf = Vec::new();
        pack(src.path(), &mut buf, "t").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let (got, manifest) = unpack(&buf, dest.path()).unwrap();
        fs::write(dest.path().join("hello.txt"), b"tampered").unwrap();
        let mut legacy = got.clone();
        legacy.sha256_root = "0".repeat(64);
        assert!(verify(dest.path(), &legacy, &manifest).is_err());
    }

    /// A tree containing a Unix-domain socket (which the tar format cannot
    /// carry) must still round-trip and verify: the socket is skipped by
    /// both the pack hash and the tar, so the recorded hash matches the
    /// restored tree. This is exactly the class of file a running Termius
    /// leaves in its data dir (`app.*` single-instance sockets), and it is
    /// the bug behind "restored tree hash mismatch" on a live dir.
    #[cfg(unix)]
    #[test]
    fn socket_in_tree_still_round_trips_and_verifies() {
        use std::os::unix::net::UnixListener;
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("f.txt"), b"content").unwrap();
        fs::create_dir_all(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/inner.txt"), b"inner").unwrap();
        let _sock = UnixListener::bind(src.path().join("sock")).unwrap();

        let mut buf = Vec::new();
        let meta = pack(src.path(), &mut buf, "t").unwrap();
        // The socket is not an archived entry.
        assert_eq!(meta.entry_count, 3);
        assert_eq!(meta.byte_size, 12);

        let dest = tempfile::tempdir().unwrap();
        let (got, manifest) = unpack(&buf, dest.path()).unwrap();
        assert_eq!(got.sha256_root, meta.sha256_root);
        verify(dest.path(), &got, &manifest).unwrap();
        // The socket was not (and cannot be) restored.
        assert!(!dest.path().join("sock").exists());
    }
}
