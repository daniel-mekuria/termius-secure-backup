// SPDX-License-Identifier: Apache-2.0

//! Tagged, **unencrypted** rollback snapshots of the live Termius directory.
//!
//! A snapshot is a directory under the snapshots root:
//! - `data.tar`  — plain tar of the live Termius dir (perms/symlinks preserved)
//! - `manifest.json` — tag metadata (reason, timestamps, provenance)
//!
//! The snapshots root also holds `index.json`, a cache of all manifests for
//! fast listing. It is rebuilt whenever snapshots change.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::util;

/// Why a snapshot was taken.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// Taken automatically before a restore overwrites the live dir.
    PreRestore,
    /// Taken automatically before a rollback overwrites the live dir.
    PreRollback,
    /// Taken on explicit user request.
    Manual,
}

impl Reason {
    pub fn as_tag(&self) -> &'static str {
        match self {
            Reason::PreRestore => "pre-restore",
            Reason::PreRollback => "pre-rollback",
            Reason::Manual => "manual",
        }
    }
    #[allow(dead_code)]
    pub fn from_tag(s: &str) -> Option<Self> {
        match s {
            "pre-restore" => Some(Reason::PreRestore),
            "pre-rollback" => Some(Reason::PreRollback),
            "manual" => Some(Reason::Manual),
            _ => None,
        }
    }
}

/// Snapshot tag metadata, persisted as `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub created_at: String,
    pub reason: String,
    pub source_dir: String,
    pub trigger_file: Option<String>,
    pub trigger_sha256: Option<String>,
    pub entry_count: u64,
    pub byte_size: u64,
    pub tool_version: String,
}

impl Manifest {
    fn manifest_path(snapshots_dir: &Path, id: &str) -> PathBuf {
        snapshots_dir.join(id).join("manifest.json")
    }
    fn data_path(snapshots_dir: &Path, id: &str) -> PathBuf {
        snapshots_dir.join(id).join("data.tar")
    }
}

/// The cached index of all snapshots, newest-first.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Index {
    pub entries: Vec<Manifest>,
}

/// Create a tagged snapshot of `source_dir` under `snapshots_dir`.
///
/// `trigger_file`/`trigger_sha256` describe the `.tsb` (or other) file that
/// caused the snapshot, for `pre-restore` provenance. Returns the manifest.
pub fn create(
    snapshots_dir: &Path,
    source_dir: &Path,
    reason: Reason,
    trigger: Option<(&Path, &str)>,
    now: &time::OffsetDateTime,
) -> Result<Manifest> {
    util::ensure_dir(snapshots_dir)?;
    if !source_dir.is_dir() {
        return Err(Error::NotFound(format!(
            "cannot snapshot a non-directory: {}",
            source_dir.display()
        )));
    }
    let (byte_size, entry_count) = util::dir_stats(source_dir)?;
    let trigger_sha = trigger
        .map(|(p, _)| util::sha256_file(p).unwrap_or_default())
        .unwrap_or_default();
    let id = util::snapshot_id(now, reason.as_tag(), &trigger_sha);
    let snap_dir = snapshots_dir.join(&id);
    util::ensure_dir(&snap_dir)?;

    // Write the plain tar.
    let data_path = snap_dir.join("data.tar");
    let data_bytes = pack_plain_tar(source_dir)?;
    util::atomic_write(&data_path, &data_bytes)?;

    let manifest = Manifest {
        id: id.clone(),
        created_at: util::local_timestamp_string(now),
        reason: reason.as_tag().to_string(),
        source_dir: source_dir.display().to_string(),
        trigger_file: trigger.map(|(p, _)| p.display().to_string()),
        trigger_sha256: if trigger.is_some() {
            Some(trigger_sha)
        } else {
            None
        },
        entry_count,
        byte_size,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    util::atomic_write(
        &Manifest::manifest_path(snapshots_dir, &id),
        &manifest_bytes,
    )?;

    rebuild_index(snapshots_dir)?;
    Ok(manifest)
}

/// List all snapshots, newest-first (by id, which is timestamp-prefixed).
pub fn list(snapshots_dir: &Path) -> Result<Vec<Manifest>> {
    let index_path = crate::paths::snapshots_index_path(snapshots_dir);
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&index_path)?;
    let idx: Index = serde_json::from_slice(&bytes).map_err(|e| Error::BadFormat {
        detail: format!("index.json: {e}"),
        offset: 0,
    })?;
    let mut entries = idx.entries;
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(entries)
}

/// Extract a snapshot's `data.tar` over `dest_dir` (the live Termius dir),
/// replacing its contents. `dest_dir` is cleared first.
pub fn restore(snapshots_dir: &Path, id: &str, dest_dir: &Path) -> Result<()> {
    let data_path = Manifest::data_path(snapshots_dir, id);
    if !data_path.exists() {
        return Err(Error::SnapshotNotFound(id.to_string()));
    }
    if dest_dir.exists() {
        // Remove existing contents, then recreate.
        let _ = std::fs::remove_dir_all(dest_dir);
    }
    std::fs::create_dir_all(dest_dir)?;
    let mut archive = tar::Archive::new(std::fs::File::open(&data_path)?);
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry.set_preserve_permissions(true);
        entry.unpack_in(dest_dir)?;
    }
    Ok(())
}

/// Delete snapshots older than the newest `keep` per `source_dir`.
/// Returns the number deleted.
pub fn prune(snapshots_dir: &Path, keep: usize) -> Result<usize> {
    let entries = list(snapshots_dir)?;
    let mut by_source: std::collections::HashMap<String, Vec<Manifest>> =
        std::collections::HashMap::new();
    for m in entries {
        by_source.entry(m.source_dir.clone()).or_default().push(m);
    }
    let mut deleted = 0;
    for (_, group) in by_source {
        // group already newest-first from list()
        for m in group.iter().skip(keep) {
            let dir = snapshots_dir.join(&m.id);
            let _ = std::fs::remove_dir_all(&dir);
            deleted += 1;
        }
    }
    if deleted > 0 {
        rebuild_index(snapshots_dir)?;
    }
    Ok(deleted)
}

/// Rebuild `index.json` from the on-disk manifests.
fn rebuild_index(snapshots_dir: &Path) -> Result<()> {
    let mut entries = Vec::new();
    if snapshots_dir.exists() {
        for e in std::fs::read_dir(snapshots_dir)? {
            let e = e?;
            let mp = e.path().join("manifest.json");
            if mp.is_file() {
                let bytes = std::fs::read(&mp)?;
                if let Ok(m) = serde_json::from_slice::<Manifest>(&bytes) {
                    entries.push(m);
                }
            }
        }
    }
    entries.sort_by(|a, b| b.id.cmp(&a.id));
    let idx = Index { entries };
    let bytes = serde_json::to_vec_pretty(&idx)?;
    util::atomic_write(&crate::paths::snapshots_index_path(snapshots_dir), &bytes)?;
    Ok(())
}

/// Pack `root` into a plain (uncompressed) tar in memory.
fn pack_plain_tar(root: &Path) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        builder.mode(tar::HeaderMode::Deterministic);
        append_dir_recursive(&mut builder, root, root)?;
        builder.finish()?;
    }
    Ok(buf)
}

fn append_dir_recursive(
    builder: &mut tar::Builder<&mut Vec<u8>>,
    root: &Path,
    current: &Path,
) -> Result<()> {
    let mut entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(current)?.collect::<std::result::Result<_, _>>()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    fn make_tree(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("hello.txt"), b"hello").unwrap();
        std::fs::write(root.join("sub/a.txt"), b"a").unwrap();
    }

    #[test]
    fn create_then_list() {
        let snaps = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let m = create(snaps.path(), src.path(), Reason::PreRestore, None, &now()).unwrap();
        let list = list(snaps.path()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, m.id);
        assert_eq!(list[0].reason, "pre-restore");
        assert!(snaps.path().join(&m.id).join("data.tar").exists());
        assert!(snaps.path().join(&m.id).join("manifest.json").exists());
    }

    #[test]
    fn list_is_newest_first() {
        let snaps = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        // Create several with distinct timestamps.
        for i in 0..3u8 {
            let mut t = now();
            t += time::Duration::seconds(i as i64 + 1);
            let _ = create(snaps.path(), src.path(), Reason::Manual, None, &t).unwrap();
        }
        let list = list(snaps.path()).unwrap();
        assert_eq!(list.len(), 3);
        assert!(list[0].id > list[1].id);
        assert!(list[1].id > list[2].id);
    }

    #[test]
    fn restore_replaces_dest() {
        let snaps = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        let m = create(snaps.path(), src.path(), Reason::PreRestore, None, &now()).unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(dest.path().join("preexisting.txt"), b"old").unwrap();
        restore(snaps.path(), &m.id, dest.path()).unwrap();
        assert!(dest.path().join("hello.txt").exists());
        assert!(!dest.path().join("preexisting.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dest.path().join("hello.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn prune_keeps_newest_n() {
        let snaps = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        make_tree(src.path());
        for i in 0..5u8 {
            let mut t = now();
            t += time::Duration::seconds(i as i64 + 1);
            create(snaps.path(), src.path(), Reason::Manual, None, &t).unwrap();
        }
        assert_eq!(list(snaps.path()).unwrap().len(), 5);
        let deleted = prune(snaps.path(), 2).unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(list(snaps.path()).unwrap().len(), 2);
    }

    #[test]
    fn restore_missing_id_errors() {
        let snaps = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let r = restore(snaps.path(), "does-not-exist", dest.path());
        assert!(matches!(r, Err(Error::SnapshotNotFound(_))));
    }

    #[test]
    fn list_missing_dir_returns_empty() {
        let snaps = tempfile::tempdir().unwrap();
        assert!(list(snaps.path()).unwrap().is_empty());
    }

    #[test]
    fn reason_roundtrip() {
        for r in [Reason::PreRestore, Reason::PreRollback, Reason::Manual] {
            assert_eq!(Reason::from_tag(r.as_tag()), Some(r));
        }
        assert_eq!(Reason::from_tag("nope"), None);
    }
}
