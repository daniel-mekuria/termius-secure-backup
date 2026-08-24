// SPDX-License-Identifier: Apache-2.0

//! Small utilities: atomic writes, hashing, time formatting, logging.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// SHA-256 of a file's contents. Returns the hex digest.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode_lower_owned(&hasher.finalize()))
}

/// A tiny hex encoder (avoids pulling in an extra crate for two call sites).
pub mod hex {
    pub fn encode_lower_owned(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

/// Recursively compute the total size and entry count of a directory.
pub fn dir_stats(root: &Path) -> Result<(u64, u64)> {
    let mut bytes = 0u64;
    let mut entries = 0u64;
    walk(root, &mut |p| {
        if let Ok(meta) = fs::symlink_metadata(p) {
            if meta.is_file() {
                bytes += meta.len();
                entries += 1;
            } else if meta.is_dir() {
                entries += 1;
            } else {
                entries += 1; // symlink itself counts as an entry
            }
        }
    })?;
    Ok((bytes, entries))
}

fn walk<F: FnMut(&Path)>(root: &Path, f: &mut F) -> Result<()> {
    let meta = fs::symlink_metadata(root)?;
    f(root);
    if meta.is_dir() && !meta.file_type().is_symlink() {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            walk(&entry.path(), f)?;
        }
    }
    Ok(())
}

/// Write `data` to `dest` atomically: write to a temp file in the same
/// directory then rename over the destination.
pub fn atomic_write(dest: &Path, data: &[u8]) -> Result<()> {
    atomic_write_with(dest, |w| w.write_all(data).map_err(Into::into))
}

/// Atomically produce a file at `dest` using a writer closure.
pub fn atomic_write_with<F>(dest: &Path, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut fs::File) -> Result<()>,
{
    let dest_dir = dest
        .parent()
        .ok_or_else(|| Error::Other("destination has no parent directory".into()))?;
    fs::create_dir_all(dest_dir)?;
    let tmp = tempfile::NamedTempFile::new_in(dest_dir)?;
    let mut file = tmp.reopen()?;
    write_fn(&mut file)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    tmp.persist(dest)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

/// Format the current local time as `YYYY-MM-DDTHH-MM-SS`.
pub fn local_timestamp_string(now: &time::OffsetDateTime) -> String {
    now.format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_else(|_| "unknown".to_string())
        .replace(':', "-")
}

/// A filesystem-safe timestamp id: `YYYY-MM-DDTHH-MM-SS__<reason>__<sha8>`.
pub fn snapshot_id(now: &time::OffsetDateTime, reason: &str, sha_prefix: &str) -> String {
    let ts = now
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_else(|_| "unknown".to_string())
        .replace(':', "-");
    let sha8 = &sha_prefix[..sha_prefix.len().min(8)];
    format!("{ts}__{reason}__{sha8}")
}

/// Ensure a directory exists, creating it (and parents) if needed.
pub fn ensure_dir(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path)?;
    Ok(path.to_path_buf())
}

/// Initialize the tracing subscriber with a sensible default filter.
pub fn init_logging(verbose: bool) {
    let filter = if verbose { "debug" } else { "warn" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .try_init();
}

/// Compare two byte slices in constant time.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current time as a UTC `OffsetDateTime`, derived from the system clock
/// (avoids the `time` crate's `IndeterminateOffset` failure mode).
pub fn current_time() -> time::OffsetDateTime {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// A suggested backup filename: `termius-backup-<YYYY-MM-DDTHH-MM-SS>.tsb`.
pub fn suggested_backup_name(now: &time::OffsetDateTime) -> String {
    let ts = now
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_else(|_| "unknown".to_string())
        .replace(':', "-");
    format!("termius-backup-{ts}.tsb")
}
