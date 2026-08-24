// SPDX-License-Identifier: Apache-2.0

//! Per-OS path resolution: the Termius data directory and the snapshot store.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The default Termius desktop `userData` directory for the current OS.
///
/// These are the standard Electron paths used by the direct (non-sandboxed)
/// Termius build:
/// - macOS:   `~/Library/Application Support/Termius`
/// - Windows: `%APPDATA%\Termius`
/// - Linux:   `~/.config/Termius`
///
/// Sandboxed builds (Mac App Store, Snap) use different paths; callers may
/// override with an explicit `--termius-dir`.
pub fn default_termius_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| {
        Error::NotFound("could not determine the user config directory for this OS".to_string())
    })?;
    // On macOS `dirs::config_dir()` returns `~/Library/Application Support`,
    // on Windows `%APPDATA%`, on Linux `~/.config` — all correct for Termius.
    Ok(base.join("Termius"))
}

/// Resolve the Termius source directory from an explicit override or the
/// auto-detected default. Validates that the path exists.
pub fn resolve_termius_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    let dir = match override_path {
        Some(p) => p.to_path_buf(),
        None => default_termius_dir()?,
    };
    if !dir.exists() {
        return Err(Error::NotFound(format!(
            "Termius data directory not found: {}
If Termius is installed from the Mac App Store or Snap it is sandboxed and \
uses a different path — pass it explicitly with --termius-dir <PATH>.",
            dir.display()
        )));
    }
    if !dir.is_dir() {
        return Err(Error::NotFound(format!(
            "expected a directory but found a file: {}",
            dir.display()
        )));
    }
    Ok(dir)
}

/// The default snapshot store root.
///
/// - macOS/Linux: `~/.termius-secure-backup/snapshots`
/// - Windows:     `%LOCALAPPDATA%\termius-secure-backup\snapshots`
pub fn default_snapshots_dir() -> Result<PathBuf> {
    // On all three OSes `dirs::data_local_dir()` gives a per-user, non-roaming
    // location appropriate for large, machine-local rollback data.
    let base = dirs::data_local_dir().ok_or_else(|| {
        Error::NotFound("could not determine a local data directory for this OS".to_string())
    })?;
    Ok(base.join("termius-secure-backup").join("snapshots"))
}

/// Resolve the snapshots directory, applying an override if given. The
/// directory need not exist yet.
pub fn resolve_snapshots_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    Ok(match override_path {
        Some(p) => p.to_path_buf(),
        None => default_snapshots_dir()?,
    })
}

/// The default index file inside a snapshots directory.
pub fn snapshots_index_path(snapshots_dir: &Path) -> PathBuf {
    snapshots_dir.join("index.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_termius_dir_ends_with_termius() {
        let d = default_termius_dir().unwrap();
        assert_eq!(d.file_name().unwrap().to_str().unwrap(), "Termius");
    }

    #[test]
    fn default_snapshots_dir_is_under_tool_namespace() {
        let d = default_snapshots_dir().unwrap();
        let comps: Vec<_> = d.components().collect();
        assert!(comps.iter().any(|c| matches!(
            c,
            std::path::Component::Normal(s) if s.to_str() == Some("termius-secure-backup")
        )));
        assert_eq!(d.file_name().unwrap().to_str().unwrap(), "snapshots");
    }

    #[test]
    fn resolve_missing_dir_errors() {
        let bogus = PathBuf::from("/this/definitely/does/not/exist/12345");
        let r = resolve_termius_dir(Some(&bogus));
        assert!(matches!(r, Err(Error::NotFound(_))));
    }

    #[test]
    fn resolve_existing_dir_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let r = resolve_termius_dir(Some(tmp.path()));
        assert!(r.is_ok());
    }

    #[test]
    fn resolve_file_not_dir_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("afile");
        std::fs::write(&f, b"x").unwrap();
        let r = resolve_termius_dir(Some(&f));
        assert!(matches!(r, Err(Error::NotFound(_))));
    }

    #[test]
    fn override_wins_for_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let p = resolve_snapshots_dir(Some(tmp.path())).unwrap();
        assert_eq!(p, tmp.path());
    }

    #[test]
    fn index_path_under_dir() {
        let d = PathBuf::from("/tmp/snapshots");
        assert_eq!(
            snapshots_index_path(&d),
            PathBuf::from("/tmp/snapshots/index.json")
        );
    }
}
