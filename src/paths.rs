// SPDX-License-Identifier: Apache-2.0

//! Per-OS path resolution: the Termius data directory and the snapshot store.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::prompt;

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
///
/// When no `--termius-dir` was given and the auto-detected default does not
/// exist, an interactive (TTY) session is asked for the real path instead of
/// failing outright — sandboxed builds (Mac App Store, Snap) store their
/// data elsewhere, and fresh installs may not have run Termius yet.
pub fn resolve_termius_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    match override_path {
        Some(p) => validate_termius_dir(p),
        None => {
            let dir = default_termius_dir()?;
            match validate_termius_dir(&dir) {
                Ok(d) => Ok(d),
                Err(e) if std::io::stdin().is_terminal() => interactive_termius_dir(&dir, e),
                Err(e) => Err(e),
            }
        }
    }
}

/// Check that `dir` exists and is a directory.
fn validate_termius_dir(dir: &Path) -> Result<PathBuf> {
    if !dir.exists() {
        return Err(Error::NotFound(format!(
            "Termius data directory not found: {}
If Termius is installed from the Mac App Store or Snap it is sandboxed and \
uses a different path — pass it with --termius-dir <PATH>.",
            dir.display()
        )));
    }
    if !dir.is_dir() {
        return Err(Error::NotFound(format!(
            "expected a directory but found a file: {}",
            dir.display()
        )));
    }
    Ok(dir.to_path_buf())
}

/// Ask the user where their Termius data actually lives, and keep asking
/// until they give an existing directory (or confirm a not-yet-created one,
/// which is fine for restores onto a fresh machine). Empty input re-prompts
/// — Ctrl-C (or 10 consecutive empty inputs, e.g. repeated Ctrl-D) ends
/// the run.
fn interactive_termius_dir(default: &Path, original: Error) -> Result<PathBuf> {
    eprintln!("{original}");
    let mut empty_runs = 0;
    loop {
        let input = prompt::ask_path(
            &format!(
                "Enter the path to your Termius data directory \
                 (the usual place is {}):",
                default.display()
            ),
            "",
        )?;
        if input.is_empty() {
            empty_runs += 1;
            if empty_runs >= 10 {
                return Err(Error::Canceled(
                    "no Termius data directory found, so there is nothing to back up".into(),
                ));
            }
            eprintln!("a path is required — enter one to continue");
            continue;
        }
        empty_runs = 0;
        let p = expand_tilde(&input);
        if p.is_dir() {
            return Ok(p);
        }
        if p.exists() {
            eprintln!("That path is a file, not a directory: {}\n", p.display());
            continue;
        }
        eprintln!("That path does not exist yet: {}", p.display());
        if prompt::confirm("Use it anyway (restores can target a fresh directory)?")? {
            return Ok(p);
        }
        eprintln!();
    }
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(p: &str) -> PathBuf {
    if p == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(p));
    }
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
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

/// The encrypted Google Drive credential store (a `.tsb` container whose
/// plaintext is a JSON blob with the OAuth tokens). Lives in the per-user
/// config dir so it travels with the profile, not with bulky snapshot data:
/// `~/.config/termius-secure-backup/gdrive-creds.tsb` (Linux),
/// `~/Library/Application Support/termius-secure-backup/gdrive-creds.tsb`
/// (macOS), `%APPDATA%\termius-secure-backup\gdrive-creds.tsb` (Windows).
pub fn gdrive_creds_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| {
        Error::NotFound("could not determine the user config directory for this OS".to_string())
    })?;
    Ok(base.join("termius-secure-backup").join("gdrive-creds.tsb"))
}

/// Resolve the credential store path, applying an override if given. The
/// directory need not exist yet.
pub fn resolve_gdrive_creds_path(override_path: Option<&Path>) -> Result<PathBuf> {
    Ok(match override_path {
        Some(p) => p.to_path_buf(),
        None => gdrive_creds_path()?,
    })
}

/// The sync state file: for each vault, the fingerprint of the tree that
/// the most recent `gdrive backup` / `gdrive sync` uploaded. Plain JSON, no
/// sensitive content (counts, sizes, an mtime — no file names). Lives next
/// to the credential store:
/// `~/.config/termius-secure-backup/sync-state.json` (Linux),
/// `~/Library/Application Support/termius-secure-backup/sync-state.json`
/// (macOS), `%APPDATA%\termius-secure-backup\sync-state.json` (Windows).
pub fn sync_state_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| {
        Error::NotFound("could not determine the user config directory for this OS".to_string())
    })?;
    Ok(base.join("termius-secure-backup").join("sync-state.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(
            expand_tilde("~/config/Termius"),
            home.join("config/Termius")
        );
    }

    #[test]
    fn expand_tilde_leaves_other_paths_alone() {
        assert_eq!(
            expand_tilde("/home/u/.config/Termius"),
            PathBuf::from("/home/u/.config/Termius")
        );
        assert_eq!(expand_tilde("relative/dir"), PathBuf::from("relative/dir"));
    }

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
