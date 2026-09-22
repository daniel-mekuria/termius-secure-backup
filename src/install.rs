// SPDX-License-Identifier: Apache-2.0

//! Put the running `termius-backup` binary on the user's PATH so it can be
//! run from anywhere.
//!
//! - Linux/macOS: symlink the binary into `~/.local/bin`. If that directory
//!   is not already on the PATH, append a PATH line to the shell rc file
//!   that matches `$SHELL` (`~/.bashrc`, `~/.zshrc`,
//!   `~/.config/fish/config.fish`, or `~/.profile` when unknown).
//! - Windows: append the binary's directory to the *user* PATH in the
//!   registry (`HKCU\Environment`), preserving whether the value is
//!   REG_SZ or REG_EXPAND_SZ.
//!
//! The operation is idempotent: if the binary is already reachable through
//! the PATH, that is reported and nothing is changed. The change takes
//! effect in a new terminal (or after sourcing the rc file).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::{paths, prompt};

/// Put the currently running binary on the PATH.
pub fn run(yes: bool) -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| {
        Error::Other(format!(
            "could not determine the running binary's path: {e}"
        ))
    })?;
    #[cfg(unix)]
    // current_exe can come back through a symlink; canonicalize so the
    // symlink we create points at the real file.
    let exe = exe.canonicalize()?;
    install_at(&exe, yes)
}

/// Like [`run`], but for a specific binary instead of the running one
/// (used by `run` and by the tests).
pub fn install_at(exe: &Path, yes: bool) -> Result<()> {
    let name = exe.file_name().ok_or_else(|| {
        Error::Other(format!(
            "cannot install {}: the path has no file name",
            exe.display()
        ))
    })?;

    // Already runnable from anywhere? Nothing to do.
    if let Some(found) = find_in_path(std::env::var_os("PATH").as_deref(), name) {
        println!(
            "termius-backup is already on your PATH (found at {}).",
            found.display()
        );
        return Ok(());
    }

    #[cfg(unix)]
    {
        let home = paths::home_dir().ok_or_else(|| {
            Error::NotFound("could not determine your home directory".to_string())
        })?;
        let link_dir = home.join(".local").join("bin");
        let rc = rc_file_for(&shell_name(), &home);
        install_unix(exe, name, &link_dir, &rc, yes)
    }
    #[cfg(windows)]
    {
        let dir = exe.parent().ok_or_else(|| {
            Error::Other(format!(
                "cannot install {}: the path has no parent directory",
                exe.display()
            ))
        })?;
        install_windows(dir, yes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = yes;
        Err(Error::Other(
            "adding to the PATH is only supported on Linux, macOS, and Windows".into(),
        ))
    }
}

/// The first PATH entry that contains a file named `name`, if any.
fn find_in_path(path_var: Option<&OsStr>, name: &OsStr) -> Option<PathBuf> {
    path_var.and_then(|p| {
        std::env::split_paths(p).find_map(|dir| {
            let cand = dir.join(name);
            cand.is_file().then_some(cand)
        })
    })
}

/// The basename of `$SHELL` ("" when unset) — which rc file to update.
fn shell_name() -> String {
    std::env::var("SHELL")
        .ok()
        .and_then(|s| {
            Path::new(&s)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_default()
}

/// The shell rc file to update for a shell named `shell` (its basename).
/// fish keeps its config elsewhere; unknown or missing shells get
/// `~/.profile`, which sh and login bash read.
fn rc_file_for(shell: &str, home: &Path) -> PathBuf {
    if shell.contains("fish") {
        home.join(".config").join("fish").join("config.fish")
    } else if shell.contains("zsh") {
        home.join(".zshrc")
    } else if shell.contains("bash") {
        home.join(".bashrc")
    } else {
        home.join(".profile")
    }
}

/// What to do about the symlink at `link_dir/<name>`.
#[cfg(unix)]
enum SymlinkAction {
    /// It already points at the target binary.
    None,
    /// It does not exist yet — create it.
    Create,
    /// It points somewhere else — replace it.
    Replace,
}

#[cfg(unix)]
fn install_unix(exe: &Path, name: &OsStr, link_dir: &Path, rc: &Path, yes: bool) -> Result<()> {
    let link = link_dir.join(name);
    let symlink_action = match link.symlink_metadata() {
        Ok(md) if md.file_type().is_symlink() => match std::fs::read_link(&link) {
            Ok(target) if target == exe => SymlinkAction::None,
            Ok(_) => SymlinkAction::Replace,
            Err(e) => return Err(e.into()),
        },
        // A regular file (or directory) at the link path is not ours to move.
        Ok(_) => {
            return Err(Error::Other(format!(
                "refusing to replace the existing file {} — move or rename it, then re-run install",
                link.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SymlinkAction::Create,
        Err(e) => return Err(e.into()),
    };

    let dir_on_path = path_contains_dir(link_dir);
    let rc_already = rc_file_mentions(rc, link_dir)?;
    let needs_symlink = matches!(
        symlink_action,
        SymlinkAction::Create | SymlinkAction::Replace
    );
    let needs_rc = !dir_on_path && !rc_already;

    if !needs_symlink && !needs_rc {
        println!(
            "termius-backup is already installed at {} — nothing to do.",
            link.display()
        );
        return Ok(());
    }

    if !yes {
        let mut actions = Vec::new();
        match symlink_action {
            SymlinkAction::Create => actions.push(format!(
                "create a symlink: {} -> {}",
                link.display(),
                exe.display()
            )),
            SymlinkAction::Replace => actions.push(format!(
                "replace the existing symlink {} so it points to {}",
                link.display(),
                exe.display()
            )),
            SymlinkAction::None => {}
        }
        if needs_rc {
            actions.push(format!(
                "add {} to your PATH in {}",
                link_dir.display(),
                rc.display()
            ));
        }
        let question = format!(
            "Add termius-backup to your PATH?\n\nThis will:\n  - {}",
            actions.join("\n  - ")
        );
        if !prompt::confirm(&question)? {
            return Err(Error::Canceled(
                "not added to PATH — nothing was changed".into(),
            ));
        }
    }

    if needs_symlink {
        std::fs::create_dir_all(link_dir)?;
        if matches!(symlink_action, SymlinkAction::Replace) {
            std::fs::remove_file(&link)?;
        }
        std::os::unix::fs::symlink(exe, &link)?;
        println!("Installed: symlink {} -> {}", link.display(), exe.display());
    }
    if needs_rc {
        let created = !rc.exists();
        append_rc_line(rc, link_dir)?;
        if created {
            println!(
                "Created {} with a PATH line for {}.",
                rc.display(),
                link_dir.display()
            );
        } else {
            println!(
                "Updated {} to put {} on PATH.",
                rc.display(),
                link_dir.display()
            );
        }
    }
    println!(
        "Open a new terminal (or run: source {}) to use 'termius-backup' from anywhere.",
        rc.display()
    );
    Ok(())
}

/// True when `dir` is one of the current PATH entries.
#[cfg(unix)]
fn path_contains_dir(dir: &Path) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d == dir || same_path(&d, dir)))
}

#[cfg(unix)]
fn same_path(a: &Path, b: &Path) -> bool {
    a.canonicalize()
        .ok()
        .zip(b.canonicalize().ok())
        .is_some_and(|(x, y)| x == y)
}

/// True when the rc file already puts `dir` on the PATH (exact path
/// string), so a second run does not append a duplicate line.
#[cfg(unix)]
fn rc_file_mentions(rc: &Path, dir: &Path) -> Result<bool> {
    match std::fs::read_to_string(rc) {
        Ok(content) => Ok(content.contains(&dir.display().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn append_rc_line(rc: &Path, dir: &Path) -> Result<()> {
    if let Some(parent) = rc.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(rc).unwrap_or_default();
    let comment = format!(
        "# termius-backup: add {} to PATH (added by 'termius-backup install')",
        dir.display()
    );
    let is_fish = rc.file_name().map(|n| n == "config.fish").unwrap_or(false);
    let statement = if is_fish {
        format!("set -gx PATH \"{}\" $PATH", dir.display())
    } else {
        format!("export PATH=\"{}:$PATH\"", dir.display())
    };

    let mut block = String::new();
    if !existing.is_empty() {
        if !existing.ends_with('\n') {
            block.push('\n');
        }
        // A blank line between the user's content and ours.
        block.push('\n');
    }
    block.push_str(&comment);
    block.push('\n');
    block.push_str(&statement);
    block.push('\n');

    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rc)?;
    f.write_all(block.as_bytes())?;
    Ok(())
}

#[cfg(windows)]
fn install_windows(dir: &Path, yes: bool) -> Result<()> {
    // One PowerShell call does the whole job: it reads the user PATH,
    // exits 42 when the directory is already one of its entries, and
    // otherwise appends it — preserving whether the registry value is
    // REG_SZ or REG_EXPAND_SZ. PowerShell is used instead of reg.exe /
    // setx because it passes the value through untouched (reg.exe mangles
    // embedded quotes and non-ASCII text via the console code page).
    let dir_ps = dir.display().to_string().replace('\'', "''");
    let script = format!(
        r#"$dir = '{dir_ps}';
$key = Get-Item 'HKCU:\Environment';
$kind = if ($key.Property -contains 'Path') {{ [string]$key.GetValueKind('Path') }} else {{ '' }};
$type = if ($kind -ieq 'ExpandString') {{ 'ExpandString' }} else {{ 'String' }};
$p = if ($kind -ne '') {{ [string]$key.GetValue('Path') }} else {{ '' }};
if ($p -split ';' | Where-Object {{ $_.Trim() -ieq $dir }}) {{ exit 42 }};
$new = if ($p.Trim()) {{ $p + ';' + $dir }} else {{ $dir }};
Set-ItemProperty -Path 'HKCU:\Environment' -Name 'Path' -Value $new -Type $type;
exit 0"#
    );

    if !yes {
        let question = format!(
            "Add {} to your user PATH (Windows registry, HKCU\\Environment)?",
            dir.display()
        );
        if !prompt::confirm(&question)? {
            return Err(Error::Canceled(
                "not added to PATH — nothing was changed".into(),
            ));
        }
    }

    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .map_err(|e| Error::Other(format!("could not run powershell: {e}")))?;
    let code = out.status.code().unwrap_or(-1);
    if code == 42 {
        println!(
            "termius-backup is already on your PATH ({} is in the user PATH).",
            dir.display()
        );
        return Ok(());
    }
    if code != 0 {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Other(format!(
            "could not update the user PATH (powershell exit {code}): {}",
            err.trim()
        )));
    }
    println!("Added {} to your user PATH.", dir.display());
    println!("Open a new terminal to use 'termius-backup' from anywhere.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_in_path_locates_the_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("termius-backup");
        std::fs::write(&f, b"x").unwrap();
        let found = find_in_path(Some(tmp.path().as_os_str()), OsStr::new("termius-backup"));
        assert_eq!(found, Some(f));
    }

    #[test]
    fn find_in_path_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            find_in_path(Some(tmp.path().as_os_str()), OsStr::new("termius-backup")),
            None
        );
        assert_eq!(find_in_path(None, OsStr::new("termius-backup")), None);
    }

    #[test]
    fn rc_file_follows_shell() {
        let home = PathBuf::from("/home/u");
        assert_eq!(rc_file_for("bash", &home), home.join(".bashrc"));
        assert_eq!(rc_file_for("zsh", &home), home.join(".zshrc"));
        assert_eq!(
            rc_file_for("fish", &home),
            home.join(".config").join("fish").join("config.fish")
        );
        // Unknown and missing shells fall back to ~/.profile.
        assert_eq!(rc_file_for("sh", &home), home.join(".profile"));
        assert_eq!(rc_file_for("", &home), home.join(".profile"));
    }

    /// A throwaway "binary" to install into a tempdir.
    #[cfg(unix)]
    fn fake_exe(tmp: &tempfile::TempDir) -> PathBuf {
        let exe = tmp.path().join("termius-backup");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        exe
    }

    #[cfg(unix)]
    #[test]
    fn install_unix_creates_symlink_and_rc_line() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = fake_exe(&tmp);
        let link_dir = tmp.path().join("linkdir");
        let rc = tmp.path().join(".bashrc");

        install_unix(&exe, OsStr::new("termius-backup"), &link_dir, &rc, true).unwrap();

        let link = link_dir.join("termius-backup");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), exe);
        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("export PATH="), "rc content: {content}");
        assert!(
            content.contains(&link_dir.display().to_string()),
            "rc content: {content}"
        );

        // A second run changes nothing (idempotent).
        install_unix(&exe, OsStr::new("termius-backup"), &link_dir, &rc, true).unwrap();
        assert_eq!(std::fs::read_to_string(&rc).unwrap(), content);
    }

    #[cfg(unix)]
    #[test]
    fn install_unix_refuses_plain_file_at_link_path() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = fake_exe(&tmp);
        let link_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&link_dir).unwrap();
        let link = link_dir.join("termius-backup");
        std::fs::write(&link, b"i am a file, not a symlink").unwrap();
        let rc = tmp.path().join(".bashrc");

        let e = install_unix(&exe, OsStr::new("termius-backup"), &link_dir, &rc, true).unwrap_err();
        assert!(matches!(e, Error::Other(_)), "error: {e}");
        assert!(e.to_string().contains("refusing"), "error: {e}");
    }

    #[cfg(unix)]
    #[test]
    fn install_unix_writes_fish_syntax_for_fish_rc() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = fake_exe(&tmp);
        let link_dir = tmp.path().join("linkdir");
        let rc = tmp.path().join("config.fish");

        install_unix(&exe, OsStr::new("termius-backup"), &link_dir, &rc, true).unwrap();

        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("set -gx PATH"), "rc content: {content}");
        assert!(!content.contains("export PATH="), "rc content: {content}");
    }
}
