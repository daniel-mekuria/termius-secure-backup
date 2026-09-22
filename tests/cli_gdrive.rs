// SPDX-License-Identifier: Apache-2.0

//! CLI surface tests for the `gdrive` subcommand (offline: no Google).
//! Every test points `--creds-file` at a temp path so a developer's real
//! credential store can never be touched.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

fn creds_in(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().join("gdrive-creds.tsb")
}

/// Run the binary with the user directories redirected into `tmp`, so the
/// sync-state file never touches a developer's real one.
/// (HOME + XDG_CONFIG_HOME cover Linux/macOS; the tool reads
/// USERPROFILE/APPDATA/LOCALAPPDATA first on Windows, where `dirs`'
/// known-folder API ignores the environment — see `paths::config_dir`.)
fn isolated(tmp: &tempfile::TempDir) -> Command {
    let base = tmp.path();
    let mut cmd = Command::cargo_bin("termius-backup").expect("binary present");
    cmd.env("HOME", base);
    cmd.env("XDG_CONFIG_HOME", base.join("config"));
    cmd.env("USERPROFILE", base);
    cmd.env("APPDATA", base.join("appdata"));
    cmd.env("LOCALAPPDATA", base.join("localappdata"));
    cmd
}

#[test]
fn gdrive_help_lists_subcommands() {
    bin()
        .args(["gdrive", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("logout"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("restore"))
        .stdout(predicate::str::contains("sync"));
}

#[test]
fn gdrive_sync_help_lists_flags() {
    bin()
        .args(["gdrive", "sync", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--interval"))
        .stdout(predicate::str::contains("--keep"))
        .stdout(predicate::str::contains("--once"));
}

#[test]
fn gdrive_backup_help_lists_keep_flag() {
    bin()
        .args(["gdrive", "backup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--keep"));
}

/// The `gdrive sync on` / `off` subcommands exist and take `--name`.
#[test]
fn gdrive_sync_help_lists_on_off_subcommands() {
    for sub in ["off", "on"] {
        bin()
            .args(["gdrive", "sync", sub, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--name"));
    }
}

/// `gdrive sync off` (per vault or all) and `gdrive sync on` *without* a
/// vault name are pure local state operations: no login, no Termius
/// directory, no credentials file required. A per-vault `on` installs the
/// background service and therefore needs the stored credentials first.
#[test]
fn gdrive_sync_off_on_round_trip_is_local_only() {
    let tmp = tempfile::tempdir().unwrap();
    isolated(&tmp)
        .args(["gdrive", "sync", "off", "--name", "laptop"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Continuous sync turned off for vault 'laptop'",
        ));
    isolated(&tmp)
        .args(["gdrive", "sync", "off"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Continuous sync turned off for all vaults",
        ));
    // Global on installs no service — still pure local state.
    isolated(&tmp)
        .args(["gdrive", "sync", "on"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Continuous sync turned back on for all vaults",
        ));
    // Per-vault on installs the background service: without stored
    // credentials it fails with a login hint, not with a service error.
    isolated(&tmp)
        .args(["gdrive", "sync", "on", "--name", "laptop"])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_sync_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir_all(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();
    isolated(&tmp)
        .args([
            "gdrive",
            "sync",
            "--name",
            "test",
            "--termius-dir",
            &termius.display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

/// An explicit `--termius-dir` is remembered in the state file, and a
/// later `gdrive sync` run without the flag reuses it. Proven offline:
/// the first run stops at "not logged in" (exit 3) *after* the path has
/// been remembered; the second run without the flag must stop at the same
/// "not logged in" — not fail earlier with exit 2 ("Termius data
/// directory not found"), since no default directory exists in the
/// isolated config dir.
#[test]
fn gdrive_sync_remembers_termius_dir_for_later_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir_all(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();

    // First run: explicit path.
    isolated(&tmp)
        .args([
            "gdrive",
            "sync",
            "--name",
            "test",
            "--termius-dir",
            &termius.display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3);

    // Second run: no --termius-dir. Saved path honored → exit 3, "not
    // logged in". Saved path ignored → exit 2, directory not found.
    isolated(&tmp)
        .args([
            "gdrive",
            "sync",
            "--once",
            "--name",
            "test",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn main_help_mentions_gdrive() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("gdrive"));
}

#[test]
fn gdrive_status_without_creds_not_logged_in() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "status",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_backup_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir_all(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();
    let pwfile = tmp.path().join("pw.txt");
    fs::write(&pwfile, b"strong-password-123\n").unwrap();
    bin()
        .args([
            "gdrive",
            "backup",
            "--name",
            "test",
            "--termius-dir",
            &termius.display().to_string(),
            "--password-file",
            &pwfile.display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_restore_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "restore",
            "--termius-dir",
            &tmp.path().join("termius").display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_login_without_env_uses_baked_in_client() {
    // No TSBAK_GDRIVE_CLIENT_ID in the environment -> the baked-in
    // default client id is used, so login gets past client resolution
    // to the email prompt, which fails cleanly in a non-interactive
    // session (no TTY). No network is touched before that point.
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "login",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .env_remove("TSBAK_GDRIVE_CLIENT_ID")
        .env_remove("TSBAK_GDRIVE_CLIENT_SECRET")
        .assert()
        .failure()
        .code(5) // ExitCode::Canceled
        .stderr(predicate::str::contains("non-interactive"));
}

#[test]
fn gdrive_logout_without_creds_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "logout",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Not logged in"));
}
