// SPDX-License-Identifier: Apache-2.0

//! CLI surface tests for `termius-backup install` (offline). These never
//! touch the real shell config: the happy path writes to `~/.local/bin` and
//! a shell rc file, so it is covered by the unit tests in src/install.rs,
//! and here the non-interactive runs decline the confirmation.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

#[test]
fn install_help() {
    bin()
        .args(["install", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PATH"));
}

#[test]
fn install_is_a_noop_when_already_on_path() {
    // Put the binary's own directory first on PATH: install must report
    // that the binary is already reachable and change nothing.
    let exe = std::env::var("CARGO_BIN_EXE_termius-backup").expect("binary path");
    let dir = Path::new(&exe).parent().unwrap().to_path_buf();
    let mut dirs = vec![dir];
    if let Some(existing) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&existing));
    }
    bin()
        .env("PATH", std::env::join_paths(dirs).unwrap())
        .args(["install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already on your PATH"));
}

#[test]
fn install_declined_changes_nothing() {
    // Keep the run deterministic regardless of the machine: filter PATH
    // entries that already contain a file named like this binary, so the
    // "already on your PATH" early exit cannot preempt the confirmation.
    let exe = std::env::var("CARGO_BIN_EXE_termius-backup").expect("binary path");
    let bin_name = Path::new(&exe).file_name().unwrap().to_os_string();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let filtered: Vec<_> = std::env::split_paths(&path_var)
        .filter(|d| !d.join(&bin_name).is_file())
        .collect();

    // Non-TTY: the confirmation reads a line from stdin; "n" declines →
    // canceled with a "nothing was changed" message. On a machine where a
    // previous install already put everything in place, the run instead
    // reports "already installed" — either way, nothing changes.
    let out = bin()
        .env("PATH", std::env::join_paths(filtered).unwrap())
        .args(["install"])
        .write_stdin("n\n")
        .output()
        .expect("run install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let declined = out.status.code() == Some(5) // ExitCode::Canceled
        && stderr.contains("nothing was changed");
    let already_installed = out.status.success() && stdout.contains("already installed");
    assert!(
        declined || already_installed,
        "install exited {:?}: stdout={stdout} stderr={stderr}",
        out.status.code()
    );
}
