// SPDX-License-Identifier: Apache-2.0

//! CLI surface tests for the no-subcommand interactive wizard (offline).
//! The menu itself needs a TTY; here we pin the non-interactive behavior.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

#[test]
fn bare_invocation_without_tty_is_a_usage_error() {
    // No subcommand and stdin is not a TTY (assert_cmd pipes stdin) →
    // the wizard cannot show its menu, so it fails with a usage error.
    bin()
        .assert()
        .failure()
        .code(1) // ExitCode::Usage
        .stderr(predicate::str::contains("no subcommand"));
}

#[test]
fn bare_invocation_with_piped_stdin_still_requires_a_subcommand() {
    // Even with input piped in, the menu is TTY-only by design.
    bin()
        .write_stdin("1\n1\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no subcommand"));
}

#[test]
fn explicit_subcommands_bypass_the_wizard() {
    // `--help` paths are unaffected; in particular `backup --help` works
    // without a TTY, proving subcommands don't enter the wizard.
    bin()
        .args(["backup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--out"));
}
