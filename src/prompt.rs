// SPDX-License-Identifier: Apache-2.0

//! Interactive prompts: password entry (hidden), confirmations, and the
//! weak-password re-confirmation gate.

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::weakpass::{self, Strength};

/// Read a password from stdin with echo disabled. If stdin is not a TTY,
/// fall back to reading a single line (so tests / pipes work).
pub fn read_password(prompt: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        let pw = rpassword::prompt_password(prompt)
            .map_err(|e| Error::Other(format!("password prompt failed: {e}")))?;
        Ok(pw)
    } else {
        // Non-interactive: read one line from stdin.
        eprint!("{prompt}");
        let _ = io::stderr().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// Read a password from a file (first line, trailing newline trimmed).
pub fn read_password_file(path: &Path) -> Result<String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| Error::NotFound(format!("password file: {e}")))?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// Read a password from an environment variable.
pub fn read_password_env(var: &str) -> Result<String> {
    std::env::var(var).map_err(|e| Error::NotFound(format!("password env var {var}: {e}")))
}

/// Read a password, confirming by re-entry, and applying the weak-password
/// gate. If the password is weak, the user must explicitly confirm before
/// it is accepted.
///
/// `must_confirm_reentry` controls whether a second "confirm" prompt is
/// shown (true for backup; false for restore, where we only need the one).
pub fn ask_password(
    label: &str,
    must_confirm_reentry: bool,
    skip_weak_gate: bool,
) -> Result<String> {
    let pw = read_password(&format!("{label}: "))?;
    if pw.is_empty() {
        return Err(Error::WeakPassword {
            detail: "password is empty".into(),
        });
    }
    if must_confirm_reentry {
        let pw2 = read_password(&format!("confirm {label}: "))?;
        if pw != pw2 {
            return Err(Error::WeakPassword {
                detail: "passwords did not match".into(),
            });
        }
    }
    if let Strength::Weak { reason } = weakpass::assess(pw.as_bytes()) {
        if skip_weak_gate {
            eprintln!("warning: weak password ({reason}) — proceeding without confirmation.");
            return Ok(pw);
        }
        if !confirm(&format!("The password is weak ({reason}). Use it anyway?"))? {
            return Err(Error::WeakPassword {
                detail: format!("user declined weak password: {reason}"),
            });
        }
    }
    Ok(pw)
}

/// A yes/no confirmation prompt. Non-TTY stdin defaults to "no" (declined)
/// unless `default_yes` is set, for safety on destructive operations.
pub fn confirm(question: &str) -> Result<bool> {
    if io::stdin().is_terminal() {
        let theme = dialoguer::theme::ColorfulTheme::default();
        let ans = dialoguer::Confirm::with_theme(&theme)
            .with_prompt(question)
            .default(false)
            .interact()
            .map_err(|e| Error::Canceled(format!("prompt failed: {e}")))?;
        Ok(ans)
    } else {
        // Non-interactive: read a line and accept y/yes (case-insensitive).
        eprintln!("{question} [y/N]");
        let _ = io::stderr().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let s = line.trim().to_ascii_lowercase();
        Ok(s == "y" || s == "yes")
    }
}

/// Read a destination/output path from the user, with a suggested default.
pub fn ask_path(prompt: &str, suggested: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        eprintln!("{prompt}");
        eprintln!("  (press Enter to use the suggested default: {suggested})");
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let s = line.trim().to_string();
        if s.is_empty() {
            Ok(suggested.to_string())
        } else {
            Ok(s)
        }
    } else {
        Err(Error::Canceled(
            "non-interactive session cannot prompt for a path; pass --out".into(),
        ))
    }
}

/// Present a numbered menu of options and return the chosen index.
pub fn choose(label: &str, options: &[String]) -> Result<usize> {
    if options.is_empty() {
        return Err(Error::NotFound("no options to choose from".into()));
    }
    if io::stdin().is_terminal() {
        let theme = dialoguer::theme::ColorfulTheme::default();
        let idx = dialoguer::Select::with_theme(&theme)
            .with_prompt(label)
            .items(options)
            .default(0)
            .interact()
            .map_err(|e| Error::Canceled(format!("select failed: {e}")))?;
        Ok(idx)
    } else {
        eprintln!("{label}:");
        for (i, o) in options.iter().enumerate() {
            eprintln!("  [{i}] {o}");
        }
        eprint!("choose number: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let n: usize = line
            .trim()
            .parse()
            .map_err(|_| Error::Canceled("invalid selection".into()))?;
        if n >= options.len() {
            return Err(Error::Canceled("selection out of range".into()));
        }
        Ok(n)
    }
}
