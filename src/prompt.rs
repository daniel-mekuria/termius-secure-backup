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
    let s = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::NotFound(format!(
                "password file not found: {} (create it, or pass the password another way)",
                path.display()
            ))
        } else {
            Error::NotFound(format!(
                "could not read password file {}: {e}",
                path.display()
            ))
        }
    })?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// Read a password from an environment variable.
pub fn read_password_env(var: &str) -> Result<String> {
    std::env::var(var).map_err(|e| Error::NotFound(format!("password env var {var}: {e}")))
}

/// Max password attempts before a wrong-password re-prompt loop gives up.
pub const MAX_PASSWORD_ATTEMPTS: usize = 3;

/// Run `attempt(pw)` with re-acquisition on [`Error::PasswordRejected`].
///
/// `acquire` reads one password (usually a prompt); `attempt` uses it
/// (usually a decryption). On a rejected password the user is re-prompted,
/// up to `max_attempts` total tries. Every other error propagates
/// immediately — only a rejected password is worth another try.
pub fn with_password_retry<T>(
    mut acquire: impl FnMut() -> Result<String>,
    mut attempt: impl FnMut(&str) -> Result<T>,
    max_attempts: usize,
) -> Result<T> {
    let mut tries = 0;
    loop {
        tries += 1;
        let pw = acquire()?;
        match attempt(&pw) {
            Ok(v) => return Ok(v),
            Err(Error::PasswordRejected) if tries < max_attempts => {
                eprintln!("That password was incorrect — try again ({tries}/{max_attempts}).");
            }
            Err(e) => return Err(e),
        }
    }
}

/// Read a password, confirming by re-entry, and applying the weak-password
/// gate. If the password is weak, the user must explicitly confirm before
/// it is accepted.
///
/// `must_confirm_reentry` controls whether a second "confirm" prompt is
/// shown (true for backup; false for restore, where we only need the one).
///
/// On a TTY, empty input and mismatched re-entry re-prompt instead of
/// failing; a run of 10 empty entries (e.g. repeated Ctrl-D) ends the
/// prompt. Non-interactive reads stay single-shot so pipes fail fast.
pub fn ask_password(
    label: &str,
    must_confirm_reentry: bool,
    skip_weak_gate: bool,
) -> Result<String> {
    let interactive = io::stdin().is_terminal();
    let mut empty_runs = 0;
    loop {
        let pw = read_password(&format!("{label}: "))?;
        if pw.is_empty() {
            empty_runs += 1;
            if !interactive || empty_runs >= 10 {
                return Err(Error::WeakPassword {
                    detail: "the password is empty — enter a password to continue".into(),
                });
            }
            eprintln!("the password is empty — enter a password to continue");
            continue;
        }
        empty_runs = 0;
        if must_confirm_reentry {
            let pw2 = read_password(&format!("confirm {label}: "))?;
            if pw != pw2 {
                if !interactive {
                    return Err(Error::WeakPassword {
                        detail: "the two passwords you entered did not match — try again".into(),
                    });
                }
                eprintln!("the two passwords you entered did not match — try again");
                continue;
            }
        }
        if let Strength::Weak { reason } = weakpass::assess(pw.as_bytes()) {
            if skip_weak_gate {
                eprintln!("warning: weak password: {reason} Proceeding without confirmation.");
                return Ok(pw);
            }
            if !confirm(&format!("The password is weak: {reason} Use it anyway?"))? {
                return Err(Error::WeakPassword {
                    detail: format!(
                        "the password was rejected as weak ({reason}) — choose a \
                         stronger one to continue"
                    ),
                });
            }
        }
        return Ok(pw);
    }
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
        if !suggested.is_empty() {
            eprintln!("  (press Enter to use the suggested default: {suggested})");
        }
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

/// Read a free-text string from the user. On a TTY the user may press Enter
/// to accept `default` (when one is given); with no default, empty input
/// re-prompts instead of failing (EOF ends the prompt). Non-interactive
/// sessions accept `default` if present, otherwise error.
pub fn ask_string(prompt: &str, default: Option<&str>) -> Result<String> {
    if io::stdin().is_terminal() {
        loop {
            eprintln!("{prompt}");
            if let Some(d) = default {
                eprintln!("  (press Enter to use the default: {d})");
            }
            let mut line = String::new();
            let n = io::stdin().read_line(&mut line)?;
            if n == 0 {
                return Err(Error::Canceled("input ended — no value given".into()));
            }
            let s = line.trim().to_string();
            if s.is_empty() {
                match default {
                    Some(d) => return Ok(d.to_string()),
                    None => {
                        eprintln!("a value is required — enter one to continue");
                        continue;
                    }
                }
            }
            return Ok(s);
        }
    } else {
        match default {
            Some(d) => Ok(d.to_string()),
            None => Err(Error::Canceled(
                "non-interactive session cannot prompt; pass a value explicitly".into(),
            )),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_succeeds_after_wrong_password() {
        let mut tries = 0;
        let out = with_password_retry(
            || Ok("pw".to_string()),
            |pw| {
                tries += 1;
                if tries < 2 {
                    Err(Error::PasswordRejected)
                } else {
                    assert_eq!(pw, "pw");
                    Ok(tries)
                }
            },
            MAX_PASSWORD_ATTEMPTS,
        );
        assert_eq!(out.unwrap(), 2);
    }

    #[test]
    fn retry_gives_up_after_max_attempts() {
        let mut tries = 0;
        let out: Result<()> = with_password_retry(
            || Ok("pw".to_string()),
            |pw| {
                tries += 1;
                assert_eq!(pw, "pw");
                Err(Error::PasswordRejected)
            },
            MAX_PASSWORD_ATTEMPTS,
        );
        assert!(matches!(out, Err(Error::PasswordRejected)));
        assert_eq!(tries, MAX_PASSWORD_ATTEMPTS);
    }

    #[test]
    fn retry_propagates_other_errors_immediately() {
        let mut tries = 0;
        let out: Result<()> = with_password_retry(
            || Ok("pw".to_string()),
            |_pw| {
                tries += 1;
                Err(Error::NotLoggedIn)
            },
            MAX_PASSWORD_ATTEMPTS,
        );
        assert!(matches!(out, Err(Error::NotLoggedIn)));
        assert_eq!(tries, 1);
    }

    #[test]
    fn retry_single_attempt_fails_fast() {
        let mut tries = 0;
        let out: Result<()> = with_password_retry(
            || Ok("pw".to_string()),
            |pw| {
                tries += 1;
                assert_eq!(pw, "pw");
                Err(Error::PasswordRejected)
            },
            1,
        );
        assert!(matches!(out, Err(Error::PasswordRejected)));
        assert_eq!(tries, 1);
    }
}
