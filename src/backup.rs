// SPDX-License-Identifier: Apache-2.0

//! Backup orchestration: pack the Termius dir and write an encrypted `.tsb`.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::archive;
use crate::container;
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::prompt;
use crate::util;
use crate::{paths, weakpass};

/// Options for a backup run.
pub struct Options<'a> {
    pub termius_dir: Option<&'a Path>,
    pub out: Option<&'a Path>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub yes: bool,
    pub kdf: KdfParams,
}

/// Run a backup. Returns the path written.
pub fn run(opts: Options<'_>) -> Result<PathBuf> {
    let src = paths::resolve_termius_dir(opts.termius_dir)?;
    let now = util::current_time();

    // Determine output path.
    let out_path: PathBuf = match opts.out {
        Some(p) => p.to_path_buf(),
        None => {
            let suggested = util::suggested_backup_name(&now);
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let suggested_full = cwd.join(&suggested);
            let s = prompt::ask_path(
                "Enter the destination path for the encrypted backup:",
                &suggested_full.display().to_string(),
            )?;
            PathBuf::from(s)
        }
    };

    // Acquire the password.
    let password = acquire_password(
        opts.password_file,
        opts.password_env,
        /*confirm_reentry*/ true,
        opts.yes,
    )?;

    if out_path.exists()
        && !opts.yes
        && !prompt::confirm(&format!(
            "File already exists: {}\nOverwrite?",
            out_path.display()
        ))?
    {
        return Err(Error::Canceled("backup canceled".into()));
    }

    // Pack the directory into a compressed archive (the plaintext payload).
    eprintln!("Packing {} …", src.display());
    let mut payload = Vec::new();
    let meta = archive::pack(&src, &mut payload, &util::local_timestamp_string(&now))?;
    eprintln!(
        "Packed {} entries ({} bytes).",
        meta.entry_count, meta.byte_size
    );

    // Encrypt and write the container.
    eprintln!("Encrypting (Argon2id + XChaCha20-Poly1305) …");
    container::write(&out_path, password.as_bytes(), &opts.kdf, &payload)?;
    // Best-effort: zero the plaintext payload.
    for b in payload.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }

    let size = std::fs::metadata(&out_path)?.len();
    eprintln!(
        "Wrote encrypted backup: {} ({} bytes)",
        out_path.display(),
        size
    );
    Ok(out_path)
}

/// Acquire a password and use it to decrypt, re-prompting on a rejected
/// password. A file or env source is a deterministic password, so a wrong
/// one is tried only once — retrying it cannot succeed. An interactive
/// session on a TTY gets [`prompt::MAX_PASSWORD_ATTEMPTS`] attempts;
/// non-interactive prompt reads (pipes) also fail fast.
pub fn acquire_and_decrypt<T>(
    file: Option<&Path>,
    env: Option<&str>,
    confirm_reentry: bool,
    skip_weak_gate: bool,
    mut decrypt: impl FnMut(&str) -> Result<T>,
) -> Result<T> {
    let interactive = std::io::stdin().is_terminal();
    let max_attempts = if file.is_some() || env.is_some() || !interactive {
        1
    } else {
        prompt::MAX_PASSWORD_ATTEMPTS
    };
    prompt::with_password_retry(
        || acquire_password(file, env, confirm_reentry, skip_weak_gate),
        &mut decrypt,
        max_attempts,
    )
}

/// Acquire a password from a file, env var, or interactive prompt.
pub fn acquire_password(
    file: Option<&Path>,
    env: Option<&str>,
    confirm_reentry: bool,
    skip_weak_gate: bool,
) -> Result<String> {
    let pw = match (file, env) {
        (Some(f), _) => {
            let p = prompt::read_password_file(f)?;
            // Non-interactive sources still get a strength warning, but the
            // weak gate only applies interactively unless skip_weak_gate.
            warn_if_weak(&p, skip_weak_gate);
            p
        }
        (_, Some(v)) => {
            let p = prompt::read_password_env(v)?;
            warn_if_weak(&p, skip_weak_gate);
            p
        }
        (None, None) => prompt::ask_password("backup password", confirm_reentry, skip_weak_gate)?,
    };
    Ok(pw)
}

fn warn_if_weak(pw: &str, skip_weak_gate: bool) {
    if let weakpass::Strength::Weak { reason } = weakpass::assess(pw.as_bytes()) {
        if skip_weak_gate {
            eprintln!("warning: weak password: {reason}");
        } else {
            eprintln!(
                "warning: weak password: {reason} Re-run interactively to be \
                 prompted, or pass --yes to accept."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_decrypt_file_source_single_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "some-backup-pw\n").unwrap();
        let mut attempts = 0;
        let out: Result<()> = acquire_and_decrypt(
            Some(&pw_file),
            None,
            false,
            /*skip_weak_gate*/ true,
            |pw| {
                attempts += 1;
                assert_eq!(pw, "some-backup-pw");
                Err(Error::PasswordRejected)
            },
        );
        // A file source is deterministic — one attempt, even on a TTY.
        assert!(matches!(out, Err(Error::PasswordRejected)));
        assert_eq!(attempts, 1);
    }
}
