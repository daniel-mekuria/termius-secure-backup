// SPDX-License-Identifier: Apache-2.0

//! Typed errors and process exit codes.
//!
//! Every error's message is written for the person reading it on the
//! terminal: it says what went wrong and, where possible, what to do
//! next. Raw OS error codes (e.g. "No such file or directory (os error 2)")
//! are translated into plain language.

use std::io;

/// Process exit codes, documented in the README.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ExitCode {
    Success = 0,
    Usage = 1,
    NotFound = 2,
    Auth = 3,
    BadFormat = 4,
    Canceled = 5,
    Internal = 6,
    Remote = 7,
}

impl From<Error> for ExitCode {
    fn from(e: Error) -> Self {
        use Error as E;
        match e {
            E::Canceled(_) => ExitCode::Canceled,
            E::Auth(_) | E::PasswordRejected => ExitCode::Auth,
            E::BadFormat { .. }
            | E::UnsupportedVersion { .. }
            | E::UnsupportedCipher { .. }
            | E::UnsupportedKdf { .. }
            | E::Integrity(_) => ExitCode::BadFormat,
            E::NotFound(_) | E::SnapshotNotFound(_) => ExitCode::NotFound,
            E::WeakPassword { .. } => ExitCode::Usage,
            E::NotLoggedIn => ExitCode::Auth,
            E::Gdrive(_) => ExitCode::Remote,
            E::NoSubcommand => ExitCode::Usage,
            E::Io(_) | E::Archive(_) | E::Json(_) | E::Other(_) => ExitCode::Internal,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),

    Canceled(String),

    Auth(String),

    PasswordRejected,

    BadFormat {
        detail: String,
        offset: u64,
    },

    UnsupportedVersion(u8),

    UnsupportedCipher(u8),

    UnsupportedKdf(u8),

    Integrity(String),

    NotFound(String),

    SnapshotNotFound(String),

    WeakPassword {
        detail: String,
    },

    #[allow(dead_code)]
    Archive(String),

    Json(serde_json::Error),

    NotLoggedIn,

    Gdrive(String),

    NoSubcommand,

    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error as E;
        match self {
            E::Io(e) => write!(f, "I/O error: {}", friendly_io(e)),
            E::Canceled(msg) => write!(f, "canceled: {msg}"),
            E::Auth(msg) => write!(f, "authentication failed: {msg}"),
            E::PasswordRejected => write!(
                f,
                "the password was incorrect, or the file is damaged (decryption failed)"
            ),
            E::BadFormat { detail, .. } => write!(
                f,
                "the backup file is damaged or is not a valid .tsb file: {detail}"
            ),
            E::UnsupportedVersion(v) => write!(
                f,
                "the backup file uses format version {v}, but this tool only supports version 1 — try updating termius-backup"
            ),
            E::UnsupportedCipher(id) => write!(
                f,
                "the backup file uses an unsupported cipher (id {id}) — try updating termius-backup"
            ),
            E::UnsupportedKdf(id) => write!(
                f,
                "the backup file uses an unsupported KDF (id {id}) — try updating termius-backup"
            ),
            E::Integrity(msg) => write!(f, "integrity check failed: {msg}"),
            E::NotFound(msg) => write!(f, "{msg}"),
            E::SnapshotNotFound(msg) => write!(f, "snapshot not found: {msg}"),
            E::WeakPassword { detail } => write!(f, "{detail}"),
            E::Archive(msg) => write!(f, "archive error: {msg}"),
            E::Json(e) => write!(f, "could not read or write internal data: {e}"),
            E::NotLoggedIn => write!(
                f,
                "not logged in to Google Drive — run `termius-backup gdrive login` first"
            ),
            E::Gdrive(msg) => write!(f, "google drive error: {msg}"),
            E::NoSubcommand => write!(
                f,
                "no subcommand and no interactive terminal for the menu — \
                 pass one of: backup, restore, rollback, info, snapshots, gdrive (see --help)"
            ),
            E::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Other(format!("argon2: {e}"))
    }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Error::PasswordRejected
    }
}

/// Helper to wrap an arbitrary boxed error as [`Error::Other`].
impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Other(e.to_string())
    }
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Error::Gdrive(e.to_string())
    }
}

/// Translate a raw [`io::Error`] into plain language for a terminal reader:
/// common failure kinds become a sentence, and the OS-specific
/// "(os error N)" suffix is dropped from anything left over.
fn friendly_io(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "the file or directory could not be found".to_string(),
        io::ErrorKind::PermissionDenied => {
            "permission was denied — check the file's permissions".to_string()
        }
        io::ErrorKind::AlreadyExists => "the file already exists".to_string(),
        io::ErrorKind::IsADirectory => "the path is a directory, not a file".to_string(),
        io::ErrorKind::NotADirectory => "the path is a file, not a directory".to_string(),
        // Unrecognized kinds: keep the OS description, minus the jargon.
        _ => e
            .to_string()
            .split(" (os error ")
            .next()
            .unwrap_or("")
            .to_string(),
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_not_found_is_plain_language() {
        let e = Error::Io(io::Error::from_raw_os_error(2));
        let s = e.to_string();
        assert!(!s.contains("os error"), "raw os error leaked: {s}");
        assert!(s.contains("could not be found"), "message: {s}");
    }

    #[test]
    fn io_permission_denied_is_plain_language() {
        let e = Error::Io(io::Error::from(io::ErrorKind::PermissionDenied));
        let s = e.to_string();
        assert!(s.contains("permission"), "message: {s}");
        assert!(!s.contains("os error"), "raw os error leaked: {s}");
    }

    #[test]
    fn not_found_detail_is_not_double_prefixed() {
        let e = Error::NotFound("Termius data directory not found: /x".into());
        assert_eq!(e.to_string(), "Termius data directory not found: /x");
    }

    #[test]
    fn password_rejected_is_friendly() {
        let s = Error::PasswordRejected.to_string();
        assert!(s.contains("password"), "message: {s}");
        assert!(!s.is_empty());
    }
}
