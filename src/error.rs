// SPDX-License-Identifier: Apache-2.0

//! Typed errors and process exit codes.

use std::io;
use thiserror::Error;

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
            E::Io(_) | E::Archive(_) | E::Json(_) | E::Other(_) => ExitCode::Internal,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("cancelled by user: {0}")]
    Canceled(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("password rejected: decryption failed (wrong password or corrupted file)")]
    PasswordRejected,

    #[error("backup file format error: {detail} (at offset {offset})")]
    BadFormat { detail: String, offset: u64 },

    #[error("unsupported container version: {0} (this tool supports version 1)")]
    UnsupportedVersion(u8),

    #[error("unsupported cipher id: {0}")]
    UnsupportedCipher(u8),

    #[error("unsupported KDF id: {0}")]
    UnsupportedKdf(u8),

    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error("path not found: {0}")]
    NotFound(String),

    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error(
        "weak password: {detail}. Re-enter a stronger password, or confirm to proceed anyway."
    )]
    WeakPassword { detail: String },

    #[error("archive error: {0}")]
    #[allow(dead_code)]
    Archive(String),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

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
