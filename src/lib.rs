// termius-secure-backup — encrypted backup/restore for the local Termius data directory.
// SPDX-License-Identifier: Apache-2.0

//! Library crate: the backup/restore engine. The `termius-backup` binary
//! is a thin CLI wrapper over these modules.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod archive;
pub mod backup;
pub mod cli;
pub mod container;
pub mod crypto;
pub mod error;
pub mod gdrive;
pub mod paths;
pub mod prompt;
pub mod restore;
pub mod rollback;
pub mod snapshot;
pub mod sync;
pub mod util;
pub mod weakpass;
pub mod wizard;
