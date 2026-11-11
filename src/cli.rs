// SPDX-License-Identifier: Apache-2.0

//! Command-line interface definitions (clap v4, derive).

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "termius-backup",
    version,
    about = "Encrypted backup and restore for the local Termius data directory"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Override the Termius data directory (auto-detected by default).
    #[arg(long, global = true)]
    pub termius_dir: Option<PathBuf>,

    /// Override the snapshots directory (auto-detected by default).
    #[arg(long, global = true)]
    pub snapshots_dir: Option<PathBuf>,

    /// Read the password from the first line of this file.
    #[arg(long, global = true)]
    pub password_file: Option<PathBuf>,

    /// Read the password from this environment variable.
    #[arg(long, global = true)]
    pub password_env: Option<String>,

    /// Override the stored Google Drive credential path (auto-detected by default).
    #[arg(long, global = true)]
    pub creds_file: Option<PathBuf>,

    /// Read the Google Drive master password and the backup password from
    /// this JSON file instead of prompting (for the sync background
    /// service; `gdrive sync on` creates it when missing).
    #[arg(long, global = true)]
    pub service_secrets: Option<PathBuf>,

    /// Skip confirmation prompts and the weak-password gate (non-interactive).
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Do not carry Termius's OS-keyring `localKey`: backups skip reading
    /// it, restores skip installing a carried one. Without the carried key,
    /// restored hosts/keys only decrypt on machines that already hold it.
    #[arg(long, global = true)]
    pub no_carry_key: bool,

    /// Verbose logging.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// Owned global flags extracted from a parsed [`Cli`], plus the selected
/// subcommand (if any). `command: None` means the tool was run bare, which
/// triggers the interactive wizard on a TTY.
pub struct Globals {
    pub command: Option<Command>,
    pub termius_dir: Option<PathBuf>,
    pub snapshots_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub password_env: Option<String>,
    pub creds_file: Option<PathBuf>,
    pub service_secrets: Option<PathBuf>,
    pub yes: bool,
    /// Inverse of `--no-carry-key` (true = carry the Termius keyring key,
    /// the default).
    pub carry_key: bool,
}

impl Globals {
    /// Consume a parsed [`Cli`] and split it into globals + subcommand.
    pub fn from_cli(cli: Cli) -> Self {
        Globals {
            command: cli.command,
            termius_dir: cli.termius_dir,
            snapshots_dir: cli.snapshots_dir,
            password_file: cli.password_file,
            password_env: cli.password_env,
            creds_file: cli.creds_file,
            service_secrets: cli.service_secrets,
            yes: cli.yes,
            carry_key: !cli.no_carry_key,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Back up the Termius data directory into an encrypted .tsb file.
    Backup(BackupArgs),
    /// Restore the Termius data directory from an encrypted .tsb file.
    Restore(RestoreArgs),
    /// Roll the Termius directory back to a previous snapshot.
    Rollback(RollbackArgs),
    /// Inspect a .tsb file header without a password.
    Info(InfoArgs),
    /// Manage rollback snapshots.
    Snapshots(SnapshotsArgs),
    /// Back up and restore over Google Drive.
    Gdrive(GdriveArgs),
    /// Add termius-backup to your PATH so it can be run from anywhere.
    Install,
}

#[derive(Args, Debug, Default)]
pub struct BackupArgs {
    /// Output path for the encrypted backup file.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Path to the .tsb backup file to restore.
    pub file: PathBuf,
}

#[derive(Args, Debug, Default)]
pub struct RollbackArgs {
    /// Specific snapshot id to roll back to (otherwise prompts interactively).
    #[arg(long)]
    pub snap_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Path to the .tsb file to inspect.
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct SnapshotsArgs {
    #[command(subcommand)]
    pub action: SnapshotsAction,
}

#[derive(Subcommand, Debug)]
pub enum SnapshotsAction {
    /// List tagged rollback snapshots.
    List,
    /// Delete old snapshots, keeping the newest N per source directory.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Number of newest snapshots to keep per source directory.
    #[arg(long, default_value_t = 10)]
    pub keep: usize,
}

#[derive(Args, Debug)]
pub struct GdriveArgs {
    #[command(subcommand)]
    pub action: GdriveAction,
}

#[derive(Subcommand, Debug)]
pub enum GdriveAction {
    /// Log in to Google Drive (OAuth device flow) and store encrypted credentials.
    Login,
    /// Remove stored Google Drive credentials.
    Logout,
    /// Show the linked Google Drive account.
    Status,
    /// Back up the Termius data directory to a vault on Google Drive.
    Backup(GdriveBackupArgs),
    /// Restore the Termius data directory from a backup on Google Drive.
    Restore,
    /// Two-way sync with a vault: upload this machine's Termius changes and
    /// apply the ones other devices made (Ctrl-C to stop). `on`/`off` run
    /// it as a background service.
    Sync(GdriveSyncArgs),
}

#[derive(Args, Debug, Default)]
pub struct GdriveBackupArgs {
    /// Name for the backup (a `<name>.tsbak-vault` folder is created on Drive).
    #[arg(long)]
    pub name: Option<String>,
    /// Keep only the newest N backups in the vault (0 = keep all, the
    /// default).
    #[arg(long, default_value_t = 0)]
    pub keep: u32,
}

#[derive(Args, Debug)]
pub struct GdriveSyncArgs {
    /// Turn sync on or off: `gdrive sync on --name N` / `gdrive sync off`.
    #[command(subcommand)]
    pub command: Option<SyncCommand>,
    /// Vault name (prompts if absent; a `<name>.tsbak-vault` folder on Drive).
    #[arg(long)]
    pub name: Option<String>,
    /// How often (seconds) to check this machine and the vault for changes;
    /// minimum 5.
    #[arg(long, default_value_t = 60)]
    pub interval: u64,
    /// Keep only the newest N snapshots in the vault (0 = keep all).
    #[arg(long, default_value_t = 10)]
    pub keep: u32,
    /// Check once — upload this machine's changes or apply the vault's
    /// newer data — then exit (for cron / systemd timers).
    #[arg(long)]
    pub once: bool,
}

#[derive(Subcommand, Debug)]
pub enum SyncCommand {
    /// Turn sync off: stop and remove the vault's background service, stop
    /// suggesting sync after backups, and forget what this machine last
    /// synced (for every vault without `--name`). The vault's data on
    /// Drive is untouched.
    Off(SyncToggleArgs),
    /// Turn two-way sync on for `--name`: check the backup password against
    /// the vault, then install and start a background service that keeps
    /// this machine and the vault in sync across reboots. A machine syncs
    /// with one vault at a time. Without `--name`, only re-enables the
    /// post-backup offer.
    On(SyncToggleArgs),
}

#[derive(Args, Debug)]
pub struct SyncToggleArgs {
    /// Vault to turn on or off (`off`: all vaults when absent).
    #[arg(long)]
    pub name: Option<String>,
}
