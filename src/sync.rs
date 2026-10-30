// SPDX-License-Identifier: Apache-2.0

//! Continuous sync of the Termius data directory to a Google Drive vault.
//!
//! `gdrive sync` polls a cheap directory signature (file count, total size,
//! newest mtime) on an interval and uploads a fresh encrypted `.tsb` when the
//! tree has changed and settled. An in-process poller is used instead of
//! filesystem-event libraries on purpose: Termius (Electron) rewrites its
//! LevelDB files continuously, so event streams degenerate into the same
//! debounce problem with more moving parts — while a 60-second poll of a
//! size/mtime summary is portable, dependency-free, and cheap.
//!
//! Upload policy ([`sync_tick`], a pure decision function):
//! - the tree must differ from the last uploaded signature (else nothing to do);
//! - it must be *stable* — unchanged for at least `debounce` seconds — so we
//!   never capture a half-written file;
//! - at most one upload per `interval`;
//! - safety net: if the tree never settles (a continuously-touched file), a
//!   forced upload happens after `force_after` of dirtiness.
//!
//! `--once` skips the debounce entirely (check once, upload if changed, exit)
//! so the command is cron / systemd-timer friendly.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::archive;
use crate::backup;
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::gdrive;
use crate::paths;
use crate::prompt;
use crate::service;
use crate::util;

/// Cheap fingerprint of a directory tree. Any change to a file's presence,
/// size, or mtime changes the signature. (Pure renames of same-size,
/// same-mtime files are not detected — the next content change re-captures
/// them, which is fine for a backup tool.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DirSignature {
    pub file_count: u64,
    pub total_size: u64,
    pub max_mtime_secs: u64,
}

/// Compute [`DirSignature`] for `root` (recursively, not following
/// symlinks). Fails if the root does not exist.
pub fn dir_signature(root: &Path) -> Result<DirSignature> {
    let mut sig = DirSignature::default();
    walk_signature(root, &mut sig)?;
    Ok(sig)
}

fn walk_signature(current: &Path, sig: &mut DirSignature) -> Result<()> {
    let meta = std::fs::symlink_metadata(current)?;
    if meta.is_dir() && !meta.file_type().is_symlink() {
        for entry in std::fs::read_dir(current)? {
            walk_signature(&entry?.path(), sig)?;
        }
    } else if meta.is_file() {
        sig.file_count += 1;
        sig.total_size += meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        sig.max_mtime_secs = sig.max_mtime_secs.max(mtime);
    }
    Ok(())
}

/// On-disk sync state: for each vault, the fingerprint of the tree that
/// the most recent backup/sync uploaded. This is what lets a fresh `--once`
/// run (cron, or after a reboot) know what is already on Drive without
/// downloading anything, and what lets a `gdrive sync` started after a
/// reboot pick up changes made while the machine was off.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SyncStateFile {
    #[serde(default)]
    vaults: HashMap<String, DirSignature>,
    /// Vault names whose continuous-sync offer has been turned off with
    /// `gdrive sync off`; [`SYNC_OFF_ALL`] means "all vaults".
    #[serde(default)]
    sync_off: Vec<String>,
    /// Vault names explicitly turned back on while a global
    /// [`SYNC_OFF_ALL`] off is in effect — they are on even though
    /// everything else is off. "Turn back on for one vault" carves a
    /// vault out of an all-vaults off this way.
    #[serde(default)]
    sync_on: Vec<String>,
    /// The Termius data directory the last sync run used, so later runs
    /// (cron `--once`, after a reboot) don't need `--termius-dir` again.
    #[serde(default)]
    termius_dir: Option<String>,
}

/// Sentinel stored in `sync_off` for a global (all-vaults) off.
const SYNC_OFF_ALL: &str = "*";

impl SyncStateFile {
    /// Whether the continuous-sync offer is off for `vault`: either it was
    /// turned off individually, or a global off is set and `vault` has no
    /// per-vault exception.
    fn is_off(&self, vault: &str) -> bool {
        let individual = self.sync_off.iter().any(|x| x == vault);
        let global = self.sync_off.iter().any(|x| x == SYNC_OFF_ALL)
            && !self.sync_on.iter().any(|x| x == vault);
        individual || global
    }
}

fn load_state_file(path: &Path) -> SyncStateFile {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            eprintln!(
                "warning: sync state {} is unreadable ({e}) — treating it as empty.",
                path.display()
            );
            SyncStateFile::default()
        }),
        // Missing file = first run on this machine.
        Err(_) => SyncStateFile::default(),
    }
}

/// Persist the whole state file (atomic write).
fn save_state_file(path: &Path, file: &SyncStateFile) -> Result<()> {
    let json = serde_json::to_vec_pretty(file).expect("SyncStateFile serializes by construction");
    util::atomic_write(path, &json)
}

fn record_state_file(path: &Path, vault: &str, sig: DirSignature) {
    let mut file = load_state_file(path);
    file.vaults.insert(vault.to_string(), sig);
    if let Err(e) = save_state_file(path, &file) {
        eprintln!(
            "warning: could not write sync state {}: {e}",
            path.display()
        );
    }
}

/// Turn the continuous-sync offer off (or back on) for `vault` — or for
/// every vault when `vault` is `None` — in the state file at `path`.
/// Turning a vault off also forgets its recorded baseline, so a later
/// explicit sync of it starts from a fresh tree. Returns the updated list
/// of off markers.
fn toggle_sync_off(path: &Path, vault: Option<&str>, off: bool) -> Result<Vec<String>> {
    let mut file = load_state_file(path);
    if off {
        match vault {
            Some(v) => {
                if !file.sync_off.iter().any(|x| x == v) {
                    file.sync_off.push(v.to_string());
                }
                // An explicit off overrides any per-vault exception.
                file.sync_on.retain(|x| x != v);
                file.vaults.remove(v);
            }
            None => {
                if !file.sync_off.iter().any(|x| x == SYNC_OFF_ALL) {
                    file.sync_off.push(SYNC_OFF_ALL.to_string());
                }
                // Exceptions are meaningless when everything is off.
                file.sync_on.clear();
            }
        }
    } else {
        match vault {
            Some(v) => {
                file.sync_off.retain(|x| x != v);
                // With a global off in effect, record this vault as an
                // exception so it is actually on.
                if file.sync_off.iter().any(|x| x == SYNC_OFF_ALL)
                    && !file.sync_on.iter().any(|x| x == v)
                {
                    file.sync_on.push(v.to_string());
                }
            }
            None => {
                file.sync_off.clear();
                file.sync_on.clear();
            }
        }
    }
    save_state_file(path, &file)?;
    Ok(file.sync_off)
}

/// The per-vault uploaded-fingerprint record from the default state file.
fn load_sync_state() -> SyncStateFile {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p),
        Err(_) => SyncStateFile::default(),
    }
}

/// Record `sig` as the last uploaded fingerprint for `vault`. Best-effort:
/// a state-write failure never fails an otherwise-successful backup (worst
/// case, the next sync re-uploads the same state once).
pub fn record_sync_state(vault: &str, sig: DirSignature) {
    if let Ok(p) = paths::sync_state_path() {
        record_state_file(&p, vault, sig);
    }
}

/// Remember `dir` as the Termius data directory for future sync runs, so
/// `gdrive sync` / `--once` (cron, after a reboot) don't need
/// `--termius-dir` again. Best-effort: a state-write failure never fails
/// an otherwise-successful sync.
pub fn remember_termius_dir(dir: &Path) {
    if let Ok(p) = paths::sync_state_path() {
        let mut file = load_state_file(&p);
        file.termius_dir = dir.to_str().map(str::to_string);
        if let Err(e) = save_state_file(&p, &file) {
            eprintln!("warning: could not write sync state {}: {e}", p.display());
        }
    }
}

/// The Termius data directory a previous sync run used, if any.
pub fn saved_termius_dir() -> Option<PathBuf> {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p).termius_dir.map(PathBuf::from),
        Err(_) => None,
    }
}

/// Whether the continuous-sync offer is turned off for `vault` (either
/// globally without an exception, or for that vault specifically).
pub fn sync_is_off(vault: &str) -> bool {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p).is_off(vault),
        Err(_) => false,
    }
}

/// Whether the global (all-vaults) off marker is currently set.
pub fn sync_globally_off() -> bool {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p)
            .sync_off
            .iter()
            .any(|x| x == SYNC_OFF_ALL),
        Err(_) => false,
    }
}

/// Human-readable summary of the offer's on/off state, for the
/// interactive "Sync settings" page.
pub fn sync_status() -> String {
    let file = match paths::sync_state_path() {
        Ok(p) => load_state_file(&p),
        Err(_) => return "on for all vaults".to_string(),
    };
    if file.sync_off.iter().any(|x| x == SYNC_OFF_ALL) {
        if file.sync_on.is_empty() {
            "off for all vaults".to_string()
        } else {
            format!("off for all vaults except: {}", file.sync_on.join(", "))
        }
    } else if file.sync_off.is_empty() {
        "on for all vaults".to_string()
    } else {
        format!("off for: {}", file.sync_off.join(", "))
    }
}

/// What [`sync_on`] / [`sync_off`] need to manage the vault's background
/// service alongside the offer state.
pub struct ServiceCtx<'a> {
    /// The Google credential store the service's master password unlocks.
    pub creds_path: &'a Path,
    /// Skip the confirmation prompts.
    pub yes: bool,
    /// A `--service-secrets` file to read the two passwords from (or
    /// create) instead of prompting.
    pub secrets_file: Option<&'a Path>,
}

/// Turn continuous sync off for `vault` (or every vault when `None`):
/// stop and remove the vault's background service, forget the recorded
/// baseline, and stop suggesting it after backups. Returns the list of
/// off markers now in effect ("*" = all).
pub fn sync_off(vault: Option<&str>) -> Result<Vec<String>> {
    match vault {
        Some(v) => {
            let removed = service::remove_service(v)?;
            drop_secrets(v, removed);
        }
        None => {
            for slug in service::installed_vaults() {
                let removed = service::remove_service(&slug)?;
                drop_secrets(&slug, removed);
            }
        }
    }
    toggle_sync_off(&paths::sync_state_path()?, vault, true)
}

/// Turn continuous sync back on for `vault` (or every vault): start the
/// vault's background service — it keeps syncing with the terminal closed
/// and across reboots, until turned off with `gdrive sync off` — and
/// re-enable the post-backup offer. Returns the list of off markers still
/// in effect.
pub fn sync_on(vault: Option<&str>, ctx: &ServiceCtx) -> Result<Vec<String>> {
    // The background service is per-vault; a global "on" (no vault name)
    // only re-enables the offer and installs no service.
    if let Some(v) = vault {
        ensure_sync_service(v, ctx)?;
    }
    toggle_sync_off(&paths::sync_state_path()?, vault, false)
}

/// Make sure the background service for `vault` is installed and running:
/// ensure a secrets file with the two passwords exists (prompting for
/// them when none does) and (re)install the service.
fn ensure_sync_service(vault: &str, ctx: &ServiceCtx) -> Result<()> {
    let secrets_path = match ctx.secrets_file {
        Some(p) => p.to_path_buf(),
        None => paths::service_secrets_path(vault)?,
    };
    if !secrets_path.is_file() {
        let master_password = gdrive::master_password(ctx.creds_path)?;
        let backup_password = backup::acquire_password(None, None, true, ctx.yes)?;
        service::write_secrets(
            &secrets_path,
            &service::ServiceSecrets {
                master_password,
                backup_password,
            },
        )?;
    }
    service::install_service(vault, &secrets_path)
}

/// Remove a vault's default secrets file. Best-effort — the service is
/// already gone, so a leftover file is not worth failing the run. Custom
/// `--service-secrets` files are never touched.
fn drop_secrets(vault: &str, removed: bool) {
    if !removed {
        return;
    }
    if let Ok(p) = paths::service_secrets_path(vault) {
        let _ = std::fs::remove_file(&p);
    }
}

/// Scheduling parameters for the sync loop.
#[derive(Debug, Clone, Copy)]
pub struct SyncPolicy {
    /// How often to check for changes.
    pub interval: Duration,
    /// How long the tree must stay unchanged before an upload (guards
    /// against capturing mid-write state).
    pub debounce: Duration,
    /// Force an upload after this much dirtiness even if the tree never
    /// settles (continuously-written files).
    pub force_after: Duration,
}

impl SyncPolicy {
    /// Derive the policy from a user-supplied interval (seconds). The
    /// interval is clamped to a 5-second minimum so a typo like `--interval
    /// 0` cannot busy-loop; the debounce is at most 10 seconds (and never
    /// longer than the interval itself).
    pub fn from_interval(secs: u64) -> Self {
        let interval = Duration::from_secs(secs.max(5));
        let debounce = Duration::from_secs(10.min(interval.as_secs()));
        SyncPolicy {
            interval,
            debounce,
            force_after: Duration::from_secs(15 * 60),
        }
    }
}

/// Mutable sync state carried across ticks.
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Signature seen on the previous tick (drives stability detection).
    pub prev_sig: DirSignature,
    /// Signature of the last successful upload — the clean baseline.
    pub uploaded_sig: DirSignature,
    /// When the currently-observed signature was first seen.
    pub stable_since: Option<time::OffsetDateTime>,
    /// When the tree first diverged from `uploaded_sig`.
    pub dirty_since: Option<time::OffsetDateTime>,
    /// When the last successful upload happened.
    pub last_upload: Option<time::OffsetDateTime>,
}

impl SyncState {
    /// Start with `sig` as the clean baseline (nothing to upload until the
    /// tree changes).
    pub fn with_baseline(sig: DirSignature) -> Self {
        SyncState {
            prev_sig: sig,
            uploaded_sig: sig,
            stable_since: None,
            dirty_since: None,
            last_upload: None,
        }
    }

    /// Record a successful upload of `sig`.
    pub fn mark_uploaded(&mut self, sig: DirSignature, now: time::OffsetDateTime) {
        self.uploaded_sig = sig;
        self.last_upload = Some(now);
        self.stable_since = None;
        self.dirty_since = None;
    }
}

/// Decide whether `now` is a good moment to upload. Pure with respect to the
/// world (no I/O, no clocks read): it mutates `state`'s bookkeeping fields
/// and returns true when an upload should happen.
///
/// A backwards clock step (NTP correction) never panics and never uploads
/// early — durations that would be negative are treated as zero.
pub fn sync_tick(
    state: &mut SyncState,
    sig: &DirSignature,
    now: time::OffsetDateTime,
    policy: SyncPolicy,
    once: bool,
) -> bool {
    // An empty tree (or an unreadable-as-empty one) is not a backup target:
    // it would upload an almost-empty vault if the real directory vanished
    // mid-run.
    if sig == &DirSignature::default() {
        return false;
    }
    if *sig == state.uploaded_sig {
        return false; // clean — nothing to do
    }
    if once {
        return true; // cron mode: changed means upload now
    }

    // Bookkeeping: when did this signature appear, when did dirt start.
    if state.prev_sig != *sig {
        state.stable_since = Some(now);
    }
    if state.dirty_since.is_none() {
        state.dirty_since = Some(now);
    }
    state.prev_sig = *sig;

    // At most one upload per interval.
    if let Some(last) = state.last_upload {
        if since(last, now) < policy.interval {
            return false;
        }
    }
    // Debounce: the tree must be unchanged long enough to be settled.
    let stable_for = state
        .stable_since
        .map(|t| since(t, now))
        .unwrap_or_default();
    if stable_for >= policy.debounce {
        return true;
    }
    // Safety net: continuously-dirty trees still get uploaded eventually.
    let dirty_for = state.dirty_since.map(|t| since(t, now)).unwrap_or_default();
    dirty_for >= policy.force_after
}

/// `now - t` as a std duration, or zero if the clock stepped backwards.
fn since(t: time::OffsetDateTime, now: time::OffsetDateTime) -> Duration {
    if now >= t {
        (now - t).unsigned_abs()
    } else {
        Duration::ZERO
    }
}

/// Choose the sync source directory. An explicit `--termius-dir` always
/// wins; otherwise a path saved by a previous run is reused — but only
/// while it still exists, so a moved/deleted directory falls back to the
/// usual resolution instead of sticking to a stale path. Returns
/// `(directory, from_saved)`, or `None` when the caller should fall back
/// to the auto-detected default (which may prompt on a TTY).
fn pick_sync_termius_dir(
    override_path: Option<&Path>,
    saved: Option<&Path>,
) -> Result<Option<(PathBuf, bool)>> {
    if let Some(p) = override_path {
        return Ok(Some((paths::resolve_termius_dir(Some(p))?, false)));
    }
    if let Some(s) = saved.filter(|p| p.is_dir()) {
        return Ok(Some((s.to_path_buf(), true)));
    }
    Ok(None)
}

/// Resolve the directory the sync watches, honoring the saved path from a
/// previous run when no `--termius-dir` was given.
fn resolve_sync_termius_dir(override_path: Option<&Path>) -> Result<(PathBuf, bool)> {
    match pick_sync_termius_dir(override_path, saved_termius_dir().as_deref())? {
        Some(d) => Ok(d),
        None => Ok((paths::resolve_termius_dir(None)?, false)),
    }
}

/// Options for `gdrive sync`.
#[derive(Debug, Clone)]
pub struct SyncOptions<'a> {
    /// Explicit `--termius-dir`. When absent, the directory saved by a
    /// previous sync run is reused (if it still exists) before the
    /// auto-detected default; whatever is resolved is remembered for the
    /// next run.
    pub termius_dir: Option<&'a Path>,
    /// Vault name (prompts if absent).
    pub name: Option<&'a str>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub creds_path: &'a Path,
    pub yes: bool,
    /// Check interval in seconds (clamped to a 5-second minimum).
    pub interval: u64,
    /// Keep only the newest N backups in the vault (0 = keep all).
    pub keep: u32,
    /// Check once, upload if changed, then exit.
    pub once: bool,
    /// Baseline signature: changes are detected relative to this. `None`
    /// falls back to the fingerprint recorded in the on-disk sync state
    /// (the last upload for this vault), or to empty on a first run — so
    /// `--once` compares against what is really on Drive, across reboots.
    /// Set by the post-backup offer so a fresh backup is not re-uploaded a
    /// few seconds later.
    pub last_sig: Option<DirSignature>,
    /// KDF parameters for the encrypted uploads (the CLI passes the
    /// production defaults; tests use fast ones).
    pub kdf: KdfParams,
}

/// Run the sync loop. Continuous mode never returns an error for transient
/// upload failures — it logs a warning and retries on the next tick; only
/// setup failures (no creds, bad master password, unreadable Termius dir)
/// are fatal. In `once` mode any upload failure is returned.
pub fn run_sync(opts: SyncOptions<'_>) -> Result<()> {
    let (src, from_saved) = resolve_sync_termius_dir(opts.termius_dir)?;
    // Remember the directory we are about to watch so the next run (cron,
    // after a reboot) doesn't need --termius-dir.
    remember_termius_dir(&src);
    let policy = SyncPolicy::from_interval(opts.interval);

    // Unlock the stored Google credentials first, so a wrong master
    // password fails fast before any vault naming or backup-password work.
    let master = gdrive::master_password(opts.creds_path)?;
    let mut session = gdrive::Session::open(opts.creds_path, master.as_bytes())?;

    let name = match opts.name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => prompt::ask_string(
            "Name for the sync target (a <name>.tsbak-vault folder on Drive):",
            None,
        )?,
    };
    let vault_name = gdrive::vault_folder_name(&name);

    // The backup password is asked once and reused for every upload.
    let password = backup::acquire_password(opts.password_file, opts.password_env, true, opts.yes)?;

    let folder_id = session.ensure_vault(&name)?;
    // Baseline: the post-backup offer seeds it explicitly (so a fresh
    // backup is not re-uploaded); otherwise the last uploaded fingerprint
    // recorded on this machine; on a first run (no record) the baseline is
    // empty, so the current tree is uploaded on the first check.
    let baseline = match opts.last_sig {
        Some(sig) => sig,
        None => load_sync_state()
            .vaults
            .get(&name)
            .copied()
            .unwrap_or_default(),
    };
    let mut state = SyncState::with_baseline(baseline);

    if opts.once {
        eprintln!(
            "One-shot sync: checking {} against vault '{}' …",
            src.display(),
            vault_name
        );
    } else {
        eprintln!(
            "Continuous sync: watching {} → vault '{}' every {}s (Ctrl-C to stop).",
            src.display(),
            vault_name,
            policy.interval.as_secs()
        );
    }
    if from_saved {
        eprintln!("Using the Termius path saved by a previous sync run — pass --termius-dir to override it.");
    }
    if opts.keep > 0 {
        eprintln!("Keeping the newest {} backup(s) in the vault.", opts.keep);
    }

    loop {
        // Access tokens live ~1 hour; a sync can outlive them.
        if session.token_expired() {
            if let Err(e) = session.refresh_if_expired(opts.creds_path, master.as_bytes()) {
                if opts.once {
                    return Err(e);
                }
                eprintln!("warning: could not refresh Google token: {e} — retrying next tick.");
            }
        }

        let sig = match dir_signature(&src) {
            Ok(s) => s,
            Err(e) => {
                if opts.once {
                    return Err(e);
                }
                eprintln!(
                    "warning: cannot read {}: {e} — retrying next tick.",
                    src.display()
                );
                thread::sleep(policy.interval);
                continue;
            }
        };

        let now = util::current_time();
        if sync_tick(&mut state, &sig, now, policy, opts.once) {
            let ctx = UploadCtx {
                opts: &opts,
                master: &master,
                src: &src,
                password: &password,
                folder_id: &folder_id,
                vault_name: &vault_name,
            };
            match attempt_upload(&mut session, &ctx, &mut state, sig) {
                Ok(true) => record_sync_state(&name, sig),
                Ok(false) => {} // torn-write skip — the next tick retries
                Err(e) if opts.once => return Err(e),
                Err(e) => eprintln!("warning: upload failed: {e} — retrying next tick."),
            }
        }

        if opts.once {
            break;
        }
        thread::sleep(policy.interval);
    }

    if opts.once {
        eprintln!("One-shot sync complete.");
    } else {
        eprintln!("Sync stopped.");
    }
    Ok(())
}

/// Per-upload context, so [`attempt_upload`] / [`do_upload`] don't need a
/// long argument list.
struct UploadCtx<'a> {
    opts: &'a SyncOptions<'a>,
    master: &'a str,
    src: &'a Path,
    password: &'a str,
    folder_id: &'a str,
    vault_name: &'a str,
}

/// One upload attempt: pack, torn-write re-check, encrypt, upload, prune,
/// and record the new baseline. A transient auth error (401) triggers a
/// token refresh and a single retry — the token may have expired mid-run.
/// Returns true when an upload actually happened (false = torn-write skip).
fn attempt_upload(
    session: &mut gdrive::Session,
    ctx: &UploadCtx<'_>,
    state: &mut SyncState,
    sig: DirSignature,
) -> Result<bool> {
    match do_upload(session, ctx, state, sig, util::current_time()) {
        Ok(done) => Ok(done),
        Err(e) if is_auth_error(&e) => {
            eprintln!("Google token appears expired — refreshing and retrying once.");
            session.refresh_if_expired(ctx.opts.creds_path, ctx.master.as_bytes())?;
            do_upload(session, ctx, state, sig, util::current_time())
        }
        Err(e) => Err(e),
    }
}

/// Perform one backup upload for the sync loop. On success the state's
/// baseline is advanced to `sig` (so the next tick sees a clean tree) and
/// retention pruning is applied. Returns false (without error) when the
/// torn-write guard skips the window.
fn do_upload(
    session: &mut gdrive::Session,
    ctx: &UploadCtx<'_>,
    state: &mut SyncState,
    sig: DirSignature,
    now: time::OffsetDateTime,
) -> Result<bool> {
    let opts = ctx.opts;
    eprintln!("Changes detected — packing {} …", ctx.src.display());
    let mut payload = Vec::new();
    let meta = archive::pack(ctx.src, &mut payload, &util::local_timestamp_string(&now))?;

    // Torn-write guard: if the tree changed while we packed, the archive
    // may straddle two states — skip this window; the next tick picks up
    // the new signature.
    let after = dir_signature(ctx.src)?;
    if after != sig {
        eprintln!("Directory changed while packing — skipping this window.");
        zeroize(&mut payload);
        return Ok(false);
    }

    eprintln!(
        "Packed {} entries ({} bytes).",
        meta.entry_count, meta.byte_size
    );
    let tsb = gdrive::encrypt_with(&opts.kdf, ctx.password.as_bytes(), &payload)?;
    zeroize(&mut payload);

    let file_name = gdrive::tsb_file_name(&now);
    let file_id = session.upload_file(ctx.folder_id, &file_name, &tsb)?;
    state.mark_uploaded(after, util::current_time());

    if opts.keep > 0 {
        let n = gdrive::prune_vault(session, ctx.folder_id, opts.keep)?;
        if n > 0 {
            eprintln!("Pruned {n} older backup(s); kept the newest {}.", opts.keep);
        }
    }
    eprintln!(
        "Synced {file_name} to vault '{}' (Drive file id {file_id}).",
        ctx.vault_name
    );
    Ok(true)
}

/// A Drive error that looks like an expired/invalid access token.
fn is_auth_error(e: &Error) -> bool {
    matches!(e, Error::Gdrive(m) if m.contains("401") || m.contains("Unauthorized"))
}

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// After a successful `gdrive backup`, offer to keep the vault up to date
/// automatically. The offer is an interactive three-way choice: start
/// syncing now, decline, or decline *and stop being asked about this
/// vault* (which records a `gdrive sync off` for it). Accepting installs
/// the continuous sync as a background service — it keeps running after
/// this terminal closes and after reboots, until `gdrive sync off`. The
/// offer no-ops when `--yes` was passed, stdin is not a TTY (CI / pipes),
/// or the offer was turned off with `gdrive sync off`; and it swallows
/// setup errors with a message — the backup itself already succeeded, and
/// a declined or failed sync start should not fail the run.
pub fn offer_after_backup(termius_dir: Option<&Path>, ctx: &ServiceCtx, vault_name: &str) {
    if ctx.yes || !std::io::stdin().is_terminal() {
        return;
    }
    let base = gdrive::vault_base_name(vault_name);
    // The user turned the offer off with `gdrive sync off` — honor it.
    if sync_is_off(base) {
        return;
    }
    // A bare Enter keeps the old behavior (decline, ask again next time).
    let choice = match prompt::choose(
        &format!(
            "Back up to Google Drive continuously while Termius changes? (vault '{base}')\n\
             (it runs as a background service that survives reboots — \
             'gdrive sync off' stops it)"
        ),
        &[
            "Yes — start continuous sync now".to_string(),
            format!("No — and don't ask me again for '{base}'"),
            "No — ask me again next time".to_string(),
        ],
        2,
    ) {
        Ok(c) => c,
        Err(_) => return, // e.g. Ctrl-C at the prompt — the backup is done
    };
    if choice == 1 {
        match sync_off(Some(base)) {
            Ok(_) => eprintln!(
                "OK — I won't ask about vault '{base}' again \
                 ('gdrive sync on' turns it back on)."
            ),
            Err(e) => eprintln!("could not remember that choice: {e}"),
        }
        return;
    }
    if choice != 0 {
        return;
    }

    let src = match paths::resolve_termius_dir(termius_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Sync not started: {e}");
            return;
        }
    };
    // Baseline = the tree as it stands now (right after the backup), so the
    // service's first upload only happens when Termius actually changes
    // something. Also remember the directory for the service's runs.
    let last_sig = match dir_signature(&src) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Sync not started: cannot read {}: {e}", src.display());
            return;
        }
    };
    remember_termius_dir(&src);
    record_sync_state(base, last_sig);

    match sync_on(Some(base), ctx) {
        Ok(_) => eprintln!(
            "Continuous sync for vault '{base}' is now running in the background \
             ({id}).\nIt survives reboots — stop it with 'gdrive sync off'.",
            id = service::service_id(base),
        ),
        Err(e) => eprintln!("Sync not started: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container;
    use crate::gdrive::GdriveClient;

    fn at(secs: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(secs)
    }

    fn sig(count: u64, size: u64, mtime: u64) -> DirSignature {
        DirSignature {
            file_count: count,
            total_size: size,
            max_mtime_secs: mtime,
        }
    }

    #[test]
    fn dir_signature_reacts_to_tree_changes() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir_signature(dir.path()).unwrap();
        assert_eq!(empty, DirSignature::default());

        std::fs::write(dir.path().join("a"), b"12345").unwrap();
        let s1 = dir_signature(dir.path()).unwrap();
        assert_eq!(s1.file_count, 1);
        assert_eq!(s1.total_size, 5);
        assert_ne!(s1.max_mtime_secs, 0);

        // A rewrite is caught by the size (and mtime) change. A *same-size*
        // rewrite relies on the mtime bump alone, which 1-second-granularity
        // filesystems can miss within one second — so change the size here.
        std::fs::write(dir.path().join("a"), b"abcdef").unwrap();
        let s2 = dir_signature(dir.path()).unwrap();
        assert_ne!(s1, s2);
        assert_eq!(s2.total_size, 6);

        // Nested file changes the count and total size.
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b"), b"xy").unwrap();
        let s3 = dir_signature(dir.path()).unwrap();
        assert_eq!(s3.file_count, 2);
        assert_eq!(s3.total_size, 8);

        // Deletion is caught.
        std::fs::remove_file(dir.path().join("sub/b")).unwrap();
        let s4 = dir_signature(dir.path()).unwrap();
        assert_eq!(s4.file_count, 1);
        assert_ne!(s3, s4);
    }

    #[test]
    fn dir_signature_missing_root_fails() {
        let err = dir_signature(Path::new("/nonexistent-tsban-sync-dir")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn policy_clamps_interval_and_derives_debounce() {
        assert_eq!(
            SyncPolicy::from_interval(0).interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(3).interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(60).interval,
            Duration::from_secs(60)
        );
        // Debounce is at most 10 s, and never longer than the interval.
        assert_eq!(
            SyncPolicy::from_interval(60).debounce,
            Duration::from_secs(10)
        );
        assert_eq!(
            SyncPolicy::from_interval(5).debounce,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(60).force_after,
            Duration::from_secs(900)
        );
    }

    #[test]
    fn tick_uploads_after_debounce_when_stable() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(DirSignature::default());
        let s = sig(1, 10, 100);
        // Change appears at t=0: dirty, but the debounce hasn't elapsed.
        assert!(!sync_tick(&mut state, &s, at(0), policy, false));
        assert!(!sync_tick(&mut state, &s, at(9), policy, false));
        assert!(sync_tick(&mut state, &s, at(10), policy, false));
    }

    #[test]
    fn tick_waits_for_tree_to_settle() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(DirSignature::default());
        let a = sig(1, 1, 1);
        let b = sig(1, 2, 2);
        // Changing every 5 s: the debounce keeps resetting.
        assert!(!sync_tick(&mut state, &a, at(0), policy, false));
        assert!(!sync_tick(&mut state, &b, at(5), policy, false));
        assert!(!sync_tick(&mut state, &a, at(10), policy, false));
        assert!(!sync_tick(&mut state, &b, at(15), policy, false));
        // Still at b at t=20 (5 s of stability — not enough)…
        assert!(!sync_tick(&mut state, &b, at(20), policy, false));
        // …but 10 s of stability at t=25 uploads.
        assert!(sync_tick(&mut state, &b, at(25), policy, false));
    }

    #[test]
    fn tick_respects_interval_between_uploads() {
        let policy = SyncPolicy::from_interval(60);
        let a = sig(1, 1, 1);
        let b = sig(1, 2, 2);
        let mut state = SyncState::with_baseline(DirSignature::default());
        // First change appears at t=10; the debounce still applies, so the
        // first upload lands 10 s later.
        assert!(!sync_tick(&mut state, &a, at(10), policy, false));
        assert!(sync_tick(&mut state, &a, at(20), policy, false));
        state.mark_uploaded(a, at(20));

        // New change at t=22: the interval (60 s) has not elapsed, so even
        // after the debounce the tick stays quiet until t=80.
        assert!(!sync_tick(&mut state, &b, at(22), policy, false));
        assert!(!sync_tick(&mut state, &b, at(79), policy, false));
        assert!(sync_tick(&mut state, &b, at(80), policy, false));
    }

    #[test]
    fn tick_force_after_uploads_a_never_settling_tree() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(DirSignature::default());
        // A different signature every second (a continuously-touched file).
        for t in 0..=905i64 {
            let s = sig(t.unsigned_abs(), t.unsigned_abs(), t.unsigned_abs());
            if sync_tick(&mut state, &s, at(t), policy, false) {
                // Fired no later than force_after (900 s) of dirtiness.
                assert!(t >= 900, "fired too early at t={t}");
                return;
            }
        }
        panic!("never uploaded a continuously-dirty tree");
    }

    #[test]
    fn tick_clock_step_back_is_safe() {
        let policy = SyncPolicy::from_interval(60);
        let s = sig(1, 1, 1);
        let mut state = SyncState::with_baseline(DirSignature::default());
        sync_tick(&mut state, &s, at(100), policy, false); // stable_since = 100
                                                           // The clock steps backwards: no panic, no premature upload.
        assert!(!sync_tick(&mut state, &s, at(50), policy, false));
    }

    #[test]
    fn tick_clean_tree_is_never_uploaded() {
        let policy = SyncPolicy::from_interval(60);
        let s = sig(1, 1, 1);
        let mut state = SyncState::with_baseline(s);
        for t in 0..300i64 {
            assert!(!sync_tick(&mut state, &s, at(t), policy, false));
        }
    }

    #[test]
    fn tick_empty_tree_is_never_uploaded() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(sig(1, 1, 1));
        let empty = DirSignature::default();
        for t in 0..300i64 {
            assert!(!sync_tick(&mut state, &empty, at(t), policy, false));
        }
    }

    #[test]
    fn tick_once_uploads_immediately_when_dirty() {
        let policy = SyncPolicy::from_interval(60);
        let clean = sig(1, 1, 1);
        let dirty = sig(2, 2, 2);
        let mut state = SyncState::with_baseline(clean);
        assert!(sync_tick(&mut state, &dirty, at(0), policy, true));
        assert!(!sync_tick(&mut state, &clean, at(0), policy, true));
    }

    #[test]
    fn sync_state_file_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        let a = sig(1, 10, 100);
        let b = sig(2, 20, 200);
        record_state_file(&path, "laptop", a);
        record_state_file(&path, "server", b);
        let file = load_state_file(&path);
        assert_eq!(file.vaults.get("laptop"), Some(&a));
        assert_eq!(file.vaults.get("server"), Some(&b));

        // Updating an existing vault replaces its entry, keeps the others.
        let a2 = sig(1, 11, 101);
        record_state_file(&path, "laptop", a2);
        let file = load_state_file(&path);
        assert_eq!(file.vaults.get("laptop"), Some(&a2));
        assert_eq!(file.vaults.get("server"), Some(&b));
    }

    #[test]
    fn sync_state_file_missing_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let file = load_state_file(&tmp.path().join("absent.json"));
        assert!(file.vaults.is_empty());
    }

    #[test]
    fn sync_state_file_corrupt_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        std::fs::write(&path, b"not json").unwrap();
        let file = load_state_file(&path);
        assert!(file.vaults.is_empty());
    }

    #[test]
    fn sync_state_file_remembered_dir_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        let dir = tempfile::tempdir().unwrap();

        let file = SyncStateFile {
            termius_dir: dir.path().to_str().map(str::to_string),
            ..SyncStateFile::default()
        };
        save_state_file(&path, &file).unwrap();
        let loaded = load_state_file(&path);
        assert_eq!(loaded.termius_dir.as_deref(), dir.path().to_str());

        // A state file written by an older version (without the field)
        // loads with no remembered directory.
        std::fs::write(&path, r#"{"vaults":{}}"#).unwrap();
        let loaded = load_state_file(&path);
        assert!(loaded.termius_dir.is_none());
    }

    #[test]
    fn pick_termius_dir_override_wins_over_saved() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = tmp.path().join("custom");
        let saved = tmp.path().join("saved");
        std::fs::create_dir_all(&custom).unwrap();
        std::fs::create_dir_all(&saved).unwrap();
        let (d, from_saved) = pick_sync_termius_dir(Some(&custom), Some(&saved))
            .unwrap()
            .unwrap();
        assert_eq!(d, custom);
        assert!(!from_saved);
    }

    #[test]
    fn pick_termius_dir_uses_saved_when_no_override() {
        let tmp = tempfile::tempdir().unwrap();
        let saved = tmp.path().join("saved");
        std::fs::create_dir_all(&saved).unwrap();
        let (d, from_saved) = pick_sync_termius_dir(None, Some(&saved)).unwrap().unwrap();
        assert_eq!(d, saved);
        assert!(from_saved);
    }

    #[test]
    fn pick_termius_dir_stale_saved_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("never-created");
        // A saved path that no longer exists (and no override) means "use
        // the usual resolution" — the caller's fallback, not an error.
        assert!(pick_sync_termius_dir(None, Some(&gone)).unwrap().is_none());
        assert!(pick_sync_termius_dir(None, None).unwrap().is_none());
    }

    #[test]
    fn pick_termius_dir_missing_override_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("nope");
        assert!(pick_sync_termius_dir(Some(&bogus), None).is_err());
    }

    #[test]
    fn sync_off_on_toggle_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        let a = sig(1, 10, 100);
        let b = sig(2, 20, 200);
        record_state_file(&path, "laptop", a);
        record_state_file(&path, "server", b);

        // Off for one vault: marker added, its baseline forgotten, the
        // other vault's baseline untouched.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert_eq!(off, vec!["laptop".to_string()]);
        let file = load_state_file(&path);
        assert!(!file.vaults.contains_key("laptop"));
        assert_eq!(file.vaults.get("server"), Some(&b));
        assert!(file.sync_off.iter().any(|x| x == "laptop"));

        // Idempotent — no duplicate marker.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert_eq!(off, vec!["laptop".to_string()]);

        // Back on removes only that marker.
        let off = toggle_sync_off(&path, Some("laptop"), false).unwrap();
        assert!(off.is_empty());
    }

    #[test]
    fn sync_off_global_off_specific_on() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");

        // Global off: every vault is off.
        let off = toggle_sync_off(&path, None, true).unwrap();
        assert_eq!(off, vec![SYNC_OFF_ALL.to_string()]);
        let file = load_state_file(&path);
        assert!(file.is_off("laptop"));
        assert!(file.is_off("server"));

        // Turning one vault back on does not clear the global off — it
        // records the vault as an exception, so that vault is on while
        // everything else stays off.
        let off = toggle_sync_off(&path, Some("laptop"), false).unwrap();
        assert_eq!(off, vec![SYNC_OFF_ALL.to_string()]);
        let file = load_state_file(&path);
        assert!(!file.is_off("laptop"), "exception vault must be on");
        assert!(file.is_off("server"), "other vaults must stay off");
        assert!(file.sync_on.iter().any(|x| x == "laptop"));

        // Explicitly turning the exception off again removes it and adds
        // the individual marker.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert!(off.iter().any(|x| x == SYNC_OFF_ALL));
        let file = load_state_file(&path);
        assert!(file.is_off("laptop"));
        assert!(!file.sync_on.iter().any(|x| x == "laptop"));

        // Global on clears everything, exceptions included.
        let off = toggle_sync_off(&path, None, false).unwrap();
        assert!(off.is_empty());
        let file = load_state_file(&path);
        assert!(!file.is_off("laptop"));
        assert!(!file.is_off("server"));
        assert!(file.sync_on.is_empty());
    }

    #[test]
    fn do_upload_into_mock_session_produces_valid_tsb() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("hello.txt"), b"hello").unwrap();
        std::fs::write(src.path().join("sub/nested.txt"), b"nested").unwrap();

        let creds = gdrive::Creds {
            email: "test@example.com".into(),
            client_id: "client".into(),
            client_secret: None,
            refresh_token: "rt".into(),
            access_token: "at".into(),
            expires_at: i64::MAX,
        };
        let client = gdrive::MockGdriveClient::new();
        let mut session = gdrive::Session::new_with_client(creds, Box::new(client));
        let folder_id = session.ensure_vault("vault").unwrap();

        let opts = SyncOptions {
            termius_dir: None,
            name: Some("vault"),
            password_file: None,
            password_env: None,
            creds_path: Path::new("/nonexistent-creds"),
            yes: true,
            interval: 60,
            keep: 0,
            once: false,
            last_sig: None,
            // Fast KDF so the test stays quick.
            kdf: KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        };
        let sig = dir_signature(src.path()).unwrap();
        let mut state = SyncState::with_baseline(DirSignature::default());
        let ctx = UploadCtx {
            opts: &opts,
            master: "master",
            src: src.path(),
            password: "test-password",
            folder_id: &folder_id,
            vault_name: "vault.tsbak-vault",
        };
        assert!(do_upload(&mut session, &ctx, &mut state, sig, at(0)).unwrap());

        // Baseline advanced to the uploaded signature.
        assert_eq!(state.uploaded_sig, sig);

        // The uploaded bytes decrypt and unpack to the original tree.
        let backups = session.list_backups(&folder_id).unwrap();
        assert_eq!(backups.len(), 1);
        let tsb = session.download_file(&backups[0].id).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &tsb).unwrap();
        let payload = container::read_and_decrypt(file.path(), b"test-password").unwrap();
        let dest = tempfile::tempdir().unwrap();
        let (meta, _) = archive::unpack(&payload, dest.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join("hello.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read_to_string(dest.path().join("sub/nested.txt")).unwrap(),
            "nested"
        );
        assert!(meta.entry_count >= 2);
    }

    #[test]
    fn do_upload_applies_retention_pruning() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();

        let creds = gdrive::Creds {
            email: "test@example.com".into(),
            client_id: "client".into(),
            client_secret: None,
            refresh_token: "rt".into(),
            access_token: "at".into(),
            expires_at: i64::MAX,
        };
        let mut client = gdrive::MockGdriveClient::new();
        let folder_id = client.ensure_vault("vault").unwrap();
        // Seed three older backups.
        for i in 0..3 {
            client
                .upload_file(&folder_id, &format!("old-{i}.tsb"), b"old")
                .unwrap();
        }
        let mut session = gdrive::Session::new_with_client(creds, Box::new(client));

        let opts = SyncOptions {
            keep: 2,
            ..SyncOptions {
                termius_dir: None,
                name: Some("vault"),
                password_file: None,
                password_env: None,
                creds_path: Path::new("/nonexistent-creds"),
                yes: true,
                interval: 60,
                keep: 0,
                once: false,
                last_sig: None,
                kdf: KdfParams {
                    m_kib: 1024,
                    t: 1,
                    p: 1,
                },
            }
        };
        let sig = dir_signature(src.path()).unwrap();
        let mut state = SyncState::with_baseline(DirSignature::default());
        let ctx = UploadCtx {
            opts: &opts,
            master: "master",
            src: src.path(),
            password: "test-password",
            folder_id: &folder_id,
            vault_name: "vault.tsbak-vault",
        };
        assert!(do_upload(&mut session, &ctx, &mut state, sig, at(0)).unwrap());

        // 3 seeded + 1 new = 4; keep 2 → 2 deleted, 2 newest remain.
        let remaining = session.list_backups(&folder_id).unwrap();
        assert_eq!(remaining.len(), 2);
    }
}
