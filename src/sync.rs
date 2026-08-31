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
use std::path::Path;
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

fn record_state_file(path: &Path, vault: &str, sig: DirSignature) {
    let mut file = load_state_file(path);
    file.vaults.insert(vault.to_string(), sig);
    let json =
        serde_json::to_vec_pretty(&file).expect("SyncStateFile is serializable by construction");
    if let Err(e) = util::atomic_write(path, &json) {
        eprintln!(
            "warning: could not write sync state {}: {e}",
            path.display()
        );
    }
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

/// Options for `gdrive sync`.
#[derive(Debug, Clone)]
pub struct SyncOptions<'a> {
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
    let src = paths::resolve_termius_dir(opts.termius_dir)?;
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
/// automatically. No-ops when `--yes` was passed or stdin is not a TTY
/// (CI / pipes), and swallows sync errors with a message — the backup
/// itself already succeeded, and a declined or failed sync should not fail
/// the run.
pub fn offer_after_backup(
    termius_dir: Option<&Path>,
    password_file: Option<&Path>,
    password_env: Option<&str>,
    creds_path: &Path,
    yes: bool,
    vault_name: &str,
) {
    if yes || !std::io::stdin().is_terminal() {
        return;
    }
    let base = gdrive::vault_base_name(vault_name);
    let accepted = match prompt::confirm(&format!(
        "Back up to Google Drive continuously while Termius changes? (vault '{base}')"
    )) {
        Ok(b) => b,
        Err(_) => return, // e.g. Ctrl-C at the prompt — the backup is done
    };
    if !accepted {
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
    // first upload only happens when Termius actually changes something.
    let last_sig = match dir_signature(&src) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Sync not started: cannot read {}: {e}", src.display());
            return;
        }
    };

    let opts = SyncOptions {
        termius_dir: Some(&src),
        name: Some(base),
        password_file,
        password_env,
        creds_path,
        yes,
        interval: 60,
        keep: 10,
        once: false,
        last_sig: Some(last_sig),
        kdf: KdfParams::default(),
    };
    if let Err(e) = run_sync(opts) {
        eprintln!("Sync stopped: {e}");
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
        let meta = archive::unpack(&payload, dest.path()).unwrap();
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
