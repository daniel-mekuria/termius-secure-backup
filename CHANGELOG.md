# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `gdrive sync` — continuously re-backs up to a Google Drive vault while
  the Termius directory changes. An in-process watcher polls a cheap tree
  fingerprint (file count + total size + newest mtime) every
  `--interval` seconds (default 60, minimum 5) and uploads a fresh
  encrypted `.tsb` once the tree has settled (≤ 10 s debounce); a
  tree that never settles is force-uploaded every 15 minutes. A
  torn-write guard re-checks the fingerprint after packing and skips the
  window if the tree moved mid-pack. `--once` checks once, uploads if
  changed, and exits — cron / systemd-timer friendly (README has a full
  timer example). Transient network failures (and a Google token that
  expires mid-run) are retried on the next tick; Ctrl-C stops the watcher.
  Every upload (and every `gdrive backup`) records the fingerprint of the
  tree it saved in `~/.config/termius-secure-backup/sync-state.json`, and
  `--once` compares against that record rather than the current tree — so
  scheduled runs upload exactly when Termius changed since the last run,
  and baselines survive reboots (the first run uploads the current tree).
- Post-backup sync offer: after a successful `gdrive backup` (wizard or
  direct), the tool asks whether to start the continuous sync; the
  backup just made becomes the baseline so it is not re-uploaded.
- `gdrive sync on` / `gdrive sync off [--name N]`: persistently
  (re)enable the post-backup continuous-sync offer, per vault or for all
  vaults. Turning a vault off also forgets its recorded baseline, so the
  next explicit sync of it starts from a fresh tree; explicit
  `gdrive sync` runs are unaffected by the switch.
- `--keep N` retention flag: `gdrive backup --keep N` trims the vault to
  the newest N backups once per run; `gdrive sync --keep N` (default 10)
  applies it after every upload. `0` keeps everything (the old default
  for `gdrive backup`, unchanged).
- `TSBAK_GDRIVE_MASTER_PASSWORD` environment variable: when set, the
  Google Drive master password is read from it (one attempt, no prompt)
  so long syncs and `--once` runs can be fully unattended.

### Changed
- Wrong passwords no longer end the run: at every password prompt
  (backup, restore, and the Google Drive master password) a wrong entry
  re-prompts up to 3 times before failing, and the "previous data was
  preserved in snapshot …" hint is printed once after the final failure
  instead of per attempt. Piped / file / env-var passwords still fail
  fast (one attempt), so scripts keep deterministic behavior.
- Empty input at a required prompt (password, free-text value) now
  re-prompts on a TTY instead of failing; EOF ends the prompt.

### Fixed
- `gdrive restore` reported "no backup vaults found" right after a
  successful `gdrive backup`: the vault's marker file was uploaded with
  no name and no parent, so Drive created it as an "Untitled" file in
  the My Drive root and the vault folder was filtered out of the list.
  The marker is now uploaded with proper metadata (name + parent folder).
  Re-running `gdrive backup` with the same name heals an existing
  vault; the stray "Untitled" file in the Drive root is safe to delete.

## [0.2.1] - 2026-08-31

### Changed
- `gdrive` commands now work **out of the box**: the maintainer's Google
  OAuth client id (and its secret — that client is *confidential*) is
  baked into the binary, so `gdrive login` no longer needs
  `TSBAK_GDRIVE_CLIENT_ID` / `TSBAK_GDRIVE_CLIENT_SECRET` exported. Both
  env vars still override the baked-in default for users who register
  their own client; the baked-in secret is only sent to Google when the
  baked-in client is the one in use.
- Google access-token refresh now uses the client id/secret stored in the
  encrypted credential blob (the ones the login actually used) instead of
  whatever is currently configured, so switching OAuth clients after
  logging in no longer breaks token refresh.

## [0.2.0] - 2026-08-31

### Added
- `gdrive` subcommand for Google Drive backups:
  - `gdrive login` — links your Google account via the OAuth device flow
    (short code approved at `google.com/device`); when Google rejects the
    device flow for your client, it automatically falls back to browser
    login (authorization code + PKCE on a local loopback address). The
    refresh token is stored at
    `~/.config/termius-secure-backup/gdrive-creds.tsb`, **encrypted at
    rest with a master password** you choose.
  - `gdrive backup [--name N]` — encrypts the Termius directory (same
    Argon2id + XChaCha20-Poly1305 `.tsb` format) with a backup password
    and uploads a timestamped copy into a `<name>.tsbak-vault` folder on
    your Drive.
  - `gdrive restore` — lists your `.tsbak-vault` folders and their
    backups (newest first), downloads the chosen one, takes a pre-restore
    snapshot, decrypts, and restores.
  - `gdrive status` / `gdrive logout`.
- New `TSBAK_GDRIVE_CLIENT_ID` / `TSBAK_GDRIVE_CLIENT_SECRET` environment
  variables: register a free desktop OAuth client in your own Google
  Cloud project (step-by-step guide in the README); the secret is only
  needed for confidential clients and is stored in the encrypted
  credential blob, not in the shell.
- Interactive two-page wizard when the tool is run with no subcommand on
  a TTY: choose Backup/Restore, then Local file/Google Drive.
- New exit code `7` for Google Drive remote errors (documented in the
  README).

### Changed
- `gdrive login` now prints the consent URL and **waits for Enter**
  before opening the browser, so you can copy the URL elsewhere or open
  it on your cue; non-TTY sessions never auto-launch a browser.
- Weak-password detection now uses the **zxcvbn** library (dictionary,
  keyboard-pattern, sequence, date, and leetspeak analysis). The
  re-confirmation gate and the non-interactive warning show zxcvbn's
  concrete explanation (e.g. "This is a top-10 common password. Add
  another word or two."). A password is accepted without
  re-confirmation only if it is at least 12 characters **and** resists
  10^8 offline guesses (zxcvbn score ≥ 3, the library's own documented
  floor).
- All error messages are now plain language for the person reading the
  terminal: raw OS codes such as "No such file or directory (os error 2)"
  are translated, and `.tsb` read/write failures name the file involved
  (missing files report "backup file not found: \<path\>"). The
  `thiserror` dependency was dropped in favor of a manual `Display`
  impl.
- When the auto-detected Termius data directory is missing (sandboxed
  Mac App Store / Snap builds, or Termius not launched yet), an
  interactive run **asks for the real path** (with `~` expansion, and a
  "use it anyway" confirm for not-yet-existing restore targets) instead
  of failing outright; non-interactive runs get the `--termius-dir`
  hint.
- Google API/OAuth error bodies are surfaced verbatim in error messages
  (e.g. "client was not found" while a new client activates).

### Fixed
- First `gdrive login` on a fresh machine failed with "I/O error: No
  such file or directory (os error 2)": `~/.config/termius-secure-backup/`
  did not exist yet. The tool now creates the parent directory of any
  `.tsb` file it writes.

## [0.1.0] - 2026-08-24

Initial release.

- `backup` command: packs the local Termius data directory into an
  encrypted `.tsb` file (Argon2id + XChaCha20-Poly1305).
- `restore` command: decrypts a `.tsb` file and restores the Termius
  directory, creating a tagged pre-restore snapshot first.
- `rollback` command: reverts the live Termius directory from a previous
  unencrypted snapshot, after taking a pre-rollback snapshot.
- `snapshots list` / `snapshots prune` subcommands.
- `info` command: prints container version and KDF parameters without a
  password.
- Weak-password detection with re-confirmation gate.
- Non-interactive modes via `--password-file`, `--password-env`, `--yes`.
- Cross-platform support for macOS, Windows, and Linux.