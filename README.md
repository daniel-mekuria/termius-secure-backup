# Termius Secure Backup

`termius-backup` is a small, cross-platform CLI that **backs up and restores
the local Termius desktop data directory** with strong, password-based
encryption. The resulting backup file (`.tsb`) is **unreadable without the
password**, and restores are safe: the tool always snapshots the current
on-disk data first so you can roll back if something goes wrong.

Termius is an Electron-based SSH/terminal client. It stores your local data
(hosts, groups, keys, snippets, port-forwarding rules, known hosts, and the
offline encrypted copy of your vaults) in its Electron `userData` directory,
which lives in a different place on each operating system. Termius has **no
built-in backup feature for this local data** — it only offers **paid cloud
sync** — so this tool fills the gap with a local, offline, password-encrypted
backup you fully control.

> ⚠️ **Sandbox caveat.** Builds installed from the **Mac App Store** or via
> **Snap** run in a sandbox and use different, sandbox-specific paths, and
> the Snap build cannot access normal local storage. `termius-backup`
> auto-detects the standard Electron path per OS and lets you override it
> with `--termius-dir`. If the auto-detected path is missing, an
> interactive run asks you for the real path (and a non-interactive one
> gets a clear error) — point the flag at your real Termius directory.

---

## Installation

### From source

Requires a recent Rust toolchain (`rustup` stable).

```sh
cargo install --path .
# or, after cloning:
cargo build --release
# binary: target/release/termius-backup
```

### Prebuilt binaries

Download the latest binary for your platform from the
[releases page](https://github.com/daniel-mekuria/termius-secure-backup/releases)
and put it on your `PATH` — or just run `termius-backup install` and it will
do that for you.

---

## Where is my Termius data?

`termius-backup` auto-detects these paths; you can always override with
`--termius-dir <PATH>`.

| OS      | Default Termius data directory                          |
|---------|---------------------------------------------------------|
| macOS   | `~/Library/Application Support/Termius`                 |
| Windows | `%APPDATA%\Termius` (`C:\Users\<you>\AppData\Roaming\Termius`) |
| Linux   | `~/.config/Termius`                                     |

> **The encryption key lives in the OS keyring, and the backup carries it.**
> Termius stores the IndexedDB *encryption key* (`localKey`) in the OS
> keyring (Windows Credential Manager, the macOS Keychain, or the freedesktop
> Secret Service on Linux) — **not** in the `userData` directory. To make
> cross-machine restores work, a backup reads that key and stores it *inside*
> the encrypted `.tsb` (next to the data it protects); a restore installs it
> into the target machine's keyring before swapping in the data, so restored
> hosts and SSH keys decrypt on any machine, not just the source. Only the
> Termius-namespaced keyring entry is ever read or written. Pass
> `--no-carry-key` to skip this (e.g. to restore data whose key you already
> have). See [SECURITY.md](SECURITY.md) for the full threat model.

---

## Usage

### Interactive mode (no subcommand)

Run `termius-backup` with **no arguments** on a terminal and it walks you
through a menu:

```
What would you like to do?
  [1] Backup
  [2] Restore
  [3] Sync settings
  [4] Add to PATH
Back up to where?
  [1] Local file
  [2] Google Drive
```

- **Local** → asks for the output (backup) or input (restore) file path, then
  the password — the same flow as the `backup`/`restore` commands.
- **Google Drive** → runs the login flow if you are not logged in yet; if you
  are, it asks for your master password, then continues (vault name + backup
  password for backup, vault/backup selection for restore).
- **Sync settings** → shows whether sync is on and offers two options:
  **Turn on** and **Turn off**. *Turn on* runs the Google Drive flow —
  the login (when you are not logged in yet), your master password, the
  vault to sync with (pick the one your other devices sync with, or
  create a new one), and its backup password — and starts two-way sync
  in the background (see *Two-way sync between devices*). *Turn off*
  stops it.
- **Add to PATH** → the interactive version of `install`: puts
  `termius-backup` on your PATH so it can be run from anywhere (see below).

All global flags (`--termius-dir`, `--password-file`, …) still apply. In a
non-interactive session (no TTY) a bare invocation is a usage error — pass a
subcommand there.

### Back up

```sh
termius-backup backup
# → asks for a destination (suggests ./termius-backup-<timestamp>.tsb)
# → asks for a password (hidden) and reconfirms if the password is weak
# → writes an encrypted .tsb file
```

Non-interactive:

```sh
termius-backup backup \
  --out ~/backups/termius-2026.tsb \
  --password-file ~/.termius-backup.pw
```

### Inspect a backup (no password needed)

```sh
termius-backup info ~/backups/termius-2026.tsb
# → prints format version, KDF algorithm and parameters
```

### Restore

```sh
termius-backup restore ~/backups/termius-2026.tsb
# → prints a summary and asks for confirmation
# → snapshots the current Termius dir to a tagged, unencrypted snapshot
# → asks for the password, decrypts, and verifies the archive
# → installs the backup's carried Termius keyring key (if any) into the
#   OS keyring, so restored hosts/keys decrypt on this machine
# → replaces the Termius dir with the restored data
```

A backup made by an older version (before key carrying) has no carried key;
restoring it works as before, and on a different machine the restored data
only decrypts where that source machine's key is already in the keyring.

### Roll back

If a restore went wrong, roll back to the state before it:

```sh
termius-backup rollback
# → lists tagged snapshots (newest first), you pick one
# → takes a pre-rollback snapshot of the current state (so this is reversible)
# → restores the chosen snapshot over the live Termius directory
```

### Manage snapshots

```sh
termius-backup snapshots list        # list tagged rollback snapshots
termius-backup snapshots prune --keep 10   # keep the newest 10 per source dir
```

### Add to PATH

```sh
termius-backup install
```

Makes `termius-backup` runnable from any directory:

- **Linux/macOS** — symlinks the running binary into `~/.local/bin`, and if
  that directory is not already on the PATH, appends a PATH line to your
  shell's rc file — `~/.bashrc`, `~/.zshrc`, or
  `~/.config/fish/config.fish`, chosen from `$SHELL` (`~/.profile` when the
  shell is not one of those).
- **Windows** — adds the binary's directory to the *user* PATH in the
  registry (`HKCU\Environment`); the machine PATH is left alone.

A new terminal picks the change up (or `source` the rc file). It is
idempotent: re-running when the binary is already reachable from the PATH
reports that and changes nothing.

### Google Drive backups

Back up to — and restore from — your own Google Drive. Google only offers
OAuth for Drive access (no email+password login), so this uses **OAuth2**:
the tool prints a short code you approve at `google.com/device` (device
flow) — and if Google does not offer the device flow for the configured
client, it automatically falls back to **browser login**: it prints the
consent URL (press Enter to open it in your browser) and catches the
redirect on a local loopback address (authorization code + PKCE). The
resulting refresh token is **encrypted at rest** with a master password
you choose.

```sh
termius-backup gdrive login
# → asks for the account email (labels the backup)
# → prints a URL + code; approve in a browser
# → asks for a MASTER password (protects the stored Google credentials)
# → stores encrypted creds at ~/.config/termius-secure-backup/gdrive-creds.tsb

termius-backup gdrive backup --name laptop
# → asks for the BACKUP password (encrypts the .tsb, same as local backups)
# → creates a folder named laptop.tsbak-vault on Drive
# → uploads a timestamped, encrypted .tsb into it

termius-backup gdrive restore
# → lists your *.tsbak-vault folders with their most recent backup date
# → you pick a folder, then a backup
# → downloads it, confirms, snapshots the current dir, asks the BACKUP
#   password, decrypts — and asks once more before applying the restore

termius-backup gdrive status         # show the linked account
termius-backup gdrive logout         # delete the stored credentials
```

**Two distinct passwords** (on purpose):

- **Master password** — encrypts the stored Google OAuth refresh token. Lose
  it and you must re-run `gdrive login`.
- **Backup password** — encrypts each `.tsb` payload, exactly like local
  backups. It is *not* stored anywhere; re-enter it at restore time.

Uploaded backups are identical `.tsb` files, so `info`, local `restore`, and
`rollback` all work on them. `--termius-dir`, `--snapshots-dir`,
`--password-file`, `--password-env`, `--yes`, and `--creds-file` apply to
`gdrive backup` / `gdrive restore` as they do to the local commands.

### Two-way sync between devices

Turn sync on on two (or more) machines with the **same vault** and they
keep each other's Termius data in step, like Termius's own (paid) cloud
sync: a host, group, key, identity, snippet, or setting you add, change,
or delete on one machine shows up on the others.

```sh
termius-backup                                  # → Sync settings → Turn on
termius-backup gdrive sync on --name team       # the same, from the CLI
termius-backup gdrive sync off                  # turn it off
```

Turning sync on asks for the Google Drive login (only when you are not
logged in yet), your master password, the vault, and the vault's backup
password — the same one on every device, so it is checked right away
against the vault's data. When the vault already holds data, you choose
how this machine starts:

- **Use the vault's data on this machine** (recommended when another
  device already syncs with the vault) — this machine's current Termius
  data is kept in a rollback snapshot first.
- **Upload this machine's data** — the vault, and every other syncing
  device, switch to it.

Sync then runs as a background service (see below) that keeps going
after reboots until you turn it off. Every minute it compares this
machine and the vault:

- **Your changes go up.** When this machine's Termius data changes and
  the change has settled for a few seconds, an encrypted snapshot is
  uploaded to the vault.
- **Other devices' changes come down.** When the vault has a newer
  snapshot from another device, it is downloaded, decrypted, and
  verified right away, and applied as soon as **Termius is closed** on
  this machine — Termius keeps its data open and cached while it runs, so
  it shows the new data the next time you start it. If Termius is closed
  when the change arrives, it is applied immediately.

What is synced, and what is not:

- **Synced:** Termius's `IndexedDB` store — hosts, groups, SSH keys,
  identities, snippets, port-forwarding rules, known hosts, tags, and
  settings — plus the OS-keyring `localKey` that decrypts it (see
  *Where is my Termius data?*), so synced hosts and keys decrypt on
  every device.
- **Not synced:** everything machine-specific — `Local Storage` (this
  device's Termius session and device tokens), Chromium's `Local State`
  (a machine-bound key), caches, logs, and window state.
- **Not a reason to sync:** Termius writes activity logs, terminal
  command history, and last-connected times on its own, and its
  database engine (LevelDB) rewrites its files on every start. Change
  detection looks at the logical contents of your data, not at files,
  so none of that triggers an upload by itself (it does travel along
  with real changes).

**When two machines change data at the same time.** A whole-state sync
cannot merge edits made on two devices before either has synced: the
first device to upload wins, and the other device's own changes are
replaced — but never lost. They are kept in a `pre-sync` rollback
snapshot (`termius-backup rollback` restores them), and the vault keeps
older versions too (`--keep`). The usual way to hit this: Termius stays
open on machine B (so B cannot pick up A's change yet) and you edit
something on B before restarting Termius there. Restarting Termius
after switching machines avoids it.

A machine syncs with **one vault at a time** (they would all write the
same Termius data); turning sync on for another vault stops the first.

The sync can also run in the foreground or from a timer:

```sh
# Watch and sync both ways in this terminal (Ctrl-C to stop):
termius-backup gdrive sync --name team

# Cron / systemd timer friendly: one check (upload or apply), then exit:
termius-backup gdrive sync --name team --once
```

- **The path is remembered**: `--termius-dir` is only needed once. The
  directory a sync uses is saved in
  `~/.config/termius-secure-backup/sync-state.json`, which also records,
  per vault, which vault snapshot this machine last matched and a hash
  of its data at that point (ids and hashes only — no Termius data).
- **Retention**: `--keep N` (default 10) trims the vault to the newest
  N snapshots after each upload; `--keep 0` keeps everything.
- **Passwords**: in `--once` mode set `TSBAK_GDRIVE_MASTER_PASSWORD` and
  `--password-file`/`--password-env` for a fully unattended run.
- **Network hiccups** and an expiring Google token are retried on the
  next check; a problem is reported once, not every minute.

After a successful `gdrive backup` the tool also offers to turn sync on
for that vault: **Yes** turns it on (the backup you just made counts as
already synced), **No — and don't ask me again** turns the offer off for
that vault, and **No — ask me again next time** (a bare Enter) declines
once.

#### The background service

`gdrive sync on --name N`, **Turn on** in the menu, and **Yes** to the
post-backup offer all install the sync as a background service that
starts right away, starts again at every login, and keeps going until
you turn it off. The two passwords an unattended run needs — the Google
Drive master password and the backup password — are stored in
`~/.config/termius-secure-backup/sync-service-<vault>.json` with
owner-only permissions; turning sync off removes that file. Instead you
can point at your own file with `--service-secrets <file>` (JSON:
`{"master_password": "...", "backup_password": "..."}`).

What it installs, per platform:

- **Linux** — a systemd *user* unit,
  `~/.config/systemd/user/termius-backup-sync-<vault>.service`
  (`Restart=always`). Check it with
  `systemctl --user status termius-backup-sync-<vault>` and
  `journalctl --user -u termius-backup-sync-<vault>`. A systemd user
  unit starts when you log in; to have it start at boot even without a
  login, run `loginctl enable-linger <your-user>`.
- **macOS** — a launchd LaunchAgent,
  `~/Library/LaunchAgents/com.termius-secure-backup.sync-<vault>.plist`
  (`KeepAlive`); its output goes to
  `~/Library/Logs/termius-backup-sync-<vault>.log`.
- **Windows** — a Task Scheduler task, `termius-backup-sync-<vault>`,
  that runs at logon (and is started immediately when sync is turned
  on); its console window shows the sync log.

**Turning sync off.** **Turn off** in the menu, or `gdrive sync off`,
stops and removes every background sync service on this machine, forgets
what it last synced, and turns off the post-backup offer. The vaults and
their data on Google Drive are not touched, and neither is this
machine's Termius data.

```sh
termius-backup gdrive sync off                  # all vaults
termius-backup gdrive sync off --name team      # just one vault
termius-backup gdrive sync on                   # only re-enable the offer
```

### Google sign-in: nothing to set up

Google only offers OAuth for Drive access (no email+password login), and
requires every app to present an **OAuth client id**. This binary ships
with one **baked in**, so `gdrive login` works out of the box — just sign
in with your own Google account.

What the baked-in client id means:

- It is an **identifier, not a secret** (like a username) — it only tells
  Google which app is asking to sign in.
- The OAuth consent screen you approve is registered under the
  maintainer's Google Cloud project. Your data still flows only through
  **your** Google account, under the least-privilege `drive.file` scope
  (files this tool creates).
- The baked-in client is configured as *confidential*, so its client
  secret ships with the binary as well. A desktop-client secret only lets
  someone present *the app* to Google's token endpoint — it does not
  grant access to any user's account. After `gdrive login` it lives in
  the encrypted credential blob, not in a shell variable.

### Using your own Google OAuth client (optional)

If you'd rather the sign-in screen be registered under **your** Google
Cloud project (e.g. for a team), register a client there and override the
baked-in default with `TSBAK_GDRIVE_CLIENT_ID`. It takes a few minutes:

1. **Create a project.** Open the
   [Google Cloud Console](https://console.cloud.google.com) and create a
   project (any name).
2. **Enable the Drive API.** In *APIs & Services → Library*, find
   **Google Drive API** and enable it.
3. **Configure the consent screen.** In *APIs & Services → OAuth consent
   screen* (the new console calls this *Google Auth Platform*), choose
   **External** user type and give the app a name (e.g. `termius-backup`).
   If only you will use it, leave it in **Testing** and add your own
   account as a *test user* — in that mode Google refresh tokens expire
   after 7 days, so **Publish** the app if you want the login to last.
4. **Create the client.** In *APIs & Services → Credentials → Create
   credentials → OAuth client ID*, pick application type **Desktop app**
   and give it a name.
5. **Export the client id** (it looks like
   `123456789012-abcdefg.apps.googleusercontent.com`):

   ```sh
   export TSBAK_GDRIVE_CLIENT_ID="123456789012-abcdefg.apps.googleusercontent.com"
   ```

   Add the `export` to your shell rc (`~/.bashrc`, `~/.zshrc`, …) to make
   it permanent.

The client id is **not a secret** — it is an identifier (like a username)
that the tool sends to Google's login page, so keeping it in a shell rc is
fine. The *client secret* the console may display for a desktop client is
normally **not needed** — this tool's login flows use PKCE, not the
secret. If your client is configured as *confidential* (Google's token
endpoint answers `client_secret is missing`), set its secret as well:

```sh
export TSBAK_GDRIVE_CLIENT_SECRET="GOCSPX-…"
```

The secret, when present, is stored in the same encrypted credential blob
as the refresh token — protected by your master password, not kept in a
shell variable after `gdrive login`.

> ⚠️ **New clients can take a while to activate.** The console itself
> warns that "it may take five minutes to a few hours for settings to
> take effect". Until your client is live, `gdrive login` reports
> `The OAuth client was not found` — just wait and re-run it.

**How `gdrive login` uses the configured client id** (the baked-in
default, or your override). It first tries the OAuth
**device flow** — a short code you approve at `google.com/device`, which
works well over SSH. Some Google clients are not eligible for the device
flow; when Google rejects it with `invalid_client`, the tool
automatically falls back to **browser login** (authorization-code flow
with PKCE): it prints the consent URL — press Enter and it opens in your
browser (or open the URL yourself) — and catches the redirect on a local
loopback address (`http://127.0.0.1:<port>`), the same scheme `gh` and
`gcloud` use. Either way the result is a refresh
token, which is then encrypted at rest with your master password.

The scope requested is `drive.file` — least privilege, covering only files
this tool creates (the `.tsbak-vault` folders and their `.tsb` backups).

---

## How it works

### Encrypted container (`.tsb`)

A fixed, versioned binary format. Only the header is in the clear; everything
else is inside the AEAD envelope.

```
magic        : 6 bytes  b"TSBAK\x01"            // "Termius Secure Backup", v1
kdf_algo     : 1 byte   (1 = argon2id)
kdf_m_kib    : u32 LE   (memory cost, KiB; default 65536 = 64 MiB)
kdf_t        : u32 LE   (time cost; default 3)
kdf_p        : u32 LE   (parallelism; default 4)
salt_len     : u16 LE   (16)
salt         : 16 bytes
cipher       : 1 byte   (1 = xchacha20-poly1305)
nonce_len    : u16 LE   (24)
nonce        : 24 bytes
ct_len       : u64 LE
ciphertext   : ct_len bytes   (zstd(tar(termius_dir) + __meta.json) + 16-byte tag)
```

- **KDF:** `key = Argon2id(password, salt, m=64MiB, t=3, p=4)` → 32 bytes.
- **AEAD:** XChaCha20-Poly1305 with a 192-bit random nonce. The entire
  cleartext header (magic through nonce) is bound as **associated data**, so
  tampering with any header field causes decryption to fail.
- **Wrong password:** AEAD tag verification fails → clean
  "incorrect password" error; no plaintext is ever emitted.

This mirrors Termius's own model: Termius uses libsodium
(Argon2id + X25519/XSalsa20-Poly1305) for its vault encryption.

### Rollback snapshots (unencrypted, tagged)

Before any restore (or rollback), the current Termius directory is copied to
an **unencrypted** snapshot — it is already on disk in plaintext, so there is
no value in re-encrypting it. Each snapshot is tagged with a `manifest.json`:

- `id` / `created_at`
- `reason`: `pre-restore` | `pre-rollback` | `manual`
- `source_dir`, `trigger_file`, `trigger_sha256`
- `entry_count`, `byte_size`, `tool_version`

Snapshots live in `~/.termius-secure-backup/snapshots/` (Linux/macOS) or
`%LOCALAPPDATA%\termius-secure-backup\snapshots\` (Windows); override with
`--snapshots-dir`. `snapshots prune --keep N` retains the newest `N` per
source directory.

---

## Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | Success                                  |
| 1    | Usage / argument error                   |
| 2    | File not found / unreadable              |
| 3    | Authentication failure (wrong password)  |
| 4    | Container format error (bad/tampered)    |
| 5    | Canceled by user                         |
| 6    | I/O or internal error                    |
| 7    | Google Drive remote error                |

---

## Security

See [SECURITY.md](SECURITY.md) for the full threat model. In short: an
attacker with your `.tsb` file cannot read it without your password; the
security of your data rests on the strength of that password. Use a strong,
unique password and store it in a password manager.

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE)
and [NOTICE](NOTICE).

## References

- [Termius — Encryption overview](https://docs.termius.com/security/encryption-overview)
- [Termius — Learn about vaults](https://docs.termius.com/getting-started/learn-about-vaults)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
- [XChaCha20-Poly1305 IETF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
