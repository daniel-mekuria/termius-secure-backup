# Security Policy

## Threat model

`termius-backup` protects **a backup file at rest** (`.tsb`) against an
offline attacker who has a copy of the file but **not** the password.

- The entire payload (compressed archive + inner metadata) is sealed inside
  an AEAD envelope. Without the password, an attacker can read only the
  cleartext header: file magic, format version, KDF algorithm, and KDF
  parameters (memory/time/parallelism) and salt/nonce lengths. The salt and
  nonce themselves are public by design.
- The key is derived from the user's password with **Argon2id**
  (`m = 64 MiB`, `t = 3`, `p = 4`, 16-byte salt). The derived key never
  leaves the process and is zeroized when dropped.
- The AEAD is **XChaCha20-Poly1305** with a 192-bit random nonce per file,
  so nonces may be chosen uniformly at random without collision risk.
- The cleartext header is bound to the ciphertext as AEAD **associated
  data**, so any tampering with the KDF parameters, salt, or nonce causes
  authentication to fail.

## What is *not* in scope

- The strength of the user's password is the foundation. A weak password
  can be brute-forced. The tool estimates strength with
  [zxcvbn](https://crates.io/crates/zxcvbn) (dictionary, sequence,
  keyboard-pattern, and leetspeak analysis) and asks
  for explicit re-confirmation when the password is shorter than 12
  characters or can be guessed in fewer than 10^8 attempts, but it will
  proceed if you insist.
- The **live** Termius directory is read from disk in plaintext — the
  rollback snapshots it produces are also stored **unencrypted**, because
  they are only ever copies of data that already lives on disk in the
  clear. Treat your local disk as trusted.
- Termius stores the IndexedDB encryption key (`localKey`) in the **OS
  keyring** (macOS Keychain / Windows Credential Manager / the freedesktop
  Secret Service), *not* in the `userData` directory. A backup reads that
  key from the source keyring and carries it inside the encrypted `.tsb`;
  a restore installs it into the target keyring before swapping in the
  data, so restored hosts and keys decrypt on any machine. Only the
  Termius-namespaced keyring entry is ever read or written. Because the
  key rides in the `.tsb`, the backup password protects both the data and
  the key together — losing the password still means losing both. Opt out
  with `--no-carry-key`.

## Reporting a vulnerability

Please email **mekuriadaniel4@gmail.com** with a description and, if
possible, a minimal reproduction. Reports are acknowledged within 72 hours.
