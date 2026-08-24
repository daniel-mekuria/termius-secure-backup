# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of `termius-backup`.
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

## [0.1.0] - 2026-08-24

Initial release.
