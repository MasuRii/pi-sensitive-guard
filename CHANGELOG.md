# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-07-03

### Added
- Added an `enabled` toggle, anti-loop blocking, and environment-variable echo detection. ([1c71f29](https://github.com/MasuRii/pi-sensitive-guard/commit/1c71f2989238cf592586b987ef606753fa407e01))
- Added multi-encoding secret detection and a scan cache. ([a1468c9](https://github.com/MasuRii/pi-sensitive-guard/commit/a1468c93c1f0f65242fc0501cc8c30c5692e167e))
- Added write-execute correlation for agent-written scripts. ([8a6e1a8](https://github.com/MasuRii/pi-sensitive-guard/commit/8a6e1a8cea29ce32534b375d2060f953c65a1bf9))
- Added multi-scope config merge for project-local overrides. ([f96a277](https://github.com/MasuRii/pi-sensitive-guard/commit/f96a2770e5bb76b4c6196a0fbb167d94a0f19d34))

### Changed
- Extracted shared utilities and consolidated git-protection helpers, hardening protected-file edits. ([266de53](https://github.com/MasuRii/pi-sensitive-guard/commit/266de5302e80abbc41c974727cffea11cfd618bc) [e7e0672](https://github.com/MasuRii/pi-sensitive-guard/commit/e7e067247a4403828f467a73b6c469e1fb267606))
- Updated README with badges and a Ko-fi link. ([1b7d89e](https://github.com/MasuRii/pi-sensitive-guard/commit/1b7d89ea5b5504a1b6f52c2946aaecf394fee03b))
- Widened Pi peer dependency compatibility to include `^0.80.0` and added vulnerability overrides (`protobufjs`, `ws`). ([69cf308](https://github.com/MasuRii/pi-sensitive-guard/commit/69cf3081398593a78ebe40de27b4c12f1db2a043))

## [0.4.3] - 2026-06-16

### Added
- Expanded default protected-file patterns to cover Docker registry auth, Git credentials, shell startup files, macOS keychain/cookies, Unix system credentials, and backup files that may retain secrets.
- Added HashiCorp Vault, Doppler, 1Password, GitHub user/refresh tokens, Slack session tokens, AWS session keys, Stripe live keys, SendGrid, and npm token secret patterns.
- Added copy/move command detection (`cp`, `copy`, `mv`, `move`, `install`) as read-source operations with write-threshold protection.

### Changed
- Sensitive-key matching now recognizes `vault_token`, `doppler_token`, `stripe_key`, `stripe_secret`, `sendgrid_key`, and `npm_token` field names.
- File-name matching now compares the leaf file name rather than the full normalized path for non-regex patterns.
- Realpath resolution and existence checking now apply per-segment, improving accuracy for path tokens with intermediate symlinks.

## [0.4.2] - 2026-06-01

### Changed
- Deferred heavy module loading during extension bootstrap.
- Lazy-loaded shell parsing and made command matching checks asynchronous.
- Exported the sensitive-guard config command handler for deferred command registration.
- Widened the Pi coding-agent peer dependency range to include `^0.77.0 || ^0.78.0` and aligned the development dependency to `^0.78.0`.

## [0.4.1] - 2026-05-26

### Changed
- Widened peer dependency ranges to `^0.74.0 || ^0.75.0`.
- Aligned dev dependencies to `^0.75.5`.

## [0.4.0] - 2026-05-22

### Added
- Added structured protected-file edit validation for `edit` line operations and `replace_text`/`oldText` replacements when `protectedFileEdits.enabled` is explicitly enabled.

### Changed
- Hardened protected-file edit evaluation to check resulting content, changed values, sensitive-key changes, and detected secrets before allowing protected edits.
- Redacted blocked-event/debug payloads and routed debug writes through asynchronous file logging with shutdown disposal.

## [0.3.0] - 2026-05-04

### Added
- Added `/sensitive-guard` runtime configuration command with status, raw edit, and interactive menu flows.
- Added configurable `readRedaction.scope` controls for protected-only versus all-output redaction coverage.
- Added `protectedFileEdits.enabled` controls for explicitly allowing safe non-sensitive protected-file edits.

### Changed
- Expanded read redaction to cover structured JSON, key/value assignments, embedded assignments, private-key blocks, and detected secret patterns while avoiding common non-secret code references.
- Documented the revised redaction and protected-edit behavior in the README and sample configuration.

## [0.2.0] - 2026-04-30

### Added
- Added structured JSON read redaction for sensitive object keys before nested credential values can leak.
- Added high-severity secret detection for Google API keys, Slack tokens, Slack webhook URLs, and Stripe API keys.
- Added example custom JSON protected-file patterns to the sample configuration.

### Changed
- Combined default protected/safe patterns with legacy top-level custom patterns instead of replacing defaults.
- Limited read-redaction scheduling to blocked protected reads and protected shell-read output.
- Bumped Pi coding agent development dependency to `^0.70.6`.

## [0.1.0] - 2026-04-26

### Added
- Added modular TypeScript Pi extension entry point and source structure.
- Added default sensitive-file protection for environment, credential, private-key, and secret files.
- Added secret scanning for writes, edits, and Git commit/push diffs.
- Added optional read-with-redaction behavior for protected reads.
- Added file-only debug logging under `debug/` gated by user configuration.

### Changed
- Simplified user-facing runtime configuration to `enabled`, `debug`, and read-redaction controls.
- Standardized package contents to ship source, docs, license, and `config/config.example.json` while excluding user-local `config.json`.

### Removed
- Removed duplicate `pi-sensitive-guard.jsonc` runtime configuration source.
