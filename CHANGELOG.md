# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
