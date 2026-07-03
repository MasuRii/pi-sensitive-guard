<div align="center">

# pi-sensitive-guard

[![npm version](https://img.shields.io/npm/v/pi-sensitive-guard?style=for-the-badge)](https://www.npmjs.com/package/pi-sensitive-guard)
[![License](https://img.shields.io/github/license/MasuRii/pi-sensitive-guard?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blue?style=for-the-badge)]()

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y01PSSVR)

Sensitive-file protection extension for the [Pi coding agent](https://github.com/mariozechner/pi).
<img width="1389" height="768" alt="image" src="https://github.com/user-attachments/assets/46e73cce-2be9-4669-b0ec-6422b68acc31" />
`pi-sensitive-guard` blocks unsafe access to secret-bearing files, scans writes and Git diffs for common credential patterns, and can optionally return redacted protected reads for trusted workflows.

</div>

## Features

- Protects `.env`, credential, private-key, secret, Docker auth, Git credentials, shell startup, keychain, and system credential files from reads, writes, deletes, shell commands, commits, and pushes.
- Scans write/edit content and Git commit/push diffs for common high-severity secret patterns including HashiCorp Vault, Doppler, 1Password, GitHub, Slack, AWS session, Stripe, SendGrid, and npm tokens.
- Detects copy/move shell commands (`cp`, `copy`, `mv`, `move`, `install`) that read protected files, applying write-threshold protection to prevent credential exfiltration via file copy.
- Keeps runtime configuration simple with top-level enable/disable, debug logging, read-redaction controls, protected-edit controls, and the `/sensitive-guard` menu.
- Allows optional non-sensitive edits to protected files when `protectedFileEdits.enabled` is explicitly enabled.
- Supports both legacy text replacements and structured `edit` line operations for protected-file safe-edit checks.
- Redacts structured JSON values, key/value assignments, embedded assignments, private keys, and known secret patterns while preserving safe output shape.
- Writes debug output only to the extension-local `debug/` directory when `debug` is enabled.
- Emits/logs blocked-event metadata after redacting sensitive values.

## Installation

### Local extension folder

Place this folder in one of Pi's auto-discovery locations:

```text
# Global default (when PI_CODING_AGENT_DIR is unset)
~/.pi/agent/extensions/pi-sensitive-guard

# Project-specific
.pi/extensions/pi-sensitive-guard
```

### npm package

```bash
pi install npm:pi-sensitive-guard
```

### Git repository

```bash
pi install git:github.com/MasuRii/pi-sensitive-guard
```

## Usage

`pi-sensitive-guard` runs automatically after Pi loads the extension. It inspects tool calls before execution and blocks protected file access or detected secret writes with a clear TUI notification.

Typical protected flows include:

- reading `.env`, key, token, credential, and private-key files;
- writing or editing content that matches high-confidence secret patterns;
- shell commands that read, copy, move, write, delete, commit, or push protected secret-bearing files;
- optional protected reads with redacted output when `readRedaction.enabled` is set to `true`.

### `/sensitive-guard` command

Use `/sensitive-guard` inside Pi to open the interactive configuration menu. The menu can toggle the guard, read redaction, shell-output redaction, blocked-event logging, debug logging, content scanning, protected-file safe edits, and redaction limits without editing JSON by hand.

Additional command forms:

- `/sensitive-guard status` shows the resolved runtime configuration summary.
- `/sensitive-guard edit` opens the raw `config.json` editor.

After changing configuration, run `/reload` or restart Pi so the guard reloads its rules.

## Configuration

Runtime configuration is stored at:

```text
Default global path: ~/.pi/agent/extensions/pi-sensitive-guard/config.json
Actual global path: $PI_CODING_AGENT_DIR/extensions/pi-sensitive-guard/config.json when PI_CODING_AGENT_DIR is set
```

`config.json` is a user-local runtime file. It is gitignored and excluded from npm package contents. A starter template is included at `config/config.example.json`.

### Configuration options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable all sensitive-file protection. |
| `debug` | boolean | `false` | Enable file-only debug logging under `debug/debug.log`. |
| `readRedaction.enabled` | boolean | `false` | Allow redacted read output instead of hard-blocking eligible protected reads. |
| `readRedaction.includeShellOutput` | boolean | `false` | Also redact shell-command output when protected files are read through shell commands. |
| `readRedaction.scope` | `protectedOnly` \| `allOutput` | `protectedOnly` | Choose whether redaction applies only to protected read flows or to every read/shell output path covered by the redaction settings. |
| `protectedFileEdits.enabled` | boolean | `false` | Allow safe non-sensitive write/edit changes to protected files; sensitive key/value, structure, or secret-bearing edits remain blocked. |

When protected-file edits are enabled, the guard recognizes exact `oldText`/`newText` replacements, `replace_text`, and structured line-edit operations. The proposed result is still blocked if it changes sensitive keys or structure, introduces detected secret patterns, or cannot be evaluated safely.

### Example config

```json
{
  "enabled": true,
  "debug": false,
  "readRedaction": {
    "enabled": false,
    "includeShellOutput": false,
    "scope": "protectedOnly"
  },
  "blockedEvents": {
    "emit": true,
    "log": true,
    "logPath": "logs/blocked-events.jsonl"
  },
  "protectedFileEdits": {
    "enabled": false
  }
}
```

> Changes take effect after `/reload`.

## Validation

```bash
npm run build
npm run lint
npm run test
npm run check
npm run package:dry-run
```

## Publishing

The package metadata follows the same publish-ready shape used by established Pi extensions:

- entrypoint: `index.ts`
- package exports: `.` → `./index.ts`
- Pi extension manifest: `pi.extensions`
- published files: source, README, changelog, license, and config template
- runtime `config.json`, `debug/`, `logs/`, and test artifacts excluded from npm publication

> [!NOTE]
> The package requires Node.js `>=22` because its shell parser dependency declares the same minimum engine.

## Related Pi Extensions

- [pi-permission-system](https://github.com/MasuRii/pi-permission-system) — Permission enforcement for tool and command access
- [pi-multi-auth](https://github.com/MasuRii/pi-multi-auth) — Multi-provider credential management, OAuth login, and account rotation
- [pi-tool-display](https://github.com/MasuRii/pi-tool-display) — Compact tool rendering and diff visualization
- [pi-rtk-optimizer](https://github.com/MasuRii/pi-rtk-optimizer) — RTK command rewriting and output compaction

## License

[MIT](LICENSE)
