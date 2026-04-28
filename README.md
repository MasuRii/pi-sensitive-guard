# pi-sensitive-guard

[![npm version](https://img.shields.io/npm/v/pi-sensitive-guard?style=flat-square)](https://www.npmjs.com/package/pi-sensitive-guard) [![License](https://img.shields.io/github/license/MasuRii/pi-sensitive-guard?style=flat-square)](LICENSE)

Sensitive-file protection extension for the [Pi coding agent](https://github.com/mariozechner/pi).

<img width="1389" height="768" alt="image" src="https://github.com/user-attachments/assets/46e73cce-2be9-4669-b0ec-6422b68acc31" />

`pi-sensitive-guard` blocks unsafe access to secret-bearing files, scans writes and Git diffs for common credential patterns, and can optionally return redacted protected reads for trusted workflows.

## Features

- Protects `.env`, credential, private-key, and secret files from reads, writes, deletes, shell commands, commits, and pushes.
- Scans write/edit content and Git commit/push diffs for common high-severity secret patterns.
- Keeps runtime configuration simple with top-level enable/disable, debug logging, and read-redaction controls.
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
- shell commands that read, write, delete, commit, or push protected secret-bearing files;
- optional protected reads with redacted output when `readRedaction.enabled` is set to `true`.

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
| `readRedaction.enabled` | boolean | `false` | Allow protected `read` tool calls and redact sensitive values before output is returned. |
| `readRedaction.includeShellOutput` | boolean | `false` | Also redact shell-command output when protected files are read through shell commands. |

### Example config

```json
{
  "enabled": true,
  "debug": false,
  "readRedaction": {
    "enabled": false,
    "includeShellOutput": false
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
