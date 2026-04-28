import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type {
	PatternConfig,
	ResolvedSensitiveGuardConfig,
	SecretPatternDefinition,
} from "./types.js";

export const EXTENSION_NAME = "pi-sensitive-guard";
export const BLOCKED_EVENT_CHANNEL = "pi-sensitive-guard:blocked";

function resolveExtensionRoot(moduleUrl = import.meta.url): string {
	return dirname(dirname(fileURLToPath(moduleUrl)));
}

export const EXTENSION_ROOT = resolveExtensionRoot();
export const PRIMARY_CONFIG_PATH = join(EXTENSION_ROOT, "config.json");
export const LOGS_DIR = join(EXTENSION_ROOT, "logs");
export const DEBUG_DIR = join(EXTENSION_ROOT, "debug");
export const DEBUG_LOG_PATH = join(DEBUG_DIR, "debug.log");
export const DEFAULT_BLOCKED_EVENTS_LOG_PATH = join(
	LOGS_DIR,
	"blocked-events.jsonl",
);

export const DEFAULT_PROTECTED_PATTERN_CONFIGS: PatternConfig[] = [
	{ pattern: "(^|[\\\\/])\\.env(?:\\.[^\\\\/]+)?$", regex: true },
	{ pattern: "(^|[\\\\/])\\.(?:npmrc|pypirc|netrc)$", regex: true },
	{
		pattern: "(^|[\\\\/])(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$",
		regex: true,
	},
	{ pattern: "\\.(?:pem|key|p12|pfx|jks|keystore)$", regex: true },
	{
		pattern:
			"(^|[\\\\/])(?:secrets?|credentials?)(?:\\.(?:json|ya?ml|toml|ini|env|txt|cfg|conf))?$",
		regex: true,
	},
	{
		pattern:
			"(^|[\\\\/])(?:service-account|google-credentials|firebase-adminsdk)[^\\\\/]*\\.json$",
		regex: true,
	},
];

export const DEFAULT_SAFE_PATTERN_CONFIGS: PatternConfig[] = [
	{
		pattern:
			"(^|[\\\\/])\\.env\\.(?:example|sample|template|dist|defaults?)$",
		regex: true,
	},
	{
		pattern: "(^|[\\\\/])(?:example|sample|template)\\.env$",
		regex: true,
	},
	{
		pattern:
			"(^|[\\\\/])(?:secrets?|credentials?)(?:\\.(?:example|sample|template|dist|defaults?))(?:\\.(?:json|ya?ml|toml|ini|env|txt|cfg|conf))?$",
		regex: true,
	},
	{
		pattern:
			"(^|[\\\\/]).+\\.example\\.(?:json|ya?ml|toml|ini|env|txt|cfg|conf)$",
		regex: true,
	},
	{ pattern: "\\.pub$", regex: true },
];

const STANDARD_SENSITIVE_KEY_NAME_PATTERN = String.raw`(?:api[_-]?key|apikey|secret|client[_-]?secret|app[_-]?secret|password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer|private[_-]?key)`;
const AUTH_CREDENTIAL_FIELD_NAME_PATTERN = String.raw`(?:key|access|refresh)`;
const SENSITIVE_ASSIGNMENT_KEY_NAME_PATTERN = String.raw`(?:${STANDARD_SENSITIVE_KEY_NAME_PATTERN}|${AUTH_CREDENTIAL_FIELD_NAME_PATTERN})`;
const GENERIC_SECRET_VALUE_PATTERN = String.raw`[A-Za-z0-9][A-Za-z0-9\-_./+=]{19,}`;
const QUOTED_OR_BARE_ASSIGNMENT_PREFIX_PATTERN = String.raw`(?:^|[\s{[,;])['\"]?`;
const QUOTED_OR_BARE_ASSIGNMENT_SEPARATOR_PATTERN = String.raw`['\"]?\s*[=:]\s*['\"]?`;

function createSensitiveAssignmentPattern(keyNamePattern: string): RegExp {
	return new RegExp(
		`${QUOTED_OR_BARE_ASSIGNMENT_PREFIX_PATTERN}(?:${keyNamePattern})${QUOTED_OR_BARE_ASSIGNMENT_SEPARATOR_PATTERN}(${GENERIC_SECRET_VALUE_PATTERN})['\"]?`,
		"i",
	);
}

export const DEFAULT_SENSITIVE_KEY_PATTERN_CONFIGS: PatternConfig[] = [
	{
		pattern: String.raw`(?:${STANDARD_SENSITIVE_KEY_NAME_PATTERN}|^${AUTH_CREDENTIAL_FIELD_NAME_PATTERN}$)`,
		regex: true,
	},
];

export const DEFAULT_REDACTION_PLACEHOLDER = "[REDACTED]";

export const DEFAULT_CONFIG: ResolvedSensitiveGuardConfig = {
	version: 2,
	enabled: true,
	rules: [
		{
			id: "default-sensitive-files",
			name: "Default sensitive file protection",
			description:
				"Protect secret-bearing files from read, write, edit, delete, commit, and push operations.",
			patterns: [...DEFAULT_PROTECTED_PATTERN_CONFIGS],
			allowedPatterns: [...DEFAULT_SAFE_PATTERN_CONFIGS],
			protection: "noAccess",
			onlyIfExists: false,
			enabled: true,
		},
	],
	gitProtection: {
		enabled: true,
		blockCommit: true,
		blockPush: true,
		diffTimeoutMs: 10000,
		maxCommits: 50,
	},
	contentScanning: {
		enabled: true,
		blockSeverity: "high",
		maxFindings: 20,
	},
	blockedEvents: {
		emit: true,
		log: true,
		logPath: DEFAULT_BLOCKED_EVENTS_LOG_PATH,
	},
	readRedaction: {
		enabled: false,
		includeShellOutput: false,
		placeholder: DEFAULT_REDACTION_PLACEHOLDER,
		maxBytes: 262144,
		sensitiveKeyPatterns: [...DEFAULT_SENSITIVE_KEY_PATTERN_CONFIGS],
		redactSecretPatterns: true,
	},
	debug: false,
};

export const DEFAULT_CONFIG_CONTENT = `${JSON.stringify(
	{
		enabled: DEFAULT_CONFIG.enabled,
		debug: DEFAULT_CONFIG.debug,
		readRedaction: {
			enabled: DEFAULT_CONFIG.readRedaction.enabled,
			includeShellOutput: DEFAULT_CONFIG.readRedaction.includeShellOutput,
		},
	},
	null,
	2,
)}\n`;

export const FILE_READ_COMMANDS = [
	"cat",
	"less",
	"more",
	"head",
	"tail",
	"type",
	"bat",
	"grep",
	"rg",
	"ag",
	"source",
	".",
] as const;

export const FILE_WRITE_COMMANDS = [
	"tee",
	"cp",
	"copy",
	"mv",
	"move",
	"install",
	"touch",
	"truncate",
	"dd",
	"set-content",
	"add-content",
	"out-file",
	"sc",
	"ac",
] as const;

export const FILE_DELETE_COMMANDS = [
	"rm",
	"unlink",
	"shred",
	"srm",
	"wipe",
	"del",
	"erase",
	"remove-item",
	"ri",
	"trash",
	"trash-put",
	"gvfs-trash",
] as const;

export const SECRET_PATTERNS: SecretPatternDefinition[] = [
	{ name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical" },
	{
		name: "AWS Secret Access Key",
		pattern:
			/(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?/i,
		severity: "critical",
	},
	{
		name: "Google Cloud Service Account Key",
		pattern: /"private_key"\s*:\s*"-----BEGIN/,
		severity: "critical",
	},
	{
		name: "OpenAI API Key",
		pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b/,
		severity: "high",
	},
	{
		name: "Anthropic API Key",
		pattern: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/,
		severity: "high",
	},
	{
		name: "GitHub Personal Access Token",
		pattern: /\bghp_[A-Za-z0-9_]{36,}\b/,
		severity: "high",
	},
	{
		name: "GitHub Fine-grained Token",
		pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
		severity: "high",
	},
	{
		name: "GitLab Token",
		pattern: /\bglpat-[0-9A-Za-z\-_]{20,}\b/,
		severity: "high",
	},
	{
		name: "Private Key",
		pattern:
			/-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----/,
		severity: "critical",
	},
	{
		name: "JWT Token",
		pattern:
			/\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}\b/,
		severity: "high",
	},
	{
		name: "Database URL with Credentials",
		pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^:]+:[^@]+@/i,
		severity: "high",
	},
	{
		name: "Credentials in URL",
		pattern: /[a-zA-Z]+:\/\/[^:\/\s]+:[^@\/\s]{3,}@[^\s]+/,
		severity: "high",
	},
	{
		name: "API Key Assignment",
		pattern: createSensitiveAssignmentPattern(String.raw`(?:api[_-]?key|apikey)`),
		severity: "medium",
		secretGroup: 1,
	},
	{
		name: "Secret Assignment",
		pattern: createSensitiveAssignmentPattern(
			String.raw`(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)`,
		),
		severity: "medium",
		secretGroup: 1,
	},
	{
		name: "Password Assignment",
		pattern: /(?:^|[\s{[,;])['"]?(?:password|passwd|pwd)['"]?\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/i,
		severity: "medium",
		secretGroup: 1,
	},
	{
		name: "Token Assignment",
		pattern: createSensitiveAssignmentPattern(
			String.raw`(?:token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer)`,
		),
		severity: "medium",
		secretGroup: 1,
	},
	{
		name: "Sensitive Credential Assignment",
		pattern: createSensitiveAssignmentPattern(SENSITIVE_ASSIGNMENT_KEY_NAME_PATTERN),
		severity: "high",
		secretGroup: 1,
	},
];
