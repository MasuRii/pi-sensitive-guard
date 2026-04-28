import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
	DEFAULT_BLOCKED_EVENTS_LOG_PATH,
	DEFAULT_CONFIG,
	DEFAULT_CONFIG_CONTENT,
	DEFAULT_PROTECTED_PATTERN_CONFIGS,
	DEFAULT_SAFE_PATTERN_CONFIGS,
	DEFAULT_SENSITIVE_KEY_PATTERN_CONFIGS,
	PRIMARY_CONFIG_PATH,
} from "./constants.js";
import type {
	BlockedEventsConfig,
	ConfigLoadResult,
	ContentScanningConfig,
	EnsureConfigResult,
	GitProtectionConfig,
	PatternConfig,
	ProtectionLevel,
	ReadRedactionConfig,
	ResolvedProtectionRule,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardConfig,
	SecretSeverity,
} from "./types.js";

function toObject(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return {};
	}

	return value as Record<string, unknown>;
}

function clonePatternList(patterns: PatternConfig[]): PatternConfig[] {
	return patterns.map((pattern) => ({ ...pattern }));
}

function cloneDefaultConfig(): ResolvedSensitiveGuardConfig {
	return {
		version: DEFAULT_CONFIG.version,
		enabled: DEFAULT_CONFIG.enabled,
		rules: DEFAULT_CONFIG.rules.map((rule) => ({
			...rule,
			patterns: clonePatternList(rule.patterns),
			allowedPatterns: clonePatternList(rule.allowedPatterns),
		})),
		gitProtection: { ...DEFAULT_CONFIG.gitProtection },
		contentScanning: { ...DEFAULT_CONFIG.contentScanning },
		blockedEvents: { ...DEFAULT_CONFIG.blockedEvents },
		readRedaction: {
			...DEFAULT_CONFIG.readRedaction,
			sensitiveKeyPatterns: clonePatternList(
				DEFAULT_CONFIG.readRedaction.sensitiveKeyPatterns,
			),
		},
		debug: DEFAULT_CONFIG.debug,
	};
}

function normalizeString(value: unknown): string | undefined {
	if (typeof value !== "string") {
		return undefined;
	}

	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeBoolean(
	value: unknown,
	fallback: boolean,
	path: string,
	warnings: string[],
): boolean {
	if (value === undefined) {
		return fallback;
	}

	if (typeof value === "boolean") {
		return value;
	}

	warnings.push(`Invalid config value '${path}': expected a boolean.`);
	return fallback;
}

function normalizePositiveInteger(
	value: unknown,
	fallback: number,
	path: string,
	warnings: string[],
): number {
	if (value === undefined) {
		return fallback;
	}

	if (typeof value === "number" && Number.isInteger(value) && value > 0) {
		return value;
	}

	warnings.push(`Invalid config value '${path}': expected a positive integer.`);
	return fallback;
}

function normalizeVersion(value: unknown, warnings: string[]): number {
	if (value === undefined) {
		return DEFAULT_CONFIG.version;
	}

	if (typeof value === "number" && Number.isFinite(value) && value > 0) {
		return Math.trunc(value);
	}

	if (typeof value === "string") {
		const parsed = Number.parseInt(value, 10);
		if (Number.isFinite(parsed) && parsed > 0) {
			return parsed;
		}
	}

	warnings.push("Invalid config value 'version': expected a positive integer.");
	return DEFAULT_CONFIG.version;
}

function normalizeProtectionLevel(
	value: unknown,
	fallback: ProtectionLevel,
	path: string,
	warnings: string[],
): ProtectionLevel {
	if (value === undefined) {
		return fallback;
	}

	if (value === "none" || value === "readOnly" || value === "noAccess") {
		return value;
	}

	warnings.push(
		`Invalid config value '${path}': expected one of 'none', 'readOnly', or 'noAccess'.`,
	);
	return fallback;
}

function normalizeSeverity(
	value: unknown,
	fallback: SecretSeverity,
	path: string,
	warnings: string[],
): SecretSeverity {
	if (value === undefined) {
		return fallback;
	}

	if (value === "critical" || value === "high" || value === "medium") {
		return value;
	}

	warnings.push(
		`Invalid config value '${path}': expected one of 'critical', 'high', or 'medium'.`,
	);
	return fallback;
}

function normalizePatternConfig(
	value: unknown,
	path: string,
	warnings: string[],
	legacyStringIsRegex = false,
): PatternConfig | null {
	if (typeof value === "string") {
		const trimmed = value.trim();
		if (!trimmed) {
			warnings.push(`Invalid config value '${path}': expected a non-empty pattern string.`);
			return null;
		}

		return legacyStringIsRegex ? { pattern: trimmed, regex: true } : { pattern: trimmed };
	}

	const record = toObject(value);
	const pattern = normalizeString(record.pattern);
	if (!pattern) {
		warnings.push(`Invalid config value '${path}.pattern': expected a non-empty string.`);
		return null;
	}

	const regex =
		record.regex === undefined
			? undefined
			: normalizeBoolean(record.regex, false, `${path}.regex`, warnings);

	return regex === undefined ? { pattern } : { pattern, regex };
}

function normalizePatternList(
	value: unknown,
	path: string,
	warnings: string[],
	legacyStringIsRegex = false,
): PatternConfig[] {
	if (value === undefined) {
		return [];
	}

	if (!Array.isArray(value)) {
		warnings.push(`Invalid config value '${path}': expected an array.`);
		return [];
	}

	const patterns: PatternConfig[] = [];
	for (const [index, entry] of value.entries()) {
		const normalized = normalizePatternConfig(
			entry,
			`${path}[${index}]`,
			warnings,
			legacyStringIsRegex,
		);
		if (normalized) {
			patterns.push(normalized);
		}
	}

	return patterns;
}

function normalizeRule(
	value: unknown,
	index: number,
	warnings: string[],
): ResolvedProtectionRule | null {
	const record = toObject(value);
	const id = normalizeString(record.id);
	if (!id) {
		warnings.push(`Invalid config value 'rules[${index}].id': expected a non-empty string.`);
		return null;
	}

	const patterns = normalizePatternList(
		record.patterns,
		`rules[${index}].patterns`,
		warnings,
	);
	if (patterns.length === 0) {
		warnings.push(`Invalid config value 'rules[${index}].patterns': expected at least one valid pattern.`);
		return null;
	}

	const allowedPatterns = normalizePatternList(
		record.allowedPatterns,
		`rules[${index}].allowedPatterns`,
		warnings,
	);

	return {
		id,
		name: normalizeString(record.name),
		description: normalizeString(record.description),
		patterns,
		allowedPatterns,
		protection: normalizeProtectionLevel(
			record.protection,
			"noAccess",
			`rules[${index}].protection`,
			warnings,
		),
		onlyIfExists: normalizeBoolean(
			record.onlyIfExists,
			false,
			`rules[${index}].onlyIfExists`,
			warnings,
		),
		enabled: normalizeBoolean(
			record.enabled,
			true,
			`rules[${index}].enabled`,
			warnings,
		),
	};
}

function normalizeRules(
	rawRules: unknown,
	legacyProtectedPatterns: PatternConfig[],
	legacySafePatterns: PatternConfig[],
	warnings: string[],
): ResolvedProtectionRule[] {
	if (!Array.isArray(rawRules) || rawRules.length === 0) {
		return [
			{
				...DEFAULT_CONFIG.rules[0],
				patterns:
					legacyProtectedPatterns.length > 0
						? legacyProtectedPatterns
						: clonePatternList(DEFAULT_PROTECTED_PATTERN_CONFIGS),
				allowedPatterns:
					legacySafePatterns.length > 0
						? legacySafePatterns
						: clonePatternList(DEFAULT_SAFE_PATTERN_CONFIGS),
			},
		];
	}

	const rules: ResolvedProtectionRule[] = [];
	for (const [index, rule] of rawRules.entries()) {
		const normalized = normalizeRule(rule, index, warnings);
		if (normalized) {
			rules.push(normalized);
		}
	}

	if (rules.length > 0) {
		return rules;
	}

	warnings.push("No valid protection rules were found. Using default sensitive-file rule set.");
	return cloneDefaultConfig().rules;
}

function normalizeGitProtection(
	value: unknown,
	warnings: string[],
): ResolvedSensitiveGuardConfig["gitProtection"] {
	const record = toObject(value) as GitProtectionConfig;
	return {
		enabled: normalizeBoolean(
			record.enabled,
			DEFAULT_CONFIG.gitProtection.enabled,
			"gitProtection.enabled",
			warnings,
		),
		blockCommit: normalizeBoolean(
			record.blockCommit,
			DEFAULT_CONFIG.gitProtection.blockCommit,
			"gitProtection.blockCommit",
			warnings,
		),
		blockPush: normalizeBoolean(
			record.blockPush,
			DEFAULT_CONFIG.gitProtection.blockPush,
			"gitProtection.blockPush",
			warnings,
		),
		diffTimeoutMs: normalizePositiveInteger(
			record.diffTimeoutMs,
			DEFAULT_CONFIG.gitProtection.diffTimeoutMs,
			"gitProtection.diffTimeoutMs",
			warnings,
		),
		maxCommits: normalizePositiveInteger(
			record.maxCommits,
			DEFAULT_CONFIG.gitProtection.maxCommits,
			"gitProtection.maxCommits",
			warnings,
		),
	};
}

function normalizeContentScanning(
	value: unknown,
	warnings: string[],
): ResolvedSensitiveGuardConfig["contentScanning"] {
	const record = toObject(value) as ContentScanningConfig;
	return {
		enabled: normalizeBoolean(
			record.enabled,
			DEFAULT_CONFIG.contentScanning.enabled,
			"contentScanning.enabled",
			warnings,
		),
		blockSeverity: normalizeSeverity(
			record.blockSeverity,
			DEFAULT_CONFIG.contentScanning.blockSeverity,
			"contentScanning.blockSeverity",
			warnings,
		),
		maxFindings: normalizePositiveInteger(
			record.maxFindings,
			DEFAULT_CONFIG.contentScanning.maxFindings,
			"contentScanning.maxFindings",
			warnings,
		),
	};
}

function normalizeBlockedEvents(
	value: unknown,
	warnings: string[],
): ResolvedSensitiveGuardConfig["blockedEvents"] {
	const record = toObject(value) as BlockedEventsConfig;
	const configuredPath = normalizeString(record.logPath);
	return {
		emit: normalizeBoolean(
			record.emit,
			DEFAULT_CONFIG.blockedEvents.emit,
			"blockedEvents.emit",
			warnings,
		),
		log: normalizeBoolean(
			record.log,
			DEFAULT_CONFIG.blockedEvents.log,
			"blockedEvents.log",
			warnings,
		),
		logPath: configuredPath
			? resolve(dirname(PRIMARY_CONFIG_PATH), configuredPath)
			: DEFAULT_BLOCKED_EVENTS_LOG_PATH,
	};
}

function normalizeReadRedaction(
	value: unknown,
	warnings: string[],
): ResolvedSensitiveGuardConfig["readRedaction"] {
	const record = toObject(value) as ReadRedactionConfig;
	const configuredPlaceholder = normalizeString(record.placeholder);
	const configuredPatterns = normalizePatternList(
		record.sensitiveKeyPatterns,
		"readRedaction.sensitiveKeyPatterns",
		warnings,
	);

	return {
		enabled: normalizeBoolean(
			record.enabled,
			DEFAULT_CONFIG.readRedaction.enabled,
			"readRedaction.enabled",
			warnings,
		),
		includeShellOutput: normalizeBoolean(
			record.includeShellOutput,
			DEFAULT_CONFIG.readRedaction.includeShellOutput,
			"readRedaction.includeShellOutput",
			warnings,
		),
		placeholder: configuredPlaceholder ?? DEFAULT_CONFIG.readRedaction.placeholder,
		maxBytes: normalizePositiveInteger(
			record.maxBytes,
			DEFAULT_CONFIG.readRedaction.maxBytes,
			"readRedaction.maxBytes",
			warnings,
		),
		sensitiveKeyPatterns:
			configuredPatterns.length > 0
				? configuredPatterns
				: clonePatternList(DEFAULT_SENSITIVE_KEY_PATTERN_CONFIGS),
		redactSecretPatterns: normalizeBoolean(
			record.redactSecretPatterns,
			DEFAULT_CONFIG.readRedaction.redactSecretPatterns,
			"readRedaction.redactSecretPatterns",
			warnings,
		),
	};
}

export function normalizeSensitiveGuardConfig(raw: unknown): {
	config: ResolvedSensitiveGuardConfig;
	warnings: string[];
} {
	const warnings: string[] = [];
	const source = toObject(raw) as SensitiveGuardConfig & Record<string, unknown>;

	const legacyProtectedPatterns = normalizePatternList(
		source.PROTECTED_PATTERNS ?? source.protectedPatterns,
		"protectedPatterns",
		warnings,
		true,
	);
	const legacySafePatterns = normalizePatternList(
		source.SAFE_PATTERNS ?? source.safePatterns,
		"safePatterns",
		warnings,
		true,
	);
	const legacyBlockPattern = normalizeString(
		source.BLOCK_PATTERN ?? source.blockPattern,
	);
	if (legacyBlockPattern) {
		legacyProtectedPatterns.push({ pattern: legacyBlockPattern, regex: true });
	}

	const config: ResolvedSensitiveGuardConfig = {
		version: normalizeVersion(source.version, warnings),
		enabled: normalizeBoolean(
			source.enabled,
			DEFAULT_CONFIG.enabled,
			"enabled",
			warnings,
		),
		rules: normalizeRules(
			source.rules,
			legacyProtectedPatterns,
			legacySafePatterns,
			warnings,
		),
		gitProtection: normalizeGitProtection(source.gitProtection, warnings),
		contentScanning: normalizeContentScanning(source.contentScanning, warnings),
		blockedEvents: normalizeBlockedEvents(source.blockedEvents, warnings),
		readRedaction: normalizeReadRedaction(source.readRedaction, warnings),
		debug: normalizeBoolean(source.debug, DEFAULT_CONFIG.debug, "debug", warnings),
	};

	return { config, warnings };
}

function parseConfigFromPath(path: string): {
	config: ResolvedSensitiveGuardConfig;
	warnings: string[];
} {
	const fileContent = readFileSync(path, "utf-8");
	const parsed = JSON.parse(fileContent) as unknown;
	return normalizeSensitiveGuardConfig(parsed);
}

export function ensureConfigExists(): EnsureConfigResult {
	if (existsSync(PRIMARY_CONFIG_PATH)) {
		return { created: false };
	}

	try {
		mkdirSync(dirname(PRIMARY_CONFIG_PATH), { recursive: true });
		writeFileSync(PRIMARY_CONFIG_PATH, DEFAULT_CONFIG_CONTENT, "utf-8");
		return { created: true };
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return {
			created: false,
			error: `Failed to create ${PRIMARY_CONFIG_PATH}: ${message}`,
		};
	}
}

export function loadConfig(): ConfigLoadResult {
	try {
		if (existsSync(PRIMARY_CONFIG_PATH)) {
			const parsed = parseConfigFromPath(PRIMARY_CONFIG_PATH);
			return {
				config: parsed.config,
				source: "primary",
				path: PRIMARY_CONFIG_PATH,
				warnings: parsed.warnings,
			};
		}

		return {
			config: cloneDefaultConfig(),
			source: "fallback",
			warnings: [],
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return {
			config: cloneDefaultConfig(),
			source: "fallback",
			warnings: [`Failed to load ${PRIMARY_CONFIG_PATH}: ${message}`],
		};
	}
}
