import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
	DEFAULT_BLOCKED_EVENTS_LOG_PATH,
	DEFAULT_CONFIG,
	DEFAULT_CONFIG_CONTENT,
	DEFAULT_PROTECTED_PATTERN_CONFIGS,
	DEFAULT_SAFE_PATTERN_CONFIGS,
	DEFAULT_SENSITIVE_KEY_PATTERN_CONFIGS,
	PRIMARY_CONFIG_PATH,
	PROJECT_CONFIG_FILENAME,
} from "./constants.js";
import { describeError, toRecord } from "./shared/index.js";
import type {
	BlockedEventsConfig,
	ConfigLoadResult,
	ContentScanningConfig,
	EnsureConfigResult,
	GitProtectionConfig,
	PatternConfig,
	ProtectionLevel,
	ProtectedFileEditsConfig,
	ReadRedactionConfig,
	ReadRedactionScope,
	ResolvedProtectionRule,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardConfig,
	SecretSeverity,
} from "./types.js";

function clonePatternList(patterns: PatternConfig[]): PatternConfig[] {
	return patterns.map((pattern) => ({ ...pattern }));
}

function cloneResolvedConfig(config: ResolvedSensitiveGuardConfig): ResolvedSensitiveGuardConfig {
	return JSON.parse(JSON.stringify(config)) as ResolvedSensitiveGuardConfig;
}

function cloneRule(rule: ResolvedProtectionRule): ResolvedProtectionRule {
	return {
		...rule,
		patterns: clonePatternList(rule.patterns),
		allowedPatterns: clonePatternList(rule.allowedPatterns),
	};
}

function cloneDefaultConfig(): ResolvedSensitiveGuardConfig {
	return {
		version: DEFAULT_CONFIG.version,
		enabled: DEFAULT_CONFIG.enabled,
		rules: DEFAULT_CONFIG.rules.map(cloneRule),
		gitProtection: { ...DEFAULT_CONFIG.gitProtection },
		contentScanning: { ...DEFAULT_CONFIG.contentScanning },
		blockedEvents: { ...DEFAULT_CONFIG.blockedEvents },
		readRedaction: {
			...DEFAULT_CONFIG.readRedaction,
			sensitiveKeyPatterns: clonePatternList(
				DEFAULT_CONFIG.readRedaction.sensitiveKeyPatterns,
			),
		},
		protectedFileEdits: { ...DEFAULT_CONFIG.protectedFileEdits },
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

function normalizeEnumValue<T extends string>(
	value: unknown,
	fallback: T,
	allowed: readonly T[],
	path: string,
	warnings: string[],
): T {
	if (value === undefined) {
		return fallback;
	}

	for (const option of allowed) {
		if (value === option) {
			return option;
		}
	}

	warnings.push(
		`Invalid config value '${path}': expected one of ${allowed
			.map((v) => `'${v}'`)
			.join(", ")}.`,
	);
	return fallback;
}

function normalizeProtectionLevel(
	value: unknown,
	fallback: ProtectionLevel,
	path: string,
	warnings: string[],
): ProtectionLevel {
	return normalizeEnumValue(
		value,
		fallback,
		["none", "readOnly", "noAccess"] as const,
		path,
		warnings,
	);
}

function normalizeSeverity(
	value: unknown,
	fallback: SecretSeverity,
	path: string,
	warnings: string[],
): SecretSeverity {
	return normalizeEnumValue(
		value,
		fallback,
		["critical", "high", "medium"] as const,
		path,
		warnings,
	);
}

function normalizeReadRedactionScope(
	value: unknown,
	fallback: ReadRedactionScope,
	path: string,
	warnings: string[],
): ReadRedactionScope {
	return normalizeEnumValue(
		value,
		fallback,
		["protectedOnly", "allOutput"] as const,
		path,
		warnings,
	);
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

	const record = toRecord(value);
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
	const record = toRecord(value);
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
				patterns: [
					...clonePatternList(DEFAULT_PROTECTED_PATTERN_CONFIGS),
					...legacyProtectedPatterns,
				],
				allowedPatterns: [
					...clonePatternList(DEFAULT_SAFE_PATTERN_CONFIGS),
					...legacySafePatterns,
				],
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
	const record = toRecord(value) as GitProtectionConfig;
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
	const record = toRecord(value) as ContentScanningConfig;
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
	const record = toRecord(value) as BlockedEventsConfig;
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
	const record = toRecord(value) as ReadRedactionConfig;
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
		scope: normalizeReadRedactionScope(
			record.scope,
			DEFAULT_CONFIG.readRedaction.scope,
			"readRedaction.scope",
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

function normalizeProtectedFileEdits(
	value: unknown,
	warnings: string[],
): ResolvedSensitiveGuardConfig["protectedFileEdits"] {
	const record = toRecord(value) as ProtectedFileEditsConfig;
	return {
		enabled: normalizeBoolean(
			record.enabled,
			DEFAULT_CONFIG.protectedFileEdits.enabled,
			"protectedFileEdits.enabled",
			warnings,
		),
	};
}

export function normalizeSensitiveGuardConfig(raw: unknown): {
	config: ResolvedSensitiveGuardConfig;
	warnings: string[];
} {
	const warnings: string[] = [];
	const source = toRecord(raw) as SensitiveGuardConfig & Record<string, unknown>;

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
		protectedFileEdits: normalizeProtectedFileEdits(
			source.protectedFileEdits,
			warnings,
		),
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

function readConfigInput(input: unknown): unknown {
	if (typeof input !== "string") {
		return input;
	}

	const fileContent = readFileSync(input, "utf-8");
	return JSON.parse(fileContent) as unknown;
}

function mergeRuleLists(
	globalRules: ResolvedProtectionRule[],
	projectRules: ResolvedProtectionRule[],
): ResolvedProtectionRule[] {
	const rulesById = new Map<string, ResolvedProtectionRule>();
	for (const rule of globalRules) {
		rulesById.set(rule.id, rule);
	}
	for (const rule of projectRules) {
		rulesById.set(rule.id, rule);
	}
	return [...rulesById.values()].map(cloneRule);
}

export function mergeSensitiveGuardConfigs(
	globalConfigInput: unknown,
	projectConfigInput: unknown,
): ResolvedSensitiveGuardConfig {
	const globalConfig = normalizeSensitiveGuardConfig(readConfigInput(globalConfigInput)).config;
	const rawProjectConfig = readConfigInput(projectConfigInput);
	const projectRecord = toRecord(rawProjectConfig);
	const projectConfig = normalizeSensitiveGuardConfig(rawProjectConfig).config;
	const merged = cloneResolvedConfig(globalConfig);

	if (Object.hasOwn(projectRecord, "enabled")) {
		merged.enabled = globalConfig.enabled || projectConfig.enabled;
	}
	if (Object.hasOwn(projectRecord, "rules")) {
		merged.rules = mergeRuleLists(globalConfig.rules, projectConfig.rules);
	}
	if (Object.hasOwn(projectRecord, "gitProtection")) {
		merged.gitProtection = { ...projectConfig.gitProtection };
	}
	if (Object.hasOwn(projectRecord, "contentScanning")) {
		merged.contentScanning = { ...projectConfig.contentScanning };
	}
	if (Object.hasOwn(projectRecord, "blockedEvents")) {
		merged.blockedEvents = { ...projectConfig.blockedEvents };
	}
	if (Object.hasOwn(projectRecord, "readRedaction")) {
		merged.readRedaction = {
			...projectConfig.readRedaction,
			sensitiveKeyPatterns: clonePatternList(projectConfig.readRedaction.sensitiveKeyPatterns),
		};
	}
	if (Object.hasOwn(projectRecord, "protectedFileEdits")) {
		merged.protectedFileEdits = { ...projectConfig.protectedFileEdits };
	}
	if (Object.hasOwn(projectRecord, "debug")) {
		merged.debug = projectConfig.debug;
	}

	return merged;
}

let cachedLoadResult: ConfigLoadResult | undefined;
let cachedLoadFingerprint: string | undefined;

function cloneLoadResult(result: ConfigLoadResult): ConfigLoadResult {
	return {
		...result,
		config: cloneResolvedConfig(result.config),
		warnings: [...result.warnings],
	};
}

function getPrimaryConfigFingerprint(): string {
	try {
		const stats = statSync(PRIMARY_CONFIG_PATH);
		return `${PRIMARY_CONFIG_PATH}:${stats.mtimeMs}:${stats.size}`;
	} catch {
		return "missing";
	}
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
		const message = describeError(error);
		return {
			created: false,
			error: `Failed to create ${PRIMARY_CONFIG_PATH}: ${message}`,
		};
	}
}

export function loadConfig(): ConfigLoadResult {
	const fingerprint = getPrimaryConfigFingerprint();
	if (cachedLoadResult && cachedLoadFingerprint === fingerprint) {
		return cloneLoadResult(cachedLoadResult);
	}

	try {
		let result: ConfigLoadResult;
		if (existsSync(PRIMARY_CONFIG_PATH)) {
			const parsed = parseConfigFromPath(PRIMARY_CONFIG_PATH);
			result = {
				config: parsed.config,
				source: "primary",
				path: PRIMARY_CONFIG_PATH,
				warnings: parsed.warnings,
			};
		} else {
			result = {
				config: cloneDefaultConfig(),
				source: "fallback",
				warnings: [],
			};
		}

		cachedLoadFingerprint = fingerprint;
		cachedLoadResult = cloneLoadResult(result);
		return result;
	} catch (error) {
		const result: ConfigLoadResult = {
			config: cloneDefaultConfig(),
			source: "fallback",
			warnings: [`Failed to load ${PRIMARY_CONFIG_PATH}: ${describeError(error)}`],
		};
		cachedLoadFingerprint = fingerprint;
		cachedLoadResult = cloneLoadResult(result);
		return result;
	}
}

let cachedProjectConfigPath: string | undefined;
let cachedMergedFingerprint: string | undefined;
let cachedMergedResult: ConfigLoadResult | undefined;

/**
 * Resolves the project-local config path for a given workspace directory. Returns
 * `undefined` when no project-local config file exists at the expected location.
 */
export function resolveProjectConfigPath(workspaceDir: string): string | undefined {
	const projectConfigPath = resolve(workspaceDir, PROJECT_CONFIG_FILENAME);
	return existsSync(projectConfigPath) ? projectConfigPath : undefined;
}

/**
 * Loads the global config and, when a project-local config exists at
 * `workspaceDir`, merges it on top via {@link mergeSensitiveGuardConfigs}.
 * The merged result is cached by a combined fingerprint of the global and
 * project config file stats.
 */
export function loadMergedConfig(workspaceDir: string): ConfigLoadResult {
	const globalResult = loadConfig();
	const projectConfigPath = resolveProjectConfigPath(workspaceDir);

	if (!projectConfigPath) {
		return globalResult;
	}

	const projectFingerprint = (() => {
		try {
			const stats = statSync(projectConfigPath);
			return `${projectConfigPath}:${stats.mtimeMs}:${stats.size}`;
		} catch {
			return "missing";
		}
	})();
	const fingerprint = `${globalResult.source}:${globalResult.path}:${getPrimaryConfigFingerprint()}|${projectFingerprint}`;

	if (
		cachedMergedResult &&
		cachedProjectConfigPath === projectConfigPath &&
		cachedMergedFingerprint === fingerprint
	) {
		return cloneLoadResult(cachedMergedResult);
	}

	try {
		const mergedConfig = mergeSensitiveGuardConfigs(globalResult.config, projectConfigPath);
		const result: ConfigLoadResult = {
			config: mergedConfig,
			source: "merged",
			path: projectConfigPath,
			warnings: globalResult.warnings,
		};
		cachedProjectConfigPath = projectConfigPath;
		cachedMergedFingerprint = fingerprint;
		cachedMergedResult = cloneLoadResult(result);
		return result;
	} catch (error) {
		const message = describeError(error);
		const result: ConfigLoadResult = {
			config: globalResult.config,
			source: globalResult.source,
			path: globalResult.path,
			warnings: [
				...globalResult.warnings,
				`Failed to merge project config ${projectConfigPath}: ${message}`,
			],
		};
		cachedProjectConfigPath = projectConfigPath;
		cachedMergedFingerprint = fingerprint;
		cachedMergedResult = cloneLoadResult(result);
		return result;
	}
}
