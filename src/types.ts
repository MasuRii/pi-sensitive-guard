export type ConfigSource = "primary" | "fallback";
export type ProtectionLevel = "none" | "readOnly" | "noAccess";
export type ReadRedactionScope = "protectedOnly" | "allOutput";
export type BlockKind = "read" | "write" | "delete";
export type GuardFeature =
	| "pathProtection"
	| "shellCommand"
	| "contentScan"
	| "gitProtection"
	| "readRedaction";
export type GuardAction = BlockKind | "commit" | "push";
export type SecretSeverity = "critical" | "high" | "medium";

export interface PatternConfig {
	pattern: string;
	regex?: boolean;
}

export interface ProtectionRule {
	id: string;
	name?: string;
	description?: string;
	patterns: PatternConfig[];
	allowedPatterns?: PatternConfig[];
	protection: ProtectionLevel;
	onlyIfExists?: boolean;
	enabled?: boolean;
}

export interface GitProtectionConfig {
	enabled?: boolean;
	blockCommit?: boolean;
	blockPush?: boolean;
	diffTimeoutMs?: number;
	maxCommits?: number;
}

export interface ContentScanningConfig {
	enabled?: boolean;
	blockSeverity?: SecretSeverity;
	maxFindings?: number;
}

export interface BlockedEventsConfig {
	emit?: boolean;
	log?: boolean;
	logPath?: string;
}

export interface ReadRedactionConfig {
	enabled?: boolean;
	includeShellOutput?: boolean;
	scope?: ReadRedactionScope;
	placeholder?: string;
	maxBytes?: number;
	sensitiveKeyPatterns?: PatternConfig[];
	redactSecretPatterns?: boolean;
}

export interface ProtectedFileEditsConfig {
	enabled?: boolean;
}

export interface SensitiveGuardConfig {
	version?: number | string;
	enabled?: boolean;
	protectedPatterns?: string[];
	safePatterns?: string[];
	rules?: ProtectionRule[];
	gitProtection?: GitProtectionConfig;
	contentScanning?: ContentScanningConfig;
	blockedEvents?: BlockedEventsConfig;
	readRedaction?: ReadRedactionConfig;
	protectedFileEdits?: ProtectedFileEditsConfig;
	debug?: boolean;
}

export interface ResolvedProtectionRule {
	id: string;
	name?: string;
	description?: string;
	patterns: PatternConfig[];
	allowedPatterns: PatternConfig[];
	protection: ProtectionLevel;
	onlyIfExists: boolean;
	enabled: boolean;
}

export interface ResolvedSensitiveGuardConfig {
	version: number;
	enabled: boolean;
	rules: ResolvedProtectionRule[];
	gitProtection: {
		enabled: boolean;
		blockCommit: boolean;
		blockPush: boolean;
		diffTimeoutMs: number;
		maxCommits: number;
	};
	contentScanning: {
		enabled: boolean;
		blockSeverity: SecretSeverity;
		maxFindings: number;
	};
	blockedEvents: {
		emit: boolean;
		log: boolean;
		logPath: string;
	};
	readRedaction: {
		enabled: boolean;
		includeShellOutput: boolean;
		scope: ReadRedactionScope;
		placeholder: string;
		maxBytes: number;
		sensitiveKeyPatterns: PatternConfig[];
		redactSecretPatterns: boolean;
	};
	protectedFileEdits: {
		enabled: boolean;
	};
	debug: boolean;
}

export interface ConfigLoadResult {
	config: ResolvedSensitiveGuardConfig;
	source: ConfigSource;
	path?: string;
	warnings: string[];
}

export interface EnsureConfigResult {
	created: boolean;
	error?: string;
}

export interface GuardCheckResult {
	blocked: boolean;
	reason: string;
	kind?: BlockKind;
	target?: string;
	ruleId?: string;
	protection?: ProtectionLevel;
}

export interface CommandCheckResult extends GuardCheckResult {
	commandName?: string;
	commandWords?: string[];
}

export interface SensitiveGuardMatcher {
	checkReadPath(filePath: string): GuardCheckResult;
	checkWritePath(filePath: string): GuardCheckResult;
	checkDeletePath(filePath: string): GuardCheckResult;
	checkReadCommand(command: string): CommandCheckResult;
	checkWriteCommand(command: string): CommandCheckResult;
	checkDeleteCommand(command: string): CommandCheckResult;
}

export interface SecretPatternDefinition {
	name: string;
	pattern: RegExp;
	severity: SecretSeverity;
	secretGroup?: number;
}

export interface SecretFinding {
	name: string;
	severity: SecretSeverity;
	line?: number;
	file?: string;
	snippet: string;
}

export interface ParsedShellRedirect {
	operator?: string;
	target: string;
}

export interface ParsedShellCommand {
	raw: string;
	words: string[];
	redirects: ParsedShellRedirect[];
	parser: "ast" | "token";
}

export interface SensitiveGuardBlockedEvent {
	feature: GuardFeature;
	action: GuardAction;
	reason: string;
	timestamp: string;
	toolName?: string;
	target?: string;
	ruleId?: string;
	metadata?: Record<string, unknown>;
}

export interface GitProtectionCheckResult {
	blocked: boolean;
	action?: "commit" | "push";
	reason: string;
	target?: string;
	ruleId?: string;
	metadata?: Record<string, unknown>;
}

export interface PendingReadRedaction {
	toolCallId: string;
	toolName: string;
	target?: string;
	ruleId?: string;
	source: "read" | "shell";
}

export interface RedactionResult {
	content: string;
	redacted: boolean;
	redactionCount: number;
	reasons: string[];
}
