import { existsSync, realpathSync } from "node:fs";
import { matchesGlob } from "node:path";

import {
	FILE_DELETE_COMMANDS,
	FILE_READ_COMMANDS,
	FILE_WRITE_COMMANDS,
	MAX_AGENT_WRITTEN_PATHS,
} from "./constants.js";
import { type ModuleCache, loadCachedModule } from "./module-loader.js";
import { compileRegex } from "./shared/index.js";
import type {
	CommandCheckResult,
	GuardCheckResult,
	ParsedShellCommand,
	PatternConfig,
	ProtectionLevel,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardMatcher,
} from "./types.js";

const READ_COMMAND_SET = new Set(FILE_READ_COMMANDS.map((command) => command.toLowerCase()));
const READ_SOURCE_COMMAND_SET = new Set(["cp", "copy", "mv", "move", "install"]);
const WRITE_COMMAND_SET = new Set(FILE_WRITE_COMMANDS.map((command) => command.toLowerCase()));
const DELETE_COMMAND_SET = new Set(FILE_DELETE_COMMANDS.map((command) => command.toLowerCase()));
const SCRIPT_EXECUTE_COMMAND_SET = new Set([
	"bash",
	"bun",
	"cmd",
	"dash",
	"deno",
	"fish",
	"ksh",
	"node",
	"perl",
	"php",
	"powershell",
	"pwsh",
	"python",
	"python3",
	"ruby",
	"sh",
	"zsh",
]);
const ENV_ECHO_COMMAND_PATTERN = /(?:^|[;&|()\s])(?:cat|echo|env|printenv|printf|bash|dash|fish|ksh|pwsh|powershell|sh|zsh)\b|<</i;
const ENV_VAR_REFERENCE_PATTERN = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:[^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g;
const AGENT_GENERATED_SCRIPT_PATTERN = /(?:^|\/)\.pi\/agent\/generated\/.+\.(?:bash|bat|cmd|cjs|js|mjs|pl|ps1|py|rb|sh|ts|zsh)$/i;

type ShellParserModule = typeof import("./shell-parser.js");

const shellParserModuleCache: ModuleCache<ShellParserModule> = {};

async function loadShellParserModule(): Promise<ShellParserModule> {
	return loadCachedModule("./shell-parser.js", shellParserModuleCache);
}

async function parseShellCommandLazy(command: string): Promise<ParsedShellCommand[]> {
	const { parseShellCommand } = await loadShellParserModule();
	return parseShellCommand(command);
}

interface CompiledPattern {
	source: PatternConfig;
	test: (input: string) => boolean;
}

interface CompiledEnvKeyPattern {
	source: PatternConfig;
	test: (input: string) => boolean;
}

interface CompiledRule {
	id: string;
	patterns: CompiledPattern[];
	allowedPatterns: CompiledPattern[];
	protection: ProtectionLevel;
	onlyIfExists: boolean;
	enabled: boolean;
}

function normalizeFilePath(input: string): string {
	return input
		.replaceAll("\\", "/")
		.replace(/^(?:\.\/)+/, "")
		.replace(/\/+/g, "/");
}

function stripQuotes(value: string): string {
	return value.replace(/^['"`]+|['"`]+$/g, "");
}

function normalizePathToken(path: string): string {
	const trimmed = stripQuotes(path.trim());
	if (!trimmed) {
		return "";
	}

	const withoutPrefix = trimmed.replace(/^(?:@|\d*>>?\|?|\d*<<?-?|<+|>+)+/, "");
	const withoutSuffix = withoutPrefix.replace(/[;,|&)<\]}]+$/g, "");
	return normalizeFilePath(withoutSuffix);
}

function normalizeCommandWord(value: string): string {
	const normalized = normalizePathToken(value).toLowerCase();
	return normalized.split("/").pop() ?? normalized;
}

function tryCompileRegex(pattern: PatternConfig): RegExp | null {
	return pattern.regex ? compileRegex(pattern.pattern, "i") : null;
}

function compilePattern(pattern: PatternConfig): CompiledPattern {
	const compiled = tryCompileRegex(pattern);
	if (compiled) {
		return {
			source: pattern,
			test: (input) => compiled.test(normalizeFilePath(input)),
		};
	}

	const matchFullPath = pattern.pattern.includes("/") || pattern.pattern.includes("\\");
	return {
		source: pattern,
		test: (input) => {
			const normalized = normalizeFilePath(input);
			const candidate = matchFullPath
				? normalized
				: (normalized.split("/").pop() ?? normalized);
			return matchesGlob(candidate, pattern.pattern);
		},
	};
}

function compileEnvKeyPattern(pattern: PatternConfig): CompiledEnvKeyPattern {
	const compiled = tryCompileRegex(pattern);
	if (compiled) {
		return {
			source: pattern,
			test: (input) => {
				compiled.lastIndex = 0;
				return compiled.test(input);
			},
		};
	}

	return {
		source: pattern,
		test: (input) => matchesGlob(input, pattern.pattern),
	};
}

function compileRules(config: ResolvedSensitiveGuardConfig): CompiledRule[] {
	return config.rules.map((rule) => ({
		id: rule.id,
		patterns: rule.patterns.map(compilePattern),
		allowedPatterns: rule.allowedPatterns.map(compilePattern),
		protection: rule.protection,
		onlyIfExists: rule.onlyIfExists,
		enabled: rule.enabled,
	}));
}

function createAllowedResult(): GuardCheckResult {
	return { blocked: false, reason: "" };
}

function createAllowedCommandResult(): CommandCheckResult {
	return { blocked: false, reason: "" };
}

function createPathBlockResult(
	result: CommandCheckResult,
	action: "reads" | "writes",
	commandName: string,
	commandWords: string[],
): CommandCheckResult {
	return {
		...result,
		reason: `Command ${action} protected path '${result.target}'.`,
		commandName,
		commandWords,
	};
}

async function parseCommandsForCheck(command: string): Promise<ParsedShellCommand[] | null> {
	if (!command || typeof command !== "string") {
		return null;
	}
	return parseShellCommandLazy(command);
}

function checkRedirectBlock(
	parsedCommand: ParsedShellCommand,
	action: "read" | "write",
	checkPath: (path: string) => GuardCheckResult,
): CommandCheckResult | undefined {
	const redirectResult = checkRedirects(parsedCommand.redirects, action, checkPath);
	if (redirectResult.blocked) {
		return createPathBlockResult(
			redirectResult,
			action === "read" ? "reads" : "writes",
			getCommandName(getCommandWords(parsedCommand)),
			parsedCommand.words,
		);
	}
	return undefined;
}

function createBlockedResult(
	kind: "read" | "write" | "delete",
	target: string,
	ruleId: string,
	protection: ProtectionLevel,
	resolvedTarget?: string,
): GuardCheckResult {
	let reason = `Path '${target}' is protected by rule '${ruleId}' (${protection}).`;
	if (resolvedTarget && resolvedTarget !== target) {
		reason = `Path '${target}' (resolved to '${resolvedTarget}') is protected by rule '${ruleId}' (${protection}).`;
	}
	return {
		blocked: true,
		reason,
		kind,
		target,
		ruleId,
		protection,
	};
}

function candidatePaths(inputPath: string): string[] {
	const normalized = normalizePathToken(inputPath);
	if (!normalized) {
		return [];
	}
	const candidates = new Set<string>([normalized]);
	try {
		const resolved = realpathSync(inputPath).replace(/\\/g, "/");
		if (resolved && resolved !== normalized) {
			candidates.add(resolved);
		}
	} catch {
		// realpathSync fails when the path does not exist or is unreachable;
		// fall back to the normalized path already in candidates.
		return [...candidates];
	}
	return [...candidates];
}

function getActionThreshold(action: "read" | "write" | "delete"): number {
	switch (action) {
		case "read":
			return 2;
		case "write":
		case "delete":
			return 1;
	}
}

function getProtectionRank(protection: ProtectionLevel): number {
	switch (protection) {
		case "none":
			return 0;
		case "readOnly":
			return 1;
		case "noAccess":
			return 2;
	}
}

function findSensitivePathInWords(
	words: string[],
	isSensitivePath: (path: string) => GuardCheckResult,
	action: "read" | "write" | "delete",
): GuardCheckResult {
	for (const word of words) {
		if (!word || word.startsWith("-")) {
			continue;
		}

		const normalized = normalizePathToken(word);
		if (!normalized) {
			continue;
		}

		const directMatch = isSensitivePath(normalized);
		if (directMatch.blocked && directMatch.kind === action) {
			return directMatch;
		}

		const equalsIndex = normalized.indexOf("=");
		if (equalsIndex > 0 && equalsIndex < normalized.length - 1) {
			const candidate = normalizePathToken(normalized.slice(equalsIndex + 1));
			const candidateMatch = isSensitivePath(candidate);
			if (candidateMatch.blocked && candidateMatch.kind === action) {
				return candidateMatch;
			}
		}
	}

	return createAllowedResult();
}

function getCommandWords(command: ParsedShellCommand): string[] {
	return command.words
		.map((word) => normalizeCommandWord(word))
		.filter((word) => word.length > 0);
}

function getCommandName(words: string[]): string {
	for (const word of words) {
		if (!word.includes("=")) {
			return word;
		}
	}

	return "";
}

function getCommandSubcommand(words: string[]): string {
	let foundCommand = false;
	for (const word of words) {
		if (word.includes("=")) {
			continue;
		}

		if (!foundCommand) {
			foundCommand = true;
			continue;
		}

		return word;
	}

	return "";
}

function filterSourceOperands(words: string[]): string[] {
	return words.slice(1).filter((word) => !normalizePathToken(word).startsWith("-"));
}

function getCandidateWords(
	commandName: string,
	words: string[],
	selectOperands: (operands: string[]) => string[],
): string[] {
	if (!READ_SOURCE_COMMAND_SET.has(commandName)) {
		return words.slice(1);
	}

	const operands = filterSourceOperands(words);
	return operands.length > 1 ? selectOperands(operands) : operands;
}

function getReadCandidateWords(commandName: string, words: string[]): string[] {
	return getCandidateWords(commandName, words, (operands) => operands.slice(0, -1));
}

function getWriteCandidateWords(commandName: string, words: string[]): string[] {
	return getCandidateWords(commandName, words, (operands) => operands.slice(-1));
}

function findSecretEnvVarNames(command: string, patterns: CompiledEnvKeyPattern[]): string[] {
	const names = new Set<string>();
	for (const match of command.matchAll(ENV_VAR_REFERENCE_PATTERN)) {
		const name = match[1] ?? match[2] ?? "";
		if (name && patterns.some((pattern) => pattern.test(name))) {
			names.add(name);
		}
	}
	return [...names];
}

function isAgentGeneratedScriptPath(path: string): boolean {
	return AGENT_GENERATED_SCRIPT_PATTERN.test(normalizePathToken(path));
}

function findAgentWrittenExecutable(
	commandName: string,
	words: string[],
	agentWrittenPaths: Set<string>,
): string | undefined {
	if (!SCRIPT_EXECUTE_COMMAND_SET.has(commandName)) {
		return undefined;
	}

	return words
		.slice(1)
		.map(normalizePathToken)
		.find((word) => word.length > 0 && !word.startsWith("-") && agentWrittenPaths.has(word));
}

function checkRedirects(
	redirects: ParsedShellCommand["redirects"],
	kind: "read" | "write",
	checkPath: (path: string) => GuardCheckResult,
): GuardCheckResult {
	for (const redirect of redirects) {
		const operator = redirect.operator ?? "";
		const isReadRedirect = operator.startsWith("<") && !operator.startsWith(">>");
		const isWriteRedirect = operator.startsWith(">") || operator.includes(">");

		if ((kind === "read" && !isReadRedirect) || (kind === "write" && !isWriteRedirect)) {
			continue;
		}

		const result = checkPath(redirect.target);
		if (result.blocked) {
			return result;
		}
	}

	return createAllowedResult();
}

export function createSensitiveGuardMatcher(
	config: ResolvedSensitiveGuardConfig,
): SensitiveGuardMatcher {
	const compiledRules = compileRules(config);
	const compiledEnvKeyPatterns = config.readRedaction.sensitiveKeyPatterns.map(compileEnvKeyPattern);
	const agentWrittenPaths = new Set<string>();
	const agentWrittenPathOrder: string[] = [];

	const trackAgentWrittenPath = (normalizedPath: string): void => {
		if (agentWrittenPaths.has(normalizedPath)) {
			return;
		}
		agentWrittenPaths.add(normalizedPath);
		agentWrittenPathOrder.push(normalizedPath);
		while (agentWrittenPathOrder.length > MAX_AGENT_WRITTEN_PATHS) {
			const evicted = agentWrittenPathOrder.shift();
			if (evicted !== undefined) {
				agentWrittenPaths.delete(evicted);
			}
		}
	};

	const evaluatePath = (
		filePath: string,
		action: "read" | "write" | "delete",
		threshold = getActionThreshold(action),
	): GuardCheckResult => {
		if (!config.enabled || !filePath || typeof filePath !== "string") {
			return createAllowedResult();
		}

		if (action === "write" && isAgentGeneratedScriptPath(filePath)) {
			trackAgentWrittenPath(normalizePathToken(filePath));
			return createAllowedResult();
		}

		const paths = candidatePaths(filePath);
		if (paths.length === 0) {
			return createAllowedResult();
		}

		const originalPath = paths[0];

		for (let index = 0; index < paths.length; index += 1) {
			const normalizedPath = paths[index];

			let winningRule: CompiledRule | null = null;
			let winningRank = -1;
			for (const rule of compiledRules) {
				if (!rule.enabled) {
					continue;
				}

				if (!rule.patterns.some((pattern) => pattern.test(normalizedPath))) {
					continue;
				}

				if (rule.allowedPatterns.some((pattern) => pattern.test(normalizedPath))) {
					continue;
				}

				if (rule.onlyIfExists && !existsSync(normalizedPath)) {
					continue;
				}

				const rank = getProtectionRank(rule.protection);
				if (rank > winningRank) {
					winningRule = rule;
					winningRank = rank;
				}
			}

			if (!winningRule) {
				continue;
			}

			if (getProtectionRank(winningRule.protection) < threshold) {
				continue;
			}

			return createBlockedResult(
				action,
				originalPath,
				winningRule.id,
				winningRule.protection,
				index > 0 ? normalizedPath : undefined,
			);
		}

		return createAllowedResult();
	};

	const checkReadPath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "read");
	const checkReadSourcePath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "read", getActionThreshold("write"));
	const checkWritePath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "write");
	const checkDeletePath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "delete");

	return {
		checkReadPath,
		checkWritePath,
		checkDeletePath,

		async checkReadCommand(command: string): Promise<CommandCheckResult> {
			if (!command || typeof command !== "string") {
				return createAllowedCommandResult();
			}

			const parsedCommands = await parseShellCommandLazy(command);
			const secretEnvVars = findSecretEnvVarNames(command, compiledEnvKeyPatterns);
			if (secretEnvVars.length > 0 && ENV_ECHO_COMMAND_PATTERN.test(command)) {
				const firstParsedCommand = parsedCommands[0];
				const commandWords = firstParsedCommand ? getCommandWords(firstParsedCommand) : [];
				return {
					blocked: true,
					reason: `Command may echo secret environment variable '${secretEnvVars[0]}'.`,
					kind: "read",
					target: secretEnvVars[0],
					commandName: firstParsedCommand ? getCommandName(commandWords) : undefined,
					commandWords,
				};
			}

			for (const parsedCommand of parsedCommands) {
				const redirectBlock = checkRedirectBlock(parsedCommand, "read", checkReadPath);
				if (redirectBlock) {
					return redirectBlock;
				}

				const commandWords = getCommandWords(parsedCommand);
				const commandName = getCommandName(commandWords);
				const agentWrittenTarget = findAgentWrittenExecutable(
					commandName,
					parsedCommand.words,
					agentWrittenPaths,
				);
				if (agentWrittenTarget) {
					return {
						blocked: true,
						reason: `Command executes agent-written file '${agentWrittenTarget}' blocked by write/execute correlation.`,
						kind: "read",
						target: agentWrittenTarget,
						commandName,
						commandWords,
					};
				}

				if (!READ_COMMAND_SET.has(commandName) && !READ_SOURCE_COMMAND_SET.has(commandName)) {
					continue;
				}

				const sensitivePath = findSensitivePathInWords(
					getReadCandidateWords(commandName, parsedCommand.words),
					READ_SOURCE_COMMAND_SET.has(commandName) ? checkReadSourcePath : checkReadPath,
					"read",
				);
				if (sensitivePath.blocked) {
					return createPathBlockResult(sensitivePath, "reads", commandName, commandWords);
				}
			}

			return createAllowedCommandResult();
		},

		async checkWriteCommand(command: string): Promise<CommandCheckResult> {
			const parsedCommands = await parseCommandsForCheck(command);
			if (!parsedCommands) {
				return createAllowedCommandResult();
			}

			for (const parsedCommand of parsedCommands) {
				const redirectBlock = checkRedirectBlock(parsedCommand, "write", checkWritePath);
				if (redirectBlock) {
					return redirectBlock;
				}

				const commandWords = getCommandWords(parsedCommand);
				const commandName = getCommandName(commandWords);
				const sensitivePath = findSensitivePathInWords(
					getWriteCandidateWords(commandName, parsedCommand.words),
					checkWritePath,
					"write",
				);
				if (WRITE_COMMAND_SET.has(commandName) && sensitivePath.blocked) {
					return createPathBlockResult(sensitivePath, "writes", commandName, commandWords);
				}

				if (
					(commandName === "sed" || commandName === "perl") &&
					parsedCommand.words.some((word) => /(^|\s)-i(?:\S*)?$/.test(word)) &&
					sensitivePath.blocked
				) {
					return {
						...sensitivePath,
						reason: `Command edits protected path '${sensitivePath.target}' in place.`,
						commandName,
						commandWords,
					};
				}
			}

			return createAllowedCommandResult();
		},

		async checkDeleteCommand(command: string): Promise<CommandCheckResult> {
			const parsedCommands = await parseCommandsForCheck(command);
			if (parsedCommands) {
				for (const parsedCommand of parsedCommands) {
					const commandWords = getCommandWords(parsedCommand);
					const commandName = getCommandName(commandWords);
					const subcommand = getCommandSubcommand(commandWords);
					const sensitivePath = findSensitivePathInWords(
						parsedCommand.words.slice(1),
						checkDeletePath,
						"delete",
					);

					if (DELETE_COMMAND_SET.has(commandName) && sensitivePath.blocked) {
						return {
							...sensitivePath,
							reason: `Command deletes protected path '${sensitivePath.target}'.`,
							commandName,
							commandWords,
						};
					}

					if (commandName === "git" && subcommand === "rm" && sensitivePath.blocked) {
						return {
							...sensitivePath,
							reason: `Git command removes protected path '${sensitivePath.target}'.`,
							commandName,
							commandWords,
						};
					}

					if (
						((commandName === "gio" && subcommand === "trash") ||
							(commandName === "git" && subcommand === "clean")) &&
						sensitivePath.blocked
					) {
						return {
							...sensitivePath,
							reason: `Command trashes or cleans protected path '${sensitivePath.target}'.`,
							commandName,
							commandWords,
						};
					}

					if (
						(commandName === "mv" || commandName === "move") &&
						parsedCommand.words.some((word) => normalizePathToken(word) === "/dev/null") &&
						sensitivePath.blocked
					) {
						return {
							...sensitivePath,
							reason: `Command destroys protected path '${sensitivePath.target}'.`,
							commandName,
							commandWords,
						};
					}
				}
			}

			return createAllowedCommandResult();
		},
	};
}
