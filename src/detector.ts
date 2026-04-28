import { existsSync } from "node:fs";
import { matchesGlob } from "node:path";

import {
	FILE_DELETE_COMMANDS,
	FILE_READ_COMMANDS,
	FILE_WRITE_COMMANDS,
} from "./constants.js";
import { parseShellCommand } from "./shell-parser.js";
import type {
	CommandCheckResult,
	GuardCheckResult,
	ParsedShellCommand,
	PatternConfig,
	ProtectionLevel,
	ResolvedProtectionRule,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardMatcher,
} from "./types.js";

const NEVER_MATCH_PATTERN = /$a/;
const READ_COMMAND_SET = new Set(FILE_READ_COMMANDS.map((command) => command.toLowerCase()));
const WRITE_COMMAND_SET = new Set(FILE_WRITE_COMMANDS.map((command) => command.toLowerCase()));
const DELETE_COMMAND_SET = new Set(FILE_DELETE_COMMANDS.map((command) => command.toLowerCase()));

interface CompiledPattern {
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

function compileRegex(pattern: string, flags: string): RegExp {
	try {
		return new RegExp(pattern, flags);
	} catch {
		return NEVER_MATCH_PATTERN;
	}
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
	return normalizePathToken(value).toLowerCase();
}

function compilePattern(pattern: PatternConfig): CompiledPattern {
	if (pattern.regex) {
		const compiled = compileRegex(pattern.pattern, "i");
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

function createBlockedResult(
	kind: "read" | "write" | "delete",
	target: string,
	ruleId: string,
	protection: ProtectionLevel,
): GuardCheckResult {
	return {
		blocked: true,
		reason: `Path '${target}' is protected by rule '${ruleId}' (${protection}).`,
		kind,
		target,
		ruleId,
		protection,
	};
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

	const evaluatePath = (
		filePath: string,
		action: "read" | "write" | "delete",
	): GuardCheckResult => {
		if (!config.enabled || !filePath || typeof filePath !== "string") {
			return createAllowedResult();
		}

		const normalizedPath = normalizePathToken(filePath);
		if (!normalizedPath) {
			return createAllowedResult();
		}

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
			return createAllowedResult();
		}

		if (getProtectionRank(winningRule.protection) < getActionThreshold(action)) {
			return createAllowedResult();
		}

		return createBlockedResult(
			action,
			normalizedPath,
			winningRule.id,
			winningRule.protection,
		);
	};

	const checkReadPath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "read");
	const checkWritePath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "write");
	const checkDeletePath = (filePath: string): GuardCheckResult =>
		evaluatePath(filePath, "delete");

	return {
		checkReadPath,
		checkWritePath,
		checkDeletePath,

		checkReadCommand(command: string): CommandCheckResult {
			if (!command || typeof command !== "string") {
				return createAllowedCommandResult();
			}

			for (const parsedCommand of parseShellCommand(command)) {
				const redirectResult = checkRedirects(
					parsedCommand.redirects,
					"read",
					checkReadPath,
				);
				if (redirectResult.blocked) {
					return {
						...redirectResult,
						reason: `Command reads protected path '${redirectResult.target}'.`,
						commandWords: parsedCommand.words,
						commandName: getCommandName(getCommandWords(parsedCommand)),
					};
				}

				const commandWords = getCommandWords(parsedCommand);
				const commandName = getCommandName(commandWords);
				if (!READ_COMMAND_SET.has(commandName)) {
					continue;
				}

				const sensitivePath = findSensitivePathInWords(
					parsedCommand.words.slice(1),
					checkReadPath,
					"read",
				);
				if (sensitivePath.blocked) {
					return {
						...sensitivePath,
						reason: `Command reads protected path '${sensitivePath.target}'.`,
						commandName,
						commandWords,
					};
				}
			}

			return createAllowedCommandResult();
		},

		checkWriteCommand(command: string): CommandCheckResult {
			if (!command || typeof command !== "string") {
				return createAllowedCommandResult();
			}

			for (const parsedCommand of parseShellCommand(command)) {
				const redirectResult = checkRedirects(
					parsedCommand.redirects,
					"write",
					checkWritePath,
				);
				if (redirectResult.blocked) {
					return {
						...redirectResult,
						reason: `Command writes protected path '${redirectResult.target}'.`,
						commandWords: parsedCommand.words,
						commandName: getCommandName(getCommandWords(parsedCommand)),
					};
				}

				const commandWords = getCommandWords(parsedCommand);
				const commandName = getCommandName(commandWords);
				const sensitivePath = findSensitivePathInWords(
					parsedCommand.words.slice(1),
					checkWritePath,
					"write",
				);
				if (WRITE_COMMAND_SET.has(commandName) && sensitivePath.blocked) {
					return {
						...sensitivePath,
						reason: `Command writes protected path '${sensitivePath.target}'.`,
						commandName,
						commandWords,
					};
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

		checkDeleteCommand(command: string): CommandCheckResult {
			if (!command || typeof command !== "string") {
				return createAllowedCommandResult();
			}

			for (const parsedCommand of parseShellCommand(command)) {
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

			return createAllowedCommandResult();
		},
	};
}
