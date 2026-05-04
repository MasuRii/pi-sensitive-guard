import { redactSensitiveReadContent } from "./read-redactor.js";
import type { ResolvedSensitiveGuardConfig } from "./types.js";

interface EditReplacement {
	oldText: string;
	newText: string;
}

interface ParsedKeyValueLine {
	key: string;
	value: string;
}

export interface ProtectedFileEditEvaluation {
	allowed: boolean;
	reason: string;
}

const JSON_KEY_VALUE_PATTERN = /^\s*"([^"]+)"\s*:\s*(.*?)\s*,?\s*$/;
const KEY_VALUE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$/;

function createAllowedEvaluation(): ProtectedFileEditEvaluation {
	return { allowed: true, reason: "Only non-sensitive values changed." };
}

function createBlockedEvaluation(reason: string): ProtectedFileEditEvaluation {
	return { allowed: false, reason };
}

function splitLines(content: string): string[] {
	return content.split(/\r?\n/);
}

function parseKeyValueLine(line: string): ParsedKeyValueLine | null {
	const jsonMatch = line.match(JSON_KEY_VALUE_PATTERN);
	if (jsonMatch?.[1] !== undefined) {
		return {
			key: jsonMatch[1],
			value: jsonMatch[2] ?? "",
		};
	}

	const keyValueMatch = line.match(KEY_VALUE_PATTERN);
	if (keyValueMatch?.[1] !== undefined) {
		return {
			key: keyValueMatch[1],
			value: keyValueMatch[2] ?? "",
		};
	}

	return null;
}

function containsSensitiveKeyOrValue(
	content: string,
	config: ResolvedSensitiveGuardConfig,
): boolean {
	if (!content.trim()) {
		return false;
	}

	return redactSensitiveReadContent(content, {
		...config.readRedaction,
		enabled: true,
		redactSecretPatterns: true,
	}).redacted;
}

function isSafeStandaloneLineChange(
	line: string,
	config: ResolvedSensitiveGuardConfig,
): boolean {
	if (!line.trim()) {
		return true;
	}

	if (parseKeyValueLine(line)) {
		return false;
	}

	return !containsSensitiveKeyOrValue(line, config);
}

function evaluateChangedLinePair(
	oldLine: string,
	newLine: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (oldLine === newLine) {
		return createAllowedEvaluation();
	}

	const oldParsed = parseKeyValueLine(oldLine);
	const newParsed = parseKeyValueLine(newLine);
	if (oldParsed && newParsed) {
		if (oldParsed.key !== newParsed.key) {
			return createBlockedEvaluation(
				`Protected file edit changes key '${oldParsed.key}' to '${newParsed.key}'.`,
			);
		}

		if (
			containsSensitiveKeyOrValue(oldLine, config) ||
			containsSensitiveKeyOrValue(newLine, config)
		) {
			return createBlockedEvaluation(
				`Protected file edit changes sensitive key or value '${oldParsed.key}'.`,
			);
		}

		return createAllowedEvaluation();
	}

	if (oldParsed || newParsed) {
		return createBlockedEvaluation(
			"Protected file edit changes key/value structure instead of only changing a non-sensitive value.",
		);
	}

	if (
		containsSensitiveKeyOrValue(oldLine, config) ||
		containsSensitiveKeyOrValue(newLine, config)
	) {
		return createBlockedEvaluation(
			"Protected file edit changes content that contains a sensitive value.",
		);
	}

	return createAllowedEvaluation();
}

function evaluateChangedContent(
	oldContent: string,
	newContent: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	const oldLines = splitLines(oldContent);
	const newLines = splitLines(newContent);
	let oldIndex = 0;
	let newIndex = 0;

	while (oldIndex < oldLines.length || newIndex < newLines.length) {
		const oldLine = oldLines[oldIndex];
		const newLine = newLines[newIndex];
		if (oldLine !== undefined && newLine !== undefined && oldLine === newLine) {
			oldIndex += 1;
			newIndex += 1;
			continue;
		}

		if (newLine !== undefined && isSafeStandaloneLineChange(newLine, config)) {
			newIndex += 1;
			continue;
		}

		if (oldLine !== undefined && isSafeStandaloneLineChange(oldLine, config)) {
			oldIndex += 1;
			continue;
		}

		if (oldLine !== undefined && newLine !== undefined) {
			const result = evaluateChangedLinePair(oldLine, newLine, config);
			if (!result.allowed) {
				return result;
			}

			oldIndex += 1;
			newIndex += 1;
			continue;
		}

		return createBlockedEvaluation(
			"Protected file edit changes keys or sensitive values instead of only safe content.",
		);
	}

	return createAllowedEvaluation();
}

export function evaluateProtectedFileEdits(
	edits: ReadonlyArray<EditReplacement>,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (!config.protectedFileEdits.enabled) {
		return createBlockedEvaluation("Protected file non-sensitive edit bypass is disabled.");
	}

	for (const edit of edits) {
		const result = evaluateChangedContent(edit.oldText, edit.newText, config);
		if (!result.allowed) {
			return result;
		}
	}

	return createAllowedEvaluation();
}

export function evaluateProtectedFileWrite(
	currentContent: string,
	nextContent: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (!config.protectedFileEdits.enabled) {
		return createBlockedEvaluation("Protected file non-sensitive write bypass is disabled.");
	}

	return evaluateChangedContent(currentContent, nextContent, config);
}
