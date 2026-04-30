import { matchesGlob } from "node:path";

import { SECRET_PATTERNS } from "./constants.js";
import type { PatternConfig, RedactionResult, ResolvedSensitiveGuardConfig } from "./types.js";

interface CompiledKeyPattern {
	source: PatternConfig;
	test: (key: string) => boolean;
}

const NEVER_MATCH_PATTERN = /$a/;
const PRIVATE_KEY_BLOCK_PATTERN =
	/-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----/gi;
const JSON_KEY_VALUE_PATTERN = /^(\s*)"([^"]+)"(\s*:\s*)(.*?)(\s*,?\s*)$/;
const ASSIGNMENT_PATTERN = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*[=:]\s*)(.*?)(\s*)$/;
const YAML_KEY_VALUE_PATTERN = /^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*:\s+)(.*?)(\s*)$/;
const EMBEDDED_ASSIGNMENT_PATTERN = /(["']?)(\b[A-Za-z_][A-Za-z0-9_.-]*\b)\1(\s*[=:]\s*)(["']?)([^"'\s,;{}]+)(["']?)/g;

function compileRegex(pattern: string, flags: string): RegExp {
	try {
		return new RegExp(pattern, flags);
	} catch {
		return NEVER_MATCH_PATTERN;
	}
}

function compileGlobalSecretPattern(pattern: RegExp): RegExp {
	const flags = new Set(pattern.flags.split(""));
	flags.add("g");
	return compileRegex(pattern.source, [...flags].join(""));
}

function compileKeyPattern(pattern: PatternConfig): CompiledKeyPattern {
	if (pattern.regex) {
		const compiled = compileRegex(pattern.pattern, "i");
		return {
			source: pattern,
			test: (key) => compiled.test(key),
		};
	}

	return {
		source: pattern,
		test: (key) => matchesGlob(key, pattern.pattern),
	};
}

function createOversizedRedactionNotice(byteLength: number, maxBytes: number): RedactionResult {
	return {
		content: `[pi-sensitive-guard redacted ${byteLength} bytes because readRedaction.maxBytes is ${maxBytes}. Increase the limit only for trusted workflows.]`,
		redacted: true,
		redactionCount: 1,
		reasons: ["content-size-limit"],
	};
}

function isSensitiveKey(key: string, patterns: CompiledKeyPattern[]): boolean {
	const normalized = key.trim();
	return normalized.length > 0 && patterns.some((pattern) => pattern.test(normalized));
}

function redactValuePreservingQuotes(rawValue: string, placeholder: string): string {
	const trimmed = rawValue.trim();
	if (!trimmed) {
		return rawValue;
	}

	const quote = trimmed[0];
	if ((quote === '"' || quote === "'") && trimmed.endsWith(quote)) {
		return `${quote}${placeholder}${quote}`;
	}

	return placeholder;
}

function isPlaceholderValue(rawValue: string, placeholder: string): boolean {
	const trimmed = rawValue.trim();
	if (trimmed === placeholder) {
		return true;
	}

	const quote = trimmed[0];
	return (
		(quote === '"' || quote === "'") &&
		trimmed.endsWith(quote) &&
		trimmed.slice(1, -1) === placeholder
	);
}

function shouldAttemptJsonRedaction(content: string): boolean {
	const trimmed = content.trimStart();
	return trimmed.startsWith("{") || trimmed.startsWith("[");
}

function redactJsonValue(
	value: unknown,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
	state: { redactionCount: number },
): unknown {
	if (Array.isArray(value)) {
		return value.map((entry) => redactJsonValue(entry, placeholder, keyPatterns, state));
	}

	if (!value || typeof value !== "object") {
		return value;
	}

	const redactedObject: Record<string, unknown> = {};
	for (const [key, entry] of Object.entries(value)) {
		if (isSensitiveKey(key, keyPatterns)) {
			redactedObject[key] = placeholder;
			state.redactionCount += 1;
			continue;
		}

		redactedObject[key] = redactJsonValue(entry, placeholder, keyPatterns, state);
	}

	return redactedObject;
}

function redactJsonStructuredContent(
	content: string,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): { content: string; redactionCount: number } | null {
	if (!shouldAttemptJsonRedaction(content)) {
		return null;
	}

	try {
		const parsed: unknown = JSON.parse(content);
		const state = { redactionCount: 0 };
		const redacted = redactJsonValue(parsed, placeholder, keyPatterns, state);
		if (state.redactionCount === 0) {
			return null;
		}

		const trailingNewline = content.endsWith("\n") ? "\n" : "";
		return {
			content: `${JSON.stringify(redacted, null, 2)}${trailingNewline}`,
			redactionCount: state.redactionCount,
		};
	} catch {
		return null;
	}
}

function redactStructuredLine(
	line: string,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): { line: string; redacted: boolean } {
	const jsonMatch = line.match(JSON_KEY_VALUE_PATTERN);
	if (jsonMatch) {
		const [, indentation, key, separator, value, suffix] = jsonMatch;
		if (
			key &&
			value !== undefined &&
			isSensitiveKey(key, keyPatterns) &&
			!isPlaceholderValue(value, placeholder)
		) {
			return {
				line: `${indentation}"${key}"${separator}${redactValuePreservingQuotes(value, placeholder)}${suffix}`,
				redacted: true,
			};
		}
	}

	const assignmentMatch = line.match(ASSIGNMENT_PATTERN);
	if (assignmentMatch) {
		const [, prefix, key, separator, value, suffix] = assignmentMatch;
		if (
			key &&
			value !== undefined &&
			isSensitiveKey(key, keyPatterns) &&
			!isPlaceholderValue(value, placeholder)
		) {
			return {
				line: `${prefix}${key}${separator}${redactValuePreservingQuotes(value, placeholder)}${suffix}`,
				redacted: true,
			};
		}
	}

	const yamlMatch = line.match(YAML_KEY_VALUE_PATTERN);
	if (yamlMatch) {
		const [, indentation, key, separator, value, suffix] = yamlMatch;
		if (
			key &&
			value !== undefined &&
			isSensitiveKey(key, keyPatterns) &&
			!isPlaceholderValue(value, placeholder)
		) {
			return {
				line: `${indentation}${key}${separator}${redactValuePreservingQuotes(value, placeholder)}${suffix}`,
				redacted: true,
			};
		}
	}

	return { line, redacted: false };
}

function redactStructuredValues(
	content: string,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): { content: string; redactionCount: number } {
	let redactionCount = 0;
	const lines = content.split(/(\r?\n)/);
	const redactedLines = lines.map((part) => {
		if (part === "\n" || part === "\r\n") {
			return part;
		}

		const redacted = redactStructuredLine(part, placeholder, keyPatterns);
		if (redacted.redacted) {
			redactionCount += 1;
		}
		return redacted.line;
	});

	return { content: redactedLines.join(""), redactionCount };
}

function redactEmbeddedAssignments(
	content: string,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): { content: string; redactionCount: number } {
	let redactionCount = 0;
	const redactedContent = content.replace(
		EMBEDDED_ASSIGNMENT_PATTERN,
		(
			match,
			keyQuote: string,
			key: string,
			separator: string,
			openingValueQuote: string,
			value: string,
			closingValueQuote: string,
		) => {
			if (!value || value === placeholder || !isSensitiveKey(key, keyPatterns)) {
				return match;
			}

			redactionCount += 1;
			return `${keyQuote}${key}${keyQuote}${separator}${openingValueQuote}${placeholder}${closingValueQuote}`;
		},
	);

	return { content: redactedContent, redactionCount };
}

function redactKnownSecretPatterns(
	content: string,
	placeholder: string,
): { content: string; redactionCount: number } {
	let redactionCount = 0;
	let redactedContent = content.replace(PRIVATE_KEY_BLOCK_PATTERN, (match) => {
		if (match.includes(placeholder)) {
			return match;
		}
		redactionCount += 1;
		return placeholder;
	});

	for (const definition of SECRET_PATTERNS) {
		const pattern = compileGlobalSecretPattern(definition.pattern);
		redactedContent = redactedContent.replace(pattern, (match, ...args: unknown[]) => {
			if (match.includes(placeholder)) {
				return match;
			}

			redactionCount += 1;
			if (definition.secretGroup !== undefined) {
				const capturedSecret = args[definition.secretGroup - 1];
				if (typeof capturedSecret === "string" && capturedSecret.length > 0) {
					return match.replace(capturedSecret, placeholder);
				}
			}

			return placeholder;
		});
	}

	return { content: redactedContent, redactionCount };
}

export function redactSensitiveReadContent(
	content: string,
	config: ResolvedSensitiveGuardConfig["readRedaction"],
): RedactionResult {
	const maxBytes = config.maxBytes;
	const byteLength = Buffer.byteLength(content, "utf-8");
	if (byteLength > maxBytes) {
		return createOversizedRedactionNotice(byteLength, maxBytes);
	}

	const keyPatterns = config.sensitiveKeyPatterns.map(compileKeyPattern);
	const jsonStructured = redactJsonStructuredContent(
		content,
		config.placeholder,
		keyPatterns,
	);
	const structured = redactStructuredValues(
		jsonStructured?.content ?? content,
		config.placeholder,
		keyPatterns,
	);
	const embedded = redactEmbeddedAssignments(
		structured.content,
		config.placeholder,
		keyPatterns,
	);
	const secretPatternResult = config.redactSecretPatterns
		? redactKnownSecretPatterns(embedded.content, config.placeholder)
		: { content: embedded.content, redactionCount: 0 };
	const sensitiveKeyRedactionCount =
		(jsonStructured?.redactionCount ?? 0) +
		structured.redactionCount +
		embedded.redactionCount;
	const redactionCount = sensitiveKeyRedactionCount + secretPatternResult.redactionCount;
	const reasons: string[] = [];
	if (sensitiveKeyRedactionCount > 0) {
		reasons.push("sensitive-key-values");
	}
	if (secretPatternResult.redactionCount > 0) {
		reasons.push("secret-patterns");
	}

	return {
		content: secretPatternResult.content,
		redacted: redactionCount > 0,
		redactionCount,
		reasons,
	};
}
