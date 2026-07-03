import { matchesGlob } from "node:path";

import { SECRET_PATTERNS } from "./constants.js";
import {
	compileRegex,
	isCodeReferenceValue,
	NON_SECRET_VALUES,
	stripValueSyntax,
} from "./shared/index.js";
import type { PatternConfig, RedactionResult, ResolvedSensitiveGuardConfig } from "./types.js";

interface CompiledKeyPattern {
	source: PatternConfig;
	test: (key: string) => boolean;
}

type RedactionCountResult = { content: string; redactionCount: number };

const PRIVATE_KEY_BLOCK_PATTERN =
	/-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY(?:\s+BLOCK)?-----/gi;
const JSON_KEY_VALUE_PATTERN = /^(\s*)"([^"]+)"(\s*:\s*)(.*?)(\s*,?\s*)$/;
const ASSIGNMENT_PATTERN = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*[=:]\s*)(.*?)(\s*)$/;
const YAML_KEY_VALUE_PATTERN = /^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*:\s+)(.*?)(\s*)$/;
const EMBEDDED_ASSIGNMENT_PATTERN = /(["']?)(\b[A-Za-z_][A-Za-z0-9_.-]*\b)\1(\s*[=:]\s*)(["']?)([^"'\s,;{}]+)(["']?)/g;
const ENCODED_SECRET_TOKEN_PATTERN = /[A-Za-z0-9][A-Za-z0-9+/_.-]{15,}={0,2}/g;
const PRINTABLE_TEXT_PATTERN = /^[\t\n\r -~]+$/;
const STANDALONE_AUTH_CREDENTIAL_KEYS = new Set(["key", "access", "refresh"]);

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

function isStandaloneAuthCredentialKey(key: string): boolean {
	return STANDALONE_AUTH_CREDENTIAL_KEYS.has(key.trim().toLowerCase());
}

function matchesKnownSecretValue(value: string): boolean {
	PRIVATE_KEY_BLOCK_PATTERN.lastIndex = 0;
	if (PRIVATE_KEY_BLOCK_PATTERN.test(value)) {
		PRIVATE_KEY_BLOCK_PATTERN.lastIndex = 0;
		return true;
	}

	for (const definition of SECRET_PATTERNS) {
		definition.pattern.lastIndex = 0;
		if (definition.pattern.test(value)) {
			definition.pattern.lastIndex = 0;
			return true;
		}
	}

	return false;
}

function isLikelySensitiveStandaloneValue(rawValue: string): boolean {
	const value = stripValueSyntax(rawValue);
	if (!value || NON_SECRET_VALUES.has(value.toLowerCase())) {
		return false;
	}

	if (isCodeReferenceValue(rawValue)) {
		return false;
	}

	if (matchesKnownSecretValue(value)) {
		return true;
	}

	if (value.length >= 20 && /[-_./+=]/.test(value) && /[A-Za-z0-9]/.test(value)) {
		return true;
	}

	return value.length >= 32 && /[A-Za-z]/.test(value) && /\d/.test(value);
}

function rot13(value: string): string {
	return value.replace(/[A-Za-z]/g, (char) => {
		const base = char <= "Z" ? 65 : 97;
		return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
	});
}

function isPrintableDecodedValue(value: string): boolean {
	return value.length > 0 && PRINTABLE_TEXT_PATTERN.test(value);
}

function tryDecodeBase64(value: string): string | undefined {
	if (value.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
		return undefined;
	}

	try {
		const decoded = Buffer.from(value, "base64").toString("utf-8");
		if (!isPrintableDecodedValue(decoded)) {
			return undefined;
		}

		const normalizedInput = value.replace(/=+$/g, "");
		const normalizedEncoded = Buffer.from(decoded, "utf-8")
			.toString("base64")
			.replace(/=+$/g, "");
		return normalizedInput === normalizedEncoded ? decoded : undefined;
	} catch {
		return undefined;
	}
}

function tryDecodeHex(value: string): string | undefined {
	if (value.length < 20 || value.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(value)) {
		return undefined;
	}

	try {
		const decoded = Buffer.from(value, "hex").toString("utf-8");
		return isPrintableDecodedValue(decoded) ? decoded : undefined;
	} catch {
		return undefined;
	}
}

function getDecodedSecretCandidates(value: string): string[] {
	const candidates = [tryDecodeBase64(value), tryDecodeHex(value), rot13(value), [...value].reverse().join("")];
	return candidates.filter(
		(candidate): candidate is string =>
			typeof candidate === "string" && candidate.length > 0 && candidate !== value,
	);
}

function isDecodedSecretValue(value: string): boolean {
	if (value.length === 0) {
		return false;
	}

	// Only treat decoded values as secrets when they match known secret patterns
	// (API keys, private keys, JWTs, etc.) or exhibit high Shannon entropy.
	// The broader isLikelySensitiveStandaloneValue heuristic is intentionally NOT
	// used here because it was designed for key-value assignment context (where the
	// key name provides sensitivity cues), not for arbitrary decoded tokens. Using
	// it here causes false positives on package names and identifiers like
	// "pi-glm-52-cloudflare-compat" whose ROT13 decode passes the standalone-value
	// heuristic (length >= 20 with hyphens) despite being a low-entropy identifier.
	if (matchesKnownSecretValue(value)) {
		return true;
	}

	return isHighEntropySecretCandidate(value);
}

/**
 * Matches kebab-case identifiers and package names (e.g. "pi-glm-52-cloudflare-compat")
 * that should be excluded from encoded-secret detection. Real decoded secrets do
 * not use hyphens as word separators between lowercase segments.
 */
const KEBAB_CASE_IDENTIFIER_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/;

/**
 * Minimum Shannon entropy (bits/char) for a decoded value to be treated as a secret
 * candidate. Real secrets (API keys, tokens, passwords) typically exceed 3.5 bits/char
 * due to mixed-case + digits + symbols.
 */
const MIN_SECRET_ENTROPY = 3.5;

/**
 * Matches UPPER_SNAKE_CASE constants (e.g. "PROVIDER_HISTORY_OMISSION_TEXT") that
 * should be excluded from encoded-secret detection. Real decoded secrets do not
 * use underscores as word separators between uppercase segments.
 */
const UPPER_SNAKE_CASE_PATTERN = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;

/**
 * Matches camelCase identifiers (e.g. "maxSearchResults", "skillsSh") that should
 * be excluded from encoded-secret detection. Real decoded secrets do not follow
 * camelCase naming conventions.
 */
const CAMEL_CASE_PATTERN = /^[a-z][a-zA-Z0-9]+$/;

function isHighEntropySecretCandidate(value: string): boolean {
	if (value.length < 16) {
		return false;
	}

	// Reject values that look like source-code identifiers: kebab-case package
	// names (e.g. "pi-glm-52-cloudflare-compat") or UPPER_SNAKE_CASE constants
	// (e.g. "PROVIDER_HISTORY_OMISSION_TEXT"). Real decoded secrets use mixed
	// character classes without word-separator structure.
	if (KEBAB_CASE_IDENTIFIER_PATTERN.test(value) || UPPER_SNAKE_CASE_PATTERN.test(value) || CAMEL_CASE_PATTERN.test(value)) {
		return false;
	}

	const charFrequency = new Map<string, number>();
	for (const char of value) {
		charFrequency.set(char, (charFrequency.get(char) ?? 0) + 1);
	}

	let entropy = 0;
	for (const count of charFrequency.values()) {
		const probability = count / value.length;
		entropy -= probability * Math.log2(probability);
	}

	return entropy >= MIN_SECRET_ENTROPY;
}

function shouldRedactSensitiveKeyValue(
	key: string,
	rawValue: string,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): boolean {
	if (!isSensitiveKey(key, keyPatterns) || isPlaceholderValue(rawValue, placeholder)) {
		return false;
	}

	if (isStandaloneAuthCredentialKey(key)) {
		return isLikelySensitiveStandaloneValue(rawValue);
	}

	return true;
}

function shouldRedactJsonSensitiveKeyValue(
	key: string,
	value: unknown,
	placeholder: string,
	keyPatterns: CompiledKeyPattern[],
): boolean {
	if (!isSensitiveKey(key, keyPatterns)) {
		return false;
	}

	if (typeof value === "string" && isPlaceholderValue(value, placeholder)) {
		return false;
	}

	if (isStandaloneAuthCredentialKey(key)) {
		return typeof value === "string" && isLikelySensitiveStandaloneValue(value);
	}

	return true;
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
		if (shouldRedactJsonSensitiveKeyValue(key, entry, placeholder, keyPatterns)) {
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
): RedactionCountResult | null {
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
			shouldRedactSensitiveKeyValue(key, value, placeholder, keyPatterns)
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
			shouldRedactSensitiveKeyValue(key, value, placeholder, keyPatterns)
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
			shouldRedactSensitiveKeyValue(key, value, placeholder, keyPatterns)
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
): RedactionCountResult {
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
): RedactionCountResult {
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
			if (
				!value ||
				!shouldRedactSensitiveKeyValue(key, value, placeholder, keyPatterns)
			) {
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
): RedactionCountResult {
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

function redactEncodedSecretValues(
	content: string,
	placeholder: string,
): RedactionCountResult {
	let redactionCount = 0;
	const redactedContent = content.replace(ENCODED_SECRET_TOKEN_PATTERN, (match, offset: number, fullContent: string) => {
		if (match.includes(placeholder)) {
			return match;
		}

		const nextCharacter = fullContent[offset + match.length] ?? "";
		if (match.endsWith("=") && /[A-Za-z0-9_]/.test(nextCharacter)) {
			return match;
		}

		if (!getDecodedSecretCandidates(match).some(isDecodedSecretValue)) {
			return match;
		}

		redactionCount += 1;
		return placeholder;
	});

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
	const encodedSecretResult = config.redactSecretPatterns
		? redactEncodedSecretValues(secretPatternResult.content, config.placeholder)
		: { content: secretPatternResult.content, redactionCount: 0 };
	const sensitiveKeyRedactionCount =
		(jsonStructured?.redactionCount ?? 0) +
		structured.redactionCount +
		embedded.redactionCount;
	const redactionCount =
		sensitiveKeyRedactionCount +
		secretPatternResult.redactionCount +
		encodedSecretResult.redactionCount;
	const reasons: string[] = [];
	if (sensitiveKeyRedactionCount > 0) {
		reasons.push("sensitive-key-values");
	}
	if (secretPatternResult.redactionCount > 0) {
		reasons.push("secret-patterns");
	}
	if (encodedSecretResult.redactionCount > 0) {
		reasons.push("encoded-secret-patterns");
	}

	return {
		content: encodedSecretResult.content,
		redacted: redactionCount > 0,
		redactionCount,
		reasons,
	};
}
