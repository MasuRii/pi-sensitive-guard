import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG, createSensitiveAssignmentPattern } from "../src/constants.js";
import { redactSensitiveReadContent } from "../src/read-redactor.js";
import { createSensitiveGuardMatcher } from "../src/detector.js";
import type { ResolvedSensitiveGuardConfig, PatternConfig } from "../src/types.js";

test("detector safely handles oversized user-supplied regex patterns without throwing", () => {
	// An attacker or misconfigured config could supply an oversized regex pattern.
	// The matcher must fail safe (not match) rather than throw or hang.
	const oversizedPattern: PatternConfig = {
		pattern: "a".repeat(600),
		regex: true,
	};
	const config: ResolvedSensitiveGuardConfig = {
		...DEFAULT_CONFIG,
		rules: [
			{
				id: "oversized-rule",
				patterns: [oversizedPattern],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};

	const matcher = createSensitiveGuardMatcher(config);
	// Normal read of a file must not be blocked by an oversized rule that can't match.
	assert.equal(matcher.checkReadPath("normal-file.txt").blocked, false);
	assert.equal(matcher.checkWritePath("normal-file.txt").blocked, false);
	assert.equal(matcher.checkDeletePath("normal-file.txt").blocked, false);
});

test("read-redactor safely handles oversized sensitive key patterns without throwing", () => {
	const oversizedKeyPattern: PatternConfig = {
		pattern: "a".repeat(600),
		regex: true,
	};
	const result = redactSensitiveReadContent("normal content", {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
		sensitiveKeyPatterns: [oversizedKeyPattern],
	});

	assert.equal(result.redacted, false);
	assert.equal(result.redactionCount, 0);
	assert.equal(result.content, "normal content");
});

test("detector still blocks protected paths when normal-sized regex patterns are supplied", () => {
	const config: ResolvedSensitiveGuardConfig = {
		...DEFAULT_CONFIG,
	};
	const matcher = createSensitiveGuardMatcher(config);
	// auth.json is protected by default config rules.
	assert.equal(matcher.checkReadPath("auth.json").blocked, true);
	assert.equal(matcher.checkReadPath("auth.json").kind, "read");
});

test("detector rejects oversized regex patterns by returning a never-match pattern instead of compiling", () => {
	// An attacker could supply a 600-char pattern that, while it does not throw, could cause
	// catastrophic backtracking (ReDoS). The hardened compileRegex must length-bound the input
	// and substitute a never-match pattern so no backtracking can occur on the oversized input.
	const oversizedPattern: PatternConfig = {
		pattern: "a".repeat(600),
		regex: true,
	};
	const config: ResolvedSensitiveGuardConfig = {
		...DEFAULT_CONFIG,
		rules: [
			{
				id: "oversized-rule",
				patterns: [oversizedPattern],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};
	const matcher = createSensitiveGuardMatcher(config);
	// The oversized pattern must not be compiled into a backtracking-prone regex; it must be
	// replaced with a never-match pattern so the rule does not block a path it cannot match.
	assert.equal(matcher.checkReadPath("normal-file.txt").blocked, false);
	assert.equal(matcher.checkWritePath("normal-file.txt").blocked, false);
	assert.equal(matcher.checkDeletePath("normal-file.txt").blocked, false);
	// An oversized pattern that would match if compiled must also be a no-op, proving the
	// length bound short-circuits before RegExp construction.
	const oversizedMatching: PatternConfig = {
		pattern: ".*".repeat(600),
		regex: true,
	};
	const matchingConfig: ResolvedSensitiveGuardConfig = {
		...DEFAULT_CONFIG,
		rules: [
			{
				id: "oversized-matching-rule",
				patterns: [oversizedMatching],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};
	const matchingMatcher = createSensitiveGuardMatcher(matchingConfig);
	assert.equal(matchingMatcher.checkReadPath("any-file.txt").blocked, false);
});

test("read-redactor rejects oversized sensitive key patterns by never matching", () => {
	// The read-redactor's compileRegex must length-bound the key pattern so an oversized input
	// is replaced with a never-match pattern instead of being compiled into a ReDoS-prone regex.
	const oversizedKeyPattern: PatternConfig = {
		pattern: "a".repeat(600),
		regex: true,
	};
	const result = redactSensitiveReadContent("normal content", {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
		sensitiveKeyPatterns: [oversizedKeyPattern],
	});
	assert.equal(result.redacted, false);
	assert.equal(result.redactionCount, 0);
	assert.equal(result.content, "normal content");
	// Even an oversized pattern that would match if compiled must not trigger redaction.
	const oversizedMatching: PatternConfig = {
		pattern: ".*".repeat(600),
		regex: true,
	};
	const matchingResult = redactSensitiveReadContent("api_key=benignvalue123", {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
		sensitiveKeyPatterns: [oversizedMatching],
	});
	assert.equal(matchingResult.redacted, false);
	assert.equal(matchingResult.content, "api_key=benignvalue123");
});

test("createSensitiveAssignmentPattern rejects oversized keyNamePattern by returning a never-match regex", () => {
	// The sensitive-assignment pattern builder must length-bound the assembled pattern so an
	// oversized keyNamePattern is replaced with a never-match regex instead of being compiled.
	const oversizedKeyName = "a".repeat(1100);
	const pattern = createSensitiveAssignmentPattern(oversizedKeyName);
	// The returned regex must not match a sensitive assignment that the oversized pattern
	// would otherwise match if it were compiled.
	assert.equal(pattern.test("a=benignvalue1234567890123"), false);
	assert.equal(pattern.test("apikey=benignvalue1234567890123"), false);
	// A normal-sized keyNamePattern must still compile and match as expected.
	const normalPattern = createSensitiveAssignmentPattern("api[_-]?key");
	assert.equal(normalPattern.test("apikey=benignvalue1234567890123"), true);
});
