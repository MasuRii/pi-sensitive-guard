import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { normalizeSensitiveGuardConfig } from "../src/config.js";
import { redactSensitiveReadContent } from "../src/read-redactor.js";

test("redacts configured sensitive key/value content", () => {
	const result = redactSensitiveReadContent(
		[
			"MY_TOKEN=abc123",
			"password=abc123",
			'"access_token": "abc123"',
		].join("\n"),
		{
			...DEFAULT_CONFIG.readRedaction,
			enabled: true,
		},
	);

	assert.equal(result.redacted, true);
	assert.equal(result.redactionCount, 3);
	assert.ok(result.content.includes(["MY_TOKEN", "=[REDACTED]"].join("")));
	assert.ok(result.content.includes(["password", "=[REDACTED]"].join("")));
	assert.ok(result.content.includes(["\"access_token\"", ": \"[REDACTED]\""].join("")));
	assert.doesNotMatch(result.content, /abc123/);
});

test("redacts standalone auth credential fields and inline JSON assignments", () => {
	const syntheticLongToken = ["synthetic", "token", "A".repeat(32)].join("-");
	const syntheticJwt = [
		"eyJsyntheticHeader000",
		"eyJsyntheticPayload000",
		"syntheticSignature000000",
	].join(".");
	const result = redactSensitiveReadContent(
		[
			`"key": "${syntheticLongToken}",`,
			`"access": "${syntheticJwt}",`,
			`"refresh": "${syntheticLongToken}"`,
			`inline={"key":"${syntheticLongToken}","access":"${syntheticJwt}","refresh":"${syntheticLongToken}"}`,
		].join("\n"),
		{
			...DEFAULT_CONFIG.readRedaction,
			enabled: true,
		},
	);

	assert.equal(result.redacted, true);
	assert.equal(result.redactionCount, 6);
	assert.ok(result.content.includes(["\"key\"", ": \"[REDACTED]\""].join("")));
	assert.ok(result.content.includes(["\"access\"", ": \"[REDACTED]\""].join("")));
	assert.ok(result.content.includes(["\"refresh\"", ": \"[REDACTED]\""].join("")));
	assert.match(result.content, /"key":"\[REDACTED\]"/);
	assert.match(result.content, /"access":"\[REDACTED\]"/);
	assert.match(result.content, /"refresh":"\[REDACTED\]"/);
	assert.doesNotMatch(result.content, /synthetic-token/);
	assert.doesNotMatch(result.content, /eyJsynthetic/);
});

test("redacts embedded assignments and known secret patterns", () => {
	const databaseUrl = ["postgres", "://", "user", ":", "example-password", "@localhost/app"].join("");
	const apiKey = ["sk", "-", "redaction", "placeholder", "1234567890123"].join("");
	const privateKeyLabel = ["PRIVATE", "KEY"].join(" ");
	const privateKey = [
		["-----BEGIN ", privateKeyLabel, "-----"].join(""),
		"not-a-real-key-body",
		["-----END ", privateKeyLabel, "-----"].join(""),
	].join("\n");
	const result = redactSensitiveReadContent(
		[
			"echo 'password=abc123' > .env",
			`DATABASE_URL=${databaseUrl}`,
			apiKey,
			privateKey,
		].join("\n"),
		{
			...DEFAULT_CONFIG.readRedaction,
			enabled: true,
		},
	);

	assert.equal(result.redacted, true);
	assert.ok(result.content.includes(["password", "=[REDACTED]"].join("")));
	assert.doesNotMatch(result.content, /abc123/);
	assert.doesNotMatch(result.content, /example-password/);
	assert.doesNotMatch(result.content, /redactionplaceholder/);
	assert.doesNotMatch(result.content, /not-a-real-key-body/);
});

test("withholds oversized protected read content before returning values", () => {
	const result = redactSensitiveReadContent("MY_TOKEN=abc123", {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
		maxBytes: 4,
	});

	assert.equal(result.redacted, true);
	assert.equal(result.redactionCount, 1);
	assert.match(result.content, /readRedaction\.maxBytes/);
	assert.doesNotMatch(result.content, /abc123/);
});

test("normalizes simple user config while preserving protection defaults", () => {
	const { config, warnings } = normalizeSensitiveGuardConfig({
		enabled: false,
		debug: true,
		readRedaction: {
			enabled: true,
			includeShellOutput: true,
		},
	});

	assert.equal(config.enabled, false);
	assert.equal(config.debug, true);
	assert.equal(config.readRedaction.enabled, true);
	assert.equal(config.readRedaction.includeShellOutput, true);
	assert.deepEqual(config.rules, DEFAULT_CONFIG.rules);
	assert.deepEqual(config.gitProtection, DEFAULT_CONFIG.gitProtection);
	assert.deepEqual(config.contentScanning, DEFAULT_CONFIG.contentScanning);
	assert.deepEqual(config.blockedEvents, DEFAULT_CONFIG.blockedEvents);
	assert.deepEqual(warnings, []);
});

test("normalizes read redaction config with safe defaults and warnings", () => {
	const { config, warnings } = normalizeSensitiveGuardConfig({
		readRedaction: {
			enabled: true,
			includeShellOutput: "yes",
			maxBytes: 0,
			sensitiveKeyPatterns: ["*_TOKEN"],
		},
	});

	assert.equal(config.readRedaction.enabled, true);
	assert.equal(config.readRedaction.includeShellOutput, DEFAULT_CONFIG.readRedaction.includeShellOutput);
	assert.equal(config.readRedaction.maxBytes, DEFAULT_CONFIG.readRedaction.maxBytes);
	assert.deepEqual(config.readRedaction.sensitiveKeyPatterns, [{ pattern: "*_TOKEN" }]);
	assert.ok(warnings.some((warning) => warning.includes("readRedaction.includeShellOutput")));
	assert.ok(warnings.some((warning) => warning.includes("readRedaction.maxBytes")));
});

test("redacts sensitive JSON container fields before nested credentials leak", () => {
	const nestedCredential = ["sk", "live", "synthetic", "credential", "000000000000"].join("_");
	const content = JSON.stringify(
		{
			debug: false,
			providers: {
				skillsSh: true,
				skillsMp: true,
			},
			maxSearchResults: 20,
			apiKeys: {
				github: "placeholder-token",
				skillsMp: nestedCredential,
			},
		},
		null,
		2,
	);

	const result = redactSensitiveReadContent(content, {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
	});

	assert.equal(result.redacted, true);
	assert.equal(result.redactionCount, 1);
	assert.doesNotThrow(() => JSON.parse(result.content));
	assert.match(result.content, /"apiKeys": "\[REDACTED\]"/);
	assert.doesNotMatch(result.content, /skillsMp.*synthetic/s);
	assert.doesNotMatch(result.content, /placeholder-token/);
});
