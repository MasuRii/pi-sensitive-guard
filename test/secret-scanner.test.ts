import assert from "node:assert/strict";
import test from "node:test";

import { scanContentForSecrets, scanDiffForSecrets } from "../src/secret-scanner.js";

function createSyntheticToken(label: string): string {
	return ["synthetic", label, "A".repeat(32)].join("-");
}

test("detects JSON-style sensitive credential assignments without exposing values", () => {
	const sensitiveFields = [
		"key",
		"access",
		"refresh",
		"access_token",
		"refresh_token",
		"api_key",
	] as const;
	const content = sensitiveFields
		.map((field) => `"${field}": "${createSyntheticToken(field)}"`)
		.join("\n");

	const findings = scanContentForSecrets(content, 20);

	assert.equal(findings.length, sensitiveFields.length);
	for (const field of sensitiveFields) {
		const syntheticToken = createSyntheticToken(field);
		assert.ok(
			findings.some((finding) => finding.snippet.includes(field)),
			`expected finding snippet to include sanitized key ${field}`,
		);
		assert.ok(
			findings.some((finding) => finding.snippet.includes("[REDACTED")),
			"expected finding snippet to contain a redaction marker",
		);
		assert.ok(
			findings.every((finding) => !finding.snippet.includes(syntheticToken)),
			`expected synthetic value for ${field} to be redacted`,
		);
	}
});

test("detects added JSON-style sensitive credentials in diffs", () => {
	const syntheticAccessToken = createSyntheticToken("access-diff");
	const diff = [
		"diff --git a/src/auth.json b/src/auth.json",
		"+++ b/src/auth.json",
		`+  "access": "${syntheticAccessToken}"`,
	].join("\n");

	const findings = scanDiffForSecrets(diff, 5);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.file, "src/auth.json");
	assert.equal(findings[0]?.severity, "high");
	assert.match(findings[0]?.snippet ?? "", /access/);
	assert.match(findings[0]?.snippet ?? "", /\[REDACTED/);
	assert.doesNotMatch(findings[0]?.snippet ?? "", /synthetic-access-diff/);
});

test("ignores human-readable placeholder credential assignments in test fixtures", () => {
	const placeholderSecret = ["paid", "stale", "exhausted", "token"].join("-");
	const content = JSON.stringify({ secret: placeholderSecret });

	const findings = scanContentForSecrets(content, 5, {
		file: "agent/extensions/pi-multi-auth/tests/credential-entitlement.test.ts",
	});

	assert.deepEqual(findings, []);
});

test("keeps generic placeholder credential assignments blockable outside fixture paths", () => {
	const placeholderSecret = ["paid", "stale", "exhausted", "token"].join("-");
	const content = JSON.stringify({ secret: placeholderSecret });

	const findings = scanContentForSecrets(content, 5, {
		file: "src/runtime-config.ts",
	});

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "Sensitive Credential Assignment");
});

test("keeps known secret formats blockable even in test fixtures", () => {
	const openAiKey = `sk-${"A".repeat(24)}`;
	const content = JSON.stringify({ secret: openAiKey });

	const findings = scanContentForSecrets(content, 5, {
		file: "test/secret-scanner.test.ts",
	});

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "OpenAI API Key");
});

test("ignores human-readable placeholder credential assignments in fixture diffs", () => {
	const placeholderSecret = ["paid", "stale", "exhausted", "token"].join("-");
	const diff = [
		"diff --git a/test/example.test.ts b/test/example.test.ts",
		"+++ b/test/example.test.ts",
		`+${JSON.stringify({ secret: placeholderSecret })}`,
	].join("\n");

	const findings = scanDiffForSecrets(diff, 5);

	assert.deepEqual(findings, []);
});
