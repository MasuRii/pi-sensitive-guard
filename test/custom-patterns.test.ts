import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { compileCustomPattern, compileCustomPatterns } from "../src/custom-patterns.js";
import { redactSensitiveReadContent } from "../src/read-redactor.js";
import { scanContentForSecrets, scanDiffForSecrets } from "../src/secret-scanner.js";
import type { SecretPatternDefinition } from "../src/types.js";

const placeholder = DEFAULT_CONFIG.readRedaction.placeholder;

function makeCustomPattern(name: string, pattern: string, severity: "critical" | "high" | "medium" = "high"): SecretPatternDefinition {
	const warnings: string[] = [];
	const compiled = compileCustomPattern({ name, pattern, severity }, warnings, "test");
	assert.ok(compiled, `Failed to compile pattern: ${warnings.join("; ")}`);
	return compiled;
}

test("custom pattern detected in content scanning", () => {
	const customPatterns = [makeCustomPattern("My Internal API Key", "myapi_[A-Za-z0-9]{32}")];
	const content = "const key = myapi_AbCdEf1234567890AbCdEf1234567890;";

	const findings = scanContentForSecrets(content, 10, {}, customPatterns);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "My Internal API Key");
	assert.equal(findings[0]?.severity, "high");
	assert.match(findings[0]?.snippet ?? "", /My Internal API Key/);
});

test("custom pattern detected in diff scanning", () => {
	const customPatterns = [makeCustomPattern("Custom Token", "ctkn_[A-Za-z0-9]{20}")];
	const diff = [
		"diff --git a/config.ts b/config.ts",
		"+++ b/config.ts",
		"+const token = ctkn_1234567890abcdefghij;",
	].join("\n");

	const findings = scanDiffForSecrets(diff, 10, customPatterns);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "Custom Token");
	assert.equal(findings[0]?.file, "config.ts");
});

test("built-in and custom patterns merge correctly", () => {
	const customPatterns = [makeCustomPattern("Custom Token", "ctkn_[A-Za-z0-9]{20}")];
	const content = [
		'api_key = "sk-redacted-merge-builtin-test-value1234"',
		"custom_token = ctkn_1234567890abcdefghij",
	].join("\n");

	const findings = scanContentForSecrets(content, 10, {}, customPatterns);

	// Should find both the built-in pattern and the custom one
	assert.ok(findings.length >= 2);
	assert.ok(findings.some((f) => f.name !== "Custom Token"));
	assert.ok(findings.some((f) => f.name === "Custom Token"));
});

test("custom pattern redacted in read content (structured value)", () => {
	const customPatterns = [makeCustomPattern("My Internal API Key", "myapi_[A-Za-z0-9]{32}")];
	const content = "const my_key = myapi_AbCdEf1234567890AbCdEf1234567890;";

	const result = redactSensitiveReadContent(
		content,
		{ ...DEFAULT_CONFIG.readRedaction, enabled: true, redactSecretPatterns: true },
		customPatterns,
	);

	assert.equal(result.redacted, true);
	assert.doesNotMatch(result.content, /myapi_AbCdEf1234567890AbCdEf1234567890/);
	assert.ok(result.content.includes(placeholder));
});

test("custom pattern redacted in read content (JSON)", () => {
	const customPatterns = [makeCustomPattern("Custom Token", "ctkn_[A-Za-z0-9]{20}")];
	const content = JSON.stringify({
		name: "app",
		key: "ctkn_1234567890abcdefghij",
	});

	const result = redactSensitiveReadContent(
		content,
		{ ...DEFAULT_CONFIG.readRedaction, enabled: true },
		customPatterns,
	);

	assert.equal(result.redacted, true);
	assert.doesNotMatch(result.content, /ctkn_1234567890abcdefghij/);
});

test("invalid regex is skipped with a warning", () => {
	const warnings: string[] = [];
	const result = compileCustomPattern(
		{ name: "Bad Regex", pattern: "[invalid", severity: "high" },
		warnings,
		"contentScanning.customPatterns",
	);

	assert.equal(result, null);
	assert.equal(warnings.length, 1);
	assert.match(warnings[0]!, /invalid regular expression/i);
});

test("invalid severity is rejected", () => {
	const warnings: string[] = [];
	const result = compileCustomPattern(
		{ name: "Bad Severity", pattern: "test_[0-9]+", severity: "urgent" as "high" },
		warnings,
		"contentScanning.customPatterns",
	);

	assert.equal(result, null);
	assert.equal(warnings.length, 1);
	assert.match(warnings[0]!, /severity/i);
});

test("custom pattern with secretGroup captures the correct group", () => {
	const warnings: string[] = [];
	const compiled = compileCustomPattern(
		{ name: "Bearer Token", pattern: "Bearer\\s+([A-Za-z0-9_.]{20,})", severity: "high", secretGroup: 1 },
		warnings,
		"test",
	);
	assert.ok(compiled);
	assert.equal(compiled.secretGroup, 1);

	const content = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234";
	const findings = scanContentForSecrets(content, 10, {}, [compiled!]);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "Bearer Token");
});

test("custom pattern with secretGroup redacts only the captured group in read content", () => {
	const warnings: string[] = [];
	const compiled = compileCustomPattern(
		{ name: "Bearer Token", pattern: "Bearer\\s+([A-Za-z0-9_.]{20,})", severity: "high", secretGroup: 1 },
		warnings,
		"test",
	);
	assert.ok(compiled);

	const content = "Authorization: Bearer sk-secret1234567890abcdef";
	const result = redactSensitiveReadContent(
		content,
		{ ...DEFAULT_CONFIG.readRedaction, enabled: true, redactSecretPatterns: true },
		[compiled!],
	);

	assert.equal(result.redacted, true);
	assert.ok(result.content.includes("Bearer"), "Prefix 'Bearer' should be preserved");
	assert.doesNotMatch(result.content, /sk-secret1234567890abcdef/, "Token should be redacted");
	assert.ok(result.content.includes(placeholder), "Should contain the redaction placeholder");
});

test("backward compatibility: no custom patterns gives same behavior", () => {
	const content = 'api_key = "sk-test backward-compat-padding1234"';

	const findingsWithoutCustom = scanContentForSecrets(content, 10);
	const findingsWithEmptyCustom = scanContentForSecrets(content, 10, {}, []);

	assert.deepEqual(findingsWithoutCustom, findingsWithEmptyCustom);
});

test("multiple custom patterns all work together", () => {
	const customPatterns = [
		makeCustomPattern("Pattern A", "pata_[A-Za-z0-9]{16}"),
		makeCustomPattern("Pattern B", "patb_[A-Za-z0-9]{16}"),
		makeCustomPattern("Pattern C", "patc_[A-Za-z0-9]{16}", "critical"),
	];
	const content = [
		"pata_AbCdEf1234567890",
		"patb_FeDcBa0987654321",
		"patc_ZzZzZzZzZzZzZzZz",
	].join("\n");

	const findings = scanContentForSecrets(content, 10, {}, customPatterns);

	assert.equal(findings.length, 3);
	const names = findings.map((f) => f.name).sort();
	assert.deepEqual(names, ["Pattern A", "Pattern B", "Pattern C"]);
});

test("compileCustomPatterns skips invalid entries and keeps valid ones", () => {
	const warnings: string[] = [];
	const configs = [
		{ name: "Good Pattern", pattern: "good_[0-9]+", severity: "high" as const },
		{ name: "Bad Pattern", pattern: "[invalid", severity: "high" as const },
		{ name: "Also Good", pattern: "also_[a-z]+", severity: "medium" as const },
	];

	const results = compileCustomPatterns(configs, warnings, "contentScanning.customPatterns");

	assert.equal(results.length, 2);
	assert.equal(results[0]?.name, "Good Pattern");
	assert.equal(results[1]?.name, "Also Good");
	assert.equal(warnings.length, 1);
});

test("custom pattern severity is respected for blocking", () => {
	const customPatterns = [makeCustomPattern("Low Severity Pattern", "lowsec_[A-Za-z0-9]{20}", "medium")];
	const content = "lowsec_abcdefghijklmnop1234";

	const findings = scanContentForSecrets(content, 10, {}, customPatterns);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.severity, "medium");
});

test("empty custom patterns array compiles to empty array", () => {
	const warnings: string[] = [];
	const results = compileCustomPatterns([], warnings, "test");

	assert.deepEqual(results, []);
	assert.deepEqual(warnings, []);
});

test("non-array custom patterns compiles to empty array", () => {
	const warnings: string[] = [];
	const results = compileCustomPatterns("not an array", warnings, "test");

	assert.deepEqual(results, []);
	assert.deepEqual(warnings, []);
});
