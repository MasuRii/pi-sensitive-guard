import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { redactSensitiveReadContent } from "../src/read-redactor.js";

// A secret value that does NOT itself match any existing secret pattern, key name, or
// length heuristic in the current redactor. Only encoded-form detection (base64/hex/
// rot13/reversed) of a known secret should trigger redaction for these assertions.
// Uses mixed case and digits to avoid kebab-case/UPPER_SNAKE_CASE identifier filters.
const SECRET_VALUE = "S3cr3tBlobX9k2mP7vQ";
const PLACEHOLDER = DEFAULT_CONFIG.readRedaction.placeholder;

function redactionConfig() {
	return {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
	};
}

test("redacts base64-encoded secret strings in output", () => {
	const encoded = Buffer.from(SECRET_VALUE, "utf-8").toString("base64");
	const content = `build_artifact=${encoded}`;

	const result = redactSensitiveReadContent(content, redactionConfig());

	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
	assert.doesNotMatch(result.content, new RegExp(encoded));
	assert.ok(result.content.includes(PLACEHOLDER));
});

test("redacts hex-encoded secret strings in output", () => {
	const encoded = Buffer.from(SECRET_VALUE, "utf-8").toString("hex");
	const content = `build_artifact=${encoded}`;

	const result = redactSensitiveReadContent(content, redactionConfig());

	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
	assert.doesNotMatch(result.content, new RegExp(encoded));
	assert.ok(result.content.includes(PLACEHOLDER));
});

test("redacts ROT13-obfuscated secret strings in output", () => {
	const obfuscated = SECRET_VALUE.replace(/[A-Za-z]/g, (char) => {
		const base = char <= "Z" ? 65 : 97;
		return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
	});
	const content = `build_artifact=${obfuscated}`;

	const result = redactSensitiveReadContent(content, redactionConfig());

	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
	assert.doesNotMatch(result.content, new RegExp(obfuscated));
	assert.ok(result.content.includes(PLACEHOLDER));
});

test("redacts reversed secret strings in output", () => {
	const reversed = [...SECRET_VALUE].reverse().join("");
	const content = `build_artifact=${reversed}`;

	const result = redactSensitiveReadContent(content, redactionConfig());

	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
	assert.doesNotMatch(result.content, new RegExp(reversed));
	assert.ok(result.content.includes(PLACEHOLDER));
});

test("preserves non-secret multi-encoding-shaped values without redaction", () => {
	const result = redactSensitiveReadContent("config_flags=true\nport=8080", redactionConfig());

	assert.equal(result.redacted, false);
	assert.equal(result.redactionCount, 0);
});
