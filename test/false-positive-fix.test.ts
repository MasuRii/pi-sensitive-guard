import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { redactSensitiveReadContent } from "../src/read-redactor.js";

function fpConfig() {
	return {
		...DEFAULT_CONFIG.readRedaction,
		enabled: true,
	};
}

test("does not redact the pi-glm-52 omission marker string in source code", () => {
	const sourceCode = 'const PROVIDER_HISTORY_OMISSION_TEXT =\n\t"[pi-glm-52-cloudflare-compat: omitted malformed diagnostic/tool output from provider context]";\nconst SANITIZED_TOOL_ARGUMENTS = JSON.stringify({});';
	const result = redactSensitiveReadContent(sourceCode, fpConfig());
	assert.equal(result.redacted, false, `Expected no redaction but got ${result.redactionCount} redactions`);
});

test("does not redact the omission marker string alone", () => {
	const omissionMarker = "[pi-glm-52-cloudflare-compat: omitted malformed diagnostic/tool output from provider context]";
	const result = redactSensitiveReadContent(omissionMarker, fpConfig());
	assert.equal(result.redacted, false);
});

test("still redacts real base64-encoded secret strings", () => {
	const encoded = Buffer.from("S3cr3tBlobX9k2mP7vQ", "utf-8").toString("base64");
	const content = `build_artifact=${encoded}`;
	const result = redactSensitiveReadContent(content, fpConfig());
	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
});

test("still redacts real hex-encoded secret strings", () => {
	const encoded = Buffer.from("S3cr3tBlobX9k2mP7vQ", "utf-8").toString("hex");
	const content = `build_artifact=${encoded}`;
	const result = redactSensitiveReadContent(content, fpConfig());
	assert.equal(result.redacted, true);
	assert.ok(result.redactionCount >= 1);
});
