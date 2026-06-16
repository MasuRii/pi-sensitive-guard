import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { createSensitiveGuardMatcher } from "../src/detector.js";
import { scanContentForSecrets } from "../src/secret-scanner.js";
import type { ResolvedSensitiveGuardConfig } from "../src/types.js";

function createReadOnlyConfig(): ResolvedSensitiveGuardConfig {
	return {
		...DEFAULT_CONFIG,
		rules: [
			{
				id: "readonly-env",
				patterns: [{ pattern: "(^|[\\\\/])\\.env$", regex: true }],
				allowedPatterns: [],
				protection: "readOnly",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};
}

test("blocks absolute read command binaries targeting protected files", async () => {
	const matcher = createSensitiveGuardMatcher(DEFAULT_CONFIG);

	const result = await matcher.checkReadCommand("/bin/cat .env");

	assert.equal(result.blocked, true);
	assert.equal(result.commandName, "cat");
	assert.equal(result.kind, "read");
	assert.equal(result.target, ".env");
});

test("blocks copy commands that read from readOnly protected files", async () => {
	const matcher = createSensitiveGuardMatcher(createReadOnlyConfig());

	const readResult = await matcher.checkReadCommand("cp .env /tmp/env-copy");
	const writeResult = await matcher.checkWriteCommand("cp .env /tmp/env-copy");

	assert.equal(readResult.blocked, true);
	assert.equal(readResult.kind, "read");
	assert.equal(readResult.target, ".env");
	assert.equal(writeResult.blocked, false);
});

test("includes file context when scanning standalone file content for secrets", () => {
	const findings = scanContentForSecrets(
		`sk-${"A".repeat(24)}`,
		5,
		{ file: "src/runtime-config.ts" },
	);

	assert.equal(findings.length, 1);
	assert.equal(findings[0]?.name, "OpenAI API Key");
	assert.equal(findings[0]?.file, "src/runtime-config.ts");
});
