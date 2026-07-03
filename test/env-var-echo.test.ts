import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { createSensitiveGuardMatcher } from "../src/detector.js";
import type { ResolvedSensitiveGuardConfig } from "../src/types.js";

function echoConfig(): ResolvedSensitiveGuardConfig {
	return DEFAULT_CONFIG;
}

test("blocks shell echo of a known secret environment variable", async () => {
	const matcher = createSensitiveGuardMatcher(echoConfig());

	const result = await matcher.checkReadCommand("echo $TOKEN");

	assert.equal(result.blocked, true);
	assert.match(result.reason ?? "", /secret|env|token/i);
});

test("blocks printf that dereferences a secret environment variable", async () => {
	const matcher = createSensitiveGuardMatcher(echoConfig());

	const result = await matcher.checkReadCommand('printf "%s" "$API_KEY"');

	assert.equal(result.blocked, true);
	assert.match(result.reason ?? "", /secret|env|api[_-]?key/i);
});

test("blocks heredoc that echoes a secret environment variable into a file", async () => {
	const matcher = createSensitiveGuardMatcher(echoConfig());

	const result = await matcher.checkReadCommand("cat <<EOF > .env\nTOKEN=$TOKEN\nEOF");

	assert.equal(result.blocked, true);
	assert.match(result.reason ?? "", /secret|env|token|heredoc/i);
});

test("blocks a script invocation that echoes a secret environment variable", async () => {
	const matcher = createSensitiveGuardMatcher(echoConfig());

	const result = await matcher.checkReadCommand("sh -c 'echo $MY_API_TOKEN'");

	assert.equal(result.blocked, true);
	assert.match(result.reason ?? "", /secret|env|api[_-]?token|token/i);
});

test("does not block echo of non-secret environment variables", async () => {
	const matcher = createSensitiveGuardMatcher(echoConfig());

	const result = await matcher.checkReadCommand("echo $PATH");

	assert.equal(result.blocked, false);
});
