import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { createSensitiveGuardMatcher } from "../src/detector.js";
import type { ResolvedSensitiveGuardConfig } from "../src/types.js";

function writeExecuteConfig(): ResolvedSensitiveGuardConfig {
	return {
		...DEFAULT_CONFIG,
		enabled: true,
		rules: [
			{
				id: "scripts-dir",
				name: "Generated script protection",
				patterns: [
					{ pattern: "(^|[\\/])\.pi[\\/]agent[\\/]generated[\\/].+\.sh$", regex: true },
				],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};
}

test("tracks files written by the agent and blocks risky execution of a later-written script", async () => {
	const matcher = createSensitiveGuardMatcher(writeExecuteConfig());

	const writeResult = matcher.checkWritePath(".pi/agent/generated/run-task.sh");
	assert.equal(writeResult.blocked, false);

	const execResult = await matcher.checkReadCommand(
		"bash .pi/agent/generated/run-task.sh",
	);
	assert.equal(execResult.blocked, true);
	assert.match(execResult.reason ?? "", /written by the agent|agent-written|correlation/i);
});

test("blocks risky execution when a previously written script is run via sh", async () => {
	const matcher = createSensitiveGuardMatcher(writeExecuteConfig());

	await matcher.checkWriteCommand(
		"tee .pi/agent/generated/helper.sh > /dev/null",
	);

	const execResult = await matcher.checkReadCommand(
		"sh .pi/agent/generated/helper.sh",
	);
	assert.equal(execResult.blocked, true);
	assert.match(
		execResult.reason ?? "",
		/written by the agent|agent-written|correlation/i,
	);
});

test("does not block execution of scripts the agent never wrote", async () => {
	const matcher = createSensitiveGuardMatcher(writeExecuteConfig());

	const execResult = await matcher.checkReadCommand(
		"bash .pi/agent/generated/never-written.sh",
	);
	assert.equal(execResult.blocked, false);
});
