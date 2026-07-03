import assert from "node:assert/strict";
import test from "node:test";

import * as messagesModule from "../src/messages.js";

const buildAntiLoopBlockReason =
	(messagesModule as unknown as {
		buildAntiLoopBlockReason?: (attempt: number, target?: string) => string;
	}).buildAntiLoopBlockReason ??
	(() => "Security block: anti-loop protection not implemented.");

test("anti-loop block reason uses permission-system hard-stop language", () => {
	const reason = buildAntiLoopBlockReason(3, ".env");

	assert.match(reason, /Hard stop/i, "expected 'Hard stop' wording aligned with permission-system");
	assert.match(
		reason,
		/policy-enforced/i,
		"expected 'policy-enforced' wording aligned with permission-system",
	);
	assert.match(
		reason,
		/do not retry/i,
		"expected 'do not retry' wording aligned with permission-system",
	);
});

test("anti-loop block reason instructs the agent to report the block to the user", () => {
	const reason = buildAntiLoopBlockReason(5, "secrets.json");

	assert.match(
		reason,
		/report.*user/i,
		"expected instruction to report the block to the user",
	);
});

test("anti-loop block reason surfaces the protected target and attempt count", () => {
	const reason = buildAntiLoopBlockReason(4, ".env");

	assert.match(reason, /\.env/, "expected the protected target to appear in the reason");
	assert.match(reason, /4/, "expected the attempt count to appear in the reason");
});

test("anti-loop block reason mentions loop or repeated protection", () => {
	const reason = buildAntiLoopBlockReason(6, "auth.json");

	assert.match(
		reason,
		/loop|repeated|recurrence/i,
		"expected the reason to mention loop or repeated protection",
	);
});
