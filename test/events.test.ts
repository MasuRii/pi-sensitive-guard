import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { emitBlocked } from "../src/events.js";
import type { ResolvedSensitiveGuardConfig, SensitiveGuardBlockedEvent } from "../src/types.js";

test("redacts sensitive command metadata before blocked events are emitted or logged", () => {
	const tempDir = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-events-"));
	const logPath = join(tempDir, "blocked-events.jsonl");
	const emittedEvents: unknown[] = [];
	const pi = {
		events: {
			emit: (_channel: string, event: unknown) => {
				emittedEvents.push(event);
			},
		},
	} as ExtensionAPI;
	const config: ResolvedSensitiveGuardConfig = {
		...DEFAULT_CONFIG,
		blockedEvents: {
			emit: true,
			log: true,
			logPath,
		},
	};
	const secretAssignment = ["password", "=", "abc123"].join("");
	const event: SensitiveGuardBlockedEvent = {
		feature: "shellCommand",
		action: "write",
		reason: "Command writes protected path '.env'.",
		timestamp: new Date(0).toISOString(),
		toolName: "bash",
		target: ".env",
		metadata: {
			command: ["echo '", secretAssignment, "' > .env"].join(""),
			commandWords: ["echo", secretAssignment, ".env"],
		},
	};

	try {
		const error = emitBlocked(pi, config, event);
		assert.equal(error, undefined);
		assert.equal(emittedEvents.length, 1);

		const emitted = JSON.stringify(emittedEvents[0]);
		const logContent = readFileSync(logPath, "utf-8");
		assert.doesNotMatch(emitted, /abc123/);
		assert.doesNotMatch(logContent, /abc123/);
		assert.match(emitted, /\[REDACTED\]/);
		assert.match(logContent, /\[REDACTED\]/);
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
});
