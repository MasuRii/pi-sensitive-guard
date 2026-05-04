import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import test from "node:test";

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";

import { DEFAULT_CONFIG, PRIMARY_CONFIG_PATH } from "../src/constants.js";
import { normalizeSensitiveGuardConfig } from "../src/config.js";
import sensitiveGuardExtension from "../src/index.js";
import {
	evaluateProtectedFileEdits,
	evaluateProtectedFileWrite,
} from "../src/protected-file-edits.js";
import type { ResolvedSensitiveGuardConfig } from "../src/types.js";

function createConfig(): ResolvedSensitiveGuardConfig {
	return {
		...DEFAULT_CONFIG,
		protectedFileEdits: {
			enabled: true,
		},
		readRedaction: {
			...DEFAULT_CONFIG.readRedaction,
			enabled: true,
		},
	};
}

async function runEditToolCall(edits: ReadonlyArray<{ oldText: string; newText: string }>): Promise<unknown> {
	writeFileSync(
		PRIMARY_CONFIG_PATH,
		`${JSON.stringify(
			{
				enabled: true,
				protectedPatterns: ["(^|[\\\\/])secrets\\.env$"],
				protectedFileEdits: {
					enabled: true,
				},
			},
			null,
			2,
		)}\n`,
		"utf-8",
	);

	const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<unknown> | unknown>();
	const pi = {
		on: (name: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<unknown> | unknown) => {
			handlers.set(name, handler);
		},
		events: { emit: () => undefined },
		exec: async () => ({ stdout: "", stderr: "", exitCode: 0 }),
	} as unknown as ExtensionAPI;
	const ctx = {
		cwd: process.cwd(),
		hasUI: false,
		ui: { notify: () => undefined },
	} as unknown as ExtensionContext;

	sensitiveGuardExtension(pi);
	await handlers.get("session_start")?.({ type: "session_start" }, ctx);
	return handlers.get("tool_call")?.(
		{
			type: "tool_call",
			toolCallId: "protected-edit-tool-call",
			toolName: "edit",
			input: {
				path: "secrets.env",
				edits,
			},
		},
		ctx,
	);
}

test("allows protected file edits that only change non-sensitive values", () => {
	const result = evaluateProtectedFileEdits(
		[
			{
				oldText: "MAX_CONCURRENT_REQUESTS=1",
				newText: "MAX_CONCURRENT_REQUESTS=2",
			},
		],
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("blocks protected file edits that change sensitive keys or values", () => {
	const result = evaluateProtectedFileEdits(
		[
			{
				oldText: "AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
				newText: "AISTUDIO_API_KEY_1=new-secret-value-12345678901234567890",
			},
		],
		createConfig(),
	);

	assert.equal(result.allowed, false);
	assert.match(result.reason, /sensitive/i);
});

test("blocks protected file edits that rename keys", () => {
	const result = evaluateProtectedFileEdits(
		[
			{
				oldText: "MAX_CONCURRENT_REQUESTS=1",
				newText: "TIMEOUT_CONNECT=1",
			},
		],
		createConfig(),
	);

	assert.equal(result.allowed, false);
	assert.match(result.reason, /key/i);
});

test("allows protected file edits that add harmless comment lines", () => {
	const result = evaluateProtectedFileEdits(
		[
			{
				oldText: "MAX_CONCURRENT_REQUESTS=1",
				newText: [
					"MAX_CONCURRENT_REQUESTS=1",
					"# pi-sensitive-guard harmless edit test",
				].join("\n"),
			},
		],
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("allows protected file writes when sensitive lines are unchanged and only non-sensitive values change", () => {
	const result = evaluateProtectedFileWrite(
		[
			"AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
			"MAX_CONCURRENT_REQUESTS=1",
		].join("\n"),
		[
			"AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
			"MAX_CONCURRENT_REQUESTS=2",
		].join("\n"),
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("extension allows configured non-sensitive edits to protected files", async () => {
	const result = await runEditToolCall([
		{
			oldText: "MAX_CONCURRENT_REQUESTS=1",
			newText: "MAX_CONCURRENT_REQUESTS=2",
		},
	]);

	assert.deepEqual(result, {});
});

test("extension blocks configured protected file edits that touch sensitive values", async () => {
	const result = await runEditToolCall([
		{
			oldText: "AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
			newText: "AISTUDIO_API_KEY_1=new-secret-value-12345678901234567890",
		},
	]);

	assert.equal((result as { block?: boolean }).block, true);
});

test("normalizes protected file edit config", () => {
	const { config, warnings } = normalizeSensitiveGuardConfig({
		protectedFileEdits: {
			enabled: true,
		},
	});

	assert.equal(config.protectedFileEdits.enabled, true);
	assert.deepEqual(warnings, []);
});
