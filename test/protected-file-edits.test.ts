import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { DEFAULT_CONFIG, PRIMARY_CONFIG_PATH } from "../src/constants.js";
import { normalizeSensitiveGuardConfig } from "../src/config.js";
import sensitiveGuardExtension from "../src/index.js";
import {
	evaluateProtectedFileEditInput,
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

async function runEditToolCall(
	edits: unknown,
	path = "secrets.env",
	initialContent = [
		"AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
		"MAX_CONCURRENT_REQUESTS=1",
	].join("\n"),
): Promise<unknown> {
	const hadOriginalConfig = existsSync(PRIMARY_CONFIG_PATH);
	const originalConfig = hadOriginalConfig ? readFileSync(PRIMARY_CONFIG_PATH, "utf-8") : undefined;
	const tempRoot = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-edit-"));

	try {
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

		writeFileSync(join(tempRoot, path), initialContent, "utf-8");

		const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<unknown> | unknown>();
		const pi = {
			on: (name: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<unknown> | unknown) => {
				handlers.set(name, handler);
			},
			events: { emit: () => undefined },
			exec: async () => ({ stdout: "", stderr: "", exitCode: 0 }),
		} as unknown as ExtensionAPI;
		const ctx = {
			cwd: tempRoot,
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
					path,
					edits,
				},
			},
			ctx,
		);
	} finally {
		rmSync(tempRoot, { recursive: true, force: true });
		if (hadOriginalConfig && originalConfig !== undefined) {
			writeFileSync(PRIMARY_CONFIG_PATH, originalConfig, "utf-8");
		} else if (existsSync(PRIMARY_CONFIG_PATH)) {
			unlinkSync(PRIMARY_CONFIG_PATH);
		}
	}
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

test("allows structured replace_text protected file edits with exact oldText/newText", async () => {
	const result = await evaluateProtectedFileEditInput(
		"MAX_CONCURRENT_REQUESTS=1\n",
		{
			path: "secrets.env",
			edits: [
				{
					op: "replace_text",
					oldText: "MAX_CONCURRENT_REQUESTS=1",
					newText: "MAX_CONCURRENT_REQUESTS=2",
				},
			],
		},
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("allows protected file edits accepted by Pi native fuzzy matching", async () => {
	const result = await evaluateProtectedFileEditInput(
		"MAX_CONCURRENT_REQUESTS=1   \n",
		{
			path: "secrets.env",
			edits: [
				{
					oldText: "MAX_CONCURRENT_REQUESTS=1\n",
					newText: "MAX_CONCURRENT_REQUESTS=2\n",
				},
			],
		},
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("allows structured anchored protected file edits after applying them to current content", async () => {
	const result = await evaluateProtectedFileEditInput(
		"MAX_CONCURRENT_REQUESTS=1\n",
		{
			path: "secrets.env",
			edits: [
				{
					op: "replace",
					pos: "1#ZP:MAX_CONCURRENT_REQUESTS=1",
					lines: ["MAX_CONCURRENT_REQUESTS=2"],
				},
			],
		},
		createConfig(),
	);

	assert.equal(result.allowed, true);
});

test("blocks structured anchored protected file edits that touch sensitive values", async () => {
	const result = await evaluateProtectedFileEditInput(
		"AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890\n",
		{
			path: "secrets.env",
			edits: [
				{
					op: "replace",
					pos: "1#ZP:AISTUDIO_API_KEY_1=old-secret-value-12345678901234567890",
					lines: ["AISTUDIO_API_KEY_1=new-secret-value-12345678901234567890"],
				},
			],
		},
		createConfig(),
	);

	assert.equal(result.allowed, false);
	assert.match(result.reason, /sensitive/i);
});

test("allows alternate hash-anchored edit shapes without extension-specific coupling", async () => {
	const result = await evaluateProtectedFileEditInput(
		"MAX_CONCURRENT_REQUESTS=1\n",
		{
			path: "secrets.env",
			edits: [
				{
					set_line: {
						anchor: "1:aa|MAX_CONCURRENT_REQUESTS=1",
						new_text: "MAX_CONCURRENT_REQUESTS=2",
					},
				},
			],
		},
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

test("extension allows configured non-sensitive anchored edits to protected files", async () => {
	const result = await runEditToolCall([
		{
			op: "replace",
			pos: "2#ZP:MAX_CONCURRENT_REQUESTS=1",
			lines: ["MAX_CONCURRENT_REQUESTS=2"],
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

test("extension returns protected edit validation details in block responses", async () => {
	const result = await runEditToolCall([
		{
			oldText: "MISSING_NON_SECRET=1",
			newText: "MISSING_NON_SECRET=2",
		},
	]);
	const blocked = result as { block?: boolean; reason?: string };

	assert.equal(blocked.block, true);
	assert.match(blocked.reason ?? "", /Security block: protected write denied/);
	assert.match(blocked.reason ?? "", /Text replacement oldText was not found/);
});

test("extension scans structured edit lines for secret-bearing content", async () => {
	const result = await runEditToolCall(
		[
			{
				op: "append",
				pos: "1#ZP:MAX_CONCURRENT_REQUESTS=1",
				lines: ["AISTUDIO_API_KEY_1=new-secret-value-12345678901234567890"],
			},
		],
		"public.env",
	);

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
