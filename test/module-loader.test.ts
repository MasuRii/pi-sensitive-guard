import assert from "node:assert/strict";
import test from "node:test";

import {
	isRetriableImportError,
	loadCachedModule,
	tryImportWithRetry,
	type ModuleCache,
} from "../src/module-loader.js";

class CodeError extends Error {
	constructor(
		message: string,
		public readonly code: string,
	) {
		super(message);
	}
}

test("isRetriableImportError is true for ENOENT and ERR_MODULE_NOT_FOUND", () => {
	assert.equal(isRetriableImportError(new CodeError("missing", "ENOENT")), true);
	assert.equal(
		isRetriableImportError(new CodeError("missing", "ERR_MODULE_NOT_FOUND")),
		true,
	);
	assert.equal(
		isRetriableImportError(new Error("ENOENT: no such file or directory, open '...'")),
		true,
	);
});

test("isRetriableImportError is false for non-retriable errors", () => {
	assert.equal(isRetriableImportError(new Error("some evaluation error")), false);
	assert.equal(isRetriableImportError(new CodeError("syntax", "ERR_SYNTAX_ERROR")), false);
	assert.equal(isRetriableImportError("not an error"), false);
});

test("tryImportWithRetry succeeds on the first attempt", async () => {
	const result = await tryImportWithRetry<{ value: string }>("./mod.js", 0, async () => ({
		value: "ok",
	}));
	assert.equal(result.value, "ok");
});

test("tryImportWithRetry retries once on a retriable failure", async () => {
	let attempts = 0;
	const importer = async (specifier: string) => {
		attempts += 1;
		if (attempts === 1) {
			throw new CodeError("ENOENT: no such file or directory", "ENOENT");
		}
		return { value: specifier };
	};

	const result = await tryImportWithRetry<{ value: string }>("./mod.js", 1, importer);
	assert.equal(attempts, 2);
	assert.equal(result.value, "./mod.js?__sensitive_guard_retry=1");
});

test("tryImportWithRetry throws after exhausting retriable retries", async () => {
	let attempts = 0;
	const importer = async () => {
		attempts += 1;
		throw new CodeError("ENOENT: no such file or directory", "ENOENT");
	};

	await assert.rejects(
		tryImportWithRetry<string>("./mod.js", 2, importer),
		/ENOENT: no such file or directory/,
	);
	assert.equal(attempts, 3);
});

test("tryImportWithRetry does not retry non-retriable errors", async () => {
	let attempts = 0;
	const importer = async () => {
		attempts += 1;
		throw new Error("module evaluation failed");
	};

	await assert.rejects(
		tryImportWithRetry<string>("./mod.js", 2, importer),
		/module evaluation failed/,
	);
	assert.equal(attempts, 1);
});

test("loadCachedModule caches and reuses a resolved module", async () => {
	let calls = 0;
	const cache: ModuleCache<{ id: number }> = {};
	const importer = async () => {
		calls += 1;
		return { id: calls };
	};

	const first = await loadCachedModule<{ id: number }>("./cache.js", cache, 0, importer);
	const second = await loadCachedModule<{ id: number }>("./cache.js", cache, 0, importer);
	assert.equal(calls, 1);
	assert.equal(first.id, 1);
	assert.equal(second.id, 1);
});

test("loadCachedModule retries transient import failures", async () => {
	let calls = 0;
	const cache: ModuleCache<{ ok: boolean }> = {};
	const importer = async () => {
		calls += 1;
		if (calls === 1) {
			throw new CodeError("ENOENT: no such file or directory", "ENOENT");
		}
		return { ok: true };
	};

	const result = await loadCachedModule<{ ok: boolean }>("./cache.js", cache, 2, importer);
	assert.equal(calls, 2);
	assert.equal(result.ok, true);
});
