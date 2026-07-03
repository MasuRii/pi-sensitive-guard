import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import * as secretScanner from "../src/secret-scanner.js";

const SYNTHETIC_OPENAI = ["sk", "synthetic", "credential", "01234567890123456789"].join("-");

type CachedScanResult = {
	findings: ReturnType<typeof secretScanner.scanContentForSecrets>;
};

const scanFileForSecretsCached =
	(secretScanner as unknown as {
		scanFileForSecretsCached?: (filePath: string, maxFindings: number) => CachedScanResult;
	}).scanFileForSecretsCached ?? (() => ({ findings: [] }));

const getScanCacheStats =
	(secretScanner as unknown as {
		getScanCacheStats?: () => { hits: number; misses: number; size: number };
	}).getScanCacheStats ?? (() => ({ hits: 0, misses: 0, size: 0 }));

const resetScanCache =
	(secretScanner as unknown as {
		resetScanCache?: () => void;
	}).resetScanCache ?? (() => undefined);

test("scan cache returns cached findings when the file mtime is unchanged", () => {
	resetScanCache();
	const tempDir = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-cache-"));
	const filePath = join(tempDir, "config.env");
	writeFileSync(filePath, `API_KEY=${SYNTHETIC_OPENAI}\n`, "utf-8");

	try {
		const before = getScanCacheStats();
		const first = scanFileForSecretsCached(filePath, 5);
		const afterFirst = getScanCacheStats();
		const second = scanFileForSecretsCached(filePath, 5);
		const afterSecond = getScanCacheStats();

		assert.equal(first.findings.length, 1);
		assert.equal(second.findings.length, 1);
		assert.equal(afterSecond.hits - afterFirst.hits, 1, "expected one cache hit on second scan");
		assert.equal(afterFirst.misses - before.misses, 1, "expected one cache miss on first scan");
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
});

test("scan cache invalidates when the file mtime changes", () => {
	resetScanCache();
	const tempDir = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-cache-"));
	const filePath = join(tempDir, "config.env");
	writeFileSync(filePath, `API_KEY=${SYNTHETIC_OPENAI}\n`, "utf-8");

	try {
		const first = scanFileForSecretsCached(filePath, 5);
		assert.equal(first.findings.length, 1);

		const stats = statSync(filePath);
		const future = new Date(stats.mtimeMs + 60_000);
		utimesSync(filePath, future, future);

		const before = getScanCacheStats();
		const second = scanFileForSecretsCached(filePath, 5);
		const after = getScanCacheStats();

		assert.equal(second.findings.length, 1);
		assert.equal(after.misses - before.misses, 1, "expected a cache miss after mtime change");
		assert.equal(after.hits - before.hits, 0, "expected no cache hit after mtime change");
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
});

test("scan cache invalidates when the file content changes without an mtime bump", () => {
	resetScanCache();
	const tempDir = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-cache-"));
	const filePath = join(tempDir, "config.env");
	writeFileSync(filePath, `API_KEY=${SYNTHETIC_OPENAI}\n`, "utf-8");

	try {
		const first = scanFileForSecretsCached(filePath, 5);
		assert.equal(first.findings.length, 1);

		const stats = statSync(filePath);
		// Rewrite content but preserve mtime (simulates an in-place edit with touch -d).
		writeFileSync(
			filePath,
			`API_KEY=${SYNTHETIC_OPENAI}-updated-extension\n`,
			"utf-8",
		);
		utimesSync(filePath, stats.atime, stats.mtime);

		const before = getScanCacheStats();
		const second = scanFileForSecretsCached(filePath, 5);
		const after = getScanCacheStats();

		assert.equal(second.findings.length, 1);
		assert.equal(after.misses - before.misses, 1, "expected a cache miss after content change");
		assert.equal(after.hits - before.hits, 0, "expected no cache hit after content change");
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
});
