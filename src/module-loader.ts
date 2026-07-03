import { tmpdir } from "node:os";

import { describeError, ensureDirectory } from "./shared/index.js";

const RETRIABLE_IMPORT_ERROR_CODES = new Set([
	"ENOENT",
	"EACCES",
	"EPERM",
	"EBUSY",
	"EMFILE",
	"ENFILE",
	"ENOTDIR",
	"ERR_MODULE_NOT_FOUND",
]);

export function isRetriableImportError(error: unknown): boolean {
	if (error instanceof Error && "code" in error) {
		const code = (error as { code?: unknown }).code;
		if (typeof code === "string" && RETRIABLE_IMPORT_ERROR_CODES.has(code)) {
			return true;
		}
	}

	const message = describeError(error);
	return /no such file or directory/i.test(message);
}

export interface ModuleCache<T> {
	module?: T;
	promise?: Promise<T>;
}

export type ModuleImporter = (specifier: string) => Promise<unknown>;

export async function tryImportWithRetry<T>(
	specifier: string,
	maxRetries: number,
	tryImport: ModuleImporter,
): Promise<T> {
	let lastError: unknown;

	for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
		try {
			const url =
				attempt === 0
					? specifier
					: `${specifier}?__sensitive_guard_retry=${attempt}`;
			return (await tryImport(url)) as T;
		} catch (error) {
			lastError = error;

			if (!isRetriableImportError(error) || attempt === maxRetries) {
				throw error;
			}

			ensureDirectory(`${tmpdir()}/jiti`, "jiti fallback dir");
			await new Promise((resolve) => {
				setTimeout(resolve, 50 * attempt);
			});
		}
	}

	throw lastError;
}

export async function importWithRetry<T>(
	specifier: string,
	maxRetries = 2,
): Promise<T> {
	return tryImportWithRetry<T>(specifier, maxRetries, (url) => import(url));
}

export function loadCachedModule<T>(
	specifier: string,
	cache: ModuleCache<T>,
	maxRetries = 2,
	tryImport?: ModuleImporter,
): Promise<T> {
	if (cache.module) {
		return Promise.resolve(cache.module);
	}

	if (cache.promise) {
		return cache.promise;
	}

	const loadPromise = tryImport
		? tryImportWithRetry<T>(specifier, maxRetries, tryImport)
		: importWithRetry<T>(specifier, maxRetries);
	cache.promise = loadPromise.then((module) => {
		cache.module = module;
		return module;
	});
	return cache.promise;
}
