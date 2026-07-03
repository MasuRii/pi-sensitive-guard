import { mkdirSync } from "node:fs";

import { describeError } from "./error-utils.js";

/**
 * Ensures a directory exists, creating it recursively if needed. Returns
 * undefined on success or an error-message string on failure, so callers can
 * surface the failure without throwing. Shared by the debug logger (debug/
 * dir) and the module loader (jiti cache dir) to avoid duplicated mkdir+catch
 * boilerplate.
 */
export function ensureDirectory(dirPath: string, label: string): string | undefined {
	try {
		mkdirSync(dirPath, { recursive: true });
		return undefined;
	} catch (error) {
		const message = describeError(error);
		return `Failed to create ${label}: ${message}`;
	}
}
