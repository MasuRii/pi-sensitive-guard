/**
 * Extracts a human-readable message from an unknown error value. Shared across
 * the extension's catch blocks so the `error instanceof Error ? ... : ...`
 * boilerplate is defined once instead of duplicated per call site.
 */
export function describeError(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
