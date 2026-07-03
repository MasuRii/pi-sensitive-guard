/**
 * Narrows an unknown value to a plain record. Returns an empty object when the
 * value is not a non-array object, so callers can safely destructure/iterate
 * without additional guards. Shared across config loading, config commands,
 * index entry point, and protected-file-edit parsing.
 */
export function toRecord(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return {};
	}
	return value as Record<string, unknown>;
}
