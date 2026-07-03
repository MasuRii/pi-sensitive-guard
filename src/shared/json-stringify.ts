/**
 * Shared JSON serialization helper that safely handles Error objects, bigint
 * values, and circular references. Used by debug logging and blocked-event
 * recording to produce deterministic, crash-free JSON log lines.
 */
export function safeJsonStringify(value: unknown): string {
	const seen = new WeakSet<object>();
	return JSON.stringify(value, (_key: string, currentValue: unknown) => {
		if (currentValue instanceof Error) {
			return {
				name: currentValue.name,
				message: currentValue.message,
				stack: currentValue.stack,
			};
		}

		if (typeof currentValue === "bigint") {
			return currentValue.toString();
		}

		if (typeof currentValue === "object" && currentValue !== null) {
			if (seen.has(currentValue)) {
				return "[Circular]";
			}
			seen.add(currentValue);
		}

		return currentValue;
	});
}
