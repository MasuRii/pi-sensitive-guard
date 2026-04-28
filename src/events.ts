import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

import { BLOCKED_EVENT_CHANNEL } from "./constants.js";
import { redactSensitiveReadContent } from "./read-redactor.js";
import type {
	ResolvedSensitiveGuardConfig,
	SensitiveGuardBlockedEvent,
} from "./types.js";

function safeJsonStringify(value: unknown): string {
	const seen = new WeakSet<object>();
	return JSON.stringify(value, (_key, currentValue) => {
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

function redactEventString(
	value: string,
	config: ResolvedSensitiveGuardConfig,
): string {
	return redactSensitiveReadContent(value, {
		...config.readRedaction,
		enabled: true,
		redactSecretPatterns: true,
	}).content;
}

function sanitizeEventValue(
	value: unknown,
	config: ResolvedSensitiveGuardConfig,
	seen: WeakSet<object>,
): unknown {
	if (typeof value === "string") {
		return redactEventString(value, config);
	}

	if (!value || typeof value !== "object") {
		return value;
	}

	if (seen.has(value)) {
		return "[Circular]";
	}
	seen.add(value);

	if (Array.isArray(value)) {
		return value.map((entry) => sanitizeEventValue(entry, config, seen));
	}

	return Object.fromEntries(
		Object.entries(value).map(([key, entry]) => [
			key,
			sanitizeEventValue(entry, config, seen),
		]),
	);
}

function sanitizeBlockedEvent(
	config: ResolvedSensitiveGuardConfig,
	event: SensitiveGuardBlockedEvent,
): SensitiveGuardBlockedEvent {
	return sanitizeEventValue(
		event,
		config,
		new WeakSet<object>(),
	) as SensitiveGuardBlockedEvent;
}

export function emitBlocked(
	pi: ExtensionAPI,
	config: ResolvedSensitiveGuardConfig,
	event: SensitiveGuardBlockedEvent,
): string | undefined {
	try {
		const sanitizedEvent = sanitizeBlockedEvent(config, event);
		if (config.blockedEvents.emit) {
			pi.events.emit(BLOCKED_EVENT_CHANNEL, sanitizedEvent);
		}

		if (config.blockedEvents.log) {
			mkdirSync(dirname(config.blockedEvents.logPath), { recursive: true });
			appendFileSync(
				config.blockedEvents.logPath,
				`${safeJsonStringify(sanitizedEvent)}\n`,
				"utf-8",
			);
		}

		return undefined;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return `Failed to record blocked sensitive-guard event: ${message}`;
	}
}
