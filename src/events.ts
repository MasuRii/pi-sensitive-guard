import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { BLOCKED_EVENT_CHANNEL } from "./constants.js";
import { redactSensitiveReadContent } from "./read-redactor.js";
import { describeError, safeJsonStringify } from "./shared/index.js";
import type {
	ResolvedSensitiveGuardConfig,
	SensitiveGuardBlockedEvent,
} from "./types.js";

let blockedEventLogQueue: Promise<void> = Promise.resolve();

function enqueueBlockedEventLog(logPath: string, line: string): void {
	const writeLogEntry = async () => {
		await mkdir(dirname(logPath), { recursive: true });
		await appendFile(logPath, `${line}\n`, "utf-8");
	};
	blockedEventLogQueue = blockedEventLogQueue.then(writeLogEntry, writeLogEntry);
	void blockedEventLogQueue.catch(() => {
		// Blocked-event logging must never affect sensitive guard enforcement.
	});
}

export function flushBlockedEventLog(): Promise<void> {
	return blockedEventLogQueue.catch(() => undefined);
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
			enqueueBlockedEventLog(config.blockedEvents.logPath, safeJsonStringify(sanitizedEvent));
		}

		return undefined;
	} catch (error) {
		const message = describeError(error);
		return `Failed to record blocked sensitive-guard event: ${message}`;
	}
}
