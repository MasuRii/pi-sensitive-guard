import { mkdirSync } from "node:fs";

import { DEBUG_DIR, DEBUG_LOG_PATH, EXTENSION_NAME } from "./constants.js";
import { AsyncBufferedLogWriter } from "./async-buffered-log-writer.js";

export type SensitiveGuardDebugLogLevel = "info" | "warn";

export interface SensitiveGuardDebugLoggerOptions {
	debugDir?: string;
	logPath?: string;
}

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

function ensureDebugDirectory(debugDir: string): string | undefined {
	try {
		mkdirSync(debugDir, { recursive: true });
		return undefined;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return `Failed to create ${debugDir}: ${message}`;
	}
}

export class SensitiveGuardDebugLogger {
	private readonly writer: AsyncBufferedLogWriter;

	constructor(private readonly options: SensitiveGuardDebugLoggerOptions = {}) {
		const debugDir = this.options.debugDir ?? DEBUG_DIR;
		this.writer = new AsyncBufferedLogWriter({
			enabled: false,
			logPath: this.options.logPath ?? DEBUG_LOG_PATH,
			ensureDirectory: () => ensureDebugDirectory(debugDir),
			createDroppedEntriesLine: (droppedEntries) =>
				`${safeJsonStringify({
					timestamp: new Date().toISOString(),
					level: "warn",
					extension: EXTENSION_NAME,
					event: "debug_log_overflow",
					droppedEntries,
				})}\n`,
		});
	}

	setEnabled(enabled: boolean): void {
		this.writer.setEnabled(enabled);
	}

	write(
		level: SensitiveGuardDebugLogLevel,
		event: string,
		payload: Record<string, unknown> = {},
	): string | undefined {
		try {
			return this.writer.writeLine(
				`${safeJsonStringify({
					timestamp: new Date().toISOString(),
					level,
					extension: EXTENSION_NAME,
					event,
					...payload,
				})}\n`,
			);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return `Failed to buffer ${EXTENSION_NAME} ${level} debug log '${this.options.logPath ?? DEBUG_LOG_PATH}': ${message}`;
		}
	}

	info(event: string, payload: Record<string, unknown> = {}): string | undefined {
		return this.write("info", event, payload);
	}

	warn(event: string, payload: Record<string, unknown> = {}): string | undefined {
		return this.write("warn", event, payload);
	}

	flush(): Promise<void> {
		return this.writer.flush();
	}

	dispose(): Promise<void> {
		return this.writer.dispose();
	}
}
