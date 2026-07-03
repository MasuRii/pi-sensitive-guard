import { DEBUG_DIR, DEBUG_LOG_PATH, EXTENSION_NAME } from "./constants.js";
import { AsyncBufferedLogWriter } from "./async-buffered-log-writer.js";
import { describeError, ensureDirectory, safeJsonStringify } from "./shared/index.js";

export type SensitiveGuardDebugLogLevel = "info" | "warn";

export interface SensitiveGuardDebugLoggerOptions {
	debugDir?: string;
	logPath?: string;
}

export class SensitiveGuardDebugLogger {
	private readonly writer: AsyncBufferedLogWriter;

	constructor(private readonly options: SensitiveGuardDebugLoggerOptions = {}) {
		const debugDir = this.options.debugDir ?? DEBUG_DIR;
		this.writer = new AsyncBufferedLogWriter({
			enabled: false,
			logPath: this.options.logPath ?? DEBUG_LOG_PATH,
			ensureDirectory: () => ensureDirectory(debugDir, debugDir),
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
			const message = describeError(error);
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
