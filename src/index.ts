import {
	type ExtensionAPI,
	type ExtensionContext,
	isToolCallEventType,
} from "@mariozechner/pi-coding-agent";

import { ensureConfigExists, loadConfig } from "./config.js";
import { SensitiveGuardDebugLogger } from "./debug-logger.js";
import { emitBlocked } from "./events.js";
import { checkGitProtection } from "./git-protection.js";
import {
	DEFAULT_CONFIG,
	EXTENSION_NAME,
} from "./constants.js";
import { createSensitiveGuardMatcher } from "./detector.js";
import {
	buildContentScanSecurityMessage,
	buildGitProtectionSecurityMessage,
	DELETE_SECURITY_MESSAGE,
	READ_SECURITY_MESSAGE,
	WRITE_SECURITY_MESSAGE,
} from "./messages.js";
import { redactSensitiveReadContent } from "./read-redactor.js";
import {
	formatSecretFindings,
	getBlockableSecretFindings,
	scanContentForSecrets,
} from "./secret-scanner.js";
import type {
	CommandCheckResult,
	GuardFeature,
	PendingReadRedaction,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardBlockedEvent,
	SensitiveGuardMatcher,
} from "./types.js";

function notify(ctx: ExtensionContext, message: string, level: "warning" | "error"): void {
	if (!ctx.hasUI) {
		return;
	}

	ctx.ui.notify(message, level);
}

function getPathBlockMessage(action: "read" | "write" | "delete", path: string): string {
	return `Blocked: attempted to ${action} protected path '${path}'`;
}

function getCommandBlockMessage(result: CommandCheckResult): string {
	if (result.kind && result.target) {
		return `Blocked: attempted to ${result.kind} protected path '${result.target}'`;
	}

	return `Blocked: ${result.reason}`;
}

function getEditReplacementContent(edits: ReadonlyArray<{ newText: string }>): string {
	return edits.map((edit) => edit.newText).join("\n");
}

function createBlockedEvent(
	feature: GuardFeature,
	action: SensitiveGuardBlockedEvent["action"],
	reason: string,
	toolName: string,
	target?: string,
	ruleId?: string,
	metadata?: Record<string, unknown>,
): SensitiveGuardBlockedEvent {
	return {
		feature,
		action,
		reason,
		timestamp: new Date().toISOString(),
		toolName,
		target,
		ruleId,
		metadata,
	};
}

function toRecord(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return {};
	}
	return value as Record<string, unknown>;
}

interface TextContentBlock {
	type: "text";
	text: string;
	[key: string]: unknown;
}

function isTextContentBlock(value: unknown): value is TextContentBlock {
	const record = toRecord(value);
	return record.type === "text" && typeof record.text === "string";
}

function mergeRedactionDetails(
	existingDetails: unknown,
	redaction: PendingReadRedaction,
	redactionCount: number,
	reasons: string[],
): Record<string, unknown> {
	const baseDetails = toRecord(existingDetails);
	const baseMetadata = toRecord(baseDetails.metadata);
	const metadata = {
		readRedaction: {
			target: redaction.target,
			ruleId: redaction.ruleId,
			source: redaction.source,
			redactionCount,
			reasons,
		},
	};

	return {
		...baseDetails,
		...metadata,
		metadata: {
			...baseMetadata,
			...metadata,
		},
	};
}

export default function sensitiveGuardExtension(pi: ExtensionAPI): void {
	let config: ResolvedSensitiveGuardConfig = DEFAULT_CONFIG;
	let matcher: SensitiveGuardMatcher = createSensitiveGuardMatcher(DEFAULT_CONFIG);
	const warnedMessages = new Set<string>();
	const pendingRedactions = new Map<string, PendingReadRedaction>();
	const debugLogger = new SensitiveGuardDebugLogger();

	const warnOnce = (ctx: ExtensionContext, message: string): void => {
		if (warnedMessages.has(message)) {
			return;
		}

		warnedMessages.add(message);
		notify(ctx, message, "warning");
	};

	const writeDebug = (
		ctx: ExtensionContext,
		level: "info" | "warn",
		event: string,
		payload: Record<string, unknown> = {},
	): void => {
		const logError = debugLogger.write(level, event, payload);
		if (logError) {
			warnOnce(ctx, logError);
		}
	};

	const reportBlockedEvent = (
		ctx: ExtensionContext,
		event: SensitiveGuardBlockedEvent,
	): void => {
		const logError = emitBlocked(pi, config, event);
		if (logError) {
			warnOnce(ctx, `${EXTENSION_NAME}: ${logError}`);
		}
	};

	const scheduleReadRedaction = (
		ctx: ExtensionContext,
		redaction: PendingReadRedaction,
		debugEvent: string,
		debugPayload: Record<string, unknown>,
	): void => {
		pendingRedactions.set(redaction.toolCallId, redaction);
		writeDebug(ctx, "info", debugEvent, debugPayload);
	};

	const refreshConfig = (ctx: ExtensionContext): void => {
		const ensureResult = ensureConfigExists();
		if (ensureResult.error) {
			warnOnce(ctx, ensureResult.error);
		}

		const loaded = loadConfig();
		for (const warning of loaded.warnings) {
			warnOnce(ctx, `${EXTENSION_NAME}: ${warning}`);
		}


		config = loaded.config;
		matcher = createSensitiveGuardMatcher(config);
		debugLogger.setEnabled(config.debug);
		pendingRedactions.clear();
		writeDebug(ctx, "info", "config_loaded", {
			source: loaded.source,
			path: loaded.path,
			enabled: config.enabled,
			readRedactionEnabled: config.readRedaction.enabled,
			includeShellOutput: config.readRedaction.includeShellOutput,
		});
	};

	// Load config on startup and refresh on /reload.
	pi.on("session_start", async (_event, ctx) => {
		refreshConfig(ctx);
	});

	pi.on("tool_call", async (event, ctx) => {
		try {
			if (!config.enabled) {
				return {};
			}

			if (isToolCallEventType("read", event)) {
				const result = matcher.checkReadPath(event.input.path);
				if (config.readRedaction.enabled) {
					scheduleReadRedaction(
						ctx,
						{
							toolCallId: event.toolCallId,
							toolName: event.toolName,
							target: result.target ?? event.input.path,
							ruleId: result.ruleId,
							source: "read",
						},
						"read_redaction_scheduled",
						{
							toolCallId: event.toolCallId,
							target: result.target ?? event.input.path,
							ruleId: result.ruleId,
							pathProtected: result.blocked,
						},
					);
					return {};
				}

				if (result.blocked) {
					notify(ctx, getPathBlockMessage("read", result.target ?? event.input.path), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"pathProtection",
							"read",
							result.reason,
							event.toolName,
							result.target,
							result.ruleId,
							{ path: event.input.path },
						),
					);
					return { block: true, reason: READ_SECURITY_MESSAGE };
				}

				return {};
			}

			if (isToolCallEventType("write", event)) {
				const pathResult = matcher.checkWritePath(event.input.path);
				if (pathResult.blocked) {
					notify(ctx, getPathBlockMessage("write", pathResult.target ?? event.input.path), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"pathProtection",
							"write",
							pathResult.reason,
							event.toolName,
							pathResult.target,
							pathResult.ruleId,
							{ path: event.input.path },
						),
					);
					return { block: true, reason: WRITE_SECURITY_MESSAGE };
				}

				if (config.contentScanning.enabled) {
					const findings = getBlockableSecretFindings(
						scanContentForSecrets(
							event.input.content,
							config.contentScanning.maxFindings,
						),
						config.contentScanning.blockSeverity,
					);
					if (findings.length > 0) {
						const detail = formatSecretFindings(findings);
						notify(ctx, "Blocked: attempted to write secret-bearing content", "error");
						reportBlockedEvent(
							ctx,
							createBlockedEvent(
								"contentScan",
								"write",
								detail,
								event.toolName,
								event.input.path,
								undefined,
								{ findings },
							),
						);
						return {
							block: true,
							reason: buildContentScanSecurityMessage(findings),
						};
					}
				}

				return {};
			}

			if (isToolCallEventType("edit", event)) {
				const pathResult = matcher.checkWritePath(event.input.path);
				if (pathResult.blocked) {
					notify(ctx, getPathBlockMessage("write", pathResult.target ?? event.input.path), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"pathProtection",
							"write",
							pathResult.reason,
							event.toolName,
							pathResult.target,
							pathResult.ruleId,
							{ path: event.input.path },
						),
					);
					return { block: true, reason: WRITE_SECURITY_MESSAGE };
				}

				if (config.contentScanning.enabled) {
					const findings = getBlockableSecretFindings(
						scanContentForSecrets(
							getEditReplacementContent(event.input.edits),
							config.contentScanning.maxFindings,
						),
						config.contentScanning.blockSeverity,
					);
					if (findings.length > 0) {
						const detail = formatSecretFindings(findings);
						notify(ctx, "Blocked: attempted to edit in secret-bearing content", "error");
						reportBlockedEvent(
							ctx,
							createBlockedEvent(
								"contentScan",
								"write",
								detail,
								event.toolName,
								event.input.path,
								undefined,
								{ findings },
							),
						);
						return {
							block: true,
							reason: buildContentScanSecurityMessage(findings),
						};
					}
				}

				return {};
			}

			if (isToolCallEventType("bash", event)) {
				const gitCheck = await checkGitProtection({
					command: event.input.command,
					cwd: ctx.cwd,
					exec: (command, args, options) => pi.exec(command, args, options),
					matcher,
					config,
				});
				if (gitCheck.blocked && gitCheck.action) {
					notify(
						ctx,
						`Blocked: attempted to git ${gitCheck.action} sensitive changes`,
						"error",
					);
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"gitProtection",
							gitCheck.action,
							gitCheck.reason,
							event.toolName,
							gitCheck.target,
							gitCheck.ruleId,
							gitCheck.metadata,
						),
					);
					return {
						block: true,
						reason: buildGitProtectionSecurityMessage(
							gitCheck.action,
							gitCheck.reason,
						),
					};
				}

				const deleteCheck = matcher.checkDeleteCommand(event.input.command);
				if (deleteCheck.blocked) {
					notify(ctx, getCommandBlockMessage(deleteCheck), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"shellCommand",
							"delete",
							deleteCheck.reason,
							event.toolName,
							deleteCheck.target,
							deleteCheck.ruleId,
							{ command: event.input.command, commandWords: deleteCheck.commandWords },
						),
					);
					return { block: true, reason: DELETE_SECURITY_MESSAGE };
				}

				const writeCheck = matcher.checkWriteCommand(event.input.command);
				if (writeCheck.blocked) {
					notify(ctx, getCommandBlockMessage(writeCheck), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"shellCommand",
							"write",
							writeCheck.reason,
							event.toolName,
							writeCheck.target,
							writeCheck.ruleId,
							{ command: event.input.command, commandWords: writeCheck.commandWords },
						),
					);
					return { block: true, reason: WRITE_SECURITY_MESSAGE };
				}

				const readCheck = matcher.checkReadCommand(event.input.command);
				if (config.readRedaction.enabled && config.readRedaction.includeShellOutput) {
					scheduleReadRedaction(
						ctx,
						{
							toolCallId: event.toolCallId,
							toolName: event.toolName,
							target: readCheck.target,
							ruleId: readCheck.ruleId,
							source: "shell",
						},
						"shell_read_redaction_scheduled",
						{
							toolCallId: event.toolCallId,
							target: readCheck.target,
							ruleId: readCheck.ruleId,
							commandName: readCheck.commandName,
							pathProtected: readCheck.blocked,
						},
					);
					return {};
				}

				if (readCheck.blocked) {
					notify(ctx, getCommandBlockMessage(readCheck), "error");
					reportBlockedEvent(
						ctx,
						createBlockedEvent(
							"shellCommand",
							"read",
							readCheck.reason,
							event.toolName,
							readCheck.target,
							readCheck.ruleId,
							{ command: event.input.command, commandWords: readCheck.commandWords },
						),
					);
					return { block: true, reason: READ_SECURITY_MESSAGE };
				}

				return {};
			}

			return {};
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			const reason = `${EXTENSION_NAME}: blocked command because protection checks failed (${message}).`;
			warnOnce(ctx, reason);
			writeDebug(ctx, "warn", "tool_call_check_failed", { message });
			return { block: true, reason };
		}
	});

	pi.on("tool_result", async (event, ctx) => {
		const pending = pendingRedactions.get(event.toolCallId);
		if (!pending) {
			return {};
		}
		pendingRedactions.delete(event.toolCallId);

		try {
			if (event.isError) {
				writeDebug(ctx, "info", "read_redaction_skipped", {
					toolCallId: event.toolCallId,
					target: pending.target,
					isError: event.isError,
				});
				return {};
			}

			let redactionCount = 0;
			const reasons = new Set<string>();
			let contentChanged = false;
			const nextContent = event.content.map((block) => {
				if (!isTextContentBlock(block)) {
					return block;
				}

				const redacted = redactSensitiveReadContent(block.text, config.readRedaction);
				if (!redacted.redacted) {
					return block;
				}

				contentChanged = true;
				redactionCount += redacted.redactionCount;
				for (const reason of redacted.reasons) {
					reasons.add(reason);
				}
				return { ...block, text: redacted.content };
			});

			if (!contentChanged) {
				writeDebug(ctx, "info", "read_redaction_noop", {
					toolCallId: event.toolCallId,
					target: pending.target,
				});
				return {};
			}

			const redactionReasons = [...reasons];
			reportBlockedEvent(
				ctx,
				createBlockedEvent(
					"readRedaction",
					"read",
					`Redacted ${redactionCount} sensitive value(s) from protected read output.`,
					pending.toolName,
					pending.target,
					pending.ruleId,
					{
						source: pending.source,
						redactionCount,
						reasons: redactionReasons,
					},
				),
			);
			writeDebug(ctx, "info", "read_redaction_applied", {
				toolCallId: event.toolCallId,
				target: pending.target,
				redactionCount,
				reasons: redactionReasons,
			});

			return {
				content: nextContent,
				details: mergeRedactionDetails(
					event.details,
					pending,
					redactionCount,
					redactionReasons,
				),
			};
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			const safeContent = `[${EXTENSION_NAME}: read redaction failed; protected content was withheld. ${message}]`;
			warnOnce(ctx, `${EXTENSION_NAME}: failed to redact protected read output: ${message}`);
			writeDebug(ctx, "warn", "read_redaction_failed", {
				toolCallId: event.toolCallId,
				target: pending.target,
				message,
			});
			return { content: [{ type: "text", text: safeContent }] };
		}
	});
}
