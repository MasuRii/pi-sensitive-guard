import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

import {
	type ExtensionAPI,
	type ExtensionContext,
	isToolCallEventType,
} from "@earendil-works/pi-coding-agent";

import { ensureConfigExists, loadConfig } from "./config.js";
import { registerSensitiveGuardConfigCommand } from "./config-command.js";
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
import {
	evaluateProtectedFileEditInput,
	evaluateProtectedFileWrite,
} from "./protected-file-edits.js";
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

function collectStringValue(value: unknown, chunks: string[]): void {
	if (typeof value === "string" && value.length > 0) {
		chunks.push(value);
	}
}

function collectLineValue(value: unknown, chunks: string[]): void {
	if (Array.isArray(value)) {
		const lines = value.filter((line): line is string => typeof line === "string");
		if (lines.length > 0) {
			chunks.push(lines.join("\n"));
		}
		return;
	}

	collectStringValue(value, chunks);
}

function collectEditReplacementContent(edit: unknown, chunks: string[]): void {
	const editRecord = toRecord(edit);
	collectStringValue(editRecord.newText, chunks);
	collectStringValue(editRecord.new_text, chunks);
	collectStringValue(editRecord.text, chunks);
	collectStringValue(editRecord.content, chunks);
	collectLineValue(editRecord.lines, chunks);

	for (const nestedKey of ["set_line", "replace_lines", "insert_after", "replace"] as const) {
		const nestedRecord = toRecord(editRecord[nestedKey]);
		collectStringValue(nestedRecord.newText, chunks);
		collectStringValue(nestedRecord.new_text, chunks);
		collectStringValue(nestedRecord.text, chunks);
		collectStringValue(nestedRecord.content, chunks);
		collectLineValue(nestedRecord.lines, chunks);
	}
}

function getEditReplacementContent(input: unknown): string {
	const inputRecord = toRecord(input);
	const chunks: string[] = [];
	collectStringValue(inputRecord.newText, chunks);
	collectStringValue(inputRecord.new_text, chunks);

	const edits = Array.isArray(inputRecord.edits)
		? inputRecord.edits
		: Array.isArray(input)
			? input
			: [];
	for (const edit of edits) {
		collectEditReplacementContent(edit, chunks);
	}

	return chunks.filter((chunk) => chunk.length > 0).join("\n");
}

function resolveToolPath(cwd: string, path: string): string {
	return isAbsolute(path) ? path : resolve(cwd, path);
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

	const shouldRedactReadPath = (blocked: boolean): boolean =>
		config.readRedaction.enabled &&
		(blocked || config.readRedaction.scope === "allOutput");

	const shouldRedactShellOutput = (blocked: boolean): boolean =>
		config.readRedaction.enabled &&
		config.readRedaction.includeShellOutput &&
		(blocked || config.readRedaction.scope === "allOutput");

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
			readRedactionScope: config.readRedaction.scope,
			includeShellOutput: config.readRedaction.includeShellOutput,
			blockedEventLog: config.blockedEvents.log,
		});
	};

	registerSensitiveGuardConfigCommand(pi, {
		getConfig: () => config,
		refreshConfig,
	});

	// Load config on startup and refresh on /reload.
	pi.on("session_start", async (_event, ctx) => {
		refreshConfig(ctx);
	});

	pi.on("session_shutdown", async () => {
		await debugLogger.dispose();
	});

	pi.on("tool_call", async (event, ctx) => {
		try {
			if (!config.enabled) {
				return {};
			}

			if (isToolCallEventType("read", event)) {
				const result = matcher.checkReadPath(event.input.path);
				if (shouldRedactReadPath(result.blocked)) {
					scheduleReadRedaction(
						ctx,
						{
							toolCallId: event.toolCallId,
							toolName: event.toolName,
							target: result.target ?? event.input.path,
							ruleId: result.ruleId,
							source: "read",
						},
						result.blocked ? "read_redaction_scheduled" : "read_output_redaction_scheduled",
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
				let protectedWriteBypass = false;
				if (pathResult.blocked) {
					let blockReason = pathResult.reason;
					if (config.protectedFileEdits.enabled) {
						try {
							const currentContent = readFileSync(
								resolveToolPath(ctx.cwd, event.input.path),
								"utf-8",
							);
							const evaluation = evaluateProtectedFileWrite(
								currentContent,
								event.input.content,
								config,
							);
							if (evaluation.allowed) {
								protectedWriteBypass = true;
								writeDebug(ctx, "info", "protected_file_write_allowed", {
									path: event.input.path,
									ruleId: pathResult.ruleId,
								});
							} else {
								blockReason = evaluation.reason;
							}
						} catch (error) {
							const message = error instanceof Error ? error.message : String(error);
							blockReason = `Protected file write could not be validated safely: ${message}`;
						}
					}

					if (!protectedWriteBypass) {
						notify(ctx, getPathBlockMessage("write", pathResult.target ?? event.input.path), "error");
						reportBlockedEvent(
							ctx,
							createBlockedEvent(
								"pathProtection",
								"write",
								blockReason,
								event.toolName,
								pathResult.target,
								pathResult.ruleId,
								{ path: event.input.path },
							),
						);
						return { block: true, reason: WRITE_SECURITY_MESSAGE };
					}
				}

				if (config.contentScanning.enabled && !protectedWriteBypass) {
					const findings = getBlockableSecretFindings(
						scanContentForSecrets(
							event.input.content,
							config.contentScanning.maxFindings,
							{ file: event.input.path },
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
					let evaluation = { allowed: false, reason: pathResult.reason };
					if (config.protectedFileEdits.enabled) {
						try {
							const currentContent = readFileSync(
								resolveToolPath(ctx.cwd, event.input.path),
								"utf-8",
							);
							evaluation = evaluateProtectedFileEditInput(
								currentContent,
								event.input,
								config,
							);
						} catch (error) {
							const message = error instanceof Error ? error.message : String(error);
							evaluation = {
								allowed: false,
								reason: `Protected file edit could not be validated safely: ${message}`,
							};
						}
					}
					if (!evaluation.allowed) {
						notify(ctx, getPathBlockMessage("write", pathResult.target ?? event.input.path), "error");
						reportBlockedEvent(
							ctx,
							createBlockedEvent(
								"pathProtection",
								"write",
								evaluation.reason,
								event.toolName,
								pathResult.target,
								pathResult.ruleId,
								{ path: event.input.path },
							),
						);
						return { block: true, reason: WRITE_SECURITY_MESSAGE };
					}

					writeDebug(ctx, "info", "protected_file_edit_allowed", {
						path: event.input.path,
						ruleId: pathResult.ruleId,
					});
				}

				if (config.contentScanning.enabled) {
					const findings = getBlockableSecretFindings(
						scanContentForSecrets(
							getEditReplacementContent(event.input),
							config.contentScanning.maxFindings,
							{ file: event.input.path },
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
				if (shouldRedactShellOutput(readCheck.blocked)) {
					scheduleReadRedaction(
						ctx,
						{
							toolCallId: event.toolCallId,
							toolName: event.toolName,
							target: readCheck.target,
							ruleId: readCheck.ruleId,
							source: "shell",
						},
						readCheck.blocked ? "shell_read_redaction_scheduled" : "shell_output_redaction_scheduled",
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
			const outputKind = pending.ruleId ? "protected output" : "tool output";
			reportBlockedEvent(
				ctx,
				createBlockedEvent(
					"readRedaction",
					"read",
					`Redacted ${redactionCount} sensitive value(s) from ${outputKind}.`,
					pending.toolName,
					pending.target,
					pending.ruleId,
					{
						source: pending.source,
						redactionScope: config.readRedaction.scope,
						pathProtected: Boolean(pending.ruleId),
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
