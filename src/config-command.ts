import { existsSync, readFileSync, writeFileSync } from "node:fs";

import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
} from "@mariozechner/pi-coding-agent";

import { ensureConfigExists } from "./config.js";
import {
	DEFAULT_BLOCKED_EVENTS_LOG_PATH,
	EXTENSION_NAME,
	PRIMARY_CONFIG_PATH,
} from "./constants.js";
import type {
	ReadRedactionScope,
	ResolvedSensitiveGuardConfig,
	SecretSeverity,
} from "./types.js";

interface ConfigCommandOptions {
	getConfig: () => ResolvedSensitiveGuardConfig;
	refreshConfig: (ctx: ExtensionContext) => void;
}

type RuntimeConfig = Record<string, unknown>;
type RuntimeConfigMutator = (config: RuntimeConfig) => void;

interface MenuItem {
	label: string;
	run: () => Promise<boolean>;
}

const READ_REDACTION_SCOPES: ReadRedactionScope[] = ["protectedOnly", "allOutput"];
const SECRET_SEVERITIES: SecretSeverity[] = ["critical", "high", "medium"];

function toObject(value: unknown): RuntimeConfig {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as RuntimeConfig)
		: {};
}

function getNestedObject(config: RuntimeConfig, key: string): RuntimeConfig {
	const current = config[key];
	if (current && typeof current === "object" && !Array.isArray(current)) {
		return current as RuntimeConfig;
	}

	const next: RuntimeConfig = {};
	config[key] = next;
	return next;
}

function setReadRedactionValue(
	config: RuntimeConfig,
	key: string,
	value: boolean | number | string,
): void {
	getNestedObject(config, "readRedaction")[key] = value;
}

function setBlockedEventsValue(
	config: RuntimeConfig,
	key: string,
	value: boolean | string,
): void {
	getNestedObject(config, "blockedEvents")[key] = value;
}

function setContentScanningValue(
	config: RuntimeConfig,
	key: string,
	value: boolean | number | string,
): void {
	getNestedObject(config, "contentScanning")[key] = value;
}

function setProtectedFileEditsValue(
	config: RuntimeConfig,
	key: string,
	value: boolean,
): void {
	getNestedObject(config, "protectedFileEdits")[key] = value;
}

function readRuntimeConfig(): { config?: RuntimeConfig; error?: string } {
	const ensureResult = ensureConfigExists();
	if (ensureResult.error) {
		return { error: ensureResult.error };
	}

	try {
		if (!existsSync(PRIMARY_CONFIG_PATH)) {
			return { config: {} };
		}

		const parsed = JSON.parse(readFileSync(PRIMARY_CONFIG_PATH, "utf-8")) as unknown;
		return { config: toObject(parsed) };
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return { error: `Failed to read ${PRIMARY_CONFIG_PATH}: ${message}` };
	}
}

function writeRuntimeConfig(mutator: RuntimeConfigMutator): string | undefined {
	const loaded = readRuntimeConfig();
	if (loaded.error) {
		return loaded.error;
	}

	try {
		const config = loaded.config ?? {};
		mutator(config);
		writeFileSync(PRIMARY_CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
		return undefined;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return `Failed to write ${PRIMARY_CONFIG_PATH}: ${message}`;
	}
}

function formatOnOff(value: boolean): string {
	return value ? "on" : "off";
}

function formatStatus(config: ResolvedSensitiveGuardConfig): string {
	return [
		`${EXTENSION_NAME}`,
		`Guard: ${formatOnOff(config.enabled)}`,
		`Read redaction: ${formatOnOff(config.readRedaction.enabled)} (${config.readRedaction.scope})`,
		`Shell redaction: ${formatOnOff(config.readRedaction.includeShellOutput)}`,
		`Blocked-event file: ${formatOnOff(config.blockedEvents.log)}`,
		`Debug file: ${formatOnOff(config.debug)}`,
		`Content scan: ${formatOnOff(config.contentScanning.enabled)} (${config.contentScanning.blockSeverity})`,
		`Protected edits: ${formatOnOff(config.protectedFileEdits.enabled)}`,
	].join("\n");
}

async function persistAndRefresh(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
	mutator: RuntimeConfigMutator,
	successMessage: string,
): Promise<void> {
	const error = writeRuntimeConfig(mutator);
	if (error) {
		ctx.ui.notify(`${EXTENSION_NAME}: ${error}`, "error");
		return;
	}

	options.refreshConfig(ctx);
	ctx.ui.notify(successMessage, "info");
}

async function selectReadRedactionScope(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	const selected = await ctx.ui.select(
		"Read redaction scope",
		READ_REDACTION_SCOPES.map((scope) =>
			scope === "protectedOnly"
				? "protectedOnly - redact protected reads only"
				: "allOutput - redact every read and shell output",
		),
	);
	const scope = READ_REDACTION_SCOPES.find((entry) => selected?.startsWith(entry));
	if (!scope) {
		return;
	}

	await persistAndRefresh(
		ctx,
		options,
		(config) => setReadRedactionValue(config, "scope", scope),
		`${EXTENSION_NAME}: read redaction scope set to ${scope}.`,
	);
}

async function selectContentScanSeverity(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	const selected = await ctx.ui.select(
		"Content scan block severity",
		SECRET_SEVERITIES.map((severity) => `${severity}`),
	);
	const severity = SECRET_SEVERITIES.find((entry) => selected === entry);
	if (!severity) {
		return;
	}

	await persistAndRefresh(
		ctx,
		options,
		(config) => setContentScanningValue(config, "blockSeverity", severity),
		`${EXTENSION_NAME}: content scan severity set to ${severity}.`,
	);
}

async function setMaxRedactionBytes(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	const current = options.getConfig().readRedaction.maxBytes;
	const input = await ctx.ui.input("readRedaction.maxBytes", String(current));
	if (input === undefined) {
		return;
	}

	const parsed = Number.parseInt(input.trim(), 10);
	if (!Number.isInteger(parsed) || parsed <= 0) {
		ctx.ui.notify(`${EXTENSION_NAME}: maxBytes MUST be a positive integer.`, "error");
		return;
	}

	await persistAndRefresh(
		ctx,
		options,
		(config) => setReadRedactionValue(config, "maxBytes", parsed),
		`${EXTENSION_NAME}: max redaction bytes set to ${parsed}.`,
	);
}

async function setBlockedEventLogPath(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	const current = options.getConfig().blockedEvents.logPath || DEFAULT_BLOCKED_EVENTS_LOG_PATH;
	const input = await ctx.ui.input("blockedEvents.logPath", current);
	if (input === undefined) {
		return;
	}

	const nextPath = input.trim();
	if (!nextPath) {
		ctx.ui.notify(`${EXTENSION_NAME}: logPath MUST be a non-empty path.`, "error");
		return;
	}

	await persistAndRefresh(
		ctx,
		options,
		(config) => setBlockedEventsValue(config, "logPath", nextPath),
		`${EXTENSION_NAME}: blocked-event log path updated.`,
	);
}

async function editRawConfig(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	const loaded = readRuntimeConfig();
	if (loaded.error) {
		ctx.ui.notify(`${EXTENSION_NAME}: ${loaded.error}`, "error");
		return;
	}

	const current = `${JSON.stringify(loaded.config ?? {}, null, 2)}\n`;
	const edited = await ctx.ui.editor("pi-sensitive-guard config.json", current);
	if (edited === undefined || edited === current) {
		return;
	}

	try {
		JSON.parse(edited);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		ctx.ui.notify(`${EXTENSION_NAME}: invalid JSON: ${message}`, "error");
		return;
	}

	try {
		writeFileSync(PRIMARY_CONFIG_PATH, edited.endsWith("\n") ? edited : `${edited}\n`, "utf-8");
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		ctx.ui.notify(`${EXTENSION_NAME}: failed to save config: ${message}`, "error");
		return;
	}

	options.refreshConfig(ctx);
	ctx.ui.notify(`${EXTENSION_NAME}: config saved and applied.`, "info");
}

function buildMenuItems(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): MenuItem[] {
	const config = options.getConfig();
	return [
		{
			label: `Guard: ${formatOnOff(config.enabled)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => {
						runtimeConfig.enabled = !config.enabled;
					},
					`${EXTENSION_NAME}: guard ${formatOnOff(!config.enabled)}.`,
				);
				return true;
			},
		},
		{
			label: `Read redaction: ${formatOnOff(config.readRedaction.enabled)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setReadRedactionValue(
						runtimeConfig,
						"enabled",
						!config.readRedaction.enabled,
					),
					`${EXTENSION_NAME}: read redaction ${formatOnOff(!config.readRedaction.enabled)}.`,
				);
				return true;
			},
		},
		{
			label: `Read redaction scope: ${config.readRedaction.scope}`,
			run: async () => {
				await selectReadRedactionScope(ctx, options);
				return true;
			},
		},
		{
			label: `Shell output redaction: ${formatOnOff(config.readRedaction.includeShellOutput)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setReadRedactionValue(
						runtimeConfig,
						"includeShellOutput",
						!config.readRedaction.includeShellOutput,
					),
					`${EXTENSION_NAME}: shell redaction ${formatOnOff(!config.readRedaction.includeShellOutput)}.`,
				);
				return true;
			},
		},
		{
			label: `Blocked-event file logging: ${formatOnOff(config.blockedEvents.log)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setBlockedEventsValue(
						runtimeConfig,
						"log",
						!config.blockedEvents.log,
					),
					`${EXTENSION_NAME}: blocked-event file logging ${formatOnOff(!config.blockedEvents.log)}.`,
				);
				return true;
			},
		},
		{
			label: `Blocked-event bus emit: ${formatOnOff(config.blockedEvents.emit)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setBlockedEventsValue(
						runtimeConfig,
						"emit",
						!config.blockedEvents.emit,
					),
					`${EXTENSION_NAME}: blocked-event bus emit ${formatOnOff(!config.blockedEvents.emit)}.`,
				);
				return true;
			},
		},
		{
			label: `Debug file logging: ${formatOnOff(config.debug)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => {
						runtimeConfig.debug = !config.debug;
					},
					`${EXTENSION_NAME}: debug logging ${formatOnOff(!config.debug)}.`,
				);
				return true;
			},
		},
		{
			label: `Content scan: ${formatOnOff(config.contentScanning.enabled)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setContentScanningValue(
						runtimeConfig,
						"enabled",
						!config.contentScanning.enabled,
					),
					`${EXTENSION_NAME}: content scan ${formatOnOff(!config.contentScanning.enabled)}.`,
				);
				return true;
			},
		},
		{
			label: `Content scan severity: ${config.contentScanning.blockSeverity}`,
			run: async () => {
				await selectContentScanSeverity(ctx, options);
				return true;
			},
		},
		{
			label: `Protected-file safe edits: ${formatOnOff(config.protectedFileEdits.enabled)}`,
			run: async () => {
				await persistAndRefresh(
					ctx,
					options,
					(runtimeConfig) => setProtectedFileEditsValue(
						runtimeConfig,
						"enabled",
						!config.protectedFileEdits.enabled,
					),
					`${EXTENSION_NAME}: protected-file safe edits ${formatOnOff(!config.protectedFileEdits.enabled)}.`,
				);
				return true;
			},
		},
		{
			label: `Max redaction bytes: ${config.readRedaction.maxBytes}`,
			run: async () => {
				await setMaxRedactionBytes(ctx, options);
				return true;
			},
		},
		{
			label: `Blocked-event log path: ${config.blockedEvents.logPath}`,
			run: async () => {
				await setBlockedEventLogPath(ctx, options);
				return true;
			},
		},
		{
			label: "Edit raw config JSON",
			run: async () => {
				await editRawConfig(ctx, options);
				return true;
			},
		},
		{
			label: "Show status",
			run: async () => {
				ctx.ui.notify(formatStatus(options.getConfig()), "info");
				return true;
			},
		},
		{
			label: "Done",
			run: async () => false,
		},
	];
}

async function openConfigMenu(
	ctx: ExtensionCommandContext,
	options: ConfigCommandOptions,
): Promise<void> {
	if (!ctx.hasUI) {
		ctx.ui.notify(`${EXTENSION_NAME}: UI unavailable. Edit ${PRIMARY_CONFIG_PATH}.`, "warning");
		return;
	}

	let keepOpen = true;
	while (keepOpen) {
		const menuItems = buildMenuItems(ctx, options);
		const selected = await ctx.ui.select(
			"pi-sensitive-guard config",
			menuItems.map((item) => item.label),
		);
		const item = menuItems.find((entry) => entry.label === selected);
		if (!item) {
			return;
		}
		keepOpen = await item.run();
	}
}

export function registerSensitiveGuardConfigCommand(
	pi: ExtensionAPI,
	options: ConfigCommandOptions,
): void {
	if (typeof pi.registerCommand !== "function") {
		return;
	}

	pi.registerCommand("sensitive-guard", {
		description: "Configure pi-sensitive-guard",
		getArgumentCompletions: (prefix) => {
			const completions = ["status", "edit"].filter((entry) => entry.startsWith(prefix));
			return completions.length > 0
				? completions.map((value) => ({ value, label: value }))
				: null;
		},
		handler: async (args, ctx) => {
			const command = args.trim().toLowerCase();
			if (command === "status") {
				ctx.ui.notify(formatStatus(options.getConfig()), "info");
				return;
			}
			if (command === "edit") {
				await editRawConfig(ctx, options);
				return;
			}

			await openConfigMenu(ctx, options);
		},
	});
}
