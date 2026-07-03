import { redactSensitiveReadContent } from "./read-redactor.js";
import { describeError, toRecord } from "./shared/index.js";
import type { ResolvedSensitiveGuardConfig } from "./types.js";

interface EditReplacement {
	oldText: string;
	newText: string;
	all?: boolean;
}

interface ParsedKeyValueLine {
	key: string;
	value: string;
}

interface NormalizedEditReplacements {
	replacements: EditReplacement[];
	error?: string;
}

interface ParsedAnchor {
	line: number;
	textHint?: string;
}

type StructuredLineEdit =
	| { kind: "replace"; start: ParsedAnchor; end?: ParsedAnchor; lines: string[] }
	| { kind: "append"; anchor?: ParsedAnchor; lines: string[] }
	| { kind: "prepend"; anchor?: ParsedAnchor; lines: string[] };

interface StructuredEditApplication {
	content: string;
	recognized: boolean;
	error?: string;
}

interface PiNativeEditDiffModule {
	normalizeToLF: (text: string) => string;
	applyEditsToNormalizedContent: (
		normalizedContent: string,
		edits: Array<Pick<EditReplacement, "oldText" | "newText">>,
		path: string,
	) => { baseContent: string; newContent: string };
}

type PiNativeEditDiffModuleLoader = () => Promise<unknown>;

export interface ProtectedFileEditEvaluation {
	allowed: boolean;
	reason: string;
}

export const PI_NATIVE_EDIT_DIFF_FALLBACK_NOTE =
	"Pi v0.79.7 does not publicly export normalizeToLF/applyEditsToNormalizedContent; " +
	"pi-sensitive-guard probes @earendil-works/pi-coding-agent's internal core/tools/edit-diff.js module " +
	"and uses a fallback to manual exact text replacement when the internal module is missing or invalid.";

let piNativeEditDiffModulePromise: Promise<PiNativeEditDiffModule | undefined> | undefined;
let piNativeEditDiffModuleLoader: PiNativeEditDiffModuleLoader = importPiNativeEditDiffModule;

function resolvePiNativeEditDiffModuleUrl(): string {
	const packageEntryUrl = import.meta.resolve("@earendil-works/pi-coding-agent");
	return new URL("./core/tools/edit-diff.js", packageEntryUrl).href;
}

async function importPiNativeEditDiffModule(): Promise<unknown> {
	return import(resolvePiNativeEditDiffModuleUrl());
}

function isPiNativeEditDiffModule(module: unknown): module is PiNativeEditDiffModule {
	const candidate = module as Partial<PiNativeEditDiffModule>;
	return (
		typeof candidate.normalizeToLF === "function" &&
		typeof candidate.applyEditsToNormalizedContent === "function"
	);
}

export function __setPiNativeEditDiffModuleLoaderForTest(loader?: PiNativeEditDiffModuleLoader): void {
	piNativeEditDiffModulePromise = undefined;
	piNativeEditDiffModuleLoader = loader ?? importPiNativeEditDiffModule;
}

async function loadPiNativeEditDiffModule(): Promise<PiNativeEditDiffModule | undefined> {
	piNativeEditDiffModulePromise ??= piNativeEditDiffModuleLoader()
		.then((module: unknown) => (isPiNativeEditDiffModule(module) ? module : undefined))
		.catch(() => undefined);
	return piNativeEditDiffModulePromise;
}

function normalizePiNativeEditError(message: string): string {
	if (/Could not find (?:the exact text|edits\[\d+\])/.test(message)) {
		return `Text replacement oldText was not found in the current file. Pi native edit detail: ${message}`;
	}

	if (/Found \d+ occurrences/.test(message)) {
		return `Text replacement oldText is not unique in the current file. Pi native edit detail: ${message}`;
	}

	return message;
}

async function applyPiNativeTextReplacements(
	content: string,
	replacements: EditReplacement[],
	path: string,
): Promise<StructuredEditApplication | undefined> {
	if (replacements.some((replacement) => replacement.all)) {
		return undefined;
	}

	const piEditDiff = await loadPiNativeEditDiffModule();
	if (!piEditDiff) {
		return undefined;
	}

	try {
		const normalizedContent = piEditDiff.normalizeToLF(content);
		const { newContent } = piEditDiff.applyEditsToNormalizedContent(
			normalizedContent,
			replacements.map(({ oldText, newText }) => ({ oldText, newText })),
			path,
		);
		return { content: newContent, recognized: true };
	} catch (error) {
		const message = describeError(error);
		return { content, recognized: true, error: normalizePiNativeEditError(message) };
	}
}

const JSON_KEY_VALUE_PATTERN = /^\s*"([^"]+)"\s*:\s*(.*?)\s*,?\s*$/;
const KEY_VALUE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$/;

function createAllowedEvaluation(): ProtectedFileEditEvaluation {
	return { allowed: true, reason: "Only non-sensitive values changed." };
}

function createBlockedEvaluation(reason: string): ProtectedFileEditEvaluation {
	return { allowed: false, reason };
}

function splitLines(content: string): string[] {
	return content.split(/\r?\n/);
}


function normalizeExactText(text: string): string {
	return text.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
}

function normalizeEditTextLines(value: unknown, emptyStringDeletes = false): string[] | undefined {
	if (Array.isArray(value)) {
		return value.every((line) => typeof line === "string") ? value : undefined;
	}

	if (value === null) {
		return [];
	}

	if (typeof value !== "string") {
		return undefined;
	}

	const normalized = normalizeExactText(value);
	if (emptyStringDeletes && normalized.length === 0) {
		return [];
	}

	const withoutFinalNewline = normalized.endsWith("\n")
		? normalized.slice(0, -1)
		: normalized;
	return withoutFinalNewline.split("\n");
}


function normalizeEditReplacements(editsOrInput: unknown): NormalizedEditReplacements {
	const root = toRecord(editsOrInput);
	const edits = Array.isArray(editsOrInput)
		? editsOrInput
		: Array.isArray(root.edits)
			? root.edits
			: [];
	const replacements: EditReplacement[] = [];
	for (const [index, edit] of edits.entries()) {
		const editRecord = toRecord(edit);
		const oldText = editRecord.oldText ?? editRecord.old_text;
		const newText = editRecord.newText ?? editRecord.new_text;
		if (typeof oldText === "string" && typeof newText === "string") {
			replacements.push({ oldText, newText });
			continue;
		}

		return {
			replacements: [],
			error: `Protected file edit ${index} bypass requires exact oldText/newText replacements or a supported structured line-edit shape.`,
		};
	}
	if (replacements.length > 0) {
		return { replacements };
	}

	const topLevelOldText = root.oldText ?? root.old_text;
	const topLevelNewText = root.newText ?? root.new_text;
	if (typeof topLevelOldText === "string" || typeof topLevelNewText === "string") {
		if (typeof topLevelOldText === "string" && typeof topLevelNewText === "string") {
			return { replacements: [{ oldText: topLevelOldText, newText: topLevelNewText }] };
		}
		return {
			replacements: [],
			error: "Protected file edit bypass requires both oldText and newText for legacy replacements.",
		};
	}

	return { replacements };
}

function parseAnchor(value: unknown): ParsedAnchor | undefined {
	if (typeof value !== "string") {
		return undefined;
	}

	const trimmed = value.replace(/^\s*[>+\-]*\s*/, "").trimEnd();
	const hashAnchor = trimmed.match(/^(\d+)\s*#\s*([^\s:|]+)(?::(.*))?$/s);
	const colonAnchor = hashAnchor
		? null
		: trimmed.match(/^(\d+)\s*:\s*([^\s|]+)(?:\|(.*))?$/s);
	const match = hashAnchor ?? colonAnchor;
	if (!match) {
		return undefined;
	}

	const line = Number.parseInt(match[1] ?? "", 10);
	if (!Number.isInteger(line) || line < 1) {
		return undefined;
	}

	const textHint = match[3];
	return textHint === undefined ? { line } : { line, textHint };
}

function getReplacementLines(record: Record<string, unknown>): string[] | undefined {
	if (Object.prototype.hasOwnProperty.call(record, "lines")) {
		return normalizeEditTextLines(record.lines);
	}

	for (const key of ["newText", "new_text", "text", "content"] as const) {
		if (Object.prototype.hasOwnProperty.call(record, key)) {
			return normalizeEditTextLines(record[key], key === "new_text" || key === "text" || key === "content");
		}
	}

	return undefined;
}

function buildAnchorEdit(
	kind: "append" | "prepend",
	record: Record<string, unknown>,
): StructuredLineEdit | undefined {
	const lines = getReplacementLines(record);
	if (!lines) {
		return undefined;
	}
	const anchor = parseAnchor(record.pos ?? record.anchor);
	return anchor ? { kind, anchor, lines } : { kind, lines };
}

function buildSimpleReplaceEdit(record: Record<string, unknown>): StructuredLineEdit | undefined {
	const start = parseAnchor(record.anchor ?? record.pos);
	const lines = getReplacementLines(record);
	return start && lines ? { kind: "replace", start, lines } : undefined;
}

function buildReplaceEdit(
	record: Record<string, unknown>,
	startAnchor: unknown,
	endAnchor: unknown,
): StructuredLineEdit | undefined {
	const start = parseAnchor(startAnchor);
	const lines = getReplacementLines(record);
	if (!start || !lines) {
		return undefined;
	}
	const end = parseAnchor(endAnchor);
	return end ? { kind: "replace", start, end, lines } : { kind: "replace", start, lines };
}

function buildRangedReplaceEdit(record: Record<string, unknown>): StructuredLineEdit | undefined {
	return buildReplaceEdit(
		record,
		record.start_anchor ?? record.pos ?? record.anchor,
		record.end_anchor ?? record.end,
	);
}

function parseStructuredLineEdit(edit: unknown): StructuredLineEdit | undefined {
	const record = toRecord(edit);
	const op = record.op;

	if (op === "replace") {
		return buildReplaceEdit(
			record,
			record.pos ?? record.anchor ?? record.start_anchor,
			record.end ?? record.end_anchor,
		);
	}

	if (op === "append" || op === "insert_after") {
		return buildAnchorEdit("append", record);
	}

	if (op === "prepend") {
		return buildAnchorEdit("prepend", record);
	}

	if (op === "set_line") {
		return buildSimpleReplaceEdit(record);
	}

	if (op === "replace_lines") {
		return buildRangedReplaceEdit(record);
	}

	const setLine = toRecord(record.set_line);
	if (Object.keys(setLine).length > 0) {
		return buildSimpleReplaceEdit(setLine);
	}

	const replaceLines = toRecord(record.replace_lines);
	if (Object.keys(replaceLines).length > 0) {
		return buildRangedReplaceEdit(replaceLines);
	}

	const insertAfter = toRecord(record.insert_after);
	if (Object.keys(insertAfter).length > 0) {
		const anchor = parseAnchor(insertAfter.anchor ?? insertAfter.pos);
		const lines = getReplacementLines(insertAfter);
		return anchor && lines ? { kind: "append", anchor, lines } : undefined;
	}

	return undefined;
}

function resolveAnchorIndex(anchor: ParsedAnchor, fileLines: string[]): { index: number; error?: string } {
	const expectedIndex = anchor.line - 1;
	const expectedLine = fileLines[expectedIndex];
	if (anchor.textHint !== undefined) {
		const textHint = anchor.textHint.replace(/\r$/, "");
		if (expectedLine === textHint) {
			return { index: expectedIndex };
		}

		const matchingIndexes = fileLines
			.map((line, index) => ({ line, index }))
			.filter((entry) => entry.line === textHint)
			.map((entry) => entry.index);
		if (matchingIndexes.length === 1) {
			return { index: matchingIndexes[0] ?? expectedIndex };
		}

		return {
			index: expectedIndex,
			error: `Structured line-edit anchor ${anchor.line} does not match current file content.`,
		};
	}

	if (expectedIndex < 0 || expectedIndex >= fileLines.length) {
		return {
			index: expectedIndex,
			error: `Structured line-edit anchor ${anchor.line} is outside the current file.`,
		};
	}

	return { index: expectedIndex };
}

function getContentLines(content: string): string[] {
	const lines = normalizeExactText(content).split("\n");
	return content.endsWith("\n") || content.endsWith("\r\n") ? lines.slice(0, -1) : lines;
}

function joinContentLines(lines: string[], hadTerminalNewline: boolean): string {
	if (lines.length === 0) {
		return "";
	}

	const content = lines.join("\n");
	return hadTerminalNewline ? `${content}\n` : content;
}

function applyStructuredLineEdits(content: string, edits: StructuredLineEdit[]): StructuredEditApplication {
	const hadTerminalNewline = content.endsWith("\n") || content.endsWith("\r\n");
	const fileLines = getContentLines(content);
	const operations: Array<{ start: number; deleteCount: number; lines: string[] }> = [];

	for (const edit of edits) {
		if (edit.kind === "append" || edit.kind === "prepend") {
			const defaultStart = edit.kind === "append" ? fileLines.length : 0;
			const anchorOffset = edit.kind === "append" ? 1 : 0;
			if (!edit.anchor) {
				operations.push({ start: defaultStart, deleteCount: 0, lines: edit.lines });
				continue;
			}

			const anchor = resolveAnchorIndex(edit.anchor, fileLines);
			if (anchor.error) {
				return { content, recognized: true, error: anchor.error };
			}
			operations.push({ start: anchor.index + anchorOffset, deleteCount: 0, lines: edit.lines });
			continue;
		}

		const start = resolveAnchorIndex(edit.start, fileLines);
		if (start.error) {
			return { content, recognized: true, error: start.error };
		}
		const end = edit.end ? resolveAnchorIndex(edit.end, fileLines) : start;
		if (end.error) {
			return { content, recognized: true, error: end.error };
		}
		if (end.index < start.index) {
			return {
				content,
				recognized: true,
				error: "Structured line-edit range end is before its start anchor.",
			};
		}

		operations.push({
			start: start.index,
			deleteCount: end.index - start.index + 1,
			lines: edit.lines,
		});
	}

	const sorted = operations
		.map((operation, index) => ({ ...operation, index }))
		.sort((left, right) => right.start - left.start || right.index - left.index);
	let previousStart: number | undefined;
	let previousDeleteEnd: number | undefined;
	const nextLines = [...fileLines];
	for (const operation of sorted) {
		if (
			previousStart !== undefined &&
			previousDeleteEnd !== undefined &&
			operation.deleteCount > 0 &&
			operation.start < previousDeleteEnd &&
			operation.start + operation.deleteCount > previousStart
		) {
			return {
				content,
				recognized: true,
				error: "Structured line-edit operations overlap and cannot be evaluated safely.",
			};
		}

		nextLines.splice(operation.start, operation.deleteCount, ...operation.lines);
		if (operation.deleteCount > 0) {
			previousStart = operation.start;
			previousDeleteEnd = operation.start + operation.deleteCount;
		}
	}

	return {
		content: joinContentLines(nextLines, hadTerminalNewline),
		recognized: true,
	};
}

function applyTextReplacement(content: string, replacement: EditReplacement): StructuredEditApplication {
	if (replacement.oldText.length === 0) {
		return { content, recognized: true, error: "Text replacement requires non-empty oldText." };
	}

	const oldText = normalizeExactText(replacement.oldText);
	const newText = normalizeExactText(replacement.newText);
	const matches: number[] = [];
	let from = 0;
	while (from <= content.length - oldText.length) {
		const index = content.indexOf(oldText, from);
		if (index === -1) {
			break;
		}
		matches.push(index);
		from = index + Math.max(oldText.length, 1);
	}

	if (matches.length === 0) {
		return { content, recognized: true, error: "Text replacement oldText was not found in the current file." };
	}

	if (!replacement.all && matches.length !== 1) {
		return { content, recognized: true, error: "Text replacement oldText is not unique in the current file." };
	}

	if (replacement.all) {
		return { content: content.split(oldText).join(newText), recognized: true };
	}

	const index = matches[0] ?? 0;
	return {
		content: content.slice(0, index) + newText + content.slice(index + oldText.length),
		recognized: true,
	};
}

function extractTextReplacement(edit: unknown): EditReplacement | undefined {
	const record = toRecord(edit);
	const oldText = record.oldText ?? record.old_text;
	const newText = record.newText ?? record.new_text;
	if (typeof oldText === "string" && typeof newText === "string") {
		return { oldText, newText, all: record.all === true };
	}

	const replace = toRecord(record.replace);
	if (Object.keys(replace).length > 0) {
		const replaceOldText = replace.oldText ?? replace.old_text;
		const replaceNewText = replace.newText ?? replace.new_text;
		if (typeof replaceOldText === "string" && typeof replaceNewText === "string") {
			return { oldText: replaceOldText, newText: replaceNewText, all: replace.all === true };
		}
	}

	return undefined;
}

function getEditInputPath(root: Record<string, unknown>): string {
	return typeof root.path === "string" ? root.path : "protected file";
}

async function applyStructuredEditInput(
	currentContent: string,
	editsOrInput: unknown,
): Promise<StructuredEditApplication> {
	const root = toRecord(editsOrInput);
	const path = getEditInputPath(root);
	const topLevelOldText = root.oldText ?? root.old_text;
	const topLevelNewText = root.newText ?? root.new_text;
	let content = currentContent;

	if (typeof topLevelOldText === "string" || typeof topLevelNewText === "string") {
		if (typeof topLevelOldText !== "string" || typeof topLevelNewText !== "string") {
			return {
				content,
				recognized: true,
				error: "Protected file edit bypass requires both oldText and newText for legacy replacements.",
			};
		}

		const piNativeResult = await applyPiNativeTextReplacements(
			content,
			[{ oldText: topLevelOldText, newText: topLevelNewText }],
			path,
		);
		return piNativeResult ?? applyTextReplacement(content, { oldText: topLevelOldText, newText: topLevelNewText });
	}

	const rawEdits = Array.isArray(editsOrInput)
		? editsOrInput
		: Array.isArray(root.edits)
			? root.edits
			: [];
	if (rawEdits.length === 0) {
		return { content, recognized: false };
	}

	const nativeTextReplacements: EditReplacement[] = [];
	let allEditsAreNativeTextReplacements = true;
	for (const edit of rawEdits) {
		const textReplacement = extractTextReplacement(edit);
		if (!textReplacement || textReplacement.all) {
			allEditsAreNativeTextReplacements = false;
			break;
		}
		nativeTextReplacements.push(textReplacement);
	}

	if (allEditsAreNativeTextReplacements) {
		const piNativeResult = await applyPiNativeTextReplacements(
			content,
			nativeTextReplacements,
			path,
		);
		if (piNativeResult) {
			return piNativeResult;
		}
	}

	const lineEdits: StructuredLineEdit[] = [];
	for (const [index, edit] of rawEdits.entries()) {
		const textReplacement = extractTextReplacement(edit);
		if (textReplacement) {
			const result = applyTextReplacement(content, textReplacement);
			if (result.error) {
				return result;
			}
			content = result.content;
			continue;
		}

		const lineEdit = parseStructuredLineEdit(edit);
		if (!lineEdit) {
			return {
				content,
				recognized: true,
				error: `Protected file edit ${index} uses an unsupported shape and cannot be evaluated safely.`,
			};
		}
		lineEdits.push(lineEdit);
	}

	if (lineEdits.length === 0) {
		return { content, recognized: true };
	}

	return applyStructuredLineEdits(content, lineEdits);
}

function parseKeyValueLine(line: string): ParsedKeyValueLine | null {
	const jsonMatch = line.match(JSON_KEY_VALUE_PATTERN);
	if (jsonMatch?.[1] !== undefined) {
		return {
			key: jsonMatch[1],
			value: jsonMatch[2] ?? "",
		};
	}

	const keyValueMatch = line.match(KEY_VALUE_PATTERN);
	if (keyValueMatch?.[1] !== undefined) {
		return {
			key: keyValueMatch[1],
			value: keyValueMatch[2] ?? "",
		};
	}

	return null;
}

function containsSensitiveKeyOrValue(
	content: string,
	config: ResolvedSensitiveGuardConfig,
): boolean {
	if (!content.trim()) {
		return false;
	}

	return redactSensitiveReadContent(content, {
		...config.readRedaction,
		enabled: true,
		redactSecretPatterns: true,
	}).redacted;
}

function isSafeStandaloneLineChange(
	line: string,
	config: ResolvedSensitiveGuardConfig,
): boolean {
	if (!line.trim()) {
		return true;
	}

	if (parseKeyValueLine(line)) {
		return false;
	}

	return !containsSensitiveKeyOrValue(line, config);
}

function evaluateChangedLinePair(
	oldLine: string,
	newLine: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (oldLine === newLine) {
		return createAllowedEvaluation();
	}

	const oldParsed = parseKeyValueLine(oldLine);
	const newParsed = parseKeyValueLine(newLine);
	if (oldParsed && newParsed) {
		if (oldParsed.key !== newParsed.key) {
			return createBlockedEvaluation(
				`Protected file edit changes key '${oldParsed.key}' to '${newParsed.key}'.`,
			);
		}

		if (
			containsSensitiveKeyOrValue(oldLine, config) ||
			containsSensitiveKeyOrValue(newLine, config)
		) {
			return createBlockedEvaluation(
				`Protected file edit changes sensitive key or value '${oldParsed.key}'.`,
			);
		}

		return createAllowedEvaluation();
	}

	if (oldParsed || newParsed) {
		return createBlockedEvaluation(
			"Protected file edit changes key/value structure instead of only changing a non-sensitive value.",
		);
	}

	if (
		containsSensitiveKeyOrValue(oldLine, config) ||
		containsSensitiveKeyOrValue(newLine, config)
	) {
		return createBlockedEvaluation(
			"Protected file edit changes content that contains a sensitive value.",
		);
	}

	return createAllowedEvaluation();
}

function evaluateChangedContent(
	oldContent: string,
	newContent: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	const oldLines = splitLines(oldContent);
	const newLines = splitLines(newContent);
	let oldIndex = 0;
	let newIndex = 0;

	while (oldIndex < oldLines.length || newIndex < newLines.length) {
		const oldLine = oldLines[oldIndex];
		const newLine = newLines[newIndex];
		if (oldLine !== undefined && newLine !== undefined && oldLine === newLine) {
			oldIndex += 1;
			newIndex += 1;
			continue;
		}

		if (newLine !== undefined && isSafeStandaloneLineChange(newLine, config)) {
			newIndex += 1;
			continue;
		}

		if (oldLine !== undefined && isSafeStandaloneLineChange(oldLine, config)) {
			oldIndex += 1;
			continue;
		}

		if (oldLine !== undefined && newLine !== undefined) {
			const result = evaluateChangedLinePair(oldLine, newLine, config);
			if (!result.allowed) {
				return result;
			}

			oldIndex += 1;
			newIndex += 1;
			continue;
		}

		return createBlockedEvaluation(
			"Protected file edit changes keys or sensitive values instead of only safe content.",
		);
	}

	return createAllowedEvaluation();
}

export function evaluateProtectedFileEdits(
	editsOrInput: unknown,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (!config.protectedFileEdits.enabled) {
		return createBlockedEvaluation("Protected file non-sensitive edit bypass is disabled.");
	}

	const normalized = normalizeEditReplacements(editsOrInput);
	if (normalized.error) {
		return createBlockedEvaluation(normalized.error);
	}

	for (const edit of normalized.replacements) {
		const result = evaluateChangedContent(edit.oldText, edit.newText, config);
		if (!result.allowed) {
			return result;
		}
	}

	return createAllowedEvaluation();
}

export async function evaluateProtectedFileEditInput(
	currentContent: string,
	editsOrInput: unknown,
	config: ResolvedSensitiveGuardConfig,
): Promise<ProtectedFileEditEvaluation> {
	if (!config.protectedFileEdits.enabled) {
		return createBlockedEvaluation("Protected file non-sensitive edit bypass is disabled.");
	}

	const application = await applyStructuredEditInput(currentContent, editsOrInput);
	if (application.error) {
		return createBlockedEvaluation(application.error);
	}

	if (!application.recognized) {
		return evaluateProtectedFileEdits(editsOrInput, config);
	}

	return evaluateChangedContent(currentContent, application.content, config);
}

export function evaluateProtectedFileWrite(
	currentContent: string,
	nextContent: string,
	config: ResolvedSensitiveGuardConfig,
): ProtectedFileEditEvaluation {
	if (!config.protectedFileEdits.enabled) {
		return createBlockedEvaluation("Protected file non-sensitive write bypass is disabled.");
	}

	return evaluateChangedContent(currentContent, nextContent, config);
}
