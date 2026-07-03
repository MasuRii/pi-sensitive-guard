import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

import { SECRET_PATTERNS } from "./constants.js";
import {
	isCodeReferenceValue,
	NON_SECRET_VALUES,
	stripValueSyntax,
} from "./shared/index.js";
import type { SecretFinding, SecretSeverity } from "./types.js";

const SEVERITY_ORDER: Record<SecretSeverity, number> = {
	medium: 1,
	high: 2,
	critical: 3,
};
const ASSIGNMENT_FINDING_NAMES = new Set([
	"API Key Assignment",
	"Secret Assignment",
	"Password Assignment",
	"Token Assignment",
	"Sensitive Credential Assignment",
]);
const TEST_FIXTURE_PATH_PATTERN = /(?:^|[\\/._-])(?:__tests__|tests?|specs?|fixtures?|mocks?|samples?|examples?)(?:[\\/._-]|$)/i;
const PLACEHOLDER_SECRET_WORD_PATTERN = /(?:^|[-_.])(?:test|fake|mock|dummy|fixture|sample|example|synthetic|placeholder|stale)(?:[-_.]|$)/i;
const HUMAN_READABLE_FIXTURE_VALUE_PATTERN = /^[a-z0-9]+(?:[-_.][a-z0-9]+)+$/;

export interface SecretScanOptions {
	file?: string;
}

export interface CachedSecretScanResult {
	findings: SecretFinding[];
}

export interface SecretScanCacheStats {
	hits: number;
	misses: number;
	size: number;
}

interface SecretScanCacheEntry {
	mtimeMs: number;
	size: number;
	contentHash: string;
	findings: SecretFinding[];
}

let scanCacheHits = 0;
let scanCacheMisses = 0;
const scanCache = new Map<string, SecretScanCacheEntry>();

function cloneFindings(findings: SecretFinding[]): SecretFinding[] {
	return findings.map((finding) => ({ ...finding }));
}

function createScanCacheKey(filePath: string, maxFindings: number): string {
	return `${filePath}\u0000${maxFindings}`;
}

function hashContent(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

export function resetScanCache(): void {
	scanCache.clear();
	scanCacheHits = 0;
	scanCacheMisses = 0;
}

export function getScanCacheStats(): SecretScanCacheStats {
	return {
		hits: scanCacheHits,
		misses: scanCacheMisses,
		size: scanCache.size,
	};
}

export function scanFileForSecretsCached(
	filePath: string,
	maxFindings: number,
): CachedSecretScanResult {
	const stats = statSync(filePath);
	const content = readFileSync(filePath, "utf-8");
	const contentHash = hashContent(content);
	const cacheKey = createScanCacheKey(filePath, maxFindings);
	const cached = scanCache.get(cacheKey);
	if (
		cached &&
		cached.mtimeMs === stats.mtimeMs &&
		cached.size === stats.size &&
		cached.contentHash === contentHash
	) {
		scanCacheHits += 1;
		return { findings: cloneFindings(cached.findings) };
	}

	scanCacheMisses += 1;
	const findings = scanContentForSecrets(content, maxFindings, { file: filePath });
	scanCache.set(cacheKey, {
		mtimeMs: stats.mtimeMs,
		size: stats.size,
		contentHash,
		findings: cloneFindings(findings),
	});
	return { findings };
}

function sanitizeSnippet(snippet: string): string {
	return snippet.replace(/\s+/g, " ").trim().slice(0, 160);
}

function maskMatch(line: string, matchText: string, label: string): string {
	if (!matchText) {
		return sanitizeSnippet(line);
	}

	return sanitizeSnippet(line.replace(matchText, `[REDACTED ${label}]`));
}

function selectSecretMatchText(
	match: RegExpMatchArray,
	secretGroup?: number,
): string {
	if (secretGroup === undefined) {
		return match[0] ?? "";
	}

	return match[secretGroup] ?? match[0] ?? "";
}

function createFinding(
	line: string,
	matchText: string,
	name: string,
	severity: SecretSeverity,
	lineNumber?: number,
	file?: string,
): SecretFinding {
	return {
		name,
		severity,
		line: lineNumber,
		file,
		snippet: maskMatch(line, matchText, name),
	};
}

function isTestFixturePath(file: string | undefined): boolean {
	return typeof file === "string" && TEST_FIXTURE_PATH_PATTERN.test(file);
}

function isHumanReadableFixtureValue(value: string): boolean {
	if (!HUMAN_READABLE_FIXTURE_VALUE_PATTERN.test(value)) {
		return false;
	}

	return value
		.split(/[-_.]/g)
		.every((segment) => segment.length > 0 && segment.length <= 16 && !/^\d{6,}$/.test(segment));
}

function isFixtureAssignmentValue(value: string, file: string | undefined): boolean {
	if (!isTestFixturePath(file)) {
		return false;
	}

	return PLACEHOLDER_SECRET_WORD_PATTERN.test(value) || isHumanReadableFixtureValue(value);
}

function shouldIgnoreAssignmentFinding(
	name: string,
	matchText: string,
	options: SecretScanOptions = {},
): boolean {
	if (!ASSIGNMENT_FINDING_NAMES.has(name)) {
		return false;
	}

	const value = stripValueSyntax(matchText);
	return (
		!value ||
		NON_SECRET_VALUES.has(value.toLowerCase()) ||
		isCodeReferenceValue(matchText) ||
		isFixtureAssignmentValue(value, options.file)
	);
}

export function severityAtOrAbove(
	severity: SecretSeverity,
	threshold: SecretSeverity,
): boolean {
	return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

function findFirstSecretInLine(
	lineContent: string,
	lineNumber: number,
	file: string | undefined,
	options: SecretScanOptions,
): SecretFinding | undefined {
	for (const pattern of SECRET_PATTERNS) {
		const match = lineContent.match(pattern.pattern);
		if (!match) {
			continue;
		}

		const matchText = selectSecretMatchText(match, pattern.secretGroup);
		if (shouldIgnoreAssignmentFinding(pattern.name, matchText, options)) {
			continue;
		}

		return createFinding(
			lineContent,
			matchText,
			pattern.name,
			pattern.severity,
			lineNumber,
			file,
		);
	}
	return undefined;
}

function scanLinesForSecrets(
	lines: string[],
	maxFindings: number,
	processLine: (line: string, index: number) => SecretFinding | undefined,
): SecretFinding[] {
	const findings: SecretFinding[] = [];
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		const finding = processLine(line, index);
		if (finding) {
			findings.push(finding);
		}

		if (findings.length >= maxFindings) {
			break;
		}
	}
	return findings;
}

export function scanContentForSecrets(
	content: string,
	maxFindings: number,
	options: SecretScanOptions = {},
): SecretFinding[] {
	if (!content || maxFindings <= 0) {
		return [];
	}

	const lines = content.split(/\r?\n/);

	return scanLinesForSecrets(lines, maxFindings, (line, index) =>
		findFirstSecretInLine(line, index + 1, options.file, options),
	);
}

export function scanDiffForSecrets(
	diff: string,
	maxFindings: number,
): SecretFinding[] {
	if (!diff || maxFindings <= 0) {
		return [];
	}

	const lines = diff.split(/\r?\n/);
	let currentFile: string | undefined;

	return scanLinesForSecrets(lines, maxFindings, (line, index) => {
		if (line.startsWith("+++ b/")) {
			currentFile = line.slice(6);
			return undefined;
		}

		if (!line.startsWith("+") || line.startsWith("+++")) {
			return undefined;
		}

		return findFirstSecretInLine(line.slice(1), index + 1, currentFile, { file: currentFile });
	});
}

export function getBlockableSecretFindings(
	findings: SecretFinding[],
	threshold: SecretSeverity,
): SecretFinding[] {
	return findings.filter((finding) => severityAtOrAbove(finding.severity, threshold));
}

export function formatSecretFindings(findings: SecretFinding[]): string {
	if (findings.length === 0) {
		return "No secret findings.";
	}

	return findings
		.map((finding) => {
			const locationParts: string[] = [];
			if (finding.file) {
				locationParts.push(finding.file);
			}
			if (finding.line) {
				locationParts.push(`line ${finding.line}`);
			}
			const location = locationParts.length > 0 ? ` (${locationParts.join(": ")})` : "";
			return `- ${finding.name} [${finding.severity}]${location}: ${finding.snippet}`;
		})
		.join("\n");
}
