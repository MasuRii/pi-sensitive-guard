import { SECRET_PATTERNS } from "./constants.js";
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
const CODE_REFERENCE_VALUE_PATTERN = /^(?:process\.env\.|import\.meta\.env\.)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;
const TEST_FIXTURE_PATH_PATTERN = /(?:^|[\\/._-])(?:__tests__|tests?|specs?|fixtures?|mocks?|samples?|examples?)(?:[\\/._-]|$)/i;
const PLACEHOLDER_SECRET_WORD_PATTERN = /(?:^|[-_.])(?:test|fake|mock|dummy|fixture|sample|example|synthetic|placeholder|stale)(?:[-_.]|$)/i;
const HUMAN_READABLE_FIXTURE_VALUE_PATTERN = /^[a-z0-9]+(?:[-_.][a-z0-9]+)+$/;
const NON_SECRET_ASSIGNMENT_VALUES = new Set([
	"boolean",
	"false",
	"null",
	"number",
	"object",
	"private",
	"protected",
	"public",
	"string",
	"true",
	"undefined",
	"unknown",
	"void",
]);

export interface SecretScanOptions {
	file?: string;
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

function stripAssignmentValueSyntax(matchText: string): string {
	let value = matchText.trim().replace(/[;,]+$/g, "").trim();
	const quote = value[0];
	if ((quote === '"' || quote === "'") && value.endsWith(quote)) {
		value = value.slice(1, -1).trim();
	}
	return value;
}

function isCodeReferenceValue(matchText: string): boolean {
	return CODE_REFERENCE_VALUE_PATTERN.test(stripAssignmentValueSyntax(matchText));
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

	const value = stripAssignmentValueSyntax(matchText);
	return (
		!value ||
		NON_SECRET_ASSIGNMENT_VALUES.has(value.toLowerCase()) ||
		isCodeReferenceValue(value) ||
		isFixtureAssignmentValue(value, options.file)
	);
}

export function severityAtOrAbove(
	severity: SecretSeverity,
	threshold: SecretSeverity,
): boolean {
	return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function scanContentForSecrets(
	content: string,
	maxFindings: number,
	options: SecretScanOptions = {},
): SecretFinding[] {
	if (!content || maxFindings <= 0) {
		return [];
	}

	const findings: SecretFinding[] = [];
	const lines = content.split(/\r?\n/);

	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		for (const pattern of SECRET_PATTERNS) {
			const match = line.match(pattern.pattern);
			if (!match) {
				continue;
			}

			const matchText = selectSecretMatchText(match, pattern.secretGroup);
			if (shouldIgnoreAssignmentFinding(pattern.name, matchText, options)) {
				continue;
			}

			findings.push(
				createFinding(
					line,
					matchText,
					pattern.name,
					pattern.severity,
					index + 1,
					options.file,
				),
			);
			break;
		}

		if (findings.length >= maxFindings) {
			break;
		}
	}

	return findings;
}

export function scanDiffForSecrets(
	diff: string,
	maxFindings: number,
): SecretFinding[] {
	if (!diff || maxFindings <= 0) {
		return [];
	}

	const findings: SecretFinding[] = [];
	const lines = diff.split(/\r?\n/);
	let currentFile: string | undefined;

	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index] ?? "";
		if (line.startsWith("+++ b/")) {
			currentFile = line.slice(6);
			continue;
		}

		if (!line.startsWith("+") || line.startsWith("+++")) {
			continue;
		}

		const content = line.slice(1);
		for (const pattern of SECRET_PATTERNS) {
			const match = content.match(pattern.pattern);
			if (!match) {
				continue;
			}

			const matchText = selectSecretMatchText(match, pattern.secretGroup);
			if (shouldIgnoreAssignmentFinding(pattern.name, matchText, { file: currentFile })) {
				continue;
			}

			findings.push(
				createFinding(
					content,
					matchText,
					pattern.name,
					pattern.severity,
					index + 1,
					currentFile,
				),
			);
			break;
		}

		if (findings.length >= maxFindings) {
			break;
		}
	}

	return findings;
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
