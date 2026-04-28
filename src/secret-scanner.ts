import { SECRET_PATTERNS } from "./constants.js";
import type { SecretFinding, SecretSeverity } from "./types.js";

const SEVERITY_ORDER: Record<SecretSeverity, number> = {
	medium: 1,
	high: 2,
	critical: 3,
};

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

export function severityAtOrAbove(
	severity: SecretSeverity,
	threshold: SecretSeverity,
): boolean {
	return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function scanContentForSecrets(
	content: string,
	maxFindings: number,
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

			findings.push(
				createFinding(
					line,
					selectSecretMatchText(match, pattern.secretGroup),
					pattern.name,
					pattern.severity,
					index + 1,
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

			findings.push(
				createFinding(
					content,
					selectSecretMatchText(match, pattern.secretGroup),
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
