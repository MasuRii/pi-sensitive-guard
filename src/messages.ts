import { formatSecretFindings } from "./secret-scanner.js";
import type { SecretFinding } from "./types.js";

const MAX_FINDINGS_IN_MESSAGE = 5;

function formatCompactFindings(findings: SecretFinding[]): string {
	const shown = findings.slice(0, MAX_FINDINGS_IN_MESSAGE);
	const summary = formatSecretFindings(shown);
	const remaining = findings.length - shown.length;
	return remaining > 0 ? `${summary}\n- ${remaining} more finding(s).` : summary;
}

export const READ_SECURITY_MESSAGE =
	"Security block: protected read denied. Use a safe example/template file or ask the user for the required value.";

export const WRITE_SECURITY_MESSAGE =
	"Security block: protected write denied. Keep live secrets user-managed; write placeholders or templates only.";

export const DELETE_SECURITY_MESSAGE =
	"Security block: protected delete denied. Exclude sensitive files from cleanup or ask the user to remove them manually.";

export function buildContentScanSecurityMessage(findings: SecretFinding[]): string {
	return [
		"Security block: secret-like content detected.",
		formatCompactFindings(findings),
		"Replace live values with placeholders before writing.",
	].join("\n");
}

export function buildGitProtectionSecurityMessage(
	action: "commit" | "push",
	details: string,
): string {
	return [
		`Security block: git ${action} denied; protected files or secrets are included.`,
		details,
		"Remove sensitive changes, then retry.",
	].join("\n");
}
