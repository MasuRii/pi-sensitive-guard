import { formatSecretFindings } from "./secret-scanner.js";
import type { SecretFinding } from "./types.js";

export const READ_SECURITY_MESSAGE = `
════════════════════════════════════════════════════════════════════════════════
🔒 SECURITY BLOCK: SENSITIVE FILE READ ACCESS DENIED
════════════════════════════════════════════════════════════════════════════════

This request was blocked because it attempts to READ a sensitive file.

WHY THIS IS BLOCKED:
• Sensitive files often contain credentials, tokens, private keys, or secrets
• These values must never be exposed, logged, or transmitted without user action
• This protection applies to direct file reads and risky shell command access

EXAMPLES OF PROTECTED FILES:
• .env and .env.* files
• .npmrc, .pypirc, and .netrc
• SSH private keys such as id_rsa and id_ed25519
• Secret or credential files such as secrets.json or credentials.yml
• Private key bundles such as .pem, .key, .p12, .pfx, .jks, and .keystore

SAFE ALTERNATIVES:
• Ask the user which variables or values are relevant
• Reference example/template files that match the configured safe patterns
• Describe the required setup steps instead of reading the secret directly

This is a hard security boundary. Attempting to bypass it is inappropriate.
════════════════════════════════════════════════════════════════════════════════
`.trim();

export const WRITE_SECURITY_MESSAGE = `
════════════════════════════════════════════════════════════════════════════════
🔒 SECURITY BLOCK: SENSITIVE FILE WRITE ACCESS DENIED
════════════════════════════════════════════════════════════════════════════════

This request was blocked because it attempts to CREATE, OVERWRITE, or EDIT a
sensitive file.

WHY THIS IS BLOCKED:
• Sensitive files are usually maintained manually by the user
• Automated writes can silently replace credentials or corrupt working secrets
• This protection applies to write/edit tools and risky shell write commands

WHAT TO DO INSTEAD:
• Ask the user to update the sensitive file manually
• Write instructions or a safe example file rather than the real secret file
• Use non-sensitive template/example targets when preparing config changes

This is a hard security boundary. Attempting to bypass it is inappropriate.
════════════════════════════════════════════════════════════════════════════════
`.trim();

export const DELETE_SECURITY_MESSAGE = `
════════════════════════════════════════════════════════════════════════════════
🔒 SECURITY BLOCK: SENSITIVE FILE DELETION DENIED
════════════════════════════════════════════════════════════════════════════════

This request was blocked because it attempts to DELETE or DESTROY a sensitive
file.

WHY THIS IS BLOCKED:
• Sensitive files often contain credentials that are difficult to recover
• Deleting them can break applications, environments, or developer access
• This protection applies to delete, trash, clean, and destructive move commands

WHAT TO DO INSTEAD:
• Ask the user to perform intentional cleanup manually
• Exclude sensitive targets from cleanup commands
• Use template/example files for safe housekeeping tasks

This is a hard security boundary. Attempting to bypass it is inappropriate.
════════════════════════════════════════════════════════════════════════════════
`.trim();

export function buildContentScanSecurityMessage(findings: SecretFinding[]): string {
	return `
════════════════════════════════════════════════════════════════════════════════
🔒 SECURITY BLOCK: SECRET CONTENT DETECTED
════════════════════════════════════════════════════════════════════════════════

This request was blocked because the content being written appears to contain
real secrets or credentials.

DETECTED FINDINGS:
${formatSecretFindings(findings)}

WHAT TO DO INSTEAD:
• Replace live secrets with placeholders before writing files
• Ask the user to inject credentials manually outside the agent session
• Use example or template files when documenting required environment values

This is a hard security boundary. Attempting to bypass it is inappropriate.
════════════════════════════════════════════════════════════════════════════════
`.trim();
}

export function buildGitProtectionSecurityMessage(
	action: "commit" | "push",
	details: string,
): string {
	const verb = action === "commit" ? "COMMIT" : "PUSH";
	return `
════════════════════════════════════════════════════════════════════════════════
🔒 SECURITY BLOCK: GIT ${verb} DENIED
════════════════════════════════════════════════════════════════════════════════

This request was blocked because the git ${action} would include protected files
or secret content.

DETECTED FINDINGS:
${details}

WHAT TO DO INSTEAD:
• Remove the sensitive change from the staged or outgoing diff
• Move credentials into local-only files or secret managers
• Commit templates, placeholders, or documented setup steps instead

This is a hard security boundary. Attempting to bypass it is inappropriate.
════════════════════════════════════════════════════════════════════════════════
`.trim();
}
