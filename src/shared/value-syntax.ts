/**
 * Regex matching code-reference values (e.g. `process.env.FOO`,
 * `import.meta.env.BAR`, `config.secretKey`) that should be excluded from
 * secret detection because they reference a value rather than containing it.
 */
export const CODE_REFERENCE_VALUE_PATTERN =
	/^(?:process\.env\.|import\.meta\.env\.)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/;

/**
 * Non-secret literal values that appear in type annotations and config schemas.
 * Used to exclude TypeScript/JSON literal keywords from secret detection.
 */
export const NON_SECRET_VALUES = new Set([
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

/**
 * Strips surrounding quotes and trailing statement separators (`;`, `,`) from a
 * raw value/match text so the inner value can be inspected for sensitivity.
 */
export function stripValueSyntax(rawValue: string): string {
	let value = rawValue.trim().replace(/[;,]+$/g, "").trim();
	const quote = value[0];
	if ((quote === '"' || quote === "'") && value.endsWith(quote)) {
		value = value.slice(1, -1).trim();
	}
	return value;
}

/**
 * Returns true when the value (after stripping quote/separator syntax) is a
 * code reference such as `process.env.FOO` or `config.apiKey`, indicating it
 * references a secret rather than containing one inline.
 */
export function isCodeReferenceValue(rawValue: string): boolean {
	return CODE_REFERENCE_VALUE_PATTERN.test(stripValueSyntax(rawValue));
}
