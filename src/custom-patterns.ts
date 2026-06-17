import type { CustomSecretPatternConfig, SecretPatternDefinition, SecretSeverity } from "./types.js";

// Re-export so existing `import { CustomSecretPatternConfig } from "./custom-patterns.js"` still works.
export type { CustomSecretPatternConfig };

/**
 * Compile a user-provided custom pattern config (from JSON) into a runtime
 * SecretPatternDefinition with a compiled RegExp.
 *
 * Returns null and pushes a warning if the regex is invalid.
 */
export function compileCustomPattern(
	config: CustomSecretPatternConfig,
	warnings: string[],
	pathPrefix: string,
): SecretPatternDefinition | null {
	if (!config.name || typeof config.name !== "string" || config.name.trim().length === 0) {
		warnings.push(`Invalid config value '${pathPrefix}.name': expected a non-empty string.`);
		return null;
	}

	if (!config.pattern || typeof config.pattern !== "string" || config.pattern.trim().length === 0) {
		warnings.push(`Invalid config value '${pathPrefix}.pattern': expected a non-empty regex string.`);
		return null;
	}

	const validSeverities: SecretSeverity[] = ["critical", "high", "medium"];
	if (!validSeverities.includes(config.severity)) {
		warnings.push(
			`Invalid config value '${pathPrefix}.severity': expected one of 'critical', 'high', or 'medium'.`,
		);
		return null;
	}

	const flags = config.flags ?? "i";
	if (!/^[gimsuy]*$/.test(flags)) {
		warnings.push(
			`Invalid config value '${pathPrefix}.flags': expected only valid regex flags (i, g, m, s, u, y).`,
		);
		return null;
	}

	let compiled: RegExp;
	try {
		compiled = new RegExp(config.pattern, flags);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		warnings.push(`Invalid config value '${pathPrefix}.pattern': invalid regular expression: ${message}`);
		return null;
	}

	const definition: SecretPatternDefinition = {
		name: config.name.trim(),
		pattern: compiled,
		severity: config.severity,
	};

	if (
		typeof config.secretGroup === "number" &&
		Number.isInteger(config.secretGroup) &&
		config.secretGroup > 0
	) {
		definition.secretGroup = config.secretGroup;
	}

	return definition;
}

/**
 * Compile an array of custom pattern configs into SecretPatternDefinitions.
 * Invalid patterns are skipped with warnings.
 */
export function compileCustomPatterns(
	configs: unknown,
	warnings: string[],
	pathPrefix: string,
): SecretPatternDefinition[] {
	if (!Array.isArray(configs)) {
		return [];
	}

	const compiled: SecretPatternDefinition[] = [];
	for (const [index, entry] of configs.entries()) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
			warnings.push(`Invalid config value '${pathPrefix}[${index}]': expected an object.`);
			continue;
		}

		const definition = compileCustomPattern(
			entry as CustomSecretPatternConfig,
			warnings,
			`${pathPrefix}[${index}]`,
		);
		if (definition) {
			compiled.push(definition);
		}
	}

	return compiled;
}
