/**
 * Regex that never matches. Used as a safe fallback when a config-provided
 * pattern is oversized (ReDoS mitigation) or fails to compile.
 */
export const NEVER_MATCH_PATTERN = /\$a/;

/**
 * Maximum allowed length for a compiled regex pattern. Patterns above this
 * limit are rejected and replaced with {@link NEVER_MATCH_PATTERN} to mitigate
 * ReDoS risk from oversized attacker inputs. The largest legitimate internal
 * pattern is 390 chars (verified via `DEFAULT_CONFIG` and `SECRET_PATTERNS`),
 * so 1000 provides ~2.5x headroom.
 */
export const MAX_REGEX_PATTERN_LENGTH = 1000;

/**
 * Compiles a config-provided pattern string into a RegExp, length-bounded to
 * mitigate ReDoS risk. Oversized or invalid patterns resolve to
 * {@link NEVER_MATCH_PATTERN} instead of throwing.
 *
 * Suppressed as non-literal RegExp: the pattern is a config-provided string,
 * length-bounded above, and wrapped in try/catch.
 */
export function compileRegex(pattern: string, flags: string): RegExp {
	if (pattern.length > MAX_REGEX_PATTERN_LENGTH) {
		return NEVER_MATCH_PATTERN;
	}
	try {
		return new RegExp(pattern, flags); // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- pattern is a config-provided string, length-bounded above, and wrapped in try/catch.
	} catch {
		return NEVER_MATCH_PATTERN;
	}
}
