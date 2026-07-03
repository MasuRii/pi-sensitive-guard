/**
 * Returns command-completion entries for the `sensitive-guard` command.
 * Shared by the extension entry point (registerCommand getArgumentCompletions)
 * and the config-command module so the completion list is defined once.
 */
export function getSensitiveGuardConfigCompletions(
	prefix: string,
): { value: string; label: string }[] | null {
	const completions = ["status", "edit"].filter((entry) => entry.startsWith(prefix));
	return completions.length > 0
		? completions.map((value) => ({ value, label: value }))
		: null;
}
