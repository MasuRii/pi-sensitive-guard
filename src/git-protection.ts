import type { ExecResult } from "@earendil-works/pi-coding-agent";

import { formatSecretFindings, getBlockableSecretFindings, scanDiffForSecrets } from "./secret-scanner.js";
import { parseShellCommand } from "./shell-parser.js";
import type {
	GitProtectionCheckResult,
	ResolvedSensitiveGuardConfig,
	SensitiveGuardMatcher,
} from "./types.js";

interface GitActionTarget {
	action: "commit" | "push";
	commitAll: boolean;
}

interface GitExec {
	(command: string, args: string[], options?: { cwd?: string; timeout?: number }): Promise<ExecResult>;
}

function createAllowedResult(): GitProtectionCheckResult {
	return { blocked: false, reason: "" };
}

async function detectGitActions(
	command: string,
	config: ResolvedSensitiveGuardConfig,
): Promise<GitActionTarget[]> {
	const actions = new Map<string, GitActionTarget>();

	for (const parsedCommand of await parseShellCommand(command)) {
		const words = parsedCommand.words.map((word) => word.trim().toLowerCase()).filter(Boolean);
		if (words[0] !== "git") {
			continue;
		}

		const subcommand = words[1];
		if (subcommand === "commit" && config.gitProtection.enabled && config.gitProtection.blockCommit) {
			const commitAll = words.some(
				(word) =>
					word === "-a" ||
					word === "--all" ||
					(word.startsWith("-") && word.includes("a") && word.length > 2),
			);
			actions.set("commit", { action: "commit", commitAll });
		}

		if (subcommand === "push" && config.gitProtection.enabled && config.gitProtection.blockPush) {
			actions.set("push", { action: "push", commitAll: false });
		}
	}

	return [...actions.values()];
}

async function runGit(
	exec: GitExec,
	cwd: string,
	timeout: number,
	args: string[],
): Promise<ExecResult> {
	return exec("git", args, { cwd, timeout });
}

async function ensureGitRepository(
	exec: GitExec,
	cwd: string,
	timeout: number,
): Promise<boolean> {
	const result = await runGit(exec, cwd, timeout, ["rev-parse", "--is-inside-work-tree"]);
	return result.code === 0 && result.stdout.trim() === "true";
}

function collectDiffPaths(diff: string): string[] {
	const paths = new Set<string>();
	for (const line of diff.split(/\r?\n/)) {
		if (line.startsWith("+++ b/")) {
			const path = line.slice(6).trim();
			if (path && path !== "/dev/null") {
				paths.add(path);
			}
			continue;
		}

		if (line.startsWith("--- a/")) {
			const path = line.slice(6).trim();
			if (path && path !== "/dev/null") {
				paths.add(path);
			}
		}
	}

	return [...paths];
}

async function getCommitDiff(
	exec: GitExec,
	cwd: string,
	config: ResolvedSensitiveGuardConfig,
	target: GitActionTarget,
): Promise<{ diff: string; error?: string }> {
	const staged = await runGit(exec, cwd, config.gitProtection.diffTimeoutMs, [
		"diff",
		"--cached",
		"--binary",
		"--no-ext-diff",
		"--relative",
	]);
	if (staged.code !== 0) {
		return {
			diff: "",
			error: staged.stderr.trim() || "Unable to inspect staged git changes.",
		};
	}

	if (!target.commitAll) {
		return { diff: staged.stdout };
	}

	const tracked = await runGit(exec, cwd, config.gitProtection.diffTimeoutMs, [
		"diff",
		"--binary",
		"--no-ext-diff",
		"--relative",
	]);
	if (tracked.code !== 0) {
		return {
			diff: staged.stdout,
			error: tracked.stderr.trim() || "Unable to inspect tracked git changes for git commit --all.",
		};
	}

	return {
		diff: [staged.stdout, tracked.stdout].filter((part) => part.trim().length > 0).join("\n"),
	};
}

async function getPushCommitHashes(
	exec: GitExec,
	cwd: string,
	config: ResolvedSensitiveGuardConfig,
): Promise<{ hashes: string[]; error?: string }> {
	const withUpstream = await runGit(exec, cwd, config.gitProtection.diffTimeoutMs, [
		"rev-list",
		"--reverse",
		"@{upstream}..HEAD",
	]);
	if (withUpstream.code === 0) {
		return {
			hashes: withUpstream.stdout
				.split(/\r?\n/)
				.map((line) => line.trim())
				.filter((line) => line.length > 0)
				.slice(0, config.gitProtection.maxCommits),
		};
	}

	const withoutRemote = await runGit(exec, cwd, config.gitProtection.diffTimeoutMs, [
		"rev-list",
		"--reverse",
		"HEAD",
		"--not",
		"--remotes",
	]);
	if (withoutRemote.code !== 0) {
		return {
			hashes: [],
			error:
				withoutRemote.stderr.trim() || withUpstream.stderr.trim() || "Unable to inspect outgoing commits.",
		};
	}

	return {
		hashes: withoutRemote.stdout
			.split(/\r?\n/)
			.map((line) => line.trim())
			.filter((line) => line.length > 0)
			.slice(0, config.gitProtection.maxCommits),
	};
}

async function getPushDiff(
	exec: GitExec,
	cwd: string,
	config: ResolvedSensitiveGuardConfig,
): Promise<{ diff: string; error?: string }> {
	const hashes = await getPushCommitHashes(exec, cwd, config);
	if (hashes.error) {
		return { diff: "", error: hashes.error };
	}

	if (hashes.hashes.length === 0) {
		return { diff: "" };
	}

	const diffParts: string[] = [];
	for (const hash of hashes.hashes) {
		const show = await runGit(exec, cwd, config.gitProtection.diffTimeoutMs, [
			"show",
			"--binary",
			"--no-ext-diff",
			"--format=",
			"--relative",
			hash,
		]);
		if (show.code !== 0) {
			return {
				diff: diffParts.join("\n"),
				error: show.stderr.trim() || `Unable to inspect outgoing commit '${hash}'.`,
			};
		}
		if (show.stdout.trim().length > 0) {
			diffParts.push(show.stdout);
		}
	}

	return { diff: diffParts.join("\n") };
}

function createPathFindingSummary(paths: string[]): string {
	return paths.map((path) => `- Protected file change detected: ${path}`).join("\n");
}

export async function checkGitProtection(input: {
	command: string;
	cwd: string;
	exec: GitExec;
	matcher: SensitiveGuardMatcher;
	config: ResolvedSensitiveGuardConfig;
}): Promise<GitProtectionCheckResult> {
	const { command, cwd, exec, matcher, config } = input;
	const actions = await detectGitActions(command, config);
	if (actions.length === 0) {
		return createAllowedResult();
	}

	const isRepo = await ensureGitRepository(exec, cwd, config.gitProtection.diffTimeoutMs);
	if (!isRepo) {
		return createAllowedResult();
	}

	for (const actionTarget of actions) {
		const diffResult =
			actionTarget.action === "commit"
				? await getCommitDiff(exec, cwd, config, actionTarget)
				: await getPushDiff(exec, cwd, config);
		if (diffResult.error) {
			return {
				blocked: true,
				action: actionTarget.action,
				reason: `Sensitive guard could not inspect git ${actionTarget.action} changes: ${diffResult.error}`,
			};
		}

		const diff = diffResult.diff;
		if (!diff.trim()) {
			continue;
		}

		const protectedPaths = collectDiffPaths(diff)
			.map((path) => matcher.checkWritePath(path))
			.filter((result) => result.blocked);
		if (protectedPaths.length > 0) {
			const first = protectedPaths[0];
			return {
				blocked: true,
				action: actionTarget.action,
				target: first?.target,
				ruleId: first?.ruleId,
				reason: createPathFindingSummary(
					protectedPaths
						.map((result) => result.target)
						.filter((target): target is string => typeof target === "string"),
				),
				metadata: {
					protectedPaths: protectedPaths.map((result) => ({
						target: result.target,
						ruleId: result.ruleId,
						protection: result.protection,
					})),
				},
			};
		}

		if (config.contentScanning.enabled) {
			const findings = getBlockableSecretFindings(
				scanDiffForSecrets(diff, config.contentScanning.maxFindings, config.contentScanning.customPatterns),
				config.contentScanning.blockSeverity,
			);
			if (findings.length > 0) {
				return {
					blocked: true,
					action: actionTarget.action,
					reason: formatSecretFindings(findings),
					metadata: {
						findings,
					},
				};
			}
		}
	}

	return createAllowedResult();
}
