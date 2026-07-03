import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { normalizeSensitiveGuardConfig } from "../src/config.js";
import * as configModule from "../src/config.js";
import type { ResolvedSensitiveGuardConfig } from "../src/types.js";

const PROJECT_RULE_PATTERN = "(^|[\\/])project-local-secrets\.json$";

const mergeSensitiveGuardConfigs =
	(configModule as unknown as {
		mergeSensitiveGuardConfigs?: (
			global: unknown,
			project: unknown,
		) => ResolvedSensitiveGuardConfig;
	}).mergeSensitiveGuardConfigs ??
	(() => normalizeSensitiveGuardConfig({ enabled: true }).config);

test("multi-scope config merge layers project-local rules on top of global defaults", () => {
	const globalConfig = {
		enabled: true,
		rules: [
			{
				id: "global-secrets",
				patterns: [{ pattern: "(^|[\\/])\.env$", regex: true }],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};

	const projectConfig = {
		rules: [
			{
				id: "project-local-secrets",
				patterns: [{ pattern: PROJECT_RULE_PATTERN, regex: true }],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};

	const merged = mergeSensitiveGuardConfigs(globalConfig, projectConfig);

	assert.ok(
		merged.rules.some((rule) => rule.id === "global-secrets"),
		"expected global rule to survive merge",
	);
	assert.ok(
		merged.rules.some((rule) => rule.id === "project-local-secrets"),
		"expected project-local rule to be added by merge",
	);
});

test("project-local rule overrides a global rule with the same id", () => {
	const globalConfig = {
		enabled: true,
		rules: [
			{
				id: "shared-rule",
				patterns: [{ pattern: "(^|[\\/])\.env$", regex: true }],
				allowedPatterns: [],
				protection: "readOnly",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};

	const projectConfig = {
		rules: [
			{
				id: "shared-rule",
				patterns: [{ pattern: "(^|[\\/])\.env$", regex: true }],
				allowedPatterns: [],
				protection: "noAccess",
				onlyIfExists: false,
				enabled: true,
			},
		],
	};

	const merged = mergeSensitiveGuardConfigs(globalConfig, projectConfig);

	const matchingRules = merged.rules.filter((rule) => rule.id === "shared-rule");
	assert.equal(matchingRules.length, 1);
	assert.equal(matchingRules[0]?.protection, "noAccess");
});

test("project-local enabled=false does not disable a globally enabled guard", () => {
	const globalConfig = { enabled: true };
	const projectConfig = { enabled: false };

	const merged = mergeSensitiveGuardConfigs(globalConfig, projectConfig);

	assert.equal(merged.enabled, true);
});

test("mergeSensitiveGuardConfigs loads project-local config from a path and merges with global config", () => {
	const tempDir = mkdtempSync(join(tmpdir(), "pi-sensitive-guard-merge-"));
	const projectConfigPath = join(tempDir, "sensitive-guard.local.json");
	writeFileSync(
		projectConfigPath,
		`${JSON.stringify({
			rules: [
				{
					id: "project-local-secrets",
					patterns: [{ pattern: PROJECT_RULE_PATTERN, regex: true }],
					allowedPatterns: [],
					protection: "noAccess",
					onlyIfExists: false,
					enabled: true,
				},
			],
		})}\n`,
		"utf-8",
	);

	try {
		const globalConfig = normalizeSensitiveGuardConfig({ enabled: true }).config;
		const merged = mergeSensitiveGuardConfigs(globalConfig, projectConfigPath);

		assert.ok(
			merged.rules.some((rule) => rule.id === "project-local-secrets"),
			"expected project-local rule loaded from path",
		);
		assert.ok(
			merged.rules.some((rule) => rule.id === "default-sensitive-files"),
			"expected default global rules to survive merge",
		);
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
});
