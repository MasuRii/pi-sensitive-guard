import assert from "node:assert/strict";
import test from "node:test";

import { DEFAULT_CONFIG } from "../src/constants.js";
import { createSensitiveGuardMatcher } from "../src/detector.js";

for (const command of [
	"rg secret src",
	"rg secrets src",
	"grep credential README.md",
	"rg '.env' src",
	"rg --glob '!**/auth.json' secret .",
	"rg --glob='!**/auth.json' secret .",
	"rg -g '!**/auth.json' secret .",
	"rg -g'!**/auth.json' secret .",
	"rg --iglob auth.json secret .",
	"grep --exclude auth.json secret README.md",
	"grep --include .env secret README.md",
	"grep --exclude-dir credentials secret README.md",
	"grep --label credentials secret README.md",
	"rg --type-add 'secret:*.ts' secret src",
	"rg --replace secret pattern src",
	"rg -nreplacement secret src",
	"grep -rn secret src",
	"rg -e secret src",
	"rg -nesecret src",
	"rg --regexp=secret src",
	"grep -e secret -e credentials README.md",
	"grep --regexp secret README.md",
	"grep -e secret -- README.md",
	"rg -- secret src",
	"rg secret --glob auth.json src",
	"rg --files --glob auth.json .",
	"/usr/bin/grep -n secret README.md",
	"LC_ALL=C rg secret src",
	"rg -E utf-8 secret src",
	"grep -E secret README.md",
	"grep --color secret README.md",
	"rg -e '' src",
	"rg --regexp='' src",
	"rg -f patterns.txt src",
	"rg --ignore-file .gitignore secret src",
	"grep --exclude-from .gitignore secret README.md",
]) {
	test(`does not treat search text or metadata as a protected read: ${command}`, async () => {
		const matcher = createSensitiveGuardMatcher(DEFAULT_CONFIG);
		const result = await matcher.checkReadCommand(command);

		assert.equal(result.blocked, false, result.reason);
	});
}

for (const command of [
	"rg pattern .env",
	"grep pattern credentials.json",
	"rg secret auth.json",
	"rg --glob '!**/auth.json' secret .env",
	"grep --exclude auth.json secret .env",
	"rg -e pattern .env",
	"rg -nepattern .env",
	"rg --regexp=pattern .env",
	"grep --regexp pattern .env",
	"grep .env -e pattern",
	"rg -- pattern .env",
	"grep -e pattern -- .env",
	"rg -f .env src",
	"rg -f.env src",
	"rg -nf.env src",
	"grep --file .env README.md",
	"grep --file=.env README.md",
	"rg --ignore-file .env pattern src",
	"rg --ignore-file=.env pattern src",
	"grep --exclude-from .env pattern README.md",
	"grep --exclude-from=.env pattern README.md",
	"rg -f patterns.txt .env",
	"rg --files .env",
	"rg pattern < .env",
	"grep -e pattern < .env",
	"rg --unknown-option pattern .env",
	"rg --no-config -f.env src",
	"rg -f.env --unknown-option src",
	"grep --unknown-option --file=.env README.md",
	"grep --color pattern .env",
	"rg -E utf-8 pattern .env",
	"grep -E pattern .env",
	"rg -n -e secret credentials.json",
	"LC_ALL=C rg secret .env",
	"rg -e pattern -- -secret.key",
	"grep -e pattern -- -secret.key",
]) {
	test(`still blocks protected search input: ${command}`, async () => {
		const matcher = createSensitiveGuardMatcher(DEFAULT_CONFIG);
		const result = await matcher.checkReadCommand(command);

		assert.equal(result.blocked, true, command);
		assert.equal(result.kind, "read");
	});
}
