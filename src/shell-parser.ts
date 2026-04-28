import { parse } from "@aliou/sh";
import type {
	Command,
	Program,
	SimpleCommand,
	Statement,
	Word,
	WordPart,
} from "@aliou/sh";

import type { ParsedShellCommand, ParsedShellRedirect } from "./types.js";

const QUOTED_OR_BARE_TOKEN_PATTERN =
	/"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`|[^\s]+/g;
const REDIRECT_TOKEN_PATTERN = /^(\d*>>?\|?|\d*<<?-?|&?>|<?&?|<>)(.*)$/;

function partToString(part: WordPart): string {
	switch (part.type) {
		case "Literal":
			return part.value;
		case "SglQuoted":
			return part.value;
		case "DblQuoted":
			return part.parts.map(partToString).join("");
		case "ParamExp":
			return part.short
				? `$${part.param.value}`
				: "${" +
					part.param.value +
					(part.op ?? "") +
					(part.value ? wordToString(part.value) : "") +
					"}";
		case "CmdSubst":
			return "$(...)";
		case "ArithExp":
			return `$((${part.expr}))`;
		case "ProcSubst":
			return `${part.op}(...)`;
	}

	return "";
}

function wordToString(word: Word): string {
	return word.parts.map(partToString).join("");
}

function walkCommands(
	node: Program,
	callback: (cmd: SimpleCommand) => boolean | undefined,
): void {
	for (const statement of node.body) {
		if (walkStatement(statement, callback)) {
			return;
		}
	}
}

function walkStatement(
	statement: Statement,
	callback: (cmd: SimpleCommand) => boolean | undefined,
): boolean {
	return walkCommand(statement.command, callback);
}

function walkStatements(
	statements: Statement[],
	callback: (cmd: SimpleCommand) => boolean | undefined,
): boolean {
	for (const statement of statements) {
		if (walkStatement(statement, callback)) {
			return true;
		}
	}

	return false;
}

function walkCommand(
	command: Command,
	callback: (cmd: SimpleCommand) => boolean | undefined,
): boolean {
	switch (command.type) {
		case "SimpleCommand":
			return callback(command) === true;
		case "Pipeline":
			return walkStatements(command.commands, callback);
		case "Logical":
			return (
				walkStatement(command.left, callback) ||
				walkStatement(command.right, callback)
			);
		case "Subshell":
		case "Block":
			return walkStatements(command.body, callback);
		case "IfClause":
			return (
				walkStatements(command.cond, callback) ||
				walkStatements(command.then, callback) ||
				(command.else ? walkStatements(command.else, callback) : false)
			);
		case "ForClause":
		case "SelectClause":
		case "WhileClause":
			return (
				("cond" in command && command.cond
					? walkStatements(command.cond, callback)
					: false) || walkStatements(command.body, callback)
			);
		case "CaseClause":
			for (const item of command.items) {
				if (walkStatements(item.body, callback)) {
					return true;
				}
			}
			return false;
		case "FunctionDecl":
			return walkStatements(command.body, callback);
		case "TimeClause":
			return walkStatement(command.command, callback);
		case "CoprocClause":
			return walkStatement(command.body, callback);
		case "CStyleLoop":
			return walkStatements(command.body, callback);
		case "TestClause":
		case "ArithCmd":
		case "DeclClause":
		case "LetClause":
			return false;
	}

	return false;
}

function tokenizeSegment(segment: string): string[] {
	return segment.match(QUOTED_OR_BARE_TOKEN_PATTERN) ?? [];
}

function stripOuterQuotes(value: string): string {
	if (value.length < 2) {
		return value;
	}

	const first = value[0];
	const last = value[value.length - 1];
	if (
		(first === '"' && last === '"') ||
		(first === "'" && last === "'") ||
		(first === "`" && last === "`")
	) {
		return value.slice(1, -1);
	}

	return value;
}

function splitRawSegments(command: string): string[] {
	return command
		.split(/(?:&&|\|\||;|\r?\n)/)
		.map((segment) => segment.trim())
		.filter((segment) => segment.length > 0);
}

function parseTokenRedirect(
	token: string,
	nextToken: string | undefined,
): { redirect: ParsedShellRedirect | null; consumedNext: boolean } {
	const match = REDIRECT_TOKEN_PATTERN.exec(token);
	if (!match) {
		return { redirect: null, consumedNext: false };
	}

	const operator = match[1] ?? undefined;
	const inlineTarget = stripOuterQuotes(match[2] ?? "").trim();
	if (inlineTarget) {
		return {
			redirect: { operator, target: inlineTarget },
			consumedNext: false,
		};
	}

	const target = stripOuterQuotes(nextToken ?? "").trim();
	return {
		redirect: target ? { operator, target } : null,
		consumedNext: target.length > 0,
	};
}

function parseTokenSegment(segment: string): ParsedShellCommand {
	const tokens = tokenizeSegment(segment);
	const words: string[] = [];
	const redirects: ParsedShellRedirect[] = [];

	for (let index = 0; index < tokens.length; index += 1) {
		const token = tokens[index] ?? "";
		const nextToken = tokens[index + 1];
		const redirectResult = parseTokenRedirect(token, nextToken);
		if (redirectResult.redirect) {
			redirects.push(redirectResult.redirect);
			if (redirectResult.consumedNext) {
				index += 1;
			}
			continue;
		}

		words.push(stripOuterQuotes(token));
	}

	return {
		raw: segment,
		words,
		redirects,
		parser: "token",
	};
}

function parseAstCommand(command: string): ParsedShellCommand[] {
	const parsedCommands: ParsedShellCommand[] = [];
	const { ast } = parse(command);

	walkCommands(ast, (simpleCommand) => {
		const words = (simpleCommand.words ?? []).map(wordToString);
		const redirects = (simpleCommand.redirects ?? []).map((redirect: unknown) => {
			const redirectRecord = redirect as { op?: string; target: Word };
			return {
				operator: redirectRecord.op,
				target: wordToString(redirectRecord.target),
			};
		});

		parsedCommands.push({
			raw: words.join(" "),
			words,
			redirects,
			parser: "ast",
		});
		return false;
	});

	return parsedCommands;
}

export function parseShellCommand(command: string): ParsedShellCommand[] {
	if (!command || typeof command !== "string") {
		return [];
	}

	try {
		const parsedCommands = parseAstCommand(command);
		if (parsedCommands.length > 0) {
			return parsedCommands;
		}
	} catch {
		// Fall through to token parsing for shells or syntaxes unsupported by @aliou/sh.
	}

	return splitRawSegments(command).map(parseTokenSegment);
}
