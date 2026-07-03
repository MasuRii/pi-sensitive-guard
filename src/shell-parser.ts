import type { ParsedShellCommand, ParsedShellRedirect } from "./types.js";

// --- Local structural types mirroring the @aliou/sh AST nodes consumed here. ---
// Defined locally (rather than imported from @aliou/sh) so the module's type
// contracts are explicit, self-documenting, and resilient to external package
// type-resolution differences under the type-aware linter's project service.

interface ShellLiteral {
	type: "Literal";
	value: string;
}

interface ShellSglQuoted {
	type: "SglQuoted";
	value: string;
}

interface ShellDblQuoted {
	type: "DblQuoted";
	parts: ShellWordPart[];
}

interface ShellParamExp {
	type: "ParamExp";
	short: boolean;
	param: { value: string };
	op?: string;
	value?: ShellWord;
}

interface ShellCmdSubst {
	type: "CmdSubst";
}

interface ShellArithExp {
	type: "ArithExp";
	expr: unknown;
}

interface ShellProcSubst {
	type: "ProcSubst";
	op: string;
}

interface ShellBraceExp {
	type: "BraceExp";
}

interface ShellExtGlob {
	type: "ExtGlob";
}

type ShellWordPart =
	| ShellLiteral
	| ShellSglQuoted
	| ShellDblQuoted
	| ShellParamExp
	| ShellCmdSubst
	| ShellArithExp
	| ShellProcSubst
	| ShellBraceExp
	| ShellExtGlob;

interface ShellWord {
	parts: ShellWordPart[];
}

interface ShellRedirect {
	op?: string;
	target: ShellWord;
}

interface ShellSimpleCommand {
	type: "SimpleCommand";
	words?: ShellWord[];
	redirects?: ShellRedirect[];
}

interface ShellPipeline {
	type: "Pipeline";
	commands: ShellStatement[];
}

interface ShellLogical {
	type: "Logical";
	left: ShellStatement;
	right: ShellStatement;
}

interface ShellSubshell {
	type: "Subshell";
	body: ShellStatement[];
}

interface ShellBlock {
	type: "Block";
	body: ShellStatement[];
}

interface ShellIfClause {
	type: "IfClause";
	cond: ShellStatement[];
	then: ShellStatement[];
	else?: ShellStatement[];
}

interface ShellWhileClause {
	type: "WhileClause";
	cond: ShellStatement[];
	body: ShellStatement[];
}

interface ShellForClause {
	type: "ForClause";
	body: ShellStatement[];
}

interface ShellSelectClause {
	type: "SelectClause";
	body: ShellStatement[];
}

interface ShellCaseItem {
	body: ShellStatement[];
}

interface ShellCaseClause {
	type: "CaseClause";
	items: ShellCaseItem[];
}

interface ShellFunctionDecl {
	type: "FunctionDecl";
	body: ShellStatement[];
}

interface ShellTimeClause {
	type: "TimeClause";
	command: ShellStatement;
}

interface ShellCoprocClause {
	type: "CoprocClause";
	body: ShellStatement;
}

interface ShellCStyleLoop {
	type: "CStyleLoop";
	body: ShellStatement[];
}

interface ShellTerminalCommand {
	type: "TestClause" | "ArithCmd" | "DeclClause" | "LetClause";
}

type ShellCommand =
	| ShellSimpleCommand
	| ShellPipeline
	| ShellLogical
	| ShellSubshell
	| ShellBlock
	| ShellIfClause
	| ShellWhileClause
	| ShellForClause
	| ShellSelectClause
	| ShellCaseClause
	| ShellFunctionDecl
	| ShellTimeClause
	| ShellCoprocClause
	| ShellCStyleLoop
	| ShellTerminalCommand;

interface ShellStatement {
	command: ShellCommand;
}

interface ShellProgram {
	body: ShellStatement[];
}

interface ShellParserModule {
	parse: (input: string) => { ast: ShellProgram };
}

const QUOTED_OR_BARE_TOKEN_PATTERN =
	/"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`|[^\s]+/g;
const REDIRECT_TOKEN_PATTERN = /^(\d*>>?\|?|\d*<<?-?|&?>|<?&?|<>)(.*)$/;

let shellAstParserModule: ShellParserModule | undefined;
let shellAstParserModulePromise: Promise<ShellParserModule> | undefined;

async function loadShellAstParserModule(): Promise<ShellParserModule> {
	if (shellAstParserModule) {
		return shellAstParserModule;
	}

	shellAstParserModulePromise ??= import("@aliou/sh").then(
		(module): ShellParserModule => {
			const typed = module as unknown as ShellParserModule;
			shellAstParserModule = typed;
			return typed;
		},
	);
	return shellAstParserModulePromise;
}

function partToString(part: ShellWordPart): string {
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

function wordToString(word: ShellWord): string {
	return word.parts.map(partToString).join("");
}

function walkCommands(
	node: ShellProgram,
	callback: (cmd: ShellSimpleCommand) => boolean | undefined,
): void {
	for (const statement of node.body) {
		if (walkStatement(statement, callback)) {
			return;
		}
	}
}

function walkStatement(
	statement: ShellStatement,
	callback: (cmd: ShellSimpleCommand) => boolean | undefined,
): boolean {
	return walkCommand(statement.command, callback);
}

function walkStatements(
	statements: ShellStatement[],
	callback: (cmd: ShellSimpleCommand) => boolean | undefined,
): boolean {
	for (const statement of statements) {
		if (walkStatement(statement, callback)) {
			return true;
		}
	}

	return false;
}

function walkCommand(
	command: ShellCommand,
	callback: (cmd: ShellSimpleCommand) => boolean | undefined,
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

function parseTokenCommands(command: string): ParsedShellCommand[] {
	return splitRawSegments(command).map(parseTokenSegment);
}

async function parseAstCommand(command: string): Promise<ParsedShellCommand[]> {
	const parsedCommands: ParsedShellCommand[] = [];
	const { parse } = await loadShellAstParserModule();
	const { ast } = parse(command);

	walkCommands(ast, (simpleCommand) => {
		const words = (simpleCommand.words ?? []).map(wordToString);
		const redirects = (simpleCommand.redirects ?? []).map((redirect) => {
			return {
				operator: redirect.op,
				target: wordToString(redirect.target),
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

export async function parseShellCommand(command: string): Promise<ParsedShellCommand[]> {
	if (!command || typeof command !== "string") {
		return [];
	}

	try {
		const parsedCommands = await parseAstCommand(command);
		if (parsedCommands.length > 0) {
			return parsedCommands;
		}
	} catch (error) {
		// @aliou/sh cannot parse this shell syntax; fall back to token parsing.
		return parseTokenCommands(command);
	}

	return parseTokenCommands(command);
}
