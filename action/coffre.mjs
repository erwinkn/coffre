#!/usr/bin/env node
import { createRequire } from "node:module";
import { inspect, parseArgs, promisify } from "node:util";
import { execFile, spawn } from "node:child_process";
import { appendFileSync, chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { EOL, homedir, hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as setTimeout$1 } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { createCipheriv, createDecipheriv, createHash, createSecretKey, hkdfSync, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { emitKeypressEvents } from "node:readline";
import tty from "node:tty";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createServer as createServer$1 } from "node:net";
//#region \0rolldown/runtime.js
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod), cb = null), mod.exports);
var __copyProps = (to, from, except, desc) => {
	if (from && typeof from === "object" || typeof from === "function") for (var keys = __getOwnPropNames(from), i = 0, n = keys.length, key; i < n; i++) {
		key = keys[i];
		if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, {
			get: ((k) => from[k]).bind(null, key),
			enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
		});
	}
	return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", {
	value: mod,
	enumerable: true
}) : target, mod));
var __require = /* #__PURE__ */ (() => createRequire(import.meta.url))();
//#endregion
//#region src/init.ts
const KINDS$1 = ["workers", "node"];
/** Where a template lives: in the package when published, else in the repository. */
function templateDir(kind) {
	const packed = fileURLToPath(new URL(`./templates/${kind}/`, import.meta.url));
	if (existsSync(packed)) return packed;
	return fileURLToPath(new URL(`../../../examples/${kind}/`, import.meta.url));
}
/**
* A template's files, relative and sorted: everything but what its own
* `.gitignore` names, such as installed packages, local state and secrets.
* Patterns are file or directory names, `*` standing for any run of
* characters.
*/
function templateFiles(dir) {
	const ignoreFile = [join(dir, ".gitignore"), join(dir, "gitignore")].find((path) => existsSync(path));
	const ignored = (ignoreFile === void 0 ? "" : readFileSync(ignoreFile, "utf8")).split("\n").map((line) => line.trim()).filter((line) => line !== "" && !line.startsWith("#")).map((glob) => new RegExp(`^${glob.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`));
	const files = [];
	const walk = (relative) => {
		for (const entry of readdirSync(join(dir, relative), { withFileTypes: true })) {
			if (ignored.some((pattern) => pattern.test(entry.name))) continue;
			const path = relative === "" ? entry.name : `${relative}/${entry.name}`;
			if (entry.isDirectory()) walk(path);
			else files.push(path);
		}
	};
	walk("");
	return files.sort();
}
/** The name a template file has in a project. */
function projectPath(templatePath) {
	return templatePath === "gitignore" ? ".gitignore" : templatePath;
}
/** A package name from a directory's, e.g. `Acme Secrets` → `acme-secrets`. */
function packageName(dir) {
	const name = basename(dir).toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[-._]+|-+$/g, "");
	return name === "" ? "coffre" : name;
}
/** The template's package.json, for this project and this version of coffre. */
function manifest(source, name, version) {
	const pkg = JSON.parse(source);
	pkg.name = name;
	for (const field of ["dependencies", "devDependencies"]) {
		const deps = pkg[field];
		for (const dep of Object.keys(deps ?? {})) if (dep.startsWith("@coffre/")) deps[dep] = version;
	}
	return `${JSON.stringify(pkg, null, 2)}\n`;
}
/** Whether a directory holds nothing yet, or nothing but `.git`: a repository made first, then cloned. */
function isEmpty(dir) {
	return !existsSync(dir) || readdirSync(dir).every((entry) => entry === ".git");
}
/** Write a new deployment into `target`, which must be empty (`isEmpty`) or absent. Returns the files written. */
function init(kind, target, version) {
	if (!isEmpty(target)) throw new Error(`${target} is not empty; give \`coffre init\` a new directory`);
	const source = templateDir(kind);
	const written = [];
	for (const file of templateFiles(source)) {
		const path = projectPath(file);
		const content = readFileSync(join(source, file), "utf8");
		mkdirSync(dirname(join(target, path)), { recursive: true });
		writeFileSync(join(target, path), path === "package.json" ? manifest(content, packageName(target), version) : content);
		written.push(path);
	}
	return written;
}
//#endregion
//#region src/clipboard.ts
const CLEAR_AFTER_MS = 3e4;
/** The system's clipboard tool, by platform and display server; null for none known. */
function systemTool(platform = process.platform, env = process.env) {
	const windows = {
		copy: ["clip.exe"],
		clear: ["clip.exe"],
		paste: [
			"powershell.exe",
			"-NoProfile",
			"-Command",
			"Get-Clipboard"
		]
	};
	if (platform === "darwin") return {
		copy: ["pbcopy"],
		clear: ["pbcopy"],
		paste: ["pbpaste"]
	};
	if (platform === "win32") return windows;
	if (platform !== "linux") return null;
	if (env.WSL_DISTRO_NAME) return windows;
	if (env.WAYLAND_DISPLAY) return {
		copy: ["wl-copy"],
		clear: ["wl-copy", "--clear"],
		paste: ["wl-paste", "--no-newline"]
	};
	if (env.DISPLAY) {
		const xclip = [
			"xclip",
			"-selection",
			"clipboard"
		];
		return {
			copy: [...xclip],
			clear: [...xclip],
			paste: [...xclip, "-o"]
		};
	}
	return null;
}
var Clipboard = class {
	#tool;
	#terminal;
	#pending = null;
	#onCleared;
	/** `terminal` writes an escape sequence to the screen, for OSC 52; `onCleared` hears of a clear. */
	constructor(terminal, onCleared = () => {}, tool = systemTool()) {
		this.#tool = tool;
		this.#terminal = terminal;
		this.#onCleared = onCleared;
	}
	async copy(text) {
		if (this.#tool !== null) try {
			await feed(this.#tool.copy, text);
			this.#schedule(text);
			return "system";
		} catch {
			this.#tool = null;
		}
		this.#terminal(`\x1b]52;c;${Buffer.from(text).toString("base64")}\x07`);
		return "terminal";
	}
	/** Clear a copy still pending now, as the screen closes. */
	async settle() {
		const pending = this.#pending;
		if (pending === null) return;
		clearTimeout(pending.timer);
		this.#pending = null;
		await this.#clearIfHolds(pending.text);
	}
	#schedule(text) {
		if (this.#pending !== null) clearTimeout(this.#pending.timer);
		const timer = setTimeout(() => {
			this.#pending = null;
			this.#clearIfHolds(text).then(this.#onCleared, () => {});
		}, CLEAR_AFTER_MS);
		this.#pending = {
			text,
			timer
		};
	}
	/** Clear the clipboard if it still holds `text`: whatever was copied since stays. */
	async #clearIfHolds(text) {
		const tool = this.#tool;
		if (tool === null) return;
		try {
			if (await read(tool.paste) === text) await feed(tool.clear, "");
		} catch {}
	}
};
const TOOL_TIMEOUT_MS = 3e3;
/** Run `command` with `input` on its stdin; its output is not waited for, since xclip and wl-copy stay to serve it. */
function feed([command, ...args], input) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, {
			stdio: [
				"pipe",
				"ignore",
				"ignore"
			],
			timeout: TOOL_TIMEOUT_MS
		});
		child.on("error", reject);
		child.on("close", (code) => code === 0 ? resolve() : reject(/* @__PURE__ */ new Error(`${command} exited with ${code}`)));
		child.stdin.on("error", () => {});
		if (input === "") child.stdin.end();
		else child.stdin.end(input);
	});
}
function read([command, ...args]) {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, {
			stdio: [
				"ignore",
				"pipe",
				"ignore"
			],
			timeout: TOOL_TIMEOUT_MS
		});
		let out = "";
		child.stdout.setEncoding("utf8").on("data", (chunk) => out += chunk);
		child.on("error", reject);
		child.on("close", (code) => code === 0 ? resolve(out.replace(/\r?\n$/, "")) : reject(/* @__PURE__ */ new Error(`${command} exited with ${code}`)));
	});
}
//#endregion
//#region src/tty.ts
const plain = (text) => text;
/**
* The web UI's accent, green and red, at the depth the terminal takes:
* 24-bit, 256 colours or the 16 named ones. NO_COLOR (and FORCE_COLOR) are
* the stream's own `hasColors`; bold and dim stay, being no colour.
*/
function style(stream) {
	if (stream.isTTY !== true) return {
		ansi: false,
		bold: plain,
		dim: plain,
		accent: plain,
		green: plain,
		red: plain
	};
	const terminal = stream;
	const depth = typeof terminal.hasColors === "function" && terminal.hasColors() ? terminal.getColorDepth() : 1;
	const sgr = (open, close) => (text) => `\x1b[${open}m${text}\x1b[${close}m`;
	const colour = (rgb, index256, index16) => depth >= 24 ? sgr(`38;2;${rgb.join(";")}`, "39") : depth >= 8 ? sgr(`38;5;${index256}`, "39") : depth >= 4 ? sgr(String(index16), "39") : plain;
	return {
		ansi: true,
		bold: sgr("1", "22"),
		dim: sgr("2", "22"),
		accent: colour([
			91,
			141,
			239
		], 69, 94),
		green: colour([
			63,
			174,
			111
		], 71, 32),
		red: colour([
			229,
			83,
			75
		], 167, 31)
	};
}
const ESCAPE = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07/g;
/** Columns `text` takes on screen: its characters, less its escape codes. */
function width(text) {
	return [...text.replace(ESCAPE, "")].length;
}
/** `text` cut to `columns` on screen, escape codes kept, an ellipsis where it was cut. */
function truncate(text, columns) {
	if (width(text) <= columns) return text;
	let out = "";
	let used = 0;
	for (let i = 0; i < text.length;) {
		ESCAPE.lastIndex = i;
		const code = text[i] === "\x1B" ? ESCAPE.exec(text) : null;
		if (code !== null && code.index === i) {
			out += code[0];
			i += code[0].length;
			continue;
		}
		const char = String.fromCodePoint(text.codePointAt(i));
		if (used === columns - 1) return `${out}…${text.includes("\x1B") ? "\x1B[0m" : ""}`;
		out += char;
		used += 1;
		i += char.length;
	}
	return out;
}
/** Plain `text` in lines of at most `columns`, broken at spaces, or anywhere in a word longer than a line. */
function wrap(text, columns) {
	const lines = [];
	let line = "";
	for (const word of text.split(" ")) {
		let rest = word;
		while (width(rest) > columns) {
			if (line !== "") lines.push(line);
			line = "";
			lines.push([...rest].slice(0, columns).join(""));
			rest = [...rest].slice(columns).join("");
		}
		if (line === "") line = rest;
		else if (width(line) + 1 + width(rest) <= columns) line += ` ${rest}`;
		else {
			lines.push(line);
			line = rest;
		}
	}
	return [...lines, line];
}
/** `text` wrapped to the stream's width, each line indented by `indent` spaces. */
function paragraph(out, text, indent = 2) {
	const pad = " ".repeat(indent);
	return wrap(text, Math.max(20, (out.columns || 80) - indent - 1)).map((line) => `${pad}${line}`).join("\n");
}
/** "a, b or c". */
function listed(items, last) {
	return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} ${last} ${items.at(-1)}`;
}
/** A labelled row: `label` in a column of `column`, `text` wrapped beside it with a hanging indent. */
function row(out, s, label, text, indent = 4, column = 10) {
	const lines = wrap(text, Math.max(20, (out.columns || 80) - indent - column - 1));
	const pad = " ".repeat(indent);
	return lines.map((line, i) => `${pad}${i === 0 ? s.dim(label.padEnd(column)) : " ".repeat(column)}${line}`).join("\n");
}
/**
* The keyboard: stdin when it is a terminal, otherwise the terminal itself,
* as `less` reads it when its input is piped. Null without one.
*/
function keyboard() {
	if (process.stdin.isTTY) return process.stdin;
	try {
		return new tty.ReadStream(openSync("/dev/tty", "r"));
	} catch {
		return null;
	}
}
/** Where a screen is drawn and read from: stdout, and the keyboard. Null unless both are a terminal. */
function openTerminal() {
	if (!process.stdout.isTTY) return null;
	const keys = keyboard();
	return keys === null ? null : {
		keys,
		out: process.stdout
	};
}
/** Release a keyboard `keyboard()` opened: stdin stays, /dev/tty closes. */
function release(keys) {
	keys.setRawMode?.(false);
	keys.pause();
	if (keys !== process.stdin) keys.destroy?.();
}
/**
* Every key pressed, in raw mode, until `until` returns true, or `signal`
* aborts the reading. Raw mode is on when this returns: a prompt shown after
* it gets every key, none echoed or edited by the terminal first.
*/
function readKeys$1(keys, until, signal) {
	emitKeypressEvents(keys);
	keys.setRawMode?.(true);
	keys.resume();
	return new Promise((resolve, reject) => {
		let busy = Promise.resolve();
		const stop = () => {
			keys.off("keypress", onKey);
			signal?.removeEventListener("abort", stop);
			keys.setRawMode?.(false);
			keys.pause();
			resolve();
		};
		const onKey = (sequence, key) => {
			busy = busy.then(async () => {
				if (await until(key ?? { sequence }, sequence ?? key?.sequence ?? "")) stop();
			}).catch(reject);
		};
		keys.on("keypress", onKey);
		if (signal?.aborted) stop();
		else signal?.addEventListener("abort", stop);
	});
}
/** What a typed key does to a line: its new text, or `submit`, or `cancel`. */
function edit(text, key, sequence) {
	if (key.ctrl && key.name === "c") return "cancel";
	if (key.name === "return" || key.name === "enter") return "submit";
	if (key.name === "backspace") return text.slice(0, -1);
	if (key.ctrl && key.name === "u") return "";
	if (!key.ctrl && !key.meta && sequence.length > 0 && !sequence.startsWith("\x1B") && sequence >= " ") return text + sequence;
	return text;
}
/** One of `options`, chosen with the arrows and Enter; then one line, as `textLine` leaves. Ctrl-C cancels. */
async function select(keys, out, s, question, options) {
	const columns = Math.max(20, (out.columns || 80) - 1);
	let at = 0;
	let drawn = 0;
	const draw = () => {
		const lines = [`  ${s.accent("?")} ${s.bold(question)} ${s.dim("↑↓ then Enter")}`, ...options.map((option, i) => i === at ? `    ${s.accent("›")} ${s.accent(option)}` : `      ${option}`)];
		out.write(`${drawn > 0 ? `\x1b[${drawn}F` : ""}${lines.map((line) => `${truncate(line, columns)}\x1b[K\n`).join("")}`);
		drawn = lines.length;
	};
	let cancelled = false;
	const chosen = readKeys$1(keys, (key) => {
		if (key.ctrl && key.name === "c") cancelled = true;
		else if (key.name === "return" || key.name === "enter") return true;
		else if (key.name === "up" || key.name === "k") at = (at - 1 + options.length) % options.length;
		else if (key.name === "down" || key.name === "j" || key.name === "tab") at = (at + 1) % options.length;
		if (cancelled) return true;
		draw();
		return false;
	});
	draw();
	await chosen;
	out.write(`\x1b[${drawn}F\x1b[J`);
	if (cancelled) throw new Cancelled();
	out.write(`${truncate(`  ${s.green("✓")} ${s.dim(question)}  ${options[at]}`, columns)}\n`);
	return at;
}
var Cancelled = class extends Error {
	constructor() {
		super("cancelled");
	}
};
/**
* A line typed without echo: a bullet for each character, so that a paste
* shows it arrived. The question, its hint and the bullets go once it is
* given. Ctrl-C cancels.
*/
/** A line typed without echo; trimmed, unless `exact`, for a value whose outer spaces are its own. */
async function hiddenLine(keys, out, s, question, hint, exact = false) {
	const columns = Math.max(20, (out.columns || 80) - 1);
	let typed = "";
	const draw = () => {
		const count = typed.length > 0 ? s.dim(`  ${typed.length} characters`) : "";
		out.write(`\r\x1b[2K${truncate(`    ${s.accent("›")} ${"•".repeat(typed.length)}`, columns - width(count))}${count}`);
	};
	let cancelled = false;
	const typedIn = readKeys$1(keys, (key, sequence) => {
		const next = edit(typed, key, sequence);
		if (next === "cancel") cancelled = true;
		else if (next === "submit") return true;
		else typed = next;
		if (cancelled) return true;
		draw();
		return false;
	});
	out.write(`${truncate(`  ${s.accent("?")} ${s.bold(question)}`, columns)}\n${truncate(`    ${s.dim(hint)}`, columns)}\n`);
	draw();
	await typedIn;
	out.write("\r\x1B[2K\x1B[1A\x1B[2K\x1B[1A\x1B[2K");
	if (cancelled) throw new Cancelled();
	return exact ? typed : typed.trim();
}
//#endregion
//#region src/secrets.ts
function initialState() {
	return {
		view: "values",
		selected: {
			values: 0,
			guide: 0
		},
		scroll: {
			values: 0,
			guide: 0
		},
		revealed: /* @__PURE__ */ new Set(),
		revealAll: false,
		copied: /* @__PURE__ */ new Set(),
		status: "",
		confirming: false
	};
}
/** What the arrows move between: a view's values, or its commands. */
function items(screen, view) {
	if (view === "values") return screen.sections.flatMap(({ values }) => values.map(({ label, value, mask }) => ({
		id: label,
		text: value,
		secret: mask !== "none",
		name: `the ${lower$1(label)}`
	})));
	return screen.guide.flatMap(({ lines }) => lines.flatMap((line) => typeof line === "string" ? [] : [{
		id: line.command,
		text: line.command,
		secret: false,
		name: "the command"
	}]));
}
const DOTS = "•".repeat(32);
const URL_PASSWORD = /(:\/\/[^:@/\s']*:)([^@\s']+)(@)/g;
function masked(value, mask) {
	if (mask === "all") return DOTS;
	if (mask === "password") return value.replace(URL_PASSWORD, "$1••••••••$3");
	return value;
}
/** The values' count in words, for the question before leaving. */
function saved(count) {
	return count === 1 ? "the value" : count === 2 ? "both values" : `all ${[
		"three",
		"four",
		"five",
		"six"
	][count - 3] ?? count} values`;
}
/**
* The screen as `rows` lines of at most `columns`: a header, the view's
* lines, scrolled to keep the selected item in sight, and the keys. Sets
* the view's scroll in `state`.
*/
function render(screen, state, columns, rows, s) {
	const inner = Math.max(20, columns - 6);
	const rule = `  ${s.dim("─".repeat(Math.max(10, columns - 4)))}`;
	const count = screen.sections.reduce((n, { values }) => n + values.length, 0);
	const right = s.dim(`${count} value${count === 1 ? "" : "s"} · shown once`);
	const title = `  ${s.bold(screen.title)}`;
	const header = [
		"",
		`${title}${" ".repeat(Math.max(1, columns - width(title) - width(right) - 2))}${right}`,
		rule,
		...state.view === "values" ? wrap(screen.intro ?? "Save each one in your password manager now. They aren't stored anywhere, and won't be shown again.", columns - 4).map((line) => `  ${line}`) : [`  ${s.bold("Where these go")}`],
		""
	];
	const body = [];
	const spans = [];
	const list = items(screen, state.view);
	const selected = Math.min(state.selected[state.view], list.length - 1);
	const shown = (item) => state.revealAll || state.revealed.has(item.id);
	const bar = (on) => on ? `  ${s.accent("▎")} ` : "    ";
	if (state.view === "values") {
		let index = 0;
		for (const section of screen.sections) {
			body.push(`  ${s.dim(s.bold(section.title.toUpperCase()))}`);
			for (const value of section.values) {
				const on = index === selected;
				const item = list[index];
				const start = body.length;
				const copied = state.copied.has(item.id) ? `  ${s.green("✓ copied")}` : "";
				body.push(`${bar(on)}${on ? s.accent(s.bold(value.label)) : s.bold(value.label)}${copied}`);
				if (shown(item) || value.mask === "none") for (const line of wrap(value.value, inner)) body.push(`${bar(on)}${line}`);
				else body.push(`${bar(on)}${truncate(dimDots(masked(value.value, value.mask), s), inner)}`);
				for (const line of wrap(value.about, inner)) body.push(`${bar(on)}${s.dim(line)}`);
				spans.push([start, body.length]);
				body.push("");
				index += 1;
			}
		}
	} else {
		let index = 0;
		for (const block of screen.guide) {
			body.push(`  ${s.dim(s.bold(block.title.toUpperCase()))}`);
			let after = false;
			for (const line of block.lines) {
				if (typeof line === "string") {
					if (after) body.push("");
					for (const part of wrap(line, inner)) body.push(`    ${part}`);
					after = false;
					continue;
				}
				after = true;
				const on = index === selected;
				const item = list[index];
				const start = body.length;
				const text = line.command;
				const copied = state.copied.has(item.id) ? ` ${s.green("✓")}` : "";
				wrap(text, inner - 2).forEach((part, i) => {
					const prompt = i === 0 ? s.dim("$ ") : "  ";
					body.push(`${bar(on)}${prompt}${on ? s.accent(part) : part}${i === 0 ? copied : ""}`);
				});
				spans.push([start, body.length]);
				index += 1;
			}
			body.push("");
		}
	}
	const keys = (pairs) => {
		const lines = [];
		let line = "";
		for (const [key, what] of pairs) {
			const hint = `${s.accent(key)} ${s.dim(what)}`;
			if (line !== "" && width(line) + 3 + width(hint) > columns - 4) {
				lines.push(`  ${line}`);
				line = hint;
			} else line = line === "" ? hint : `${line}   ${hint}`;
		}
		return [...lines, `  ${line}`];
	};
	const footer = state.confirming ? [
		rule,
		...wrap(`Have you saved ${saved(count)}? They won't be shown again. (y/N)`, columns - 6).map((line, i) => `  ${i === 0 ? s.accent("?") : " "} ${s.bold(line)}`),
		...keys([["y", "yes, leave"], ["n", "stay"]])
	] : [
		rule,
		...keys([
			["↑↓", "move"],
			["c", "copy"],
			...state.view === "values" ? [["r", "reveal"], ["R", "reveal all"]] : [],
			["w", state.view === "values" ? "where these go" : "back to the values"],
			["q", "done"]
		]),
		state.status === "" ? "" : `  ${state.status}`
	];
	while (body.at(-1) === "") body.pop();
	const height = Math.max(1, rows - header.length - footer.length - 1);
	const [start, end] = spans[selected] ?? [0, 0];
	let scroll = state.scroll[state.view];
	if (start < scroll) scroll = start;
	if (end > scroll + height) scroll = end - height;
	scroll = Math.max(0, Math.min(scroll, Math.max(0, body.length - height)));
	state.scroll[state.view] = scroll;
	const visible = body.slice(scroll, scroll + height);
	const more = [scroll > 0 ? "↑" : "", scroll + height < body.length ? "↓" : ""].join("");
	const filler = Array.from({ length: height - visible.length }, () => "");
	const scrolled = more === "" ? "" : `  ${s.dim(`${more} more`)}`;
	return [
		...header,
		...visible,
		...filler,
		scrolled,
		...footer
	].slice(0, rows).map((line) => truncate(line, columns));
}
/**
* Show `screen` on the alternate screen until the operator leaves it,
* having said the values are saved. Nothing it shows reaches the main
* screen, on any way out: q, Ctrl-C, a signal or an error.
*/
async function showSecrets(terminal, screen, clipboard) {
	const { keys, out } = terminal;
	const s = style(out);
	const state = initialState();
	const draw = () => {
		const lines = render(screen, state, out.columns || 80, out.rows || 24, s);
		out.write(`\x1b[H${lines.map((line, i) => `\x1b[${i + 1};1H${line}\x1b[K`).join("")}\x1b[J`);
	};
	const board = clipboard ?? new Clipboard((sequence) => out.write(sequence), () => {
		if (state.status.startsWith("Copied")) {
			state.status = s.dim("Cleared the clipboard.");
			draw();
		}
	});
	let shown = true;
	const leave = () => {
		if (!shown) return;
		shown = false;
		out.write("\x1B[?25h\x1B[?1049l");
	};
	const signals = [
		"SIGINT",
		"SIGTERM",
		"SIGHUP"
	].map((signal) => {
		const handler = () => {
			leave();
			keys.setRawMode?.(false);
			process.exit(128 + {
				SIGINT: 2,
				SIGTERM: 15,
				SIGHUP: 1
			}[signal]);
		};
		process.on(signal, handler);
		return () => process.off(signal, handler);
	});
	process.on("exit", leave);
	const resize = () => draw();
	out.on("resize", resize);
	out.write("\x1B[?1049h\x1B[?25l\x1B[2J");
	try {
		draw();
		await readKeys$1(keys, async (key) => {
			const done = await press(key, screen, state, board, s);
			if (!done) draw();
			return done;
		});
	} finally {
		await board.settle();
		leave();
		out.off("resize", resize);
		process.off("exit", leave);
		for (const off of signals) off();
	}
}
/** Act on one key; true to leave. */
async function press(key, screen, state, clipboard, s) {
	const quit = key.name === "q" || key.name === "escape" || key.ctrl === true && key.name === "c";
	if (state.confirming) {
		if (key.name === "y" || key.ctrl === true && key.name === "c") return true;
		state.confirming = false;
		return false;
	}
	if (quit) {
		state.confirming = true;
		return false;
	}
	const list = items(screen, state.view);
	const at = state.selected[state.view];
	const item = list[at];
	if (key.name === "up" || key.name === "k" || key.name === "tab" && key.shift === true) state.selected[state.view] = (at - 1 + list.length) % list.length;
	else if (key.name === "down" || key.name === "j" || key.name === "tab") state.selected[state.view] = (at + 1) % list.length;
	else if (key.name === "w") {
		state.view = state.view === "values" ? "guide" : "values";
		state.status = "";
	} else if (key.name === "r" && key.shift === true) {
		state.revealAll = !state.revealAll;
		if (!state.revealAll) state.revealed.clear();
	} else if (key.name === "r" && item !== void 0) {
		if (state.revealed.has(item.id)) state.revealed.delete(item.id);
		else state.revealed.add(item.id);
	} else if ((key.name === "c" || key.name === "return" || key.name === "enter") && item !== void 0) try {
		const where = await clipboard.copy(item.text);
		state.copied.add(item.id);
		state.status = where === "system" ? `Copied ${item.name}. ${s.dim(`The clipboard clears in ${CLEAR_AFTER_MS / 1e3} s, or when you leave.`)}` : `Copied ${item.name}, through the terminal. ${s.dim("Clear the clipboard once it is pasted.")}`;
	} catch (error) {
		state.status = s.red(`Couldn't copy ${item.name}: ${error instanceof Error ? error.message : String(error)}. Reveal it with r.`);
	}
	return false;
}
/** Masking dots, dimmed: what is hidden recedes. */
function dimDots(text, s) {
	return text.replace(/•+/g, (dots) => s.dim(dots));
}
function lower$1(label) {
	return label.replace(/^[A-Z](?![A-Z])/, (first) => first.toLowerCase());
}
//#endregion
//#region src/keys.ts
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
/**
* A vault ID: the day, so that ids read in order, and six random base32
* characters, so that two made the same day differ. The vault refuses two
* keys under one id.
*/
function vaultKeyId(now = /* @__PURE__ */ new Date()) {
	const suffix = [...randomBytes(6)].map((byte) => BASE32[byte % 32]).join("");
	return `vault-${now.toISOString().slice(0, 10)}-${suffix}`;
}
/** Two fresh keys, each 32 random bytes in base64, and the vault key's id. */
function generateKeys(now = /* @__PURE__ */ new Date()) {
	const key = () => randomBytes(32).toString("base64");
	return {
		APP_KEY: key(),
		VAULT_KEY_ID: vaultKeyId(now),
		VAULT_KEY: key()
	};
}
/** The keys as values to save, each with what it is for and where it goes. */
function keyValues(keys) {
	return {
		app: [{
			label: "App key",
			value: keys.APP_KEY,
			mask: "all",
			about: "Signs the app's sessions, tokens and log entries. Goes in the app, as APP_KEY."
		}],
		vault: [{
			label: "Vault ID",
			value: keys.VAULT_KEY_ID,
			mask: "none",
			about: "Names the vault key, and isn't secret. Goes in the vault, as VAULT_KEY_ID."
		}, {
			label: "Vault key",
			value: keys.VAULT_KEY,
			mask: "all",
			about: "Decrypts every value: lose it, and they're lost for good. Goes in the vault, as VAULT_KEY."
		}]
	};
}
/** Where the keys go: the vault ID as a var and the keys as secrets on Workers, the env files on Node. */
function keyGuide() {
	return {
		workers: [
			"The vault ID goes under vars in vault/wrangler.jsonc, as VAULT_KEY_ID. The keys are secrets; each command asks for its value:",
			{ command: "pnpm exec wrangler secret put APP_KEY -c app/wrangler.jsonc" },
			{ command: "pnpm exec wrangler secret put VAULT_KEY -c vault/wrangler.jsonc" }
		],
		node: [".env takes APP_KEY; vault.env takes VAULT_KEY_ID and VAULT_KEY."]
	};
}
function keysScreen(keys) {
	const { app, vault } = keyValues(keys);
	const guide = keyGuide();
	return {
		title: "coffre keys",
		sections: [{
			title: "App",
			values: app
		}, {
			title: "Vault",
			values: vault
		}],
		guide: [
			{
				title: "On Cloudflare Workers",
				lines: guide.workers
			},
			{
				title: "On Node",
				lines: guide.node
			},
			{
				title: "For a rotation",
				lines: ["Take only the key you rotate. A vault ID and key: the vault key they replace moves to previousKeks, and stays there, since what it wrapped still needs it (docs/keys.md). An app key: the one it replaces moves to previousAuditChainKeys, and stays there to verify the log (docs/deploy.md, \"Rotating the app key\")."]
			}
		]
	};
}
/** Why a command that shows secrets will not print them to a pipe or a file. */
function needsTerminal(command) {
	return `${command} shows the values it makes on a screen of their own, so that they never reach a file, a pipe or the scrollback, and that needs a terminal. In a script, --json prints them to stdout instead.`;
}
/** The stderr warning before --json prints secrets. */
function jsonWarning(out, secrets) {
	const s = style(out);
	out.write(`${s.red("!")} ${s.bold(`--json prints ${secrets} to stdout.`)} ${s.dim("Keep it out of logs, and out of files others can read.")}\n`);
}
async function keys(args) {
	const { values } = parseArgs({
		args,
		options: { json: {
			type: "boolean",
			default: false
		} },
		allowPositionals: false
	});
	if (values.json) {
		jsonWarning(process.stderr, "the app key and the vault key");
		process.stdout.write(`${JSON.stringify(generateKeys())}\n`);
		return;
	}
	const terminal = openTerminal();
	if (terminal === null) {
		process.stderr.write(`coffre keys: ${needsTerminal("coffre keys")}\n`);
		process.exit(1);
	}
	const fresh = generateKeys();
	try {
		await showSecrets(terminal, keysScreen(fresh));
	} finally {
		release(terminal.keys);
	}
	const { out } = terminal;
	const s = style(out);
	out.write([
		"",
		`  ${s.green("✓")} ${s.bold("The app key and the vault key were shown once.")}`,
		s.dim(paragraph(out, "They aren't stored anywhere: a lost key can't be recovered.", 4)),
		"",
		row(out, s, "Vault ID", `${fresh.VAULT_KEY_ID}, not a secret`),
		"",
		""
	].join("\n"));
}
//#endregion
//#region ../core/dist/dotenv.js
/**
* A secret's key, as the API's `secretKey` (`schemas.ts`) has it: a plain
* pattern, so that the browser's import does not carry zod. The tests hold
* the two in agreement.
*/
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
function parseDotenv(input) {
	const entries = [];
	const problems = [];
	const seen = /* @__PURE__ */ new Set();
	const lines = input.split(/\r\n|\n|\r/);
	for (let index = 0; index < lines.length; index++) {
		const lineNumber = index + 1;
		const trimmed = lines[index].trim();
		if (trimmed === "" || trimmed.startsWith("#")) continue;
		const withoutExport = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
		const equals = withoutExport.indexOf("=");
		if (equals === -1) {
			problems.push({
				line: lineNumber,
				reason: "no \"=\" on this line"
			});
			continue;
		}
		const key = withoutExport.slice(0, equals).trim();
		if (!KEY_RE.test(key)) {
			problems.push({
				line: lineNumber,
				reason: "key must match ^[A-Za-z_][A-Za-z0-9_]{0,127}$"
			});
			continue;
		}
		let rest = withoutExport.slice(equals + 1).trim();
		let value;
		if (rest.startsWith("\"")) {
			const closing = findClosingQuote(rest, "\"");
			if (closing === -1) {
				problems.push({
					line: lineNumber,
					key,
					reason: "unterminated double quote (multi-line values are not supported)"
				});
				continue;
			}
			value = unescapeDoubleQuoted(rest.slice(1, closing));
			if (trailingIsSignificant(rest.slice(closing + 1))) {
				problems.push({
					line: lineNumber,
					key,
					reason: "unexpected text after the closing quote"
				});
				continue;
			}
		} else if (rest.startsWith("'")) {
			const closing = rest.indexOf("'", 1);
			if (closing === -1) {
				problems.push({
					line: lineNumber,
					key,
					reason: "unterminated single quote (multi-line values are not supported)"
				});
				continue;
			}
			value = rest.slice(1, closing);
			if (trailingIsSignificant(rest.slice(closing + 1))) {
				problems.push({
					line: lineNumber,
					key,
					reason: "unexpected text after the closing quote"
				});
				continue;
			}
		} else {
			const text = withoutExport.slice(equals + 1);
			const comment = text.search(/\s#/);
			value = (comment === -1 ? text : text.slice(0, comment)).trim();
			if (/^=+$/.test(value)) {
				problems.push({
					line: lineNumber,
					reason: "a value pasted on its own, not KEY=value: only \"=\" follows what would be its key"
				});
				continue;
			}
			if (value === "") {
				problems.push({
					line: lineNumber,
					reason: "no value: write KEY=\"\" for an empty one"
				});
				continue;
			}
		}
		if (value.includes("\0")) {
			problems.push({
				line: lineNumber,
				key,
				reason: "value contains a NUL byte, which cannot be passed in an environment"
			});
			continue;
		}
		if (seen.has(key)) {
			problems.push({
				line: lineNumber,
				key,
				reason: "duplicate key in this file"
			});
			continue;
		}
		seen.add(key);
		entries.push({
			key,
			value,
			line: lineNumber
		});
	}
	return {
		entries,
		problems
	};
}
/** True when what follows a closing quote is neither whitespace nor a comment. */
function trailingIsSignificant(rest) {
	const trimmed = rest.trim();
	return trimmed !== "" && !trimmed.startsWith("#");
}
function findClosingQuote(text, quote) {
	for (let index = 1; index < text.length; index++) {
		if (text[index] === "\\") {
			index++;
			continue;
		}
		if (text[index] === quote) return index;
	}
	return -1;
}
/**
* Expand escapes inside a double-quoted value.
*
* Deliberately minimal: only the escapes that are necessary. `\n` and `\r`
* because multi-line values (PEM keys) cannot otherwise be expressed on one
* line, and `\\` `\"` `\'` because quoting needs them.
*
* EVERYTHING ELSE IS PRESERVED VERBATIM, backslash included. The obvious
* implementation -- returning the character and dropping the backslash for
* unknown escapes -- silently mangles credentials: `"C:\path\to\file"` came
* out as `C:path<TAB>ofile`, and `"\d+\w"` as `d+w`. A secrets store that
* quietly rewrites what you gave it is worse than one that refuses.
*
* A value that should contain no interpretation at all belongs in single
* quotes, which are literal.
*/
function unescapeDoubleQuoted(text) {
	return text.replace(/\\(.)/g, (match, character) => {
		switch (character) {
			case "n": return "\n";
			case "r": return "\r";
			case "\\":
			case "\"":
			case "'": return character;
			default: return match;
		}
	});
}
/** Values that read the same unquoted: no spaces, quotes, `#`, `$` or backslashes. */
const PLAIN_VALUE = /^[A-Za-z0-9_./:@+,=%?-]*$/;
/**
* Write entries as a .env file that `parseDotenv` reads back exactly.
*
* Plain values stay bare; anything else is single-quoted, which is literal;
* values holding a quote or a line break are double-quoted with the four
* escapes the parser knows (`\\`, `\"`, `\n`, `\r`).
*/
function formatDotenv(entries) {
	let out = "";
	for (const [key, value] of entries) {
		assertEnvironmentEntry(key, value);
		out += `${key}=${quoteDotenv(value)}\n`;
	}
	return out;
}
/** Reject names and values that cannot be passed intact in an environment. */
function assertEnvironmentEntry(key, value) {
	if (!KEY_RE.test(key)) throw new Error(`${JSON.stringify(key)} is not a valid variable name`);
	if (value.includes("\0")) throw new Error(`${key} contains a NUL byte`);
}
function quoteDotenv(value) {
	if (PLAIN_VALUE.test(value) && !/^=*$/.test(value)) return value;
	if (!/['\n\r]/.test(value)) return `'${value}'`;
	return `"${value.replace(/[\\"\n\r]/g, (character) => {
		switch (character) {
			case "\n": return "\\n";
			case "\r": return "\\r";
			default: return `\\${character}`;
		}
	})}"`;
}
/**
* Write entries as POSIX shell `export` statements, for
* `eval "$(coffre export … --format shell)"`. Single quotes are the only
* shell quoting with no expansion inside; a single quote itself is written
* as `'\''`.
*/
function formatShellExports(entries) {
	let out = "";
	for (const [key, value] of entries) {
		assertEnvironmentEntry(key, value);
		out += `export ${key}='${value.replaceAll("'", "'\\''")}'\n`;
	}
	return out;
}
//#endregion
//#region src/github-env.ts
/**
* Names that a later step's shell, loader, runtime, build tool or git reads
* as code to run, or as where to load it from. Set through GITHUB_ENV, one
* secret would run code in every later step of the job, so these are
* refused. A `*` stands for any run of letters, digits and underscores, so
* that a family is one pattern, and names compare case-blind, as on
* Windows. GitHub refuses NODE_OPTIONS itself. What only points a tool at
* another registry (NPM_CONFIG_REGISTRY, PIP_INDEX_URL: the latter can run
* an sdist's build without --require-hashes, but it is also how a private
* index is authenticated) is no part of this,
* nor what only names a directory to read files from (HOME, CARGO_HOME),
* nor what only an interactive shell reads (ENV, PROMPT_COMMAND), nor a
* credential (NPM_CONFIG_OTP, CARGO_REGISTRIES_*_TOKEN).
*
* A tripwire, not a boundary: it blocks the common one-variable hijacks and
* is not exhaustive. Anyone who may write keys to an environment the Action
* exports is trusted with code execution in that job.
*/
const RUNS_CODE = [
	"PATH",
	"BASH_ENV",
	"SHELLOPTS",
	"BASHOPTS",
	"PS4",
	"IFS",
	"ZDOTDIR",
	"GCONV_PATH",
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT",
	"DYLD_*",
	"GIT_SSH",
	"GIT_SSH_COMMAND",
	"GIT_ASKPASS",
	"SSH_ASKPASS",
	"GIT_EXEC_PATH",
	"GIT_PROXY_COMMAND",
	"GIT_EXTERNAL_DIFF",
	"GIT_EDITOR",
	"GIT_SEQUENCE_EDITOR",
	"GIT_PAGER",
	"GIT_TEMPLATE_DIR",
	"GIT_DIR",
	"GIT_CONFIG",
	"GIT_CONFIG_*",
	"EDITOR",
	"VISUAL",
	"PAGER",
	"BROWSER",
	"NODE_OPTIONS",
	"NODE_PATH",
	"YARN_YARN_PATH",
	...[
		"SCRIPT_SHELL",
		"SHELL",
		"NODE_OPTIONS",
		"NODE_GYP",
		"GIT",
		"EDITOR",
		"BROWSER",
		"VIEWER",
		"ONLOAD_SCRIPT",
		"INIT_MODULE",
		"USERCONFIG",
		"GLOBALCONFIG",
		"PNPMFILE",
		"GLOBAL_PNPMFILE"
	].flatMap((setting) => [`NPM_CONFIG_${setting}`, `PNPM_CONFIG_${setting}`]),
	"PYTHONPATH",
	"PYTHONHOME",
	"PYTHONSTARTUP",
	"PYTHONUSERBASE",
	"PYTHONBREAKPOINT",
	"PYTHONWARNINGS",
	"PERL5OPT",
	"PERL5LIB",
	"PERLLIB",
	"PERL5DB",
	"RUBYOPT",
	"RUBYLIB",
	"LUA_INIT*",
	"PHPRC",
	"PHP_INI_SCAN_DIR",
	"JAVA_TOOL_OPTIONS",
	"JDK_JAVA_OPTIONS",
	"_JAVA_OPTIONS",
	"JAVA_OPTS",
	"MAVEN_OPTS",
	"MAVEN_ARGS",
	"GRADLE_OPTS",
	"SBT_OPTS",
	"ANT_OPTS",
	"CATALINA_OPTS",
	"CLASSPATH",
	"DOTNET_STARTUP_HOOKS",
	"DOTNET_ADDITIONAL_DEPS",
	"PREBUILDEVENT",
	"POSTBUILDEVENT",
	"RUNCOMMAND",
	"COR_ENABLE_PROFILING",
	"COR_PROFILER*",
	"CORECLR_ENABLE_PROFILING",
	"CORECLR_PROFILER*",
	"CC",
	"CXX",
	"CPP",
	"AR",
	"LD",
	"CFLAGS",
	"CXXFLAGS",
	"CPPFLAGS",
	"LDFLAGS",
	"MAKEFLAGS",
	"MFLAGS",
	"GOFLAGS",
	"GOCACHEPROG",
	"GOAUTH",
	"CGO_*FLAGS",
	"RUSTC",
	"RUSTC_*",
	"RUSTDOC",
	"RUSTDOC_*",
	"RUSTFLAGS",
	"RUSTDOCFLAGS",
	"CARGO_ENCODED_RUSTFLAGS",
	"CARGO_ENCODED_RUSTDOCFLAGS",
	"CARGO_BUILD_*",
	"CARGO_TARGET_*_RUNNER",
	"CARGO_TARGET_*_LINKER",
	"CARGO_TARGET_*_RUSTFLAGS",
	"CARGO_HOST_*",
	"CARGO_REGISTRY_CREDENTIAL_PROVIDER",
	"CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS",
	"CARGO_REGISTRIES_*_CREDENTIAL_PROVIDER",
	"CARGO_CREDENTIAL_ALIAS_*"
];
const RUNS_CODE_PATTERN = new RegExp(`^(?:${RUNS_CODE.map((pattern) => pattern.replaceAll("*", "\\w*")).join("|")})$`);
/** Whether a later step would run code that `key` names (`RUNS_CODE`). */
function runsCode(key) {
	return RUNS_CODE_PATTERN.test(key.toUpperCase());
}
/** The runner decodes %, CR and LF in command data, in this escaping order.
* https://github.com/actions/toolkit/blob/main/packages/core/src/command.ts
*/
function githubMasks(entries) {
	let out = "";
	for (const [, value] of entries) for (const mask of /* @__PURE__ */ new Set([value, ...value.split(/\r\n|\r|\n/)])) {
		if (mask === "") continue;
		out += `::add-mask::${mask.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A")}\n`;
	}
	return out;
}
/** Multiline-safe environment records, consumed by GitHub after the step.
* https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#multiline-strings
* Match the host's framing newline, including on Windows, so a trailing CR
* in the value is not mistaken for part of that newline.
*/
function githubEnvironment(entries, nextDelimiter = () => `coffre_${randomUUID()}`, newline = EOL) {
	let out = "";
	for (const [key, value] of entries) {
		assertEnvironmentEntry(key, value);
		if (runsCode(key)) throw new Error(`${key} cannot be set through GITHUB_ENV: a later step's shell, loader or runtime would take code to run from it`);
		let delimiter;
		do
			delimiter = nextDelimiter();
		while (value.includes(delimiter));
		out += `${key}<<${delimiter}${newline}${value}${newline}${delimiter}${newline}`;
	}
	return out;
}
//#endregion
//#region ../client/dist/src-oumPAEmT.js
/** Two colons or more, in hex: an IPv6 address, as `::1` or `2001:db8::1:443` with its port. */
const IPV6 = /[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*/i;
const TIMEOUT_OR_REFUSAL = /* @__PURE__ */ new Set([
	"ECONNREFUSED",
	"ETIMEDOUT",
	"UND_ERR_CONNECT_TIMEOUT",
	"ENETUNREACH",
	"EHOSTUNREACH"
]);
/** What to try for the common causes; null for the others. */
function hint(cause) {
	const code = cause.code ?? "";
	if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "the name does not resolve here: check the address, or flush this machine's DNS cache";
	const tried = [cause, ...cause.errors ?? []].flatMap((each) => [each.address ?? "", each.message]);
	if (TIMEOUT_OR_REFUSAL.has(code) && tried.some((each) => IPV6.test(each))) return "it was tried over IPv6, which this network may not carry: try NODE_OPTIONS=--dns-result-order=ipv4first";
	if (/CERT|UNABLE_TO_VERIFY|SELF_SIGNED/.test(code)) return "something between you and the instance, such as a proxy or a network filter, presents its own certificate";
	return null;
}
/** The cause's own words, with its code and address when they don't already say them. */
function described(cause) {
	const said = cause.message || (cause.errors ?? []).map((each) => each.message).join(", ");
	const address = cause.address === void 0 ? void 0 : cause.port === void 0 ? cause.address : `${cause.address}:${cause.port}`;
	const more = [cause.code, address].filter((each) => each !== void 0 && !said.includes(each));
	if (said === "") return more.join(" ") || cause.name;
	return more.length === 0 ? said : `${said} (${more.join(", ")})`;
}
/**
* `could not reach <origin>: <why>`, and what to try when the cause is a
* common one: `could not reach https://x: getaddrinfo ENOTFOUND x; the name
* does not resolve here: …`.
*/
function unreachable(origin, error) {
	const cause = error instanceof Error && error.cause instanceof Error ? error.cause : null;
	if (cause === null) return `could not reach ${origin}: ${error instanceof Error ? error.message : String(error)}`;
	const then = hint(cause);
	return `could not reach ${origin}: ${described(cause)}${then === null ? "" : `; ${then}`}`;
}
/** A request that never reached the instance: its message says why, `cause` is what `fetch` threw. */
var Unreachable = class extends Error {
	origin;
	constructor(origin, error) {
		super(unreachable(origin, error), { cause: error });
		this.name = "Unreachable";
		this.origin = origin;
	}
};
const DAY = 864e5;
/**
* Whole days since a key's value was written (`updatedAt`, a reference's
* source's): 0 on the day it was. Null while it reads no value.
*/
function ageInDays(entry, now = Date.now()) {
	return entry.updatedAt === null ? null : Math.max(0, Math.floor((now - Date.parse(entry.updatedAt)) / DAY));
}
/**
* Whether a key's value has gone unchanged for more than `days` whole days:
* against the deployment's `rotateAfterDays`, due for rotation. An archived
* key, which nothing reads, and a key with no value never are.
*/
function olderThan(entry, days, now = Date.now()) {
	const age = ageInDays(entry, now);
	return !entry.archived && age !== null && age > days;
}
/** How the audit log's entries are said, to people: by the pages and the CLI alike. */
/**
* The CI run an entry was written for, as its issuer stated it at the
* exchange: `acme/api run 7001 at 3f2a9c1`, a GitLab pipeline, or the
* token's subject. Null for an entry no trust binding's credential wrote.
*/
function runLabel(run) {
	if (run === null) return null;
	const { claims } = run;
	const text = (name) => typeof claims[name] === "string" || typeof claims[name] === "number" ? String(claims[name]) : null;
	const at = text("sha") === null ? "" : ` at ${text("sha").slice(0, 7)}`;
	if (text("repository") !== null && text("run_id") !== null) return `${text("repository")} run ${text("run_id")}${at}`;
	if (text("project_path") !== null && text("pipeline_id") !== null) return `${text("project_path")} pipeline ${text("pipeline_id")}${at}`;
	return text("sub") === null ? "a CI run" : `CI run ${text("sub")}`;
}
/**
* Rows grouped by folder, as every list shows them: those in no folder
* first, then each folder by name, each keeping the order it was given. A
* folder only arranges a list (docs/design/environments.md).
*/
function byFolder(rows) {
	const groups = /* @__PURE__ */ new Map([[null, []]]);
	for (const folder of [...new Set(rows.flatMap((row) => row.folder === null ? [] : [row.folder]))].sort()) groups.set(folder, []);
	for (const row of rows) groups.get(row.folder).push(row);
	return [...groups].filter(([, inFolder]) => inFolder.length > 0);
}
/**
* How members are named, to people and to the API. A service account, a
* machine identity that signs in by OIDC (trust bindings) or with bearer
* tokens, is `service:<name>` wherever a person reads or types one. The
* API, the vault and the audit log keep `token:<name>`, which the log's
* signed entries hold: so the rename is here, at the edges, and nothing
* stored or verified changes.
*/
/** A member as people read it: `service:deploy` for the API's `token:deploy`; anyone else as they are. */
function shownMember$1(member) {
	return member.startsWith("token:") ? `service:${member.slice(6)}` : member;
}
/** A member as the API takes it, from what a person typed: `service:deploy` and `token:deploy` alike name a service account. */
function apiMember(member) {
	return member.startsWith("service:") ? `token:${member.slice(8)}` : member;
}
/** A service account's name alone, from any of its forms: `deploy`, `service:deploy` or `token:deploy`. */
function serviceName(member) {
	return member.replace(/^(?:service|token):/, "");
}
/** The API's error shape, `{ error, message }`, with the HTTP status. */
var CoffreError = class extends Error {
	status;
	code;
	/** The vault's own code when it refused: `no_grant`, `removed`, `bulk_limit`, ... */
	reason;
	/** When to ask again, in seconds, when the answer says (`Retry-After`): a 503's, a 429's. */
	retryAfter;
	constructor(status, code, message, reason, retryAfter) {
		super(message);
		this.name = "CoffreError";
		this.status = status;
		this.code = code;
		this.reason = reason;
		this.retryAfter = retryAfter;
	}
};
/** `market/prod/KEY` as route parameters. */
function place$1(path) {
	const [project = "", environment = "", key = ""] = path.replace(/^\/+|\/+$/g, "").split("/");
	return {
		project,
		environment,
		key
	};
}
/** `?revision=57.3f9a0c2e81b4d7a6`, or nothing for a change asked without its preview. */
function asPreviewed(revision) {
	return revision === void 0 ? "" : `?revision=${encodeURIComponent(revision)}`;
}
function createClient(options) {
	const origin = options.url.replace(/\/+$/, "");
	const transport = options.transport ?? (async (request) => {
		try {
			return await fetch(request);
		} catch (error) {
			throw new Unreachable(origin, error);
		}
	});
	async function send(method, path, input) {
		const url = new URL(`${origin}/api${path}`);
		const headers = new Headers(await options.headers?.());
		let body;
		if (method === "GET") {
			for (const [name, value] of Object.entries(input ?? {})) if (value !== void 0 && value !== null) url.searchParams.set(name, String(value));
		} else if (input !== void 0) {
			headers.set("content-type", "application/json");
			body = JSON.stringify(input);
		}
		const response = await transport(new Request(url, {
			method,
			headers,
			body
		}));
		const payload = await response.json().catch(() => null);
		if (!response.ok) {
			const error = payload;
			throw new CoffreError(response.status, typeof error?.error === "string" ? error.error : "http_error", typeof error?.message === "string" ? error.message : `request failed with status ${response.status}`, typeof error?.reason === "string" ? error.reason : void 0, response.headers.get("retry-after") ?? void 0);
		}
		return payload;
	}
	/** A route key and its parameters as a method and a path. */
	function address(key, params) {
		const [method, pattern] = key.split(" ");
		return [method, pattern.replace(/:(\w+)/g, (_, name) => encodeURIComponent(params[name]))];
	}
	/** Any route by its key: `call('GET /secrets/:project/:environment', { project, environment })`. */
	async function call(key, ...[params, input]) {
		const [method, path] = address(key, params);
		return await send(method, path, input);
	}
	return {
		call,
		/** How this instance signs people in. Answers anyone, signed in or not. */
		auth: () => send("GET", "/auth", void 0),
		/** Who I am, and every place I can reach. */
		me: () => call("GET /me", {}),
		projects: {
			/** With their environments. */
			list: () => call("GET /projects", {}),
			/** Its `name`, which releases before 0.6.2 show, defaults to the slug. */
			create: (project, input = {}) => call("PUT /projects/:project", { project }, input),
			update: (project, patch) => call("PATCH /projects/:project", { project }, patch),
			/** What deleting an archived project would erase and revoke; changes nothing. */
			previewDelete: (project) => {
				const [method, route] = address("DELETE /projects/:project", { project });
				return send(method, `${route}?dryRun=1`, void 0);
			},
			/** Delete an archived project for good: its values erased, its grants revoked, its slug free. Owners only. */
			delete: (project) => call("DELETE /projects/:project", { project })
		},
		environments: {
			/** As a project's: its `name` defaults to the slug. `from` forks a sibling. */
			create: (path, input = {}) => call("PUT /projects/:project/:environment", place$1(path), input),
			update: (path, patch) => call("PATCH /projects/:project/:environment", place$1(path), patch),
			/**
			* Protected, a person holds their role's protected column there
			* (docs/design/roles.md); whoever manages the project's environments
			* protects one, and only an Owner of its project, or of the whole instance, unprotects it.
			*/
			protect: (path, on = true) => call("PATCH /projects/:project/:environment", place$1(path), { protected: on }),
			/** What deleting an archived environment would erase and revoke; changes nothing. */
			previewDelete: (path) => {
				const [method, route] = address("DELETE /projects/:project/:environment", place$1(path));
				return send(method, `${route}?dryRun=1`, void 0);
			},
			/** Delete an archived environment for good, as a project is. Owners only. */
			delete: (path) => call("DELETE /projects/:project/:environment", place$1(path)),
			/** The keys its sibling environments have and it lacks, read or not, and those its team dismissed. */
			missing: (path) => call("GET /projects/:project/:environment/missing", place$1(path)),
			/** A project's personal configs, for whoever manages its environments: whose, of what, and their key names. */
			personal: (project) => call("GET /personal/:project", place$1(project)),
			/**
			* A version of what reading it would open: it changes whenever a read
			* would, and reads no value, so it is not logged. Poll it, and read
			* only when it changed.
			*/
			version: (path) => call("GET /projects/:project/:environment/version", place$1(path)),
			/** Dismiss missing keys (`true`) or restore them (`null`). */
			dismiss: (path, patch) => call("PATCH /projects/:project/:environment/dismissals", place$1(path), patch)
		},
		secrets: {
			/** Keys, versions and who changed what; never values. */
			list: (path) => call("GET /secrets/:project/:environment", place$1(path)),
			/** Decrypts one secret, or every secret in an environment, or, `keys` named, those of it only. Logged in your name. */
			reveal: (path, keys) => call("POST /reveals", {}, keys === void 0 ? { path } : {
				path,
				keys
			}),
			/** One transaction, a version and an audit entry per key; `null` archives. */
			set: (path, values) => call("PATCH /secrets/:project/:environment", place$1(path), values),
			/**
			* What `set` would do to each key, `added`, `changed`, `unchanged` or
			* `archived`, and nothing else: no value comes back and nothing is
			* written. Comparing opens the current values, logged as reads.
			*/
			dryRun: (path, values) => {
				const [method, route] = address("PATCH /secrets/:project/:environment", place$1(path));
				return send(method, `${route}?dryRun=1`, values);
			},
			history: (path) => call("GET /secrets/:project/:environment/:key/versions", place$1(path)),
			/** A new version holding the old one's value. */
			restore: (path, version) => call("POST /secrets/:project/:environment/:key/restore", place$1(path), { version }),
			rename: (path, key) => call("PATCH /secrets/:project/:environment/:key", place$1(path), { key }),
			update: (path, patch) => call("PATCH /secrets/:project/:environment/:key", place$1(path), patch),
			/**
			* In a fork, a key back to its parent's value (`true`), its own kept,
			* or its own served again (`false`); `from` holds the parent's.
			*/
			inherit: (path, inherit) => call("PATCH /secrets/:project/:environment/:key", place$1(path), { inherit })
		},
		/**
		* References: secrets read through others (docs/design/environments.md).
		* A key becomes one with `secrets.set(path, { KEY: { ref: 'market/prod/KEY' } })`.
		*/
		references: {
			/** The live references into and out of a place, `market`, `market/prod` or `market/prod/KEY`, and who reads through them. */
			list: (path) => call("GET /references", {}, { path }),
			/** Break the reference a secret is: its readers stop reading the source through it. */
			break: (path) => call("DELETE /secrets/:project/:environment/:key/reference", place$1(path))
		},
		members: {
			/** People and tokens, their role and their access; at a place, those who reach it. */
			list: (path) => call("GET /members", {}, { path }),
			/** What they hold, and what to rotate if they leave. */
			get: (member) => call("GET /members/:member", { member }),
			/** Their instance role and scope, and the grants you manage, in one read. */
			access: (member) => call("GET /members/:member/access", { member }),
			add: (member, input = {}) => call("PUT /members/:member", { member }, input),
			/** Offboards; returns what to rotate. */
			remove: (member) => call("DELETE /members/:member", { member })
		},
		/**
		* A member's tokens: a service account's bearer tokens, or a person's
		* personal tokens (`user:<email>`), which act as them within their scope.
		*/
		tokens: {
			list: (member) => call("GET /members/:member/tokens", { member }),
			/** What the token would reach, as the server would issue it now; issues nothing. */
			preview: (member, input) => {
				const [method, route] = address("POST /members/:member/tokens", { member });
				return send(method, `${route}?dryRun=1`, input);
			},
			/** The value is in the answer, and only there. */
			issue: (member, input) => call("POST /members/:member/tokens", { member }, input),
			revoke: (member, id) => call("DELETE /members/:member/tokens/:id", {
				member,
				id
			})
		},
		/**
		* Handles: placeholders a person's app holds in place of an environment's
		* values, which only the credential proxy (`/use`) takes. The value is
		* in the answer, and only there; it is revoked as a token is.
		*/
		handles: {
			create: (input) => call("POST /handles", {}, input),
			/** Ends a handle of the caller's own, as `coffre run` does once its command ends. */
			revoke: (id) => call("DELETE /handles/:id", { id })
		},
		/** Trust bindings: which CI runs may sign in as a service, by their platform's ID token. */
		bindings: {
			list: (member) => call("GET /members/:member/bindings", { member }),
			/** The binding as it would be saved, the keys its issuer names, and what it replaces; writes nothing. */
			preview: (member, input) => {
				const [method, route] = address("POST /members/:member/bindings", { member });
				return send(method, `${route}?dryRun=1`, input);
			},
			create: (member, input) => call("POST /members/:member/bindings", { member }, input),
			/** The service's bindings on an issuer that new keys would replace, and the keys as checked; writes nothing. */
			previewKeys: (member, input) => {
				const [method, route] = address("POST /members/:member/bindings/keys", { member });
				return send(method, `${route}?dryRun=1`, input);
			},
			/** New keys, uploaded, for every binding of the service on the issuer: each replaced by one the same but for them. */
			replaceKeys: (member, input) => call("POST /members/:member/bindings/keys", { member }, input),
			remove: (member, id) => call("DELETE /members/:member/bindings/:id", {
				member,
				id
			}),
			/** A GitHub repository's or GitLab project's IDs, which bindings name: a public one's, or one the deployment's GitHub App is installed on. */
			lookup: (input) => call("GET /workloads/lookup", {}, input),
			/** The repositories the deployment's GitHub App is installed on, private ones too; `{ app: null }` without one. */
			repositories: () => call("GET /workloads/repositories", {})
		},
		access: { 
		/** What they should hold at each place; the server applies the difference. `null` revokes. */
set: (member, access) => call("PATCH /access/:member", { member }, access) },
		/** Where I am signed in. Only where coffre runs its own sign-in. */
		sessions: {
			list: () => call("GET /sessions", {}),
			revoke: (id) => call("DELETE /sessions/:id", { id })
		},
		/** The accounts I sign in with. */
		identities: {
			list: () => call("GET /identities", {}),
			unlink: (id) => call("DELETE /identities/:id", { id })
		},
		/** A `coffre login` waiting for someone to approve it, by the code it shows. */
		deviceLogins: {
			get: (code) => call("GET /device-logins/:code", { code }),
			decide: (code, approve) => call("POST /device-logins/:code", { code }, { approve })
		},
		/**
		* Folders, which arrange lists and do nothing else: a folder exists while
		* something is filed in it. Renaming one re-files all of it, onto a folder
		* that exists merges the two; removing one takes all of it out, each item
		* staying where it is, in no folder. Moving one item is `projects.update`
		* or `secrets.update` with a `folder`.
		*/
		folders: {
			/** A folder of projects, renamed. Takes managing every project in it. */
			rename: (folder, name) => call("PATCH /folders/:folder", { folder }, { name }),
			/** Every project out of a folder. */
			remove: (folder) => call("DELETE /folders/:folder", { folder }),
			/** One of an environment's key folders, `market/prod`, renamed. Takes writing there. */
			renameKeys: (environment, folder, name) => {
				const { project, environment: slug } = place$1(environment);
				return call("PATCH /folders/:project/:environment/:folder", {
					project,
					environment: slug,
					folder
				}, { name });
			},
			/** Every key out of one of an environment's folders. */
			removeKeys: (environment, folder) => {
				const { project, environment: slug } = place$1(environment);
				return call("DELETE /folders/:project/:environment/:folder", {
					project,
					environment: slug,
					folder
				});
			}
		},
		/**
		* An MCP client asking to connect, by its authorization request, and the
		* person's answer: where to send the browser next.
		*/
		oauth: {
			describe: (request) => call("GET /oauth/authorizations", {}, request),
			decide: (input) => call("POST /oauth/authorizations", {}, input)
		},
		/** The MCP clients I connected. */
		/** A change an MCP client asked for: what it would do, and the person's decision, which makes it. */
		approvals: {
			get: (id) => call("GET /approvals/:id", { id }),
			decide: (id, input) => call("POST /approvals/:id", { id }, input)
		},
		apps: {
			list: () => call("GET /apps", {}),
			disconnect: (id) => call("DELETE /apps/:id", { id })
		},
		/**
		* The instance's roles, in two columns, an environment's that is not
		* protected and one's that is (docs/design/roles.md). Any member lists
		* them; an Owner of the whole instance edits them. `instance` is about
		* instance roles, a person's across every project in their scope.
		*/
		roles: {
			list: () => call("GET /roles", {}),
			/** What defining the role so would do to everyone it reaches; changes nothing. */
			preview: (role, definition, { instance = false } = {}) => {
				const [method, route] = instance ? address("PUT /instance-roles/:role", { role }) : address("PUT /roles/:role", { role });
				return send(method, `${route}?dryRun=1`, definition);
			},
			/**
			* A built-in role edited, or one an Owner makes. With its preview's
			* `revision`, made as previewed, or refused (409 `policy_changed`)
			* if the policy changed since: preview it again.
			*/
			set: (role, definition, { instance = false, revision } = {}) => {
				const [method, route] = instance ? address("PUT /instance-roles/:role", { role }) : address("PUT /roles/:role", { role });
				return send(method, `${route}${asPreviewed(revision)}`, definition);
			},
			/** What putting it back as it ships, or deleting one an Owner made, would do; changes nothing. */
			previewReset: (role, { instance = false } = {}) => {
				const [method, route] = instance ? address("DELETE /instance-roles/:role", { role }) : address("DELETE /roles/:role", { role });
				return send(method, `${route}?dryRun=1`, void 0);
			},
			/** A built-in role back as it ships; one an Owner made, deleted, while no grant names it. With its preview's `revision`, as `set`. */
			reset: (role, { instance = false, revision } = {}) => {
				const [method, route] = instance ? address("DELETE /instance-roles/:role", { role }) : address("DELETE /roles/:role", { role });
				return send(method, `${route}${asPreviewed(revision)}`, void 0);
			}
		},
		/** The instance's settings, for those who run it: where people set up service accounts themselves. */
		settings: {
			get: () => call("GET /settings", {}),
			set: (input) => call("PUT /settings", {}, input)
		},
		audit: {
			list: (query = {}) => call("GET /audit", {}, query),
			/**
			* Whether the log holds, from the newest checkpoint; or, with `from`, a
			* stretch of the walk from the first entry: `start`, then each `next`
			* until it is null (`verifyWhole`).
			*/
			verify: (query = {}) => call("GET /audit/verification", {}, query),
			/**
			* The walk from the first entry to the head, a stretch a request, each
			* as long as the server walks in one: the first stretch that fails, or
			* the last. `onStretch` sees each verdict as it comes.
			*/
			verifyWhole: async (onStretch = () => {}) => {
				for (let from = "start";;) {
					const verdict = await call("GET /audit/verification", {}, { from });
					onStretch(verdict);
					if (!verdict.ok || verdict.next === void 0 || verdict.next === null) return verdict;
					from = verdict.next;
				}
			},
			/**
			* Whether 0.15's log holds (the vault's `verifyTrees`): its newest signed
			* checkpoint and every entry since. `kept` false where the instance
			* keeps 0.14's log alone, a server older than 0.15 (no such route)
			* included.
			*/
			verifyTrees: () => call("GET /audit/trees", {}).catch((error) => {
				if (error instanceof CoffreError && error.status === 404) return { kept: false };
				throw error;
			}),
			/** What an escrowed key is checked against: public material, for admins and owners of the whole instance. */
			keys: () => call("GET /audit/keys", {}),
			/**
			* Accept that entries `from` to `to` are lost for good, as an Owner of
			* the whole instance: the audit watch's finding, inside the range, stays
			* in the log, and its anchor goes on past them.
			*/
			acceptLoss: (range) => call("POST /audit/loss", {}, range)
		}
	};
}
/**
* What writing these entries (a parsed `.env` file) would do, from a dry run
* of the write: the server compares, so no value leaves it, and the values it
* opens to compare are logged as reads. `changes` is what to pass to
* `secrets.set`: the keys that differ, so an unchanged value does not become
* a new version.
*/
async function planImport(coffre, path, entries) {
	const values = Object.create(null);
	for (const { key, value } of entries) values[key] = value;
	const [listed, compared] = await Promise.allSettled([coffre.secrets.list(path), coffre.secrets.dryRun(path, { ...values })]);
	if (listed.status === "rejected") throw listed.reason;
	if (compared.status === "rejected") throw compared.reason;
	const [{ keys }, dryRun] = [listed.value, compared.value];
	const versions = new Map(keys.map((entry) => [entry.key, entry.version]));
	const plan = [];
	const changes = Object.create(null);
	for (const [key, value] of Object.entries(values)) {
		const action = dryRun.keys[key];
		plan.push({
			key,
			action,
			version: versions.get(key) ?? null
		});
		if (action !== "unchanged") changes[key] = value;
	}
	return {
		plan,
		changes: { ...changes }
	};
}
//#endregion
//#region ../core/dist/access-CgQTlUMz.js
/**
* Who may do what: eight permissions, the seven project roles a grant names,
* and the five instance roles a person holds across every project.
*
* Deliberately constants and not tables or a policy language. A grant names
* one role for one member on one place, a person's instance role names one
* role and its scope, and a check is a lookup in this file, so authorisation
* stays something you can read end to end.
*/
/**
* `secret.read` hands a value back: a reveal, `coffre get`, `coffre run`'s
* values. `secret.use` uses it without handing it back: a placeholder in a
* person's app, the credential proxy filling it in (docs/design/credential-proxy.md).
* Every role that reads uses too. What a person gets is the narrower of the
* two and the key's sensitivity: a sensitive key is only ever used.
*/
const PERMISSIONS = [
	"secret.read",
	"secret.use",
	"secret.write",
	"secret.archive",
	"audit.read",
	"environment.manage",
	"grant.manage",
	"project.manage"
];
/**
* Permissions that only make sense on a project. Granting
* `environment.manage` on one environment would be incoherent: what it
* authorises is creating that environment's siblings.
*/
const PROJECT_ONLY_PERMISSIONS = [
	"environment.manage",
	"grant.manage",
	"project.manage"
];
const ROLES = {
	viewer: {
		name: "Viewer",
		description: "Read and use secret values.",
		permissions: ["secret.read", "secret.use"],
		protected: ["secret.use"]
	},
	contributor: {
		name: "Contributor",
		description: "Use and write secrets, never read them: apps get placeholders through the credential proxy.",
		permissions: ["secret.use", "secret.write"],
		protected: ["secret.use", "secret.write"]
	},
	developer: {
		name: "Developer",
		description: "Read, use and write secrets.",
		permissions: [
			"secret.read",
			"secret.use",
			"secret.write"
		],
		protected: ["secret.use", "secret.write"]
	},
	maintainer: {
		name: "Maintainer",
		description: "Read, use, write and retire secrets, and manage environments.",
		permissions: [
			"secret.read",
			"secret.use",
			"secret.write",
			"secret.archive",
			"environment.manage"
		],
		protected: [
			"secret.use",
			"secret.write",
			"secret.archive"
		]
	},
	"access-manager": {
		name: "Access manager",
		description: "Manage who has access. Cannot read secret values.",
		permissions: ["grant.manage"],
		protected: []
	},
	auditor: {
		name: "Auditor",
		description: "Read the audit log. Cannot read secret values.",
		permissions: ["audit.read"],
		protected: ["audit.read"]
	},
	owner: {
		name: "Owner",
		description: "Everything, including reading secret values.",
		permissions: [...PERMISSIONS],
		protected: [...PERMISSIONS].filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission))
	}
};
Object.keys(ROLES);
/** A custom role's id: lowercase, as a slug, and no built-in one's. */
const ROLE_ID = /^[a-z][a-z0-9-]{1,31}$/;
/** Whether `value` names a role of `policy`'s: a built-in one, as it ships, unless told. */
function isRole(value, policy = DEFAULT_POLICY) {
	return Object.hasOwn(policy.roles, value);
}
/** Whether `role` holds `permission` where nothing is protected, as `policy` defines it: as it ships, unless told. */
function roleGrants(role, permission, policy = DEFAULT_POLICY) {
	return definitionOf(policy, role)?.permissions.includes(permission) ?? false;
}
/** A project role's definition in `policy`, or undefined for none. */
function definitionOf(policy, role) {
	return own(policy.roles, role);
}
/** A record's own value at `key`: `constructor` or `__proto__` names nothing. */
function own(record, key) {
	return Object.hasOwn(record, key) ? record[key] : void 0;
}
/**
* A person's role on the whole instance: what they hold in every project
* their scope covers, before any grant. Service accounts are always
* members, and hold only what their grants give. Admins and owners also
* run the instance (`runsInstance`) when nothing narrows their scope.
*/
const INSTANCE_ROLES = {
	member: {
		name: "Member",
		description: "None.",
		permissions: [],
		protected: []
	},
	auditor: {
		name: "Auditor",
		description: "Read the audit log. No secret values.",
		permissions: ["audit.read"],
		protected: ["audit.read"]
	},
	developer: {
		name: "Developer",
		description: "Read, use and write secrets.",
		permissions: [
			"secret.read",
			"secret.use",
			"secret.write"
		],
		protected: ["secret.use", "secret.write"]
	},
	admin: {
		name: "Admin",
		description: "Manage people, service accounts, projects and access. No secret values.",
		permissions: [
			"audit.read",
			"environment.manage",
			"grant.manage",
			"project.manage"
		],
		protected: ["audit.read"]
	},
	owner: {
		name: "Owner",
		description: "Everything, every secret included.",
		permissions: [...PERMISSIONS],
		protected: [...PERMISSIONS].filter((permission) => !PROJECT_ONLY_PERMISSIONS.includes(permission))
	}
};
const INSTANCE_ROLE_NAMES = Object.keys(INSTANCE_ROLES);
function isInstanceRole(value) {
	return Object.hasOwn(INSTANCE_ROLES, value);
}
/** The policy before any Owner edits it: every role as it ships, and no environment protected. */
const DEFAULT_POLICY = {
	roles: ROLES,
	instanceRoles: INSTANCE_ROLES,
	protected: [],
	protectedIn: {}
};
/** Whether a scope narrows nothing. */
function unscoped(scope) {
	return scope.projects === "all" && scope.environments === "all";
}
/**
* A scope in words, its projects named as the caller has them (slugs, at
* the API's edges): `All projects`, `All projects · dev only`,
* `web, api`, `All projects but billing · all but prod`.
*/
function scopeInWords(scope) {
	const list = (names) => names.join(", ");
	const { projects, environments } = scope;
	const where = projects === "all" ? "All projects" : "only" in projects ? projects.only.length === 0 ? "No projects" : list(projects.only) : `All projects but ${list(projects.except)}`;
	if (environments === "all") return where;
	if ("only" in environments) return `${where} · ${environments.only.length === 0 ? "no environments" : `${list(environments.only)} only`}`;
	return `${where} · all but ${list(environments.except)}`;
}
/**
* Whether a personal token's scope may name `role`: one that manages no
* access. A token acting as its person reaches their secrets and places,
* never who holds them, so it cannot hand anyone, itself included, more
* than it was given. A project's Owner who wants a token for all of it
* names `maintainer`.
*/
function delegable(role, policy = DEFAULT_POLICY) {
	return isRole(role, policy) && !roleGrants(role, "grant.manage", policy);
}
/** The roles a personal token's scope may name, in catalogue order. */
function delegableRoles(policy = DEFAULT_POLICY) {
	return Object.keys(policy.roles).filter((role) => delegable(role, policy));
}
delegableRoles();
({ ...DEFAULT_POLICY }), { ...ROLES };
/**
* The longest a personal token lasts: a week. It is for an afternoon's
* script or agent, and whoever needs it longer makes another, as a person,
* rather than keep one around.
*/
const MAX_PERSONAL_TOKEN_MINUTES = 10080;
/**
* A credential's scope, by path as the API names it, in words, each role
* with its places: `developer on market/dev, api/dev; viewer on market/prod`.
*/
function credentialScopeInWords(scope) {
	const byRole = /* @__PURE__ */ new Map();
	for (const [path, role] of Object.entries(scope)) byRole.set(role, [...byRole.get(role) ?? [], path]);
	return [...byRole].map(([role, paths]) => `${role} on ${paths.join(", ")}`).join("; ") || "nothing";
}
//#endregion
//#region ../core/dist/pages.js
/**
* A project's pages beside its environments': `/projects/market/settings`
* sits where `/projects/market/prod` does, so no environment takes one of
* these names (`environmentSlug` in `./schemas.ts`). A tab a project gains
* adds its word here.
*/
const PROJECT_PAGES = [
	"users",
	"service-accounts",
	"settings"
];
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/core.js
var _a$1;
function $constructor(name, initializer, params) {
	function init(inst, def) {
		if (!inst._zod) Object.defineProperty(inst, "_zod", {
			value: {
				def,
				constr: _,
				traits: /* @__PURE__ */ new Set()
			},
			enumerable: false
		});
		if (inst._zod.traits.has(name)) return;
		inst._zod.traits.add(name);
		initializer(inst, def);
		const proto = _.prototype;
		const keys = Object.keys(proto);
		for (let i = 0; i < keys.length; i++) {
			const k = keys[i];
			if (!(k in inst)) inst[k] = proto[k].bind(inst);
		}
	}
	const Parent = params?.Parent ?? Object;
	class Definition extends Parent {}
	Object.defineProperty(Definition, "name", { value: name });
	function _(def) {
		var _a;
		const inst = params?.Parent ? new Definition() : this;
		init(inst, def);
		(_a = inst._zod).deferred ?? (_a.deferred = []);
		for (const fn of inst._zod.deferred) fn();
		return inst;
	}
	Object.defineProperty(_, "init", { value: init });
	Object.defineProperty(_, Symbol.hasInstance, { value: (inst) => {
		if (params?.Parent && inst instanceof params.Parent) return true;
		return inst?._zod?.traits?.has(name);
	} });
	Object.defineProperty(_, "name", { value: name });
	return _;
}
var $ZodAsyncError = class extends Error {
	constructor() {
		super(`Encountered Promise during synchronous parse. Use .parseAsync() instead.`);
	}
};
var $ZodEncodeError = class extends Error {
	constructor(name) {
		super(`Encountered unidirectional transform during encode: ${name}`);
		this.name = "ZodEncodeError";
	}
};
(_a$1 = globalThis).__zod_globalConfig ?? (_a$1.__zod_globalConfig = {});
const globalConfig = globalThis.__zod_globalConfig;
function config(newConfig) {
	if (newConfig) Object.assign(globalConfig, newConfig);
	return globalConfig;
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/util.js
function getEnumValues(entries) {
	const numericValues = Object.values(entries).filter((v) => typeof v === "number");
	return Object.entries(entries).filter(([k, _]) => numericValues.indexOf(+k) === -1).map(([_, v]) => v);
}
function jsonStringifyReplacer(_, value) {
	if (typeof value === "bigint") return value.toString();
	return value;
}
function cached(getter) {
	return { get value() {
		{
			const value = getter();
			Object.defineProperty(this, "value", { value });
			return value;
		}
	} };
}
function nullish(input) {
	return input === null || input === void 0;
}
function cleanRegex(source) {
	const start = source.startsWith("^") ? 1 : 0;
	const end = source.endsWith("$") ? source.length - 1 : source.length;
	return source.slice(start, end);
}
const EVALUATING = /* @__PURE__*/ Symbol("evaluating");
function defineLazy(object, key, getter) {
	let value = void 0;
	Object.defineProperty(object, key, {
		get() {
			if (value === EVALUATING) return;
			if (value === void 0) {
				value = EVALUATING;
				value = getter();
			}
			return value;
		},
		set(v) {
			Object.defineProperty(object, key, { value: v });
		},
		configurable: true
	});
}
function assignProp(target, prop, value) {
	Object.defineProperty(target, prop, {
		value,
		writable: true,
		enumerable: true,
		configurable: true
	});
}
function mergeDefs(...defs) {
	const mergedDescriptors = {};
	for (const def of defs) {
		const descriptors = Object.getOwnPropertyDescriptors(def);
		Object.assign(mergedDescriptors, descriptors);
	}
	return Object.defineProperties({}, mergedDescriptors);
}
function esc(str) {
	return JSON.stringify(str);
}
function slugify(input) {
	return input.toLowerCase().trim().replace(/[^\w\s-]/g, "").replace(/[\s_-]+/g, "-").replace(/^-+|-+$/g, "");
}
const captureStackTrace = "captureStackTrace" in Error ? Error.captureStackTrace : (..._args) => {};
function isObject(data) {
	return typeof data === "object" && data !== null && !Array.isArray(data);
}
const allowsEval = /* @__PURE__*/ cached(() => {
	if (globalConfig.jitless) return false;
	if (typeof navigator !== "undefined" && navigator?.userAgent?.includes("Cloudflare")) return false;
	try {
		new Function("");
		return true;
	} catch (_) {
		return false;
	}
});
function isPlainObject(o) {
	if (isObject(o) === false) return false;
	const ctor = o.constructor;
	if (ctor === void 0) return true;
	if (typeof ctor !== "function") return true;
	const prot = ctor.prototype;
	if (isObject(prot) === false) return false;
	if (Object.prototype.hasOwnProperty.call(prot, "isPrototypeOf") === false) return false;
	return true;
}
function shallowClone(o) {
	if (isPlainObject(o)) return { ...o };
	if (Array.isArray(o)) return [...o];
	if (o instanceof Map) return new Map(o);
	if (o instanceof Set) return new Set(o);
	return o;
}
const propertyKeyTypes = /* @__PURE__*/ new Set([
	"string",
	"number",
	"symbol"
]);
function escapeRegex(str) {
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function clone(inst, def, params) {
	const cl = new inst._zod.constr(def ?? inst._zod.def);
	if (!def || params?.parent) cl._zod.parent = inst;
	return cl;
}
function normalizeParams(_params) {
	const params = _params;
	if (!params) return {};
	if (typeof params === "string") return { error: () => params };
	if (params?.message !== void 0) {
		if (params?.error !== void 0) throw new Error("Cannot specify both `message` and `error` params");
		params.error = params.message;
	}
	delete params.message;
	if (typeof params.error === "string") return {
		...params,
		error: () => params.error
	};
	return params;
}
function optionalKeys(shape) {
	return Object.keys(shape).filter((k) => {
		return shape[k]._zod.optin === "optional" && shape[k]._zod.optout === "optional";
	});
}
function pick(schema, mask) {
	const currDef = schema._zod.def;
	const checks = currDef.checks;
	if (checks && checks.length > 0) throw new Error(".pick() cannot be used on object schemas containing refinements");
	return clone(schema, mergeDefs(schema._zod.def, {
		get shape() {
			const newShape = {};
			for (const key in mask) {
				if (!(key in currDef.shape)) throw new Error(`Unrecognized key: "${key}"`);
				if (!mask[key]) continue;
				newShape[key] = currDef.shape[key];
			}
			assignProp(this, "shape", newShape);
			return newShape;
		},
		checks: []
	}));
}
function omit(schema, mask) {
	const currDef = schema._zod.def;
	const checks = currDef.checks;
	if (checks && checks.length > 0) throw new Error(".omit() cannot be used on object schemas containing refinements");
	return clone(schema, mergeDefs(schema._zod.def, {
		get shape() {
			const newShape = { ...schema._zod.def.shape };
			for (const key in mask) {
				if (!(key in currDef.shape)) throw new Error(`Unrecognized key: "${key}"`);
				if (!mask[key]) continue;
				delete newShape[key];
			}
			assignProp(this, "shape", newShape);
			return newShape;
		},
		checks: []
	}));
}
function extend(schema, shape) {
	if (!isPlainObject(shape)) throw new Error("Invalid input to extend: expected a plain object");
	const checks = schema._zod.def.checks;
	if (checks && checks.length > 0) {
		const existingShape = schema._zod.def.shape;
		for (const key in shape) if (Object.getOwnPropertyDescriptor(existingShape, key) !== void 0) throw new Error("Cannot overwrite keys on object schemas containing refinements. Use `.safeExtend()` instead.");
	}
	return clone(schema, mergeDefs(schema._zod.def, { get shape() {
		const _shape = {
			...schema._zod.def.shape,
			...shape
		};
		assignProp(this, "shape", _shape);
		return _shape;
	} }));
}
function safeExtend(schema, shape) {
	if (!isPlainObject(shape)) throw new Error("Invalid input to safeExtend: expected a plain object");
	return clone(schema, mergeDefs(schema._zod.def, { get shape() {
		const _shape = {
			...schema._zod.def.shape,
			...shape
		};
		assignProp(this, "shape", _shape);
		return _shape;
	} }));
}
function merge(a, b) {
	if (a._zod.def.checks?.length) throw new Error(".merge() cannot be used on object schemas containing refinements. Use .safeExtend() instead.");
	return clone(a, mergeDefs(a._zod.def, {
		get shape() {
			const _shape = {
				...a._zod.def.shape,
				...b._zod.def.shape
			};
			assignProp(this, "shape", _shape);
			return _shape;
		},
		get catchall() {
			return b._zod.def.catchall;
		},
		checks: b._zod.def.checks ?? []
	}));
}
function partial(Class, schema, mask) {
	const checks = schema._zod.def.checks;
	if (checks && checks.length > 0) throw new Error(".partial() cannot be used on object schemas containing refinements");
	return clone(schema, mergeDefs(schema._zod.def, {
		get shape() {
			const oldShape = schema._zod.def.shape;
			const shape = { ...oldShape };
			if (mask) for (const key in mask) {
				if (!(key in oldShape)) throw new Error(`Unrecognized key: "${key}"`);
				if (!mask[key]) continue;
				shape[key] = Class ? new Class({
					type: "optional",
					innerType: oldShape[key]
				}) : oldShape[key];
			}
			else for (const key in oldShape) shape[key] = Class ? new Class({
				type: "optional",
				innerType: oldShape[key]
			}) : oldShape[key];
			assignProp(this, "shape", shape);
			return shape;
		},
		checks: []
	}));
}
function required(Class, schema, mask) {
	return clone(schema, mergeDefs(schema._zod.def, { get shape() {
		const oldShape = schema._zod.def.shape;
		const shape = { ...oldShape };
		if (mask) for (const key in mask) {
			if (!(key in shape)) throw new Error(`Unrecognized key: "${key}"`);
			if (!mask[key]) continue;
			shape[key] = new Class({
				type: "nonoptional",
				innerType: oldShape[key]
			});
		}
		else for (const key in oldShape) shape[key] = new Class({
			type: "nonoptional",
			innerType: oldShape[key]
		});
		assignProp(this, "shape", shape);
		return shape;
	} }));
}
function aborted(x, startIndex = 0) {
	if (x.aborted === true) return true;
	for (let i = startIndex; i < x.issues.length; i++) if (x.issues[i]?.continue !== true) return true;
	return false;
}
function explicitlyAborted(x, startIndex = 0) {
	if (x.aborted === true) return true;
	for (let i = startIndex; i < x.issues.length; i++) if (x.issues[i]?.continue === false) return true;
	return false;
}
function prefixIssues(path, issues) {
	return issues.map((iss) => {
		var _a;
		(_a = iss).path ?? (_a.path = []);
		iss.path.unshift(path);
		return iss;
	});
}
function unwrapMessage(message) {
	return typeof message === "string" ? message : message?.message;
}
function finalizeIssue(iss, ctx, config) {
	const message = iss.message ? iss.message : unwrapMessage(iss.inst?._zod.def?.error?.(iss)) ?? unwrapMessage(ctx?.error?.(iss)) ?? unwrapMessage(config.customError?.(iss)) ?? unwrapMessage(config.localeError?.(iss)) ?? "Invalid input";
	const { inst: _inst, continue: _continue, input: _input, ...rest } = iss;
	rest.path ?? (rest.path = []);
	rest.message = message;
	if (ctx?.reportInput) rest.input = _input;
	return rest;
}
function getLengthableOrigin(input) {
	if (Array.isArray(input)) return "array";
	if (typeof input === "string") return "string";
	return "unknown";
}
function issue(...args) {
	const [iss, input, inst] = args;
	if (typeof iss === "string") return {
		message: iss,
		code: "custom",
		input,
		inst
	};
	return { ...iss };
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/errors.js
const initializer$1 = (inst, def) => {
	inst.name = "$ZodError";
	Object.defineProperty(inst, "_zod", {
		value: inst._zod,
		enumerable: false
	});
	Object.defineProperty(inst, "issues", {
		value: def,
		enumerable: false
	});
	inst.message = JSON.stringify(def, jsonStringifyReplacer, 2);
	Object.defineProperty(inst, "toString", {
		value: () => inst.message,
		enumerable: false
	});
};
const $ZodError = $constructor("$ZodError", initializer$1);
const $ZodRealError = $constructor("$ZodError", initializer$1, { Parent: Error });
function flattenError(error, mapper = (issue) => issue.message) {
	const fieldErrors = {};
	const formErrors = [];
	for (const sub of error.issues) if (sub.path.length > 0) {
		fieldErrors[sub.path[0]] = fieldErrors[sub.path[0]] || [];
		fieldErrors[sub.path[0]].push(mapper(sub));
	} else formErrors.push(mapper(sub));
	return {
		formErrors,
		fieldErrors
	};
}
function formatError(error, mapper = (issue) => issue.message) {
	const fieldErrors = { _errors: [] };
	const processError = (error, path = []) => {
		for (const issue of error.issues) if (issue.code === "invalid_union" && issue.errors.length) issue.errors.map((issues) => processError({ issues }, [...path, ...issue.path]));
		else if (issue.code === "invalid_key") processError({ issues: issue.issues }, [...path, ...issue.path]);
		else if (issue.code === "invalid_element") processError({ issues: issue.issues }, [...path, ...issue.path]);
		else {
			const fullpath = [...path, ...issue.path];
			if (fullpath.length === 0) fieldErrors._errors.push(mapper(issue));
			else {
				let curr = fieldErrors;
				let i = 0;
				while (i < fullpath.length) {
					const el = fullpath[i];
					if (!(i === fullpath.length - 1)) curr[el] = curr[el] || { _errors: [] };
					else {
						curr[el] = curr[el] || { _errors: [] };
						curr[el]._errors.push(mapper(issue));
					}
					curr = curr[el];
					i++;
				}
			}
		}
	};
	processError(error);
	return fieldErrors;
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/parse.js
const _parse = (_Err) => (schema, value, _ctx, _params) => {
	const ctx = _ctx ? {
		..._ctx,
		async: false
	} : { async: false };
	const result = schema._zod.run({
		value,
		issues: []
	}, ctx);
	if (result instanceof Promise) throw new $ZodAsyncError();
	if (result.issues.length) {
		const e = new ((_params?.Err) ?? _Err)(result.issues.map((iss) => finalizeIssue(iss, ctx, config())));
		captureStackTrace(e, _params?.callee);
		throw e;
	}
	return result.value;
};
const _parseAsync = (_Err) => async (schema, value, _ctx, params) => {
	const ctx = _ctx ? {
		..._ctx,
		async: true
	} : { async: true };
	let result = schema._zod.run({
		value,
		issues: []
	}, ctx);
	if (result instanceof Promise) result = await result;
	if (result.issues.length) {
		const e = new ((params?.Err) ?? _Err)(result.issues.map((iss) => finalizeIssue(iss, ctx, config())));
		captureStackTrace(e, params?.callee);
		throw e;
	}
	return result.value;
};
const _safeParse = (_Err) => (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		async: false
	} : { async: false };
	const result = schema._zod.run({
		value,
		issues: []
	}, ctx);
	if (result instanceof Promise) throw new $ZodAsyncError();
	return result.issues.length ? {
		success: false,
		error: new (_Err ?? $ZodError)(result.issues.map((iss) => finalizeIssue(iss, ctx, config())))
	} : {
		success: true,
		data: result.value
	};
};
const safeParse$1 = /* @__PURE__*/ _safeParse($ZodRealError);
const _safeParseAsync = (_Err) => async (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		async: true
	} : { async: true };
	let result = schema._zod.run({
		value,
		issues: []
	}, ctx);
	if (result instanceof Promise) result = await result;
	return result.issues.length ? {
		success: false,
		error: new _Err(result.issues.map((iss) => finalizeIssue(iss, ctx, config())))
	} : {
		success: true,
		data: result.value
	};
};
const safeParseAsync$1 = /* @__PURE__*/ _safeParseAsync($ZodRealError);
const _encode = (_Err) => (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		direction: "backward"
	} : { direction: "backward" };
	return _parse(_Err)(schema, value, ctx);
};
const _decode = (_Err) => (schema, value, _ctx) => {
	return _parse(_Err)(schema, value, _ctx);
};
const _encodeAsync = (_Err) => async (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		direction: "backward"
	} : { direction: "backward" };
	return _parseAsync(_Err)(schema, value, ctx);
};
const _decodeAsync = (_Err) => async (schema, value, _ctx) => {
	return _parseAsync(_Err)(schema, value, _ctx);
};
const _safeEncode = (_Err) => (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		direction: "backward"
	} : { direction: "backward" };
	return _safeParse(_Err)(schema, value, ctx);
};
const _safeDecode = (_Err) => (schema, value, _ctx) => {
	return _safeParse(_Err)(schema, value, _ctx);
};
const _safeEncodeAsync = (_Err) => async (schema, value, _ctx) => {
	const ctx = _ctx ? {
		..._ctx,
		direction: "backward"
	} : { direction: "backward" };
	return _safeParseAsync(_Err)(schema, value, ctx);
};
const _safeDecodeAsync = (_Err) => async (schema, value, _ctx) => {
	return _safeParseAsync(_Err)(schema, value, _ctx);
};
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/regexes.js
/**
* @deprecated CUID v1 is deprecated by its authors due to information leakage
* (timestamps embedded in the id). Use {@link cuid2} instead.
* See https://github.com/paralleldrive/cuid.
*/
const cuid = /^[cC][0-9a-z]{6,}$/;
const cuid2 = /^[0-9a-z]+$/;
const ulid = /^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}$/;
const xid = /^[0-9a-vA-V]{20}$/;
const ksuid = /^[A-Za-z0-9]{27}$/;
const nanoid = /^[a-zA-Z0-9_-]{21}$/;
/** ISO 8601-1 duration regex. Does not support the 8601-2 extensions like negative durations or fractional/negative components. */
const duration$2 = /^P(?:(\d+W)|(?!.*W)(?=\d|T\d)(\d+Y)?(\d+M)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+([.,]\d+)?S)?)?)$/;
/** A regex for any UUID-like identifier: 8-4-4-4-12 hex pattern */
const guid = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;
/** Returns a regex for validating an RFC 9562/4122 UUID.
*
* @param version Optionally specify a version 1-8. If no version is specified, all versions are supported. */
const uuid = (version) => {
	if (!version) return /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/;
	return new RegExp(`^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-${version}[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$`);
};
/** Practical email validation */
const email = /^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$/;
const _emoji$1 = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
function emoji() {
	return new RegExp(_emoji$1, "u");
}
const ipv4$1 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
const ipv6$1 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
const cidrv4 = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/([0-9]|[1-2][0-9]|3[0-2])$/;
const cidrv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:?){0,6})\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
const base64 = /^$|^(?:[0-9a-zA-Z+/]{4})*(?:(?:[0-9a-zA-Z+/]{2}==)|(?:[0-9a-zA-Z+/]{3}=))?$/;
const base64url$1 = /^[A-Za-z0-9_-]*$/;
const httpProtocol = /^https?$/;
const e164 = /^\+[1-9]\d{6,14}$/;
const dateSource = `(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))`;
const date$1 = /*@__PURE__*/ new RegExp(`^${dateSource}$`);
function timeSource(args) {
	const hhmm = `(?:[01]\\d|2[0-3]):[0-5]\\d`;
	return typeof args.precision === "number" ? args.precision === -1 ? `${hhmm}` : args.precision === 0 ? `${hhmm}:[0-5]\\d` : `${hhmm}:[0-5]\\d\\.\\d{${args.precision}}` : `${hhmm}(?::[0-5]\\d(?:\\.\\d+)?)?`;
}
function time$1(args) {
	return new RegExp(`^${timeSource(args)}$`);
}
function datetime$1(args) {
	const time = timeSource({ precision: args.precision });
	const opts = ["Z"];
	if (args.local) opts.push("");
	if (args.offset) opts.push(`([+-](?:[01]\\d|2[0-3]):[0-5]\\d)`);
	const timeRegex = `${time}(?:${opts.join("|")})`;
	return new RegExp(`^${dateSource}T(?:${timeRegex})$`);
}
const string$1 = (params) => {
	const regex = params ? `[\\s\\S]{${params?.minimum ?? 0},${params?.maximum ?? ""}}` : `[\\s\\S]*`;
	return new RegExp(`^${regex}$`);
};
const lowercase = /^[^A-Z]*$/;
const uppercase = /^[^a-z]*$/;
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/checks.js
const $ZodCheck = /*@__PURE__*/ $constructor("$ZodCheck", (inst, def) => {
	var _a;
	inst._zod ?? (inst._zod = {});
	inst._zod.def = def;
	(_a = inst._zod).onattach ?? (_a.onattach = []);
});
const $ZodCheckMaxLength = /*@__PURE__*/ $constructor("$ZodCheckMaxLength", (inst, def) => {
	var _a;
	$ZodCheck.init(inst, def);
	(_a = inst._zod.def).when ?? (_a.when = (payload) => {
		const val = payload.value;
		return !nullish(val) && val.length !== void 0;
	});
	inst._zod.onattach.push((inst) => {
		const curr = inst._zod.bag.maximum ?? Number.POSITIVE_INFINITY;
		if (def.maximum < curr) inst._zod.bag.maximum = def.maximum;
	});
	inst._zod.check = (payload) => {
		const input = payload.value;
		if (input.length <= def.maximum) return;
		const origin = getLengthableOrigin(input);
		payload.issues.push({
			origin,
			code: "too_big",
			maximum: def.maximum,
			inclusive: true,
			input,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckMinLength = /*@__PURE__*/ $constructor("$ZodCheckMinLength", (inst, def) => {
	var _a;
	$ZodCheck.init(inst, def);
	(_a = inst._zod.def).when ?? (_a.when = (payload) => {
		const val = payload.value;
		return !nullish(val) && val.length !== void 0;
	});
	inst._zod.onattach.push((inst) => {
		const curr = inst._zod.bag.minimum ?? Number.NEGATIVE_INFINITY;
		if (def.minimum > curr) inst._zod.bag.minimum = def.minimum;
	});
	inst._zod.check = (payload) => {
		const input = payload.value;
		if (input.length >= def.minimum) return;
		const origin = getLengthableOrigin(input);
		payload.issues.push({
			origin,
			code: "too_small",
			minimum: def.minimum,
			inclusive: true,
			input,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckLengthEquals = /*@__PURE__*/ $constructor("$ZodCheckLengthEquals", (inst, def) => {
	var _a;
	$ZodCheck.init(inst, def);
	(_a = inst._zod.def).when ?? (_a.when = (payload) => {
		const val = payload.value;
		return !nullish(val) && val.length !== void 0;
	});
	inst._zod.onattach.push((inst) => {
		const bag = inst._zod.bag;
		bag.minimum = def.length;
		bag.maximum = def.length;
		bag.length = def.length;
	});
	inst._zod.check = (payload) => {
		const input = payload.value;
		const length = input.length;
		if (length === def.length) return;
		const origin = getLengthableOrigin(input);
		const tooBig = length > def.length;
		payload.issues.push({
			origin,
			...tooBig ? {
				code: "too_big",
				maximum: def.length
			} : {
				code: "too_small",
				minimum: def.length
			},
			inclusive: true,
			exact: true,
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckStringFormat = /*@__PURE__*/ $constructor("$ZodCheckStringFormat", (inst, def) => {
	var _a, _b;
	$ZodCheck.init(inst, def);
	inst._zod.onattach.push((inst) => {
		const bag = inst._zod.bag;
		bag.format = def.format;
		if (def.pattern) {
			bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
			bag.patterns.add(def.pattern);
		}
	});
	if (def.pattern) (_a = inst._zod).check ?? (_a.check = (payload) => {
		def.pattern.lastIndex = 0;
		if (def.pattern.test(payload.value)) return;
		payload.issues.push({
			origin: "string",
			code: "invalid_format",
			format: def.format,
			input: payload.value,
			...def.pattern ? { pattern: def.pattern.toString() } : {},
			inst,
			continue: !def.abort
		});
	});
	else (_b = inst._zod).check ?? (_b.check = () => {});
});
const $ZodCheckRegex = /*@__PURE__*/ $constructor("$ZodCheckRegex", (inst, def) => {
	$ZodCheckStringFormat.init(inst, def);
	inst._zod.check = (payload) => {
		def.pattern.lastIndex = 0;
		if (def.pattern.test(payload.value)) return;
		payload.issues.push({
			origin: "string",
			code: "invalid_format",
			format: "regex",
			input: payload.value,
			pattern: def.pattern.toString(),
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckLowerCase = /*@__PURE__*/ $constructor("$ZodCheckLowerCase", (inst, def) => {
	def.pattern ?? (def.pattern = lowercase);
	$ZodCheckStringFormat.init(inst, def);
});
const $ZodCheckUpperCase = /*@__PURE__*/ $constructor("$ZodCheckUpperCase", (inst, def) => {
	def.pattern ?? (def.pattern = uppercase);
	$ZodCheckStringFormat.init(inst, def);
});
const $ZodCheckIncludes = /*@__PURE__*/ $constructor("$ZodCheckIncludes", (inst, def) => {
	$ZodCheck.init(inst, def);
	const escapedRegex = escapeRegex(def.includes);
	const pattern = new RegExp(typeof def.position === "number" ? `^.{${def.position}}${escapedRegex}` : escapedRegex);
	def.pattern = pattern;
	inst._zod.onattach.push((inst) => {
		const bag = inst._zod.bag;
		bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
		bag.patterns.add(pattern);
	});
	inst._zod.check = (payload) => {
		if (payload.value.includes(def.includes, def.position)) return;
		payload.issues.push({
			origin: "string",
			code: "invalid_format",
			format: "includes",
			includes: def.includes,
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckStartsWith = /*@__PURE__*/ $constructor("$ZodCheckStartsWith", (inst, def) => {
	$ZodCheck.init(inst, def);
	const pattern = new RegExp(`^${escapeRegex(def.prefix)}.*`);
	def.pattern ?? (def.pattern = pattern);
	inst._zod.onattach.push((inst) => {
		const bag = inst._zod.bag;
		bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
		bag.patterns.add(pattern);
	});
	inst._zod.check = (payload) => {
		if (payload.value.startsWith(def.prefix)) return;
		payload.issues.push({
			origin: "string",
			code: "invalid_format",
			format: "starts_with",
			prefix: def.prefix,
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckEndsWith = /*@__PURE__*/ $constructor("$ZodCheckEndsWith", (inst, def) => {
	$ZodCheck.init(inst, def);
	const pattern = new RegExp(`.*${escapeRegex(def.suffix)}$`);
	def.pattern ?? (def.pattern = pattern);
	inst._zod.onattach.push((inst) => {
		const bag = inst._zod.bag;
		bag.patterns ?? (bag.patterns = /* @__PURE__ */ new Set());
		bag.patterns.add(pattern);
	});
	inst._zod.check = (payload) => {
		if (payload.value.endsWith(def.suffix)) return;
		payload.issues.push({
			origin: "string",
			code: "invalid_format",
			format: "ends_with",
			suffix: def.suffix,
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodCheckOverwrite = /*@__PURE__*/ $constructor("$ZodCheckOverwrite", (inst, def) => {
	$ZodCheck.init(inst, def);
	inst._zod.check = (payload) => {
		payload.value = def.tx(payload.value);
	};
});
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/doc.js
var Doc = class {
	constructor(args = []) {
		this.content = [];
		this.indent = 0;
		if (this) this.args = args;
	}
	indented(fn) {
		this.indent += 1;
		fn(this);
		this.indent -= 1;
	}
	write(arg) {
		if (typeof arg === "function") {
			arg(this, { execution: "sync" });
			arg(this, { execution: "async" });
			return;
		}
		const lines = arg.split("\n").filter((x) => x);
		const minIndent = Math.min(...lines.map((x) => x.length - x.trimStart().length));
		const dedented = lines.map((x) => x.slice(minIndent)).map((x) => " ".repeat(this.indent * 2) + x);
		for (const line of dedented) this.content.push(line);
	}
	compile() {
		const F = Function;
		const args = this?.args;
		const lines = [...(this?.content ?? [``]).map((x) => `  ${x}`)];
		return new F(...args, lines.join("\n"));
	}
};
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/versions.js
const version$1 = {
	major: 4,
	minor: 4,
	patch: 3
};
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/schemas.js
const $ZodType = /*@__PURE__*/ $constructor("$ZodType", (inst, def) => {
	var _a;
	inst ?? (inst = {});
	inst._zod.def = def;
	inst._zod.bag = inst._zod.bag || {};
	inst._zod.version = version$1;
	const checks = [...inst._zod.def.checks ?? []];
	if (inst._zod.traits.has("$ZodCheck")) checks.unshift(inst);
	for (const ch of checks) for (const fn of ch._zod.onattach) fn(inst);
	if (checks.length === 0) {
		(_a = inst._zod).deferred ?? (_a.deferred = []);
		inst._zod.deferred?.push(() => {
			inst._zod.run = inst._zod.parse;
		});
	} else {
		const runChecks = (payload, checks, ctx) => {
			let isAborted = aborted(payload);
			let asyncResult;
			for (const ch of checks) {
				if (ch._zod.def.when) {
					if (explicitlyAborted(payload)) continue;
					if (!ch._zod.def.when(payload)) continue;
				} else if (isAborted) continue;
				const currLen = payload.issues.length;
				const _ = ch._zod.check(payload);
				if (_ instanceof Promise && ctx?.async === false) throw new $ZodAsyncError();
				if (asyncResult || _ instanceof Promise) asyncResult = (asyncResult ?? Promise.resolve()).then(async () => {
					await _;
					if (payload.issues.length === currLen) return;
					if (!isAborted) isAborted = aborted(payload, currLen);
				});
				else {
					if (payload.issues.length === currLen) continue;
					if (!isAborted) isAborted = aborted(payload, currLen);
				}
			}
			if (asyncResult) return asyncResult.then(() => {
				return payload;
			});
			return payload;
		};
		const handleCanaryResult = (canary, payload, ctx) => {
			if (aborted(canary)) {
				canary.aborted = true;
				return canary;
			}
			const checkResult = runChecks(payload, checks, ctx);
			if (checkResult instanceof Promise) {
				if (ctx.async === false) throw new $ZodAsyncError();
				return checkResult.then((checkResult) => inst._zod.parse(checkResult, ctx));
			}
			return inst._zod.parse(checkResult, ctx);
		};
		inst._zod.run = (payload, ctx) => {
			if (ctx.skipChecks) return inst._zod.parse(payload, ctx);
			if (ctx.direction === "backward") {
				const canary = inst._zod.parse({
					value: payload.value,
					issues: []
				}, {
					...ctx,
					skipChecks: true
				});
				if (canary instanceof Promise) return canary.then((canary) => {
					return handleCanaryResult(canary, payload, ctx);
				});
				return handleCanaryResult(canary, payload, ctx);
			}
			const result = inst._zod.parse(payload, ctx);
			if (result instanceof Promise) {
				if (ctx.async === false) throw new $ZodAsyncError();
				return result.then((result) => runChecks(result, checks, ctx));
			}
			return runChecks(result, checks, ctx);
		};
	}
	defineLazy(inst, "~standard", () => ({
		validate: (value) => {
			try {
				const r = safeParse$1(inst, value);
				return r.success ? { value: r.data } : { issues: r.error?.issues };
			} catch (_) {
				return safeParseAsync$1(inst, value).then((r) => r.success ? { value: r.data } : { issues: r.error?.issues });
			}
		},
		vendor: "zod",
		version: 1
	}));
});
const $ZodString = /*@__PURE__*/ $constructor("$ZodString", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.pattern = [...inst?._zod.bag?.patterns ?? []].pop() ?? string$1(inst._zod.bag);
	inst._zod.parse = (payload, _) => {
		if (def.coerce) try {
			payload.value = String(payload.value);
		} catch (_) {}
		if (typeof payload.value === "string") return payload;
		payload.issues.push({
			expected: "string",
			code: "invalid_type",
			input: payload.value,
			inst
		});
		return payload;
	};
});
const $ZodStringFormat = /*@__PURE__*/ $constructor("$ZodStringFormat", (inst, def) => {
	$ZodCheckStringFormat.init(inst, def);
	$ZodString.init(inst, def);
});
const $ZodGUID = /*@__PURE__*/ $constructor("$ZodGUID", (inst, def) => {
	def.pattern ?? (def.pattern = guid);
	$ZodStringFormat.init(inst, def);
});
const $ZodUUID = /*@__PURE__*/ $constructor("$ZodUUID", (inst, def) => {
	if (def.version) {
		const v = {
			v1: 1,
			v2: 2,
			v3: 3,
			v4: 4,
			v5: 5,
			v6: 6,
			v7: 7,
			v8: 8
		}[def.version];
		if (v === void 0) throw new Error(`Invalid UUID version: "${def.version}"`);
		def.pattern ?? (def.pattern = uuid(v));
	} else def.pattern ?? (def.pattern = uuid());
	$ZodStringFormat.init(inst, def);
});
const $ZodEmail = /*@__PURE__*/ $constructor("$ZodEmail", (inst, def) => {
	def.pattern ?? (def.pattern = email);
	$ZodStringFormat.init(inst, def);
});
const $ZodURL = /*@__PURE__*/ $constructor("$ZodURL", (inst, def) => {
	$ZodStringFormat.init(inst, def);
	inst._zod.check = (payload) => {
		try {
			const trimmed = payload.value.trim();
			if (!def.normalize && def.protocol?.source === httpProtocol.source) {
				if (!/^https?:\/\//i.test(trimmed)) {
					payload.issues.push({
						code: "invalid_format",
						format: "url",
						note: "Invalid URL format",
						input: payload.value,
						inst,
						continue: !def.abort
					});
					return;
				}
			}
			const url = new URL(trimmed);
			if (def.hostname) {
				def.hostname.lastIndex = 0;
				if (!def.hostname.test(url.hostname)) payload.issues.push({
					code: "invalid_format",
					format: "url",
					note: "Invalid hostname",
					pattern: def.hostname.source,
					input: payload.value,
					inst,
					continue: !def.abort
				});
			}
			if (def.protocol) {
				def.protocol.lastIndex = 0;
				if (!def.protocol.test(url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol)) payload.issues.push({
					code: "invalid_format",
					format: "url",
					note: "Invalid protocol",
					pattern: def.protocol.source,
					input: payload.value,
					inst,
					continue: !def.abort
				});
			}
			if (def.normalize) payload.value = url.href;
			else payload.value = trimmed;
			return;
		} catch (_) {
			payload.issues.push({
				code: "invalid_format",
				format: "url",
				input: payload.value,
				inst,
				continue: !def.abort
			});
		}
	};
});
const $ZodEmoji = /*@__PURE__*/ $constructor("$ZodEmoji", (inst, def) => {
	def.pattern ?? (def.pattern = emoji());
	$ZodStringFormat.init(inst, def);
});
const $ZodNanoID = /*@__PURE__*/ $constructor("$ZodNanoID", (inst, def) => {
	def.pattern ?? (def.pattern = nanoid);
	$ZodStringFormat.init(inst, def);
});
/**
* @deprecated CUID v1 is deprecated by its authors due to information leakage
* (timestamps embedded in the id). Use {@link $ZodCUID2} instead.
* See https://github.com/paralleldrive/cuid.
*/
const $ZodCUID = /*@__PURE__*/ $constructor("$ZodCUID", (inst, def) => {
	def.pattern ?? (def.pattern = cuid);
	$ZodStringFormat.init(inst, def);
});
const $ZodCUID2 = /*@__PURE__*/ $constructor("$ZodCUID2", (inst, def) => {
	def.pattern ?? (def.pattern = cuid2);
	$ZodStringFormat.init(inst, def);
});
const $ZodULID = /*@__PURE__*/ $constructor("$ZodULID", (inst, def) => {
	def.pattern ?? (def.pattern = ulid);
	$ZodStringFormat.init(inst, def);
});
const $ZodXID = /*@__PURE__*/ $constructor("$ZodXID", (inst, def) => {
	def.pattern ?? (def.pattern = xid);
	$ZodStringFormat.init(inst, def);
});
const $ZodKSUID = /*@__PURE__*/ $constructor("$ZodKSUID", (inst, def) => {
	def.pattern ?? (def.pattern = ksuid);
	$ZodStringFormat.init(inst, def);
});
const $ZodISODateTime = /*@__PURE__*/ $constructor("$ZodISODateTime", (inst, def) => {
	def.pattern ?? (def.pattern = datetime$1(def));
	$ZodStringFormat.init(inst, def);
});
const $ZodISODate = /*@__PURE__*/ $constructor("$ZodISODate", (inst, def) => {
	def.pattern ?? (def.pattern = date$1);
	$ZodStringFormat.init(inst, def);
});
const $ZodISOTime = /*@__PURE__*/ $constructor("$ZodISOTime", (inst, def) => {
	def.pattern ?? (def.pattern = time$1(def));
	$ZodStringFormat.init(inst, def);
});
const $ZodISODuration = /*@__PURE__*/ $constructor("$ZodISODuration", (inst, def) => {
	def.pattern ?? (def.pattern = duration$2);
	$ZodStringFormat.init(inst, def);
});
const $ZodIPv4 = /*@__PURE__*/ $constructor("$ZodIPv4", (inst, def) => {
	def.pattern ?? (def.pattern = ipv4$1);
	$ZodStringFormat.init(inst, def);
	inst._zod.bag.format = `ipv4`;
});
const $ZodIPv6 = /*@__PURE__*/ $constructor("$ZodIPv6", (inst, def) => {
	def.pattern ?? (def.pattern = ipv6$1);
	$ZodStringFormat.init(inst, def);
	inst._zod.bag.format = `ipv6`;
	inst._zod.check = (payload) => {
		try {
			new URL(`http://[${payload.value}]`);
		} catch {
			payload.issues.push({
				code: "invalid_format",
				format: "ipv6",
				input: payload.value,
				inst,
				continue: !def.abort
			});
		}
	};
});
const $ZodCIDRv4 = /*@__PURE__*/ $constructor("$ZodCIDRv4", (inst, def) => {
	def.pattern ?? (def.pattern = cidrv4);
	$ZodStringFormat.init(inst, def);
});
const $ZodCIDRv6 = /*@__PURE__*/ $constructor("$ZodCIDRv6", (inst, def) => {
	def.pattern ?? (def.pattern = cidrv6);
	$ZodStringFormat.init(inst, def);
	inst._zod.check = (payload) => {
		const parts = payload.value.split("/");
		try {
			if (parts.length !== 2) throw new Error();
			const [address, prefix] = parts;
			if (!prefix) throw new Error();
			const prefixNum = Number(prefix);
			if (`${prefixNum}` !== prefix) throw new Error();
			if (prefixNum < 0 || prefixNum > 128) throw new Error();
			new URL(`http://[${address}]`);
		} catch {
			payload.issues.push({
				code: "invalid_format",
				format: "cidrv6",
				input: payload.value,
				inst,
				continue: !def.abort
			});
		}
	};
});
function isValidBase64(data) {
	if (data === "") return true;
	if (/\s/.test(data)) return false;
	if (data.length % 4 !== 0) return false;
	try {
		atob(data);
		return true;
	} catch {
		return false;
	}
}
const $ZodBase64 = /*@__PURE__*/ $constructor("$ZodBase64", (inst, def) => {
	def.pattern ?? (def.pattern = base64);
	$ZodStringFormat.init(inst, def);
	inst._zod.bag.contentEncoding = "base64";
	inst._zod.check = (payload) => {
		if (isValidBase64(payload.value)) return;
		payload.issues.push({
			code: "invalid_format",
			format: "base64",
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
function isValidBase64URL(data) {
	if (!base64url$1.test(data)) return false;
	const base64 = data.replace(/[-_]/g, (c) => c === "-" ? "+" : "/");
	return isValidBase64(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
}
const $ZodBase64URL = /*@__PURE__*/ $constructor("$ZodBase64URL", (inst, def) => {
	def.pattern ?? (def.pattern = base64url$1);
	$ZodStringFormat.init(inst, def);
	inst._zod.bag.contentEncoding = "base64url";
	inst._zod.check = (payload) => {
		if (isValidBase64URL(payload.value)) return;
		payload.issues.push({
			code: "invalid_format",
			format: "base64url",
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodE164 = /*@__PURE__*/ $constructor("$ZodE164", (inst, def) => {
	def.pattern ?? (def.pattern = e164);
	$ZodStringFormat.init(inst, def);
});
function isValidJWT(token, algorithm = null) {
	try {
		const tokensParts = token.split(".");
		if (tokensParts.length !== 3) return false;
		const [header] = tokensParts;
		if (!header) return false;
		const parsedHeader = JSON.parse(atob(header));
		if ("typ" in parsedHeader && parsedHeader?.typ !== "JWT") return false;
		if (!parsedHeader.alg) return false;
		if (algorithm && (!("alg" in parsedHeader) || parsedHeader.alg !== algorithm)) return false;
		return true;
	} catch {
		return false;
	}
}
const $ZodJWT = /*@__PURE__*/ $constructor("$ZodJWT", (inst, def) => {
	$ZodStringFormat.init(inst, def);
	inst._zod.check = (payload) => {
		if (isValidJWT(payload.value, def.alg)) return;
		payload.issues.push({
			code: "invalid_format",
			format: "jwt",
			input: payload.value,
			inst,
			continue: !def.abort
		});
	};
});
const $ZodUnknown = /*@__PURE__*/ $constructor("$ZodUnknown", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.parse = (payload) => payload;
});
const $ZodNever = /*@__PURE__*/ $constructor("$ZodNever", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.parse = (payload, _ctx) => {
		payload.issues.push({
			expected: "never",
			code: "invalid_type",
			input: payload.value,
			inst
		});
		return payload;
	};
});
function handleArrayResult(result, final, index) {
	if (result.issues.length) final.issues.push(...prefixIssues(index, result.issues));
	final.value[index] = result.value;
}
const $ZodArray = /*@__PURE__*/ $constructor("$ZodArray", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.parse = (payload, ctx) => {
		const input = payload.value;
		if (!Array.isArray(input)) {
			payload.issues.push({
				expected: "array",
				code: "invalid_type",
				input,
				inst
			});
			return payload;
		}
		payload.value = Array(input.length);
		const proms = [];
		for (let i = 0; i < input.length; i++) {
			const item = input[i];
			const result = def.element._zod.run({
				value: item,
				issues: []
			}, ctx);
			if (result instanceof Promise) proms.push(result.then((result) => handleArrayResult(result, payload, i)));
			else handleArrayResult(result, payload, i);
		}
		if (proms.length) return Promise.all(proms).then(() => payload);
		return payload;
	};
});
function handlePropertyResult(result, final, key, input, isOptionalIn, isOptionalOut) {
	const isPresent = key in input;
	if (result.issues.length) {
		if (isOptionalIn && isOptionalOut && !isPresent) return;
		final.issues.push(...prefixIssues(key, result.issues));
	}
	if (!isPresent && !isOptionalIn) {
		if (!result.issues.length) final.issues.push({
			code: "invalid_type",
			expected: "nonoptional",
			input: void 0,
			path: [key]
		});
		return;
	}
	if (result.value === void 0) {
		if (isPresent) final.value[key] = void 0;
	} else final.value[key] = result.value;
}
function normalizeDef(def) {
	const keys = Object.keys(def.shape);
	for (const k of keys) if (!def.shape?.[k]?._zod?.traits?.has("$ZodType")) throw new Error(`Invalid element at key "${k}": expected a Zod schema`);
	const okeys = optionalKeys(def.shape);
	return {
		...def,
		keys,
		keySet: new Set(keys),
		numKeys: keys.length,
		optionalKeys: new Set(okeys)
	};
}
function handleCatchall(proms, input, payload, ctx, def, inst) {
	const unrecognized = [];
	const keySet = def.keySet;
	const _catchall = def.catchall._zod;
	const t = _catchall.def.type;
	const isOptionalIn = _catchall.optin === "optional";
	const isOptionalOut = _catchall.optout === "optional";
	for (const key in input) {
		if (key === "__proto__") continue;
		if (keySet.has(key)) continue;
		if (t === "never") {
			unrecognized.push(key);
			continue;
		}
		const r = _catchall.run({
			value: input[key],
			issues: []
		}, ctx);
		if (r instanceof Promise) proms.push(r.then((r) => handlePropertyResult(r, payload, key, input, isOptionalIn, isOptionalOut)));
		else handlePropertyResult(r, payload, key, input, isOptionalIn, isOptionalOut);
	}
	if (unrecognized.length) payload.issues.push({
		code: "unrecognized_keys",
		keys: unrecognized,
		input,
		inst
	});
	if (!proms.length) return payload;
	return Promise.all(proms).then(() => {
		return payload;
	});
}
const $ZodObject = /*@__PURE__*/ $constructor("$ZodObject", (inst, def) => {
	$ZodType.init(inst, def);
	if (!Object.getOwnPropertyDescriptor(def, "shape")?.get) {
		const sh = def.shape;
		Object.defineProperty(def, "shape", { get: () => {
			const newSh = { ...sh };
			Object.defineProperty(def, "shape", { value: newSh });
			return newSh;
		} });
	}
	const _normalized = cached(() => normalizeDef(def));
	defineLazy(inst._zod, "propValues", () => {
		const shape = def.shape;
		const propValues = {};
		for (const key in shape) {
			const field = shape[key]._zod;
			if (field.values) {
				propValues[key] ?? (propValues[key] = /* @__PURE__ */ new Set());
				for (const v of field.values) propValues[key].add(v);
			}
		}
		return propValues;
	});
	const isObject$1 = isObject;
	const catchall = def.catchall;
	let value;
	inst._zod.parse = (payload, ctx) => {
		value ?? (value = _normalized.value);
		const input = payload.value;
		if (!isObject$1(input)) {
			payload.issues.push({
				expected: "object",
				code: "invalid_type",
				input,
				inst
			});
			return payload;
		}
		payload.value = {};
		const proms = [];
		const shape = value.shape;
		for (const key of value.keys) {
			const el = shape[key];
			const isOptionalIn = el._zod.optin === "optional";
			const isOptionalOut = el._zod.optout === "optional";
			const r = el._zod.run({
				value: input[key],
				issues: []
			}, ctx);
			if (r instanceof Promise) proms.push(r.then((r) => handlePropertyResult(r, payload, key, input, isOptionalIn, isOptionalOut)));
			else handlePropertyResult(r, payload, key, input, isOptionalIn, isOptionalOut);
		}
		if (!catchall) return proms.length ? Promise.all(proms).then(() => payload) : payload;
		return handleCatchall(proms, input, payload, ctx, _normalized.value, inst);
	};
});
const $ZodObjectJIT = /*@__PURE__*/ $constructor("$ZodObjectJIT", (inst, def) => {
	$ZodObject.init(inst, def);
	const superParse = inst._zod.parse;
	const _normalized = cached(() => normalizeDef(def));
	const generateFastpass = (shape) => {
		const doc = new Doc([
			"shape",
			"payload",
			"ctx"
		]);
		const normalized = _normalized.value;
		const parseStr = (key) => {
			const k = esc(key);
			return `shape[${k}]._zod.run({ value: input[${k}], issues: [] }, ctx)`;
		};
		doc.write(`const input = payload.value;`);
		const ids = Object.create(null);
		let counter = 0;
		for (const key of normalized.keys) ids[key] = `key_${counter++}`;
		doc.write(`const newResult = {};`);
		for (const key of normalized.keys) {
			const id = ids[key];
			const k = esc(key);
			const schema = shape[key];
			const isOptionalIn = schema?._zod?.optin === "optional";
			const isOptionalOut = schema?._zod?.optout === "optional";
			doc.write(`const ${id} = ${parseStr(key)};`);
			if (isOptionalIn && isOptionalOut) doc.write(`
        if (${id}.issues.length) {
          if (${k} in input) {
            payload.issues = payload.issues.concat(${id}.issues.map(iss => ({
              ...iss,
              path: iss.path ? [${k}, ...iss.path] : [${k}]
            })));
          }
        }
        
        if (${id}.value === undefined) {
          if (${k} in input) {
            newResult[${k}] = undefined;
          }
        } else {
          newResult[${k}] = ${id}.value;
        }
        
      `);
			else if (!isOptionalIn) doc.write(`
        const ${id}_present = ${k} in input;
        if (${id}.issues.length) {
          payload.issues = payload.issues.concat(${id}.issues.map(iss => ({
            ...iss,
            path: iss.path ? [${k}, ...iss.path] : [${k}]
          })));
        }
        if (!${id}_present && !${id}.issues.length) {
          payload.issues.push({
            code: "invalid_type",
            expected: "nonoptional",
            input: undefined,
            path: [${k}]
          });
        }

        if (${id}_present) {
          if (${id}.value === undefined) {
            newResult[${k}] = undefined;
          } else {
            newResult[${k}] = ${id}.value;
          }
        }

      `);
			else doc.write(`
        if (${id}.issues.length) {
          payload.issues = payload.issues.concat(${id}.issues.map(iss => ({
            ...iss,
            path: iss.path ? [${k}, ...iss.path] : [${k}]
          })));
        }
        
        if (${id}.value === undefined) {
          if (${k} in input) {
            newResult[${k}] = undefined;
          }
        } else {
          newResult[${k}] = ${id}.value;
        }
        
      `);
		}
		doc.write(`payload.value = newResult;`);
		doc.write(`return payload;`);
		const fn = doc.compile();
		return (payload, ctx) => fn(shape, payload, ctx);
	};
	let fastpass;
	const isObject$2 = isObject;
	const jit = !globalConfig.jitless;
	const fastEnabled = jit && allowsEval.value;
	const catchall = def.catchall;
	let value;
	inst._zod.parse = (payload, ctx) => {
		value ?? (value = _normalized.value);
		const input = payload.value;
		if (!isObject$2(input)) {
			payload.issues.push({
				expected: "object",
				code: "invalid_type",
				input,
				inst
			});
			return payload;
		}
		if (jit && fastEnabled && ctx?.async === false && ctx.jitless !== true) {
			if (!fastpass) fastpass = generateFastpass(def.shape);
			payload = fastpass(payload, ctx);
			if (!catchall) return payload;
			return handleCatchall([], input, payload, ctx, value, inst);
		}
		return superParse(payload, ctx);
	};
});
function handleUnionResults(results, final, inst, ctx) {
	for (const result of results) if (result.issues.length === 0) {
		final.value = result.value;
		return final;
	}
	const nonaborted = results.filter((r) => !aborted(r));
	if (nonaborted.length === 1) {
		final.value = nonaborted[0].value;
		return nonaborted[0];
	}
	final.issues.push({
		code: "invalid_union",
		input: final.value,
		inst,
		errors: results.map((result) => result.issues.map((iss) => finalizeIssue(iss, ctx, config())))
	});
	return final;
}
const $ZodUnion = /*@__PURE__*/ $constructor("$ZodUnion", (inst, def) => {
	$ZodType.init(inst, def);
	defineLazy(inst._zod, "optin", () => def.options.some((o) => o._zod.optin === "optional") ? "optional" : void 0);
	defineLazy(inst._zod, "optout", () => def.options.some((o) => o._zod.optout === "optional") ? "optional" : void 0);
	defineLazy(inst._zod, "values", () => {
		if (def.options.every((o) => o._zod.values)) return new Set(def.options.flatMap((option) => Array.from(option._zod.values)));
	});
	defineLazy(inst._zod, "pattern", () => {
		if (def.options.every((o) => o._zod.pattern)) {
			const patterns = def.options.map((o) => o._zod.pattern);
			return new RegExp(`^(${patterns.map((p) => cleanRegex(p.source)).join("|")})$`);
		}
	});
	const first = def.options.length === 1 ? def.options[0]._zod.run : null;
	inst._zod.parse = (payload, ctx) => {
		if (first) return first(payload, ctx);
		let async = false;
		const results = [];
		for (const option of def.options) {
			const result = option._zod.run({
				value: payload.value,
				issues: []
			}, ctx);
			if (result instanceof Promise) {
				results.push(result);
				async = true;
			} else {
				if (result.issues.length === 0) return result;
				results.push(result);
			}
		}
		if (!async) return handleUnionResults(results, payload, inst, ctx);
		return Promise.all(results).then((results) => {
			return handleUnionResults(results, payload, inst, ctx);
		});
	};
});
const $ZodIntersection = /*@__PURE__*/ $constructor("$ZodIntersection", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.parse = (payload, ctx) => {
		const input = payload.value;
		const left = def.left._zod.run({
			value: input,
			issues: []
		}, ctx);
		const right = def.right._zod.run({
			value: input,
			issues: []
		}, ctx);
		if (left instanceof Promise || right instanceof Promise) return Promise.all([left, right]).then(([left, right]) => {
			return handleIntersectionResults(payload, left, right);
		});
		return handleIntersectionResults(payload, left, right);
	};
});
function mergeValues(a, b) {
	if (a === b) return {
		valid: true,
		data: a
	};
	if (a instanceof Date && b instanceof Date && +a === +b) return {
		valid: true,
		data: a
	};
	if (isPlainObject(a) && isPlainObject(b)) {
		const bKeys = Object.keys(b);
		const sharedKeys = Object.keys(a).filter((key) => bKeys.indexOf(key) !== -1);
		const newObj = {
			...a,
			...b
		};
		for (const key of sharedKeys) {
			const sharedValue = mergeValues(a[key], b[key]);
			if (!sharedValue.valid) return {
				valid: false,
				mergeErrorPath: [key, ...sharedValue.mergeErrorPath]
			};
			newObj[key] = sharedValue.data;
		}
		return {
			valid: true,
			data: newObj
		};
	}
	if (Array.isArray(a) && Array.isArray(b)) {
		if (a.length !== b.length) return {
			valid: false,
			mergeErrorPath: []
		};
		const newArray = [];
		for (let index = 0; index < a.length; index++) {
			const itemA = a[index];
			const itemB = b[index];
			const sharedValue = mergeValues(itemA, itemB);
			if (!sharedValue.valid) return {
				valid: false,
				mergeErrorPath: [index, ...sharedValue.mergeErrorPath]
			};
			newArray.push(sharedValue.data);
		}
		return {
			valid: true,
			data: newArray
		};
	}
	return {
		valid: false,
		mergeErrorPath: []
	};
}
function handleIntersectionResults(result, left, right) {
	const unrecKeys = /* @__PURE__ */ new Map();
	let unrecIssue;
	for (const iss of left.issues) if (iss.code === "unrecognized_keys") {
		unrecIssue ?? (unrecIssue = iss);
		for (const k of iss.keys) {
			if (!unrecKeys.has(k)) unrecKeys.set(k, {});
			unrecKeys.get(k).l = true;
		}
	} else result.issues.push(iss);
	for (const iss of right.issues) if (iss.code === "unrecognized_keys") for (const k of iss.keys) {
		if (!unrecKeys.has(k)) unrecKeys.set(k, {});
		unrecKeys.get(k).r = true;
	}
	else result.issues.push(iss);
	const bothKeys = [...unrecKeys].filter(([, f]) => f.l && f.r).map(([k]) => k);
	if (bothKeys.length && unrecIssue) result.issues.push({
		...unrecIssue,
		keys: bothKeys
	});
	if (aborted(result)) return result;
	const merged = mergeValues(left.value, right.value);
	if (!merged.valid) throw new Error(`Unmergable intersection. Error path: ${JSON.stringify(merged.mergeErrorPath)}`);
	result.value = merged.data;
	return result;
}
const $ZodEnum = /*@__PURE__*/ $constructor("$ZodEnum", (inst, def) => {
	$ZodType.init(inst, def);
	const values = getEnumValues(def.entries);
	const valuesSet = new Set(values);
	inst._zod.values = valuesSet;
	inst._zod.pattern = new RegExp(`^(${values.filter((k) => propertyKeyTypes.has(typeof k)).map((o) => typeof o === "string" ? escapeRegex(o) : o.toString()).join("|")})$`);
	inst._zod.parse = (payload, _ctx) => {
		const input = payload.value;
		if (valuesSet.has(input)) return payload;
		payload.issues.push({
			code: "invalid_value",
			values,
			input,
			inst
		});
		return payload;
	};
});
const $ZodLiteral = /*@__PURE__*/ $constructor("$ZodLiteral", (inst, def) => {
	$ZodType.init(inst, def);
	if (def.values.length === 0) throw new Error("Cannot create literal schema with no valid values");
	const values = new Set(def.values);
	inst._zod.values = values;
	inst._zod.pattern = new RegExp(`^(${def.values.map((o) => typeof o === "string" ? escapeRegex(o) : o ? escapeRegex(o.toString()) : String(o)).join("|")})$`);
	inst._zod.parse = (payload, _ctx) => {
		const input = payload.value;
		if (values.has(input)) return payload;
		payload.issues.push({
			code: "invalid_value",
			values: def.values,
			input,
			inst
		});
		return payload;
	};
});
const $ZodTransform = /*@__PURE__*/ $constructor("$ZodTransform", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.optin = "optional";
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") throw new $ZodEncodeError(inst.constructor.name);
		const _out = def.transform(payload.value, payload);
		if (ctx.async) return (_out instanceof Promise ? _out : Promise.resolve(_out)).then((output) => {
			payload.value = output;
			payload.fallback = true;
			return payload;
		});
		if (_out instanceof Promise) throw new $ZodAsyncError();
		payload.value = _out;
		payload.fallback = true;
		return payload;
	};
});
function handleOptionalResult(result, input) {
	if (input === void 0 && (result.issues.length || result.fallback)) return {
		issues: [],
		value: void 0
	};
	return result;
}
const $ZodOptional = /*@__PURE__*/ $constructor("$ZodOptional", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.optin = "optional";
	inst._zod.optout = "optional";
	defineLazy(inst._zod, "values", () => {
		return def.innerType._zod.values ? /* @__PURE__ */ new Set([...def.innerType._zod.values, void 0]) : void 0;
	});
	defineLazy(inst._zod, "pattern", () => {
		const pattern = def.innerType._zod.pattern;
		return pattern ? new RegExp(`^(${cleanRegex(pattern.source)})?$`) : void 0;
	});
	inst._zod.parse = (payload, ctx) => {
		if (def.innerType._zod.optin === "optional") {
			const input = payload.value;
			const result = def.innerType._zod.run(payload, ctx);
			if (result instanceof Promise) return result.then((r) => handleOptionalResult(r, input));
			return handleOptionalResult(result, input);
		}
		if (payload.value === void 0) return payload;
		return def.innerType._zod.run(payload, ctx);
	};
});
const $ZodExactOptional = /*@__PURE__*/ $constructor("$ZodExactOptional", (inst, def) => {
	$ZodOptional.init(inst, def);
	defineLazy(inst._zod, "values", () => def.innerType._zod.values);
	defineLazy(inst._zod, "pattern", () => def.innerType._zod.pattern);
	inst._zod.parse = (payload, ctx) => {
		return def.innerType._zod.run(payload, ctx);
	};
});
const $ZodNullable = /*@__PURE__*/ $constructor("$ZodNullable", (inst, def) => {
	$ZodType.init(inst, def);
	defineLazy(inst._zod, "optin", () => def.innerType._zod.optin);
	defineLazy(inst._zod, "optout", () => def.innerType._zod.optout);
	defineLazy(inst._zod, "pattern", () => {
		const pattern = def.innerType._zod.pattern;
		return pattern ? new RegExp(`^(${cleanRegex(pattern.source)}|null)$`) : void 0;
	});
	defineLazy(inst._zod, "values", () => {
		return def.innerType._zod.values ? /* @__PURE__ */ new Set([...def.innerType._zod.values, null]) : void 0;
	});
	inst._zod.parse = (payload, ctx) => {
		if (payload.value === null) return payload;
		return def.innerType._zod.run(payload, ctx);
	};
});
const $ZodDefault = /*@__PURE__*/ $constructor("$ZodDefault", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.optin = "optional";
	defineLazy(inst._zod, "values", () => def.innerType._zod.values);
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") return def.innerType._zod.run(payload, ctx);
		if (payload.value === void 0) {
			payload.value = def.defaultValue;
			/**
			* $ZodDefault returns the default value immediately in forward direction.
			* It doesn't pass the default value into the validator ("prefault"). There's no reason to pass the default value through validation. The validity of the default is enforced by TypeScript statically. Otherwise, it's the responsibility of the user to ensure the default is valid. In the case of pipes with divergent in/out types, you can specify the default on the `in` schema of your ZodPipe to set a "prefault" for the pipe.   */
			return payload;
		}
		const result = def.innerType._zod.run(payload, ctx);
		if (result instanceof Promise) return result.then((result) => handleDefaultResult(result, def));
		return handleDefaultResult(result, def);
	};
});
function handleDefaultResult(payload, def) {
	if (payload.value === void 0) payload.value = def.defaultValue;
	return payload;
}
const $ZodPrefault = /*@__PURE__*/ $constructor("$ZodPrefault", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.optin = "optional";
	defineLazy(inst._zod, "values", () => def.innerType._zod.values);
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") return def.innerType._zod.run(payload, ctx);
		if (payload.value === void 0) payload.value = def.defaultValue;
		return def.innerType._zod.run(payload, ctx);
	};
});
const $ZodNonOptional = /*@__PURE__*/ $constructor("$ZodNonOptional", (inst, def) => {
	$ZodType.init(inst, def);
	defineLazy(inst._zod, "values", () => {
		const v = def.innerType._zod.values;
		return v ? new Set([...v].filter((x) => x !== void 0)) : void 0;
	});
	inst._zod.parse = (payload, ctx) => {
		const result = def.innerType._zod.run(payload, ctx);
		if (result instanceof Promise) return result.then((result) => handleNonOptionalResult(result, inst));
		return handleNonOptionalResult(result, inst);
	};
});
function handleNonOptionalResult(payload, inst) {
	if (!payload.issues.length && payload.value === void 0) payload.issues.push({
		code: "invalid_type",
		expected: "nonoptional",
		input: payload.value,
		inst
	});
	return payload;
}
const $ZodCatch = /*@__PURE__*/ $constructor("$ZodCatch", (inst, def) => {
	$ZodType.init(inst, def);
	inst._zod.optin = "optional";
	defineLazy(inst._zod, "optout", () => def.innerType._zod.optout);
	defineLazy(inst._zod, "values", () => def.innerType._zod.values);
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") return def.innerType._zod.run(payload, ctx);
		const result = def.innerType._zod.run(payload, ctx);
		if (result instanceof Promise) return result.then((result) => {
			payload.value = result.value;
			if (result.issues.length) {
				payload.value = def.catchValue({
					...payload,
					error: { issues: result.issues.map((iss) => finalizeIssue(iss, ctx, config())) },
					input: payload.value
				});
				payload.issues = [];
				payload.fallback = true;
			}
			return payload;
		});
		payload.value = result.value;
		if (result.issues.length) {
			payload.value = def.catchValue({
				...payload,
				error: { issues: result.issues.map((iss) => finalizeIssue(iss, ctx, config())) },
				input: payload.value
			});
			payload.issues = [];
			payload.fallback = true;
		}
		return payload;
	};
});
const $ZodPipe = /*@__PURE__*/ $constructor("$ZodPipe", (inst, def) => {
	$ZodType.init(inst, def);
	defineLazy(inst._zod, "values", () => def.in._zod.values);
	defineLazy(inst._zod, "optin", () => def.in._zod.optin);
	defineLazy(inst._zod, "optout", () => def.out._zod.optout);
	defineLazy(inst._zod, "propValues", () => def.in._zod.propValues);
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") {
			const right = def.out._zod.run(payload, ctx);
			if (right instanceof Promise) return right.then((right) => handlePipeResult(right, def.in, ctx));
			return handlePipeResult(right, def.in, ctx);
		}
		const left = def.in._zod.run(payload, ctx);
		if (left instanceof Promise) return left.then((left) => handlePipeResult(left, def.out, ctx));
		return handlePipeResult(left, def.out, ctx);
	};
});
function handlePipeResult(left, next, ctx) {
	if (left.issues.length) {
		left.aborted = true;
		return left;
	}
	return next._zod.run({
		value: left.value,
		issues: left.issues,
		fallback: left.fallback
	}, ctx);
}
const $ZodReadonly = /*@__PURE__*/ $constructor("$ZodReadonly", (inst, def) => {
	$ZodType.init(inst, def);
	defineLazy(inst._zod, "propValues", () => def.innerType._zod.propValues);
	defineLazy(inst._zod, "values", () => def.innerType._zod.values);
	defineLazy(inst._zod, "optin", () => def.innerType?._zod?.optin);
	defineLazy(inst._zod, "optout", () => def.innerType?._zod?.optout);
	inst._zod.parse = (payload, ctx) => {
		if (ctx.direction === "backward") return def.innerType._zod.run(payload, ctx);
		const result = def.innerType._zod.run(payload, ctx);
		if (result instanceof Promise) return result.then(handleReadonlyResult);
		return handleReadonlyResult(result);
	};
});
function handleReadonlyResult(payload) {
	payload.value = Object.freeze(payload.value);
	return payload;
}
const $ZodCustom = /*@__PURE__*/ $constructor("$ZodCustom", (inst, def) => {
	$ZodCheck.init(inst, def);
	$ZodType.init(inst, def);
	inst._zod.parse = (payload, _) => {
		return payload;
	};
	inst._zod.check = (payload) => {
		const input = payload.value;
		const r = def.fn(input);
		if (r instanceof Promise) return r.then((r) => handleRefineResult(r, payload, input, inst));
		handleRefineResult(r, payload, input, inst);
	};
});
function handleRefineResult(result, payload, input, inst) {
	if (!result) {
		const _iss = {
			code: "custom",
			input,
			inst,
			path: [...inst._zod.def.path ?? []],
			continue: !inst._zod.def.abort
		};
		if (inst._zod.def.params) _iss.params = inst._zod.def.params;
		payload.issues.push(issue(_iss));
	}
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/registries.js
var _a;
var $ZodRegistry = class {
	constructor() {
		this._map = /* @__PURE__ */ new WeakMap();
		this._idmap = /* @__PURE__ */ new Map();
	}
	add(schema, ..._meta) {
		const meta = _meta[0];
		this._map.set(schema, meta);
		if (meta && typeof meta === "object" && "id" in meta) this._idmap.set(meta.id, schema);
		return this;
	}
	clear() {
		this._map = /* @__PURE__ */ new WeakMap();
		this._idmap = /* @__PURE__ */ new Map();
		return this;
	}
	remove(schema) {
		const meta = this._map.get(schema);
		if (meta && typeof meta === "object" && "id" in meta) this._idmap.delete(meta.id);
		this._map.delete(schema);
		return this;
	}
	get(schema) {
		const p = schema._zod.parent;
		if (p) {
			const pm = { ...this.get(p) ?? {} };
			delete pm.id;
			const f = {
				...pm,
				...this._map.get(schema)
			};
			return Object.keys(f).length ? f : void 0;
		}
		return this._map.get(schema);
	}
	has(schema) {
		return this._map.has(schema);
	}
};
function registry() {
	return new $ZodRegistry();
}
(_a = globalThis).__zod_globalRegistry ?? (_a.__zod_globalRegistry = registry());
const globalRegistry = globalThis.__zod_globalRegistry;
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/api.js
// @__NO_SIDE_EFFECTS__
function _string(Class, params) {
	return new Class({
		type: "string",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _email(Class, params) {
	return new Class({
		type: "string",
		format: "email",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _guid(Class, params) {
	return new Class({
		type: "string",
		format: "guid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _uuid(Class, params) {
	return new Class({
		type: "string",
		format: "uuid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _uuidv4(Class, params) {
	return new Class({
		type: "string",
		format: "uuid",
		check: "string_format",
		abort: false,
		version: "v4",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _uuidv6(Class, params) {
	return new Class({
		type: "string",
		format: "uuid",
		check: "string_format",
		abort: false,
		version: "v6",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _uuidv7(Class, params) {
	return new Class({
		type: "string",
		format: "uuid",
		check: "string_format",
		abort: false,
		version: "v7",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _url(Class, params) {
	return new Class({
		type: "string",
		format: "url",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _emoji(Class, params) {
	return new Class({
		type: "string",
		format: "emoji",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _nanoid(Class, params) {
	return new Class({
		type: "string",
		format: "nanoid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
/**
* @deprecated CUID v1 is deprecated by its authors due to information leakage
* (timestamps embedded in the id). Use {@link _cuid2} instead.
* See https://github.com/paralleldrive/cuid.
*/
// @__NO_SIDE_EFFECTS__
function _cuid(Class, params) {
	return new Class({
		type: "string",
		format: "cuid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _cuid2(Class, params) {
	return new Class({
		type: "string",
		format: "cuid2",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _ulid(Class, params) {
	return new Class({
		type: "string",
		format: "ulid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _xid(Class, params) {
	return new Class({
		type: "string",
		format: "xid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _ksuid(Class, params) {
	return new Class({
		type: "string",
		format: "ksuid",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _ipv4(Class, params) {
	return new Class({
		type: "string",
		format: "ipv4",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _ipv6(Class, params) {
	return new Class({
		type: "string",
		format: "ipv6",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _cidrv4(Class, params) {
	return new Class({
		type: "string",
		format: "cidrv4",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _cidrv6(Class, params) {
	return new Class({
		type: "string",
		format: "cidrv6",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _base64(Class, params) {
	return new Class({
		type: "string",
		format: "base64",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _base64url(Class, params) {
	return new Class({
		type: "string",
		format: "base64url",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _e164(Class, params) {
	return new Class({
		type: "string",
		format: "e164",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _jwt(Class, params) {
	return new Class({
		type: "string",
		format: "jwt",
		check: "string_format",
		abort: false,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _isoDateTime(Class, params) {
	return new Class({
		type: "string",
		format: "datetime",
		check: "string_format",
		offset: false,
		local: false,
		precision: null,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _isoDate(Class, params) {
	return new Class({
		type: "string",
		format: "date",
		check: "string_format",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _isoTime(Class, params) {
	return new Class({
		type: "string",
		format: "time",
		check: "string_format",
		precision: null,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _isoDuration(Class, params) {
	return new Class({
		type: "string",
		format: "duration",
		check: "string_format",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _unknown(Class) {
	return new Class({ type: "unknown" });
}
// @__NO_SIDE_EFFECTS__
function _never(Class, params) {
	return new Class({
		type: "never",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _maxLength(maximum, params) {
	return new $ZodCheckMaxLength({
		check: "max_length",
		...normalizeParams(params),
		maximum
	});
}
// @__NO_SIDE_EFFECTS__
function _minLength(minimum, params) {
	return new $ZodCheckMinLength({
		check: "min_length",
		...normalizeParams(params),
		minimum
	});
}
// @__NO_SIDE_EFFECTS__
function _length(length, params) {
	return new $ZodCheckLengthEquals({
		check: "length_equals",
		...normalizeParams(params),
		length
	});
}
// @__NO_SIDE_EFFECTS__
function _regex(pattern, params) {
	return new $ZodCheckRegex({
		check: "string_format",
		format: "regex",
		...normalizeParams(params),
		pattern
	});
}
// @__NO_SIDE_EFFECTS__
function _lowercase(params) {
	return new $ZodCheckLowerCase({
		check: "string_format",
		format: "lowercase",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _uppercase(params) {
	return new $ZodCheckUpperCase({
		check: "string_format",
		format: "uppercase",
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _includes(includes, params) {
	return new $ZodCheckIncludes({
		check: "string_format",
		format: "includes",
		...normalizeParams(params),
		includes
	});
}
// @__NO_SIDE_EFFECTS__
function _startsWith(prefix, params) {
	return new $ZodCheckStartsWith({
		check: "string_format",
		format: "starts_with",
		...normalizeParams(params),
		prefix
	});
}
// @__NO_SIDE_EFFECTS__
function _endsWith(suffix, params) {
	return new $ZodCheckEndsWith({
		check: "string_format",
		format: "ends_with",
		...normalizeParams(params),
		suffix
	});
}
// @__NO_SIDE_EFFECTS__
function _overwrite(tx) {
	return new $ZodCheckOverwrite({
		check: "overwrite",
		tx
	});
}
// @__NO_SIDE_EFFECTS__
function _normalize(form) {
	return /* @__PURE__ */ _overwrite((input) => input.normalize(form));
}
// @__NO_SIDE_EFFECTS__
function _trim() {
	return /* @__PURE__ */ _overwrite((input) => input.trim());
}
// @__NO_SIDE_EFFECTS__
function _toLowerCase() {
	return /* @__PURE__ */ _overwrite((input) => input.toLowerCase());
}
// @__NO_SIDE_EFFECTS__
function _toUpperCase() {
	return /* @__PURE__ */ _overwrite((input) => input.toUpperCase());
}
// @__NO_SIDE_EFFECTS__
function _slugify() {
	return /* @__PURE__ */ _overwrite((input) => slugify(input));
}
// @__NO_SIDE_EFFECTS__
function _array(Class, element, params) {
	return new Class({
		type: "array",
		element,
		...normalizeParams(params)
	});
}
// @__NO_SIDE_EFFECTS__
function _refine(Class, fn, _params) {
	return new Class({
		type: "custom",
		check: "custom",
		fn,
		...normalizeParams(_params)
	});
}
// @__NO_SIDE_EFFECTS__
function _superRefine(fn, params) {
	const ch = /* @__PURE__ */ _check((payload) => {
		payload.addIssue = (issue$2) => {
			if (typeof issue$2 === "string") payload.issues.push(issue(issue$2, payload.value, ch._zod.def));
			else {
				const _issue = issue$2;
				if (_issue.fatal) _issue.continue = false;
				_issue.code ?? (_issue.code = "custom");
				_issue.input ?? (_issue.input = payload.value);
				_issue.inst ?? (_issue.inst = ch);
				_issue.continue ?? (_issue.continue = !ch._zod.def.abort);
				payload.issues.push(issue(_issue));
			}
		};
		return fn(payload.value, payload);
	}, params);
	return ch;
}
// @__NO_SIDE_EFFECTS__
function _check(fn, params) {
	const ch = new $ZodCheck({
		check: "custom",
		...normalizeParams(params)
	});
	ch._zod.check = fn;
	return ch;
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/to-json-schema.js
function initializeContext(params) {
	let target = params?.target ?? "draft-2020-12";
	if (target === "draft-4") target = "draft-04";
	if (target === "draft-7") target = "draft-07";
	return {
		processors: params.processors ?? {},
		metadataRegistry: params?.metadata ?? globalRegistry,
		target,
		unrepresentable: params?.unrepresentable ?? "throw",
		override: params?.override ?? (() => {}),
		io: params?.io ?? "output",
		counter: 0,
		seen: /* @__PURE__ */ new Map(),
		cycles: params?.cycles ?? "ref",
		reused: params?.reused ?? "inline",
		external: params?.external ?? void 0
	};
}
function process$1(schema, ctx, _params = {
	path: [],
	schemaPath: []
}) {
	var _a;
	const def = schema._zod.def;
	const seen = ctx.seen.get(schema);
	if (seen) {
		seen.count++;
		if (_params.schemaPath.includes(schema)) seen.cycle = _params.path;
		return seen.schema;
	}
	const result = {
		schema: {},
		count: 1,
		cycle: void 0,
		path: _params.path
	};
	ctx.seen.set(schema, result);
	const overrideSchema = schema._zod.toJSONSchema?.();
	if (overrideSchema) result.schema = overrideSchema;
	else {
		const params = {
			..._params,
			schemaPath: [..._params.schemaPath, schema],
			path: _params.path
		};
		if (schema._zod.processJSONSchema) schema._zod.processJSONSchema(ctx, result.schema, params);
		else {
			const _json = result.schema;
			const processor = ctx.processors[def.type];
			if (!processor) throw new Error(`[toJSONSchema]: Non-representable type encountered: ${def.type}`);
			processor(schema, ctx, _json, params);
		}
		const parent = schema._zod.parent;
		if (parent) {
			if (!result.ref) result.ref = parent;
			process$1(parent, ctx, params);
			ctx.seen.get(parent).isParent = true;
		}
	}
	const meta = ctx.metadataRegistry.get(schema);
	if (meta) Object.assign(result.schema, meta);
	if (ctx.io === "input" && isTransforming(schema)) {
		delete result.schema.examples;
		delete result.schema.default;
	}
	if (ctx.io === "input" && "_prefault" in result.schema) (_a = result.schema).default ?? (_a.default = result.schema._prefault);
	delete result.schema._prefault;
	return ctx.seen.get(schema).schema;
}
function extractDefs(ctx, schema) {
	const root = ctx.seen.get(schema);
	if (!root) throw new Error("Unprocessed schema. This is a bug in Zod.");
	const idToSchema = /* @__PURE__ */ new Map();
	for (const entry of ctx.seen.entries()) {
		const id = ctx.metadataRegistry.get(entry[0])?.id;
		if (id) {
			const existing = idToSchema.get(id);
			if (existing && existing !== entry[0]) throw new Error(`Duplicate schema id "${id}" detected during JSON Schema conversion. Two different schemas cannot share the same id when converted together.`);
			idToSchema.set(id, entry[0]);
		}
	}
	const makeURI = (entry) => {
		const defsSegment = ctx.target === "draft-2020-12" ? "$defs" : "definitions";
		if (ctx.external) {
			const externalId = ctx.external.registry.get(entry[0])?.id;
			const uriGenerator = ctx.external.uri ?? ((id) => id);
			if (externalId) return { ref: uriGenerator(externalId) };
			const id = entry[1].defId ?? entry[1].schema.id ?? `schema${ctx.counter++}`;
			entry[1].defId = id;
			return {
				defId: id,
				ref: `${uriGenerator("__shared")}#/${defsSegment}/${id}`
			};
		}
		if (entry[1] === root) return { ref: "#" };
		const defUriPrefix = `#/${defsSegment}/`;
		const defId = entry[1].schema.id ?? `__schema${ctx.counter++}`;
		return {
			defId,
			ref: defUriPrefix + defId
		};
	};
	const extractToDef = (entry) => {
		if (entry[1].schema.$ref) return;
		const seen = entry[1];
		const { ref, defId } = makeURI(entry);
		seen.def = { ...seen.schema };
		if (defId) seen.defId = defId;
		const schema = seen.schema;
		for (const key in schema) delete schema[key];
		schema.$ref = ref;
	};
	if (ctx.cycles === "throw") for (const entry of ctx.seen.entries()) {
		const seen = entry[1];
		if (seen.cycle) throw new Error(`Cycle detected: #/${seen.cycle?.join("/")}/<root>

Set the \`cycles\` parameter to \`"ref"\` to resolve cyclical schemas with defs.`);
	}
	for (const entry of ctx.seen.entries()) {
		const seen = entry[1];
		if (schema === entry[0]) {
			extractToDef(entry);
			continue;
		}
		if (ctx.external) {
			const ext = ctx.external.registry.get(entry[0])?.id;
			if (schema !== entry[0] && ext) {
				extractToDef(entry);
				continue;
			}
		}
		if (ctx.metadataRegistry.get(entry[0])?.id) {
			extractToDef(entry);
			continue;
		}
		if (seen.cycle) {
			extractToDef(entry);
			continue;
		}
		if (seen.count > 1) {
			if (ctx.reused === "ref") {
				extractToDef(entry);
				continue;
			}
		}
	}
}
function finalize(ctx, schema) {
	const root = ctx.seen.get(schema);
	if (!root) throw new Error("Unprocessed schema. This is a bug in Zod.");
	const flattenRef = (zodSchema) => {
		const seen = ctx.seen.get(zodSchema);
		if (seen.ref === null) return;
		const schema = seen.def ?? seen.schema;
		const _cached = { ...schema };
		const ref = seen.ref;
		seen.ref = null;
		if (ref) {
			flattenRef(ref);
			const refSeen = ctx.seen.get(ref);
			const refSchema = refSeen.schema;
			if (refSchema.$ref && (ctx.target === "draft-07" || ctx.target === "draft-04" || ctx.target === "openapi-3.0")) {
				schema.allOf = schema.allOf ?? [];
				schema.allOf.push(refSchema);
			} else Object.assign(schema, refSchema);
			Object.assign(schema, _cached);
			if (zodSchema._zod.parent === ref) for (const key in schema) {
				if (key === "$ref" || key === "allOf") continue;
				if (!(key in _cached)) delete schema[key];
			}
			if (refSchema.$ref && refSeen.def) for (const key in schema) {
				if (key === "$ref" || key === "allOf") continue;
				if (key in refSeen.def && JSON.stringify(schema[key]) === JSON.stringify(refSeen.def[key])) delete schema[key];
			}
		}
		const parent = zodSchema._zod.parent;
		if (parent && parent !== ref) {
			flattenRef(parent);
			const parentSeen = ctx.seen.get(parent);
			if (parentSeen?.schema.$ref) {
				schema.$ref = parentSeen.schema.$ref;
				if (parentSeen.def) for (const key in schema) {
					if (key === "$ref" || key === "allOf") continue;
					if (key in parentSeen.def && JSON.stringify(schema[key]) === JSON.stringify(parentSeen.def[key])) delete schema[key];
				}
			}
		}
		ctx.override({
			zodSchema,
			jsonSchema: schema,
			path: seen.path ?? []
		});
	};
	for (const entry of [...ctx.seen.entries()].reverse()) flattenRef(entry[0]);
	const result = {};
	if (ctx.target === "draft-2020-12") result.$schema = "https://json-schema.org/draft/2020-12/schema";
	else if (ctx.target === "draft-07") result.$schema = "http://json-schema.org/draft-07/schema#";
	else if (ctx.target === "draft-04") result.$schema = "http://json-schema.org/draft-04/schema#";
	else if (ctx.target === "openapi-3.0") {}
	if (ctx.external?.uri) {
		const id = ctx.external.registry.get(schema)?.id;
		if (!id) throw new Error("Schema is missing an `id` property");
		result.$id = ctx.external.uri(id);
	}
	Object.assign(result, root.def ?? root.schema);
	const rootMetaId = ctx.metadataRegistry.get(schema)?.id;
	if (rootMetaId !== void 0 && result.id === rootMetaId) delete result.id;
	const defs = ctx.external?.defs ?? {};
	for (const entry of ctx.seen.entries()) {
		const seen = entry[1];
		if (seen.def && seen.defId) {
			if (seen.def.id === seen.defId) delete seen.def.id;
			defs[seen.defId] = seen.def;
		}
	}
	if (ctx.external) {} else if (Object.keys(defs).length > 0) {
		if (ctx.target === "draft-2020-12") result.$defs = defs;
		else result.definitions = defs;
	}
	try {
		const finalized = JSON.parse(JSON.stringify(result));
		Object.defineProperty(finalized, "~standard", {
			value: {
				...schema["~standard"],
				jsonSchema: {
					input: createStandardJSONSchemaMethod(schema, "input", ctx.processors),
					output: createStandardJSONSchemaMethod(schema, "output", ctx.processors)
				}
			},
			enumerable: false,
			writable: false
		});
		return finalized;
	} catch (_err) {
		throw new Error("Error converting schema to JSON.");
	}
}
function isTransforming(_schema, _ctx) {
	const ctx = _ctx ?? { seen: /* @__PURE__ */ new Set() };
	if (ctx.seen.has(_schema)) return false;
	ctx.seen.add(_schema);
	const def = _schema._zod.def;
	if (def.type === "transform") return true;
	if (def.type === "array") return isTransforming(def.element, ctx);
	if (def.type === "set") return isTransforming(def.valueType, ctx);
	if (def.type === "lazy") return isTransforming(def.getter(), ctx);
	if (def.type === "promise" || def.type === "optional" || def.type === "nonoptional" || def.type === "nullable" || def.type === "readonly" || def.type === "default" || def.type === "prefault") return isTransforming(def.innerType, ctx);
	if (def.type === "intersection") return isTransforming(def.left, ctx) || isTransforming(def.right, ctx);
	if (def.type === "record" || def.type === "map") return isTransforming(def.keyType, ctx) || isTransforming(def.valueType, ctx);
	if (def.type === "pipe") {
		if (_schema._zod.traits.has("$ZodCodec")) return true;
		return isTransforming(def.in, ctx) || isTransforming(def.out, ctx);
	}
	if (def.type === "object") {
		for (const key in def.shape) if (isTransforming(def.shape[key], ctx)) return true;
		return false;
	}
	if (def.type === "union") {
		for (const option of def.options) if (isTransforming(option, ctx)) return true;
		return false;
	}
	if (def.type === "tuple") {
		for (const item of def.items) if (isTransforming(item, ctx)) return true;
		if (def.rest && isTransforming(def.rest, ctx)) return true;
		return false;
	}
	return false;
}
/**
* Creates a toJSONSchema method for a schema instance.
* This encapsulates the logic of initializing context, processing, extracting defs, and finalizing.
*/
const createToJSONSchemaMethod = (schema, processors = {}) => (params) => {
	const ctx = initializeContext({
		...params,
		processors
	});
	process$1(schema, ctx);
	extractDefs(ctx, schema);
	return finalize(ctx, schema);
};
const createStandardJSONSchemaMethod = (schema, io, processors = {}) => (params) => {
	const { libraryOptions, target } = params ?? {};
	const ctx = initializeContext({
		...libraryOptions ?? {},
		target,
		io,
		processors
	});
	process$1(schema, ctx);
	extractDefs(ctx, schema);
	return finalize(ctx, schema);
};
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/core/json-schema-processors.js
const formatMap = {
	guid: "uuid",
	url: "uri",
	datetime: "date-time",
	json_string: "json-string",
	regex: ""
};
const stringProcessor = (schema, ctx, _json, _params) => {
	const json = _json;
	json.type = "string";
	const { minimum, maximum, format, patterns, contentEncoding } = schema._zod.bag;
	if (typeof minimum === "number") json.minLength = minimum;
	if (typeof maximum === "number") json.maxLength = maximum;
	if (format) {
		json.format = formatMap[format] ?? format;
		if (json.format === "") delete json.format;
		if (format === "time") delete json.format;
	}
	if (contentEncoding) json.contentEncoding = contentEncoding;
	if (patterns && patterns.size > 0) {
		const regexes = [...patterns];
		if (regexes.length === 1) json.pattern = regexes[0].source;
		else if (regexes.length > 1) json.allOf = [...regexes.map((regex) => ({
			...ctx.target === "draft-07" || ctx.target === "draft-04" || ctx.target === "openapi-3.0" ? { type: "string" } : {},
			pattern: regex.source
		}))];
	}
};
const neverProcessor = (_schema, _ctx, json, _params) => {
	json.not = {};
};
const enumProcessor = (schema, _ctx, json, _params) => {
	const def = schema._zod.def;
	const values = getEnumValues(def.entries);
	if (values.every((v) => typeof v === "number")) json.type = "number";
	if (values.every((v) => typeof v === "string")) json.type = "string";
	json.enum = values;
};
const literalProcessor = (schema, ctx, json, _params) => {
	const def = schema._zod.def;
	const vals = [];
	for (const val of def.values) if (val === void 0) {
		if (ctx.unrepresentable === "throw") throw new Error("Literal `undefined` cannot be represented in JSON Schema");
	} else if (typeof val === "bigint") {
		if (ctx.unrepresentable === "throw") throw new Error("BigInt literals cannot be represented in JSON Schema");
		else vals.push(Number(val));
	} else vals.push(val);
	if (vals.length === 0) {} else if (vals.length === 1) {
		const val = vals[0];
		json.type = val === null ? "null" : typeof val;
		if (ctx.target === "draft-04" || ctx.target === "openapi-3.0") json.enum = [val];
		else json.const = val;
	} else {
		if (vals.every((v) => typeof v === "number")) json.type = "number";
		if (vals.every((v) => typeof v === "string")) json.type = "string";
		if (vals.every((v) => typeof v === "boolean")) json.type = "boolean";
		if (vals.every((v) => v === null)) json.type = "null";
		json.enum = vals;
	}
};
const customProcessor = (_schema, ctx, _json, _params) => {
	if (ctx.unrepresentable === "throw") throw new Error("Custom types cannot be represented in JSON Schema");
};
const transformProcessor = (_schema, ctx, _json, _params) => {
	if (ctx.unrepresentable === "throw") throw new Error("Transforms cannot be represented in JSON Schema");
};
const arrayProcessor = (schema, ctx, _json, params) => {
	const json = _json;
	const def = schema._zod.def;
	const { minimum, maximum } = schema._zod.bag;
	if (typeof minimum === "number") json.minItems = minimum;
	if (typeof maximum === "number") json.maxItems = maximum;
	json.type = "array";
	json.items = process$1(def.element, ctx, {
		...params,
		path: [...params.path, "items"]
	});
};
const objectProcessor = (schema, ctx, _json, params) => {
	const json = _json;
	const def = schema._zod.def;
	json.type = "object";
	json.properties = {};
	const shape = def.shape;
	for (const key in shape) json.properties[key] = process$1(shape[key], ctx, {
		...params,
		path: [
			...params.path,
			"properties",
			key
		]
	});
	const allKeys = new Set(Object.keys(shape));
	const requiredKeys = new Set([...allKeys].filter((key) => {
		const v = def.shape[key]._zod;
		if (ctx.io === "input") return v.optin === void 0;
		else return v.optout === void 0;
	}));
	if (requiredKeys.size > 0) json.required = Array.from(requiredKeys);
	if (def.catchall?._zod.def.type === "never") json.additionalProperties = false;
	else if (!def.catchall) {
		if (ctx.io === "output") json.additionalProperties = false;
	} else if (def.catchall) json.additionalProperties = process$1(def.catchall, ctx, {
		...params,
		path: [...params.path, "additionalProperties"]
	});
};
const unionProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	const isExclusive = def.inclusive === false;
	const options = def.options.map((x, i) => process$1(x, ctx, {
		...params,
		path: [
			...params.path,
			isExclusive ? "oneOf" : "anyOf",
			i
		]
	}));
	if (isExclusive) json.oneOf = options;
	else json.anyOf = options;
};
const intersectionProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	const a = process$1(def.left, ctx, {
		...params,
		path: [
			...params.path,
			"allOf",
			0
		]
	});
	const b = process$1(def.right, ctx, {
		...params,
		path: [
			...params.path,
			"allOf",
			1
		]
	});
	const isSimpleIntersection = (val) => "allOf" in val && Object.keys(val).length === 1;
	json.allOf = [...isSimpleIntersection(a) ? a.allOf : [a], ...isSimpleIntersection(b) ? b.allOf : [b]];
};
const nullableProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	const inner = process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	if (ctx.target === "openapi-3.0") {
		seen.ref = def.innerType;
		json.nullable = true;
	} else json.anyOf = [inner, { type: "null" }];
};
const nonoptionalProcessor = (schema, ctx, _json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
};
const defaultProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
	json.default = JSON.parse(JSON.stringify(def.defaultValue));
};
const prefaultProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
	if (ctx.io === "input") json._prefault = JSON.parse(JSON.stringify(def.defaultValue));
};
const catchProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
	let catchValue;
	try {
		catchValue = def.catchValue(void 0);
	} catch {
		throw new Error("Dynamic catch values are not supported in JSON Schema");
	}
	json.default = catchValue;
};
const pipeProcessor = (schema, ctx, _json, params) => {
	const def = schema._zod.def;
	const inIsTransform = def.in._zod.traits.has("$ZodTransform");
	const innerType = ctx.io === "input" ? inIsTransform ? def.out : def.in : def.out;
	process$1(innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = innerType;
};
const readonlyProcessor = (schema, ctx, json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
	json.readOnly = true;
};
const optionalProcessor = (schema, ctx, _json, params) => {
	const def = schema._zod.def;
	process$1(def.innerType, ctx, params);
	const seen = ctx.seen.get(schema);
	seen.ref = def.innerType;
};
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/classic/iso.js
const ZodISODateTime = /*@__PURE__*/ $constructor("ZodISODateTime", (inst, def) => {
	$ZodISODateTime.init(inst, def);
	ZodStringFormat.init(inst, def);
});
function datetime(params) {
	return /* @__PURE__ */ _isoDateTime(ZodISODateTime, params);
}
const ZodISODate = /*@__PURE__*/ $constructor("ZodISODate", (inst, def) => {
	$ZodISODate.init(inst, def);
	ZodStringFormat.init(inst, def);
});
function date(params) {
	return /* @__PURE__ */ _isoDate(ZodISODate, params);
}
const ZodISOTime = /*@__PURE__*/ $constructor("ZodISOTime", (inst, def) => {
	$ZodISOTime.init(inst, def);
	ZodStringFormat.init(inst, def);
});
function time(params) {
	return /* @__PURE__ */ _isoTime(ZodISOTime, params);
}
const ZodISODuration = /*@__PURE__*/ $constructor("ZodISODuration", (inst, def) => {
	$ZodISODuration.init(inst, def);
	ZodStringFormat.init(inst, def);
});
function duration$1(params) {
	return /* @__PURE__ */ _isoDuration(ZodISODuration, params);
}
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/classic/errors.js
const initializer = (inst, issues) => {
	$ZodError.init(inst, issues);
	inst.name = "ZodError";
	Object.defineProperties(inst, {
		format: { value: (mapper) => formatError(inst, mapper) },
		flatten: { value: (mapper) => flattenError(inst, mapper) },
		addIssue: { value: (issue) => {
			inst.issues.push(issue);
			inst.message = JSON.stringify(inst.issues, jsonStringifyReplacer, 2);
		} },
		addIssues: { value: (issues) => {
			inst.issues.push(...issues);
			inst.message = JSON.stringify(inst.issues, jsonStringifyReplacer, 2);
		} },
		isEmpty: { get() {
			return inst.issues.length === 0;
		} }
	});
};
const ZodRealError = /*@__PURE__*/ $constructor("ZodError", initializer, { Parent: Error });
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/classic/parse.js
const parse$1 = /* @__PURE__ */ _parse(ZodRealError);
const parseAsync = /* @__PURE__ */ _parseAsync(ZodRealError);
const safeParse = /* @__PURE__ */ _safeParse(ZodRealError);
const safeParseAsync = /* @__PURE__ */ _safeParseAsync(ZodRealError);
const encode = /* @__PURE__ */ _encode(ZodRealError);
const decode = /* @__PURE__ */ _decode(ZodRealError);
const encodeAsync = /* @__PURE__ */ _encodeAsync(ZodRealError);
const decodeAsync = /* @__PURE__ */ _decodeAsync(ZodRealError);
const safeEncode = /* @__PURE__ */ _safeEncode(ZodRealError);
const safeDecode = /* @__PURE__ */ _safeDecode(ZodRealError);
const safeEncodeAsync = /* @__PURE__ */ _safeEncodeAsync(ZodRealError);
const safeDecodeAsync = /* @__PURE__ */ _safeDecodeAsync(ZodRealError);
//#endregion
//#region ../../node_modules/.pnpm/zod@4.4.3/node_modules/zod/v4/classic/schemas.js
const _installedGroups = /* @__PURE__ */ new WeakMap();
function _installLazyMethods(inst, group, methods) {
	const proto = Object.getPrototypeOf(inst);
	let installed = _installedGroups.get(proto);
	if (!installed) {
		installed = /* @__PURE__ */ new Set();
		_installedGroups.set(proto, installed);
	}
	if (installed.has(group)) return;
	installed.add(group);
	for (const key in methods) {
		const fn = methods[key];
		Object.defineProperty(proto, key, {
			configurable: true,
			enumerable: false,
			get() {
				const bound = fn.bind(this);
				Object.defineProperty(this, key, {
					configurable: true,
					writable: true,
					enumerable: true,
					value: bound
				});
				return bound;
			},
			set(v) {
				Object.defineProperty(this, key, {
					configurable: true,
					writable: true,
					enumerable: true,
					value: v
				});
			}
		});
	}
}
const ZodType = /*@__PURE__*/ $constructor("ZodType", (inst, def) => {
	$ZodType.init(inst, def);
	Object.assign(inst["~standard"], { jsonSchema: {
		input: createStandardJSONSchemaMethod(inst, "input"),
		output: createStandardJSONSchemaMethod(inst, "output")
	} });
	inst.toJSONSchema = createToJSONSchemaMethod(inst, {});
	inst.def = def;
	inst.type = def.type;
	Object.defineProperty(inst, "_def", { value: def });
	inst.parse = (data, params) => parse$1(inst, data, params, { callee: inst.parse });
	inst.safeParse = (data, params) => safeParse(inst, data, params);
	inst.parseAsync = async (data, params) => parseAsync(inst, data, params, { callee: inst.parseAsync });
	inst.safeParseAsync = async (data, params) => safeParseAsync(inst, data, params);
	inst.spa = inst.safeParseAsync;
	inst.encode = (data, params) => encode(inst, data, params);
	inst.decode = (data, params) => decode(inst, data, params);
	inst.encodeAsync = async (data, params) => encodeAsync(inst, data, params);
	inst.decodeAsync = async (data, params) => decodeAsync(inst, data, params);
	inst.safeEncode = (data, params) => safeEncode(inst, data, params);
	inst.safeDecode = (data, params) => safeDecode(inst, data, params);
	inst.safeEncodeAsync = async (data, params) => safeEncodeAsync(inst, data, params);
	inst.safeDecodeAsync = async (data, params) => safeDecodeAsync(inst, data, params);
	_installLazyMethods(inst, "ZodType", {
		check(...chks) {
			const def = this.def;
			return this.clone(mergeDefs(def, { checks: [...def.checks ?? [], ...chks.map((ch) => typeof ch === "function" ? { _zod: {
				check: ch,
				def: { check: "custom" },
				onattach: []
			} } : ch)] }), { parent: true });
		},
		with(...chks) {
			return this.check(...chks);
		},
		clone(def, params) {
			return clone(this, def, params);
		},
		brand() {
			return this;
		},
		register(reg, meta) {
			reg.add(this, meta);
			return this;
		},
		refine(check, params) {
			return this.check(refine(check, params));
		},
		superRefine(refinement, params) {
			return this.check(superRefine(refinement, params));
		},
		overwrite(fn) {
			return this.check(/* @__PURE__ */ _overwrite(fn));
		},
		optional() {
			return optional(this);
		},
		exactOptional() {
			return exactOptional(this);
		},
		nullable() {
			return nullable(this);
		},
		nullish() {
			return optional(nullable(this));
		},
		nonoptional(params) {
			return nonoptional(this, params);
		},
		array() {
			return array(this);
		},
		or(arg) {
			return union([this, arg]);
		},
		and(arg) {
			return intersection(this, arg);
		},
		transform(tx) {
			return pipe(this, transform(tx));
		},
		default(d) {
			return _default(this, d);
		},
		prefault(d) {
			return prefault(this, d);
		},
		catch(params) {
			return _catch(this, params);
		},
		pipe(target) {
			return pipe(this, target);
		},
		readonly() {
			return readonly(this);
		},
		describe(description) {
			const cl = this.clone();
			globalRegistry.add(cl, { description });
			return cl;
		},
		meta(...args) {
			if (args.length === 0) return globalRegistry.get(this);
			const cl = this.clone();
			globalRegistry.add(cl, args[0]);
			return cl;
		},
		isOptional() {
			return this.safeParse(void 0).success;
		},
		isNullable() {
			return this.safeParse(null).success;
		},
		apply(fn) {
			return fn(this);
		}
	});
	Object.defineProperty(inst, "description", {
		get() {
			return globalRegistry.get(inst)?.description;
		},
		configurable: true
	});
	return inst;
});
/** @internal */
const _ZodString = /*@__PURE__*/ $constructor("_ZodString", (inst, def) => {
	$ZodString.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => stringProcessor(inst, ctx, json, params);
	const bag = inst._zod.bag;
	inst.format = bag.format ?? null;
	inst.minLength = bag.minimum ?? null;
	inst.maxLength = bag.maximum ?? null;
	_installLazyMethods(inst, "_ZodString", {
		regex(...args) {
			return this.check(/* @__PURE__ */ _regex(...args));
		},
		includes(...args) {
			return this.check(/* @__PURE__ */ _includes(...args));
		},
		startsWith(...args) {
			return this.check(/* @__PURE__ */ _startsWith(...args));
		},
		endsWith(...args) {
			return this.check(/* @__PURE__ */ _endsWith(...args));
		},
		min(...args) {
			return this.check(/* @__PURE__ */ _minLength(...args));
		},
		max(...args) {
			return this.check(/* @__PURE__ */ _maxLength(...args));
		},
		length(...args) {
			return this.check(/* @__PURE__ */ _length(...args));
		},
		nonempty(...args) {
			return this.check(/* @__PURE__ */ _minLength(1, ...args));
		},
		lowercase(params) {
			return this.check(/* @__PURE__ */ _lowercase(params));
		},
		uppercase(params) {
			return this.check(/* @__PURE__ */ _uppercase(params));
		},
		trim() {
			return this.check(/* @__PURE__ */ _trim());
		},
		normalize(...args) {
			return this.check(/* @__PURE__ */ _normalize(...args));
		},
		toLowerCase() {
			return this.check(/* @__PURE__ */ _toLowerCase());
		},
		toUpperCase() {
			return this.check(/* @__PURE__ */ _toUpperCase());
		},
		slugify() {
			return this.check(/* @__PURE__ */ _slugify());
		}
	});
});
const ZodString = /*@__PURE__*/ $constructor("ZodString", (inst, def) => {
	$ZodString.init(inst, def);
	_ZodString.init(inst, def);
	inst.email = (params) => inst.check(/* @__PURE__ */ _email(ZodEmail, params));
	inst.url = (params) => inst.check(/* @__PURE__ */ _url(ZodURL, params));
	inst.jwt = (params) => inst.check(/* @__PURE__ */ _jwt(ZodJWT, params));
	inst.emoji = (params) => inst.check(/* @__PURE__ */ _emoji(ZodEmoji, params));
	inst.guid = (params) => inst.check(/* @__PURE__ */ _guid(ZodGUID, params));
	inst.uuid = (params) => inst.check(/* @__PURE__ */ _uuid(ZodUUID, params));
	inst.uuidv4 = (params) => inst.check(/* @__PURE__ */ _uuidv4(ZodUUID, params));
	inst.uuidv6 = (params) => inst.check(/* @__PURE__ */ _uuidv6(ZodUUID, params));
	inst.uuidv7 = (params) => inst.check(/* @__PURE__ */ _uuidv7(ZodUUID, params));
	inst.nanoid = (params) => inst.check(/* @__PURE__ */ _nanoid(ZodNanoID, params));
	inst.guid = (params) => inst.check(/* @__PURE__ */ _guid(ZodGUID, params));
	inst.cuid = (params) => inst.check(/* @__PURE__ */ _cuid(ZodCUID, params));
	inst.cuid2 = (params) => inst.check(/* @__PURE__ */ _cuid2(ZodCUID2, params));
	inst.ulid = (params) => inst.check(/* @__PURE__ */ _ulid(ZodULID, params));
	inst.base64 = (params) => inst.check(/* @__PURE__ */ _base64(ZodBase64, params));
	inst.base64url = (params) => inst.check(/* @__PURE__ */ _base64url(ZodBase64URL, params));
	inst.xid = (params) => inst.check(/* @__PURE__ */ _xid(ZodXID, params));
	inst.ksuid = (params) => inst.check(/* @__PURE__ */ _ksuid(ZodKSUID, params));
	inst.ipv4 = (params) => inst.check(/* @__PURE__ */ _ipv4(ZodIPv4, params));
	inst.ipv6 = (params) => inst.check(/* @__PURE__ */ _ipv6(ZodIPv6, params));
	inst.cidrv4 = (params) => inst.check(/* @__PURE__ */ _cidrv4(ZodCIDRv4, params));
	inst.cidrv6 = (params) => inst.check(/* @__PURE__ */ _cidrv6(ZodCIDRv6, params));
	inst.e164 = (params) => inst.check(/* @__PURE__ */ _e164(ZodE164, params));
	inst.datetime = (params) => inst.check(datetime(params));
	inst.date = (params) => inst.check(date(params));
	inst.time = (params) => inst.check(time(params));
	inst.duration = (params) => inst.check(duration$1(params));
});
function string(params) {
	return /* @__PURE__ */ _string(ZodString, params);
}
const ZodStringFormat = /*@__PURE__*/ $constructor("ZodStringFormat", (inst, def) => {
	$ZodStringFormat.init(inst, def);
	_ZodString.init(inst, def);
});
const ZodEmail = /*@__PURE__*/ $constructor("ZodEmail", (inst, def) => {
	$ZodEmail.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodGUID = /*@__PURE__*/ $constructor("ZodGUID", (inst, def) => {
	$ZodGUID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodUUID = /*@__PURE__*/ $constructor("ZodUUID", (inst, def) => {
	$ZodUUID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodURL = /*@__PURE__*/ $constructor("ZodURL", (inst, def) => {
	$ZodURL.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodEmoji = /*@__PURE__*/ $constructor("ZodEmoji", (inst, def) => {
	$ZodEmoji.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodNanoID = /*@__PURE__*/ $constructor("ZodNanoID", (inst, def) => {
	$ZodNanoID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
/**
* @deprecated CUID v1 is deprecated by its authors due to information leakage
* (timestamps embedded in the id). Use {@link ZodCUID2} instead.
* See https://github.com/paralleldrive/cuid.
*/
const ZodCUID = /*@__PURE__*/ $constructor("ZodCUID", (inst, def) => {
	$ZodCUID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodCUID2 = /*@__PURE__*/ $constructor("ZodCUID2", (inst, def) => {
	$ZodCUID2.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodULID = /*@__PURE__*/ $constructor("ZodULID", (inst, def) => {
	$ZodULID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodXID = /*@__PURE__*/ $constructor("ZodXID", (inst, def) => {
	$ZodXID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodKSUID = /*@__PURE__*/ $constructor("ZodKSUID", (inst, def) => {
	$ZodKSUID.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodIPv4 = /*@__PURE__*/ $constructor("ZodIPv4", (inst, def) => {
	$ZodIPv4.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodIPv6 = /*@__PURE__*/ $constructor("ZodIPv6", (inst, def) => {
	$ZodIPv6.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodCIDRv4 = /*@__PURE__*/ $constructor("ZodCIDRv4", (inst, def) => {
	$ZodCIDRv4.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodCIDRv6 = /*@__PURE__*/ $constructor("ZodCIDRv6", (inst, def) => {
	$ZodCIDRv6.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodBase64 = /*@__PURE__*/ $constructor("ZodBase64", (inst, def) => {
	$ZodBase64.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodBase64URL = /*@__PURE__*/ $constructor("ZodBase64URL", (inst, def) => {
	$ZodBase64URL.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodE164 = /*@__PURE__*/ $constructor("ZodE164", (inst, def) => {
	$ZodE164.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodJWT = /*@__PURE__*/ $constructor("ZodJWT", (inst, def) => {
	$ZodJWT.init(inst, def);
	ZodStringFormat.init(inst, def);
});
const ZodUnknown = /*@__PURE__*/ $constructor("ZodUnknown", (inst, def) => {
	$ZodUnknown.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => void 0;
});
function unknown() {
	return /* @__PURE__ */ _unknown(ZodUnknown);
}
const ZodNever = /*@__PURE__*/ $constructor("ZodNever", (inst, def) => {
	$ZodNever.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => neverProcessor(inst, ctx, json, params);
});
function never(params) {
	return /* @__PURE__ */ _never(ZodNever, params);
}
const ZodArray = /*@__PURE__*/ $constructor("ZodArray", (inst, def) => {
	$ZodArray.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => arrayProcessor(inst, ctx, json, params);
	inst.element = def.element;
	_installLazyMethods(inst, "ZodArray", {
		min(n, params) {
			return this.check(/* @__PURE__ */ _minLength(n, params));
		},
		nonempty(params) {
			return this.check(/* @__PURE__ */ _minLength(1, params));
		},
		max(n, params) {
			return this.check(/* @__PURE__ */ _maxLength(n, params));
		},
		length(n, params) {
			return this.check(/* @__PURE__ */ _length(n, params));
		},
		unwrap() {
			return this.element;
		}
	});
});
function array(element, params) {
	return /* @__PURE__ */ _array(ZodArray, element, params);
}
const ZodObject = /*@__PURE__*/ $constructor("ZodObject", (inst, def) => {
	$ZodObjectJIT.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => objectProcessor(inst, ctx, json, params);
	defineLazy(inst, "shape", () => {
		return def.shape;
	});
	_installLazyMethods(inst, "ZodObject", {
		keyof() {
			return _enum(Object.keys(this._zod.def.shape));
		},
		catchall(catchall) {
			return this.clone({
				...this._zod.def,
				catchall
			});
		},
		passthrough() {
			return this.clone({
				...this._zod.def,
				catchall: unknown()
			});
		},
		loose() {
			return this.clone({
				...this._zod.def,
				catchall: unknown()
			});
		},
		strict() {
			return this.clone({
				...this._zod.def,
				catchall: never()
			});
		},
		strip() {
			return this.clone({
				...this._zod.def,
				catchall: void 0
			});
		},
		extend(incoming) {
			return extend(this, incoming);
		},
		safeExtend(incoming) {
			return safeExtend(this, incoming);
		},
		merge(other) {
			return merge(this, other);
		},
		pick(mask) {
			return pick(this, mask);
		},
		omit(mask) {
			return omit(this, mask);
		},
		partial(...args) {
			return partial(ZodOptional, this, args[0]);
		},
		required(...args) {
			return required(ZodNonOptional, this, args[0]);
		}
	});
});
function object(shape, params) {
	const def = {
		type: "object",
		shape: shape ?? {},
		...normalizeParams(params)
	};
	return new ZodObject(def);
}
const ZodUnion = /*@__PURE__*/ $constructor("ZodUnion", (inst, def) => {
	$ZodUnion.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => unionProcessor(inst, ctx, json, params);
	inst.options = def.options;
});
function union(options, params) {
	return new ZodUnion({
		type: "union",
		options,
		...normalizeParams(params)
	});
}
const ZodIntersection = /*@__PURE__*/ $constructor("ZodIntersection", (inst, def) => {
	$ZodIntersection.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => intersectionProcessor(inst, ctx, json, params);
});
function intersection(left, right) {
	return new ZodIntersection({
		type: "intersection",
		left,
		right
	});
}
const ZodEnum = /*@__PURE__*/ $constructor("ZodEnum", (inst, def) => {
	$ZodEnum.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => enumProcessor(inst, ctx, json, params);
	inst.enum = def.entries;
	inst.options = Object.values(def.entries);
	const keys = new Set(Object.keys(def.entries));
	inst.extract = (values, params) => {
		const newEntries = {};
		for (const value of values) if (keys.has(value)) newEntries[value] = def.entries[value];
		else throw new Error(`Key ${value} not found in enum`);
		return new ZodEnum({
			...def,
			checks: [],
			...normalizeParams(params),
			entries: newEntries
		});
	};
	inst.exclude = (values, params) => {
		const newEntries = { ...def.entries };
		for (const value of values) if (keys.has(value)) delete newEntries[value];
		else throw new Error(`Key ${value} not found in enum`);
		return new ZodEnum({
			...def,
			checks: [],
			...normalizeParams(params),
			entries: newEntries
		});
	};
});
function _enum(values, params) {
	const entries = Array.isArray(values) ? Object.fromEntries(values.map((v) => [v, v])) : values;
	return new ZodEnum({
		type: "enum",
		entries,
		...normalizeParams(params)
	});
}
const ZodLiteral = /*@__PURE__*/ $constructor("ZodLiteral", (inst, def) => {
	$ZodLiteral.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => literalProcessor(inst, ctx, json, params);
	inst.values = new Set(def.values);
	Object.defineProperty(inst, "value", { get() {
		if (def.values.length > 1) throw new Error("This schema contains multiple valid literal values. Use `.values` instead.");
		return def.values[0];
	} });
});
function literal(value, params) {
	return new ZodLiteral({
		type: "literal",
		values: Array.isArray(value) ? value : [value],
		...normalizeParams(params)
	});
}
const ZodTransform = /*@__PURE__*/ $constructor("ZodTransform", (inst, def) => {
	$ZodTransform.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => transformProcessor(inst, ctx, json, params);
	inst._zod.parse = (payload, _ctx) => {
		if (_ctx.direction === "backward") throw new $ZodEncodeError(inst.constructor.name);
		payload.addIssue = (issue$1) => {
			if (typeof issue$1 === "string") payload.issues.push(issue(issue$1, payload.value, def));
			else {
				const _issue = issue$1;
				if (_issue.fatal) _issue.continue = false;
				_issue.code ?? (_issue.code = "custom");
				_issue.input ?? (_issue.input = payload.value);
				_issue.inst ?? (_issue.inst = inst);
				payload.issues.push(issue(_issue));
			}
		};
		const output = def.transform(payload.value, payload);
		if (output instanceof Promise) return output.then((output) => {
			payload.value = output;
			payload.fallback = true;
			return payload;
		});
		payload.value = output;
		payload.fallback = true;
		return payload;
	};
});
function transform(fn) {
	return new ZodTransform({
		type: "transform",
		transform: fn
	});
}
const ZodOptional = /*@__PURE__*/ $constructor("ZodOptional", (inst, def) => {
	$ZodOptional.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => optionalProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function optional(innerType) {
	return new ZodOptional({
		type: "optional",
		innerType
	});
}
const ZodExactOptional = /*@__PURE__*/ $constructor("ZodExactOptional", (inst, def) => {
	$ZodExactOptional.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => optionalProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function exactOptional(innerType) {
	return new ZodExactOptional({
		type: "optional",
		innerType
	});
}
const ZodNullable = /*@__PURE__*/ $constructor("ZodNullable", (inst, def) => {
	$ZodNullable.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => nullableProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function nullable(innerType) {
	return new ZodNullable({
		type: "nullable",
		innerType
	});
}
const ZodDefault = /*@__PURE__*/ $constructor("ZodDefault", (inst, def) => {
	$ZodDefault.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => defaultProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
	inst.removeDefault = inst.unwrap;
});
function _default(innerType, defaultValue) {
	return new ZodDefault({
		type: "default",
		innerType,
		get defaultValue() {
			return typeof defaultValue === "function" ? defaultValue() : shallowClone(defaultValue);
		}
	});
}
const ZodPrefault = /*@__PURE__*/ $constructor("ZodPrefault", (inst, def) => {
	$ZodPrefault.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => prefaultProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function prefault(innerType, defaultValue) {
	return new ZodPrefault({
		type: "prefault",
		innerType,
		get defaultValue() {
			return typeof defaultValue === "function" ? defaultValue() : shallowClone(defaultValue);
		}
	});
}
const ZodNonOptional = /*@__PURE__*/ $constructor("ZodNonOptional", (inst, def) => {
	$ZodNonOptional.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => nonoptionalProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function nonoptional(innerType, params) {
	return new ZodNonOptional({
		type: "nonoptional",
		innerType,
		...normalizeParams(params)
	});
}
const ZodCatch = /*@__PURE__*/ $constructor("ZodCatch", (inst, def) => {
	$ZodCatch.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => catchProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
	inst.removeCatch = inst.unwrap;
});
function _catch(innerType, catchValue) {
	return new ZodCatch({
		type: "catch",
		innerType,
		catchValue: typeof catchValue === "function" ? catchValue : () => catchValue
	});
}
const ZodPipe = /*@__PURE__*/ $constructor("ZodPipe", (inst, def) => {
	$ZodPipe.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => pipeProcessor(inst, ctx, json, params);
	inst.in = def.in;
	inst.out = def.out;
});
function pipe(in_, out) {
	return new ZodPipe({
		type: "pipe",
		in: in_,
		out
	});
}
const ZodReadonly = /*@__PURE__*/ $constructor("ZodReadonly", (inst, def) => {
	$ZodReadonly.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => readonlyProcessor(inst, ctx, json, params);
	inst.unwrap = () => inst._zod.def.innerType;
});
function readonly(innerType) {
	return new ZodReadonly({
		type: "readonly",
		innerType
	});
}
const ZodCustom = /*@__PURE__*/ $constructor("ZodCustom", (inst, def) => {
	$ZodCustom.init(inst, def);
	ZodType.init(inst, def);
	inst._zod.processJSONSchema = (ctx, json, params) => customProcessor(inst, ctx, json, params);
});
function refine(fn, _params = {}) {
	return /* @__PURE__ */ _refine(ZodCustom, fn, _params);
}
function superRefine(fn, params) {
	return /* @__PURE__ */ _superRefine(fn, params);
}
//#endregion
//#region ../core/dist/schemas.js
const slug = string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
/** `dev@me` as the environment it is a personal config of, `dev`; null for any other slug. */
function personalOf(environment) {
	return environment.endsWith("@me") ? environment.slice(0, -3) : null;
}
string().refine((value) => slug.safeParse(personalOf(value) ?? value).success, "not a valid environment");
slug.refine((value) => !PROJECT_PAGES.includes(value), { error: (issue) => `"${String(issue.input)}" is taken by a project's page, /projects/<project>/${String(issue.input)}: an environment cannot have it` });
string().trim().min(1).max(120);
string().min(1).max(64).refine((name) => name === name.trim(), "a folder name cannot start or end with a space").refine((name) => !/[/\p{Cc}]/u.test(name), "a folder name cannot hold \"/\" or a control character");
string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
/**
* A member as people read it, in a message or on a page: a service account
* as `service:<name>`, though the API, the vault and the log keep the
* `token:<name>` their signed entries hold.
*/
function shownMember(member) {
	return member.startsWith("token:") ? `service:${member.slice(6)}` : member;
}
_enum(["user", "service"]);
string().trim().min(1).max(320);
_enum(INSTANCE_ROLE_NAMES);
string().regex(ROLE_ID, "a role is named by lowercase letters, digits and dashes, 2 to 32, starting with a letter");
/** Which projects or environments a scope takes in, by slug: `all`, `{ only: [...] }` or `{ except: [...] }`. */
const scopeFilter = union([
	literal("all"),
	object({ only: array(slug).max(200) }).strict(),
	object({ except: array(slug).min(1).max(200) }).strict()
]);
object({
	projects: scopeFilter.optional(),
	environments: scopeFilter.optional()
}).strict();
string().uuid();
string().email().max(320);
//#endregion
//#region ../core/dist/workloads.js
const WORKLOAD_PROFILES = [
	"github",
	"github-reusable",
	"github-reusable-organization",
	"gitlab",
	"custom",
	"kubernetes",
	"gcp",
	"azure",
	"fly",
	"vercel",
	"aws",
	"enrollment",
	"cloudflare"
];
/** The profiles whose proof is no ID token: their binding's issuer is this URN, which no token names, and its keys none. */
const PROFILE_URNS = {
	aws: "urn:coffre:aws",
	enrollment: "urn:coffre:enrollment",
	cloudflare: "urn:coffre:cloudflare"
};
WORKLOAD_PROFILES.filter((profile) => !Object.hasOwn(PROFILE_URNS, profile));
/**
* The events a GitHub binding may trust. The first four are started by
* someone with write access, at the ref the binding names. The last two
* can run code nobody reviewed, so the owner opts in to each:
*
* - `pull_request` runs the pull request's own code and workflow file, at
*   `refs/pull/<n>/merge`; a binding matches it by the branch it merges
*   into. Forks get no ID token, unless the repository sends write tokens
*   to their pull requests (a setting of private repositories), so this
*   trusts whoever can push a branch to the repository.
* - `workflow_run` runs the default branch's workflow, but a fork's pull
*   request can start it: the run is as safe as what it does with the
*   code and artifacts of the run that started it.
*
* `pull_request_target` and the rest are refused, even when their ref
* happens to match: they exist to act on anyone's pull request, with the
* base repository's tokens.
*/
const GITHUB_EVENTS = [
	"push",
	"workflow_dispatch",
	"schedule",
	"release",
	"pull_request",
	"workflow_run"
];
/**
* What trusting each of the last two events exposes, as the UI, the CLI and
* the approval page say it when one is chosen.
*/
const EVENT_EXPOSURE = {
	pull_request: "Anyone who can push a branch to the repository can open a pull request and run their own code as this service account, unreviewed. Pull requests from forks get no ID token, unless the repository sends them write tokens.",
	workflow_run: "A fork's pull request can start workflow_run. The workflow comes from the default branch, so this is safe unless it runs code or artifacts from the run that started it."
};
/** Pipelines that run the project's own code, at its own ref: never a merge request's. */
const GITLAB_PIPELINE_SOURCES = [
	"push",
	"web",
	"schedule"
];
/** A binding that breaks a rule, said so an owner can fix it. */
var BindingInvalid = class extends Error {
	constructor(message) {
		super(message);
		this.name = "BindingInvalid";
	}
};
/** Google's, for every `gcp` binding. */
const GOOGLE_ISSUER = "https://accounts.google.com";
/** A claim's values, one or several. */
function claimValues(value) {
	return value === void 0 ? [] : typeof value === "string" ? [value] : value;
}
/** What a ref must be for each event: the branch or tag it runs at, or for a pull request, the branch it merges into. */
const EVENT_REFS = {
	release: {
		prefix: "refs/tags/",
		why: "a release runs at its tag: refs/tags/<tag>"
	},
	schedule: {
		prefix: "refs/heads/",
		why: "a schedule runs on the default branch: refs/heads/<branch>"
	},
	workflow_run: {
		prefix: "refs/heads/",
		why: "a workflow_run runs on the default branch: refs/heads/<branch>"
	},
	pull_request: {
		prefix: "refs/heads/",
		why: "a pull request matches by the branch it merges into: refs/heads/<branch>"
	}
};
/** `refs/heads/main`, or `refs/tags/v1`, as GitHub names a ref. */
function fullRef(kind, name) {
	return `refs/${kind === "branch" ? "heads" : "tags"}/${name}`;
}
/** The GitHub events a binding at a branch, or at a tag, may name. */
function githubEventsAt(kind) {
	return GITHUB_EVENTS.filter((event) => EVENT_REFS[event] === void 0 || EVENT_REFS[event].prefix === fullRef(kind, ""));
}
/** A workflow file at a ref, as GitHub's tokens name it: `acme/api/.github/workflows/deploy.yml@refs/heads/main`. */
function workflowRef(repository, file, ref) {
	return `${repository}/.github/workflows/${file.replace(/^\.github\/workflows\//, "")}@${ref}`;
}
function started(input, one, many) {
	const single = input[one];
	const list = input[many];
	if (single !== void 0 && list !== void 0) throw new BindingInvalid(`name ${one} or ${many}, not both`);
	if (single !== void 0) return single;
	if (list === void 0) throw new BindingInvalid(`name ${one} or ${many}`);
	return list;
}
/**
* A workflow of the repository, run at `ref` by any of `events`; a pull
* request, by the branch it merges into. An `environment` narrows it to the
* jobs that run in that GitHub environment.
*/
function githubWorkflow(input) {
	return {
		profile: "github",
		claims: {
			repository_owner_id: input.ownerId,
			repository_id: input.repositoryId,
			workflow_ref: workflowRef(input.repository, input.workflow, input.ref),
			ref: input.ref,
			event_name: started(input, "event", "events"),
			...inEnvironment(input.environment)
		}
	};
}
/** The `environment` claim, when one is named. */
function inEnvironment(environment) {
	return environment === void 0 ? {} : { environment };
}
/**
* A reusable workflow at one commit, called at `ref`: from one repository,
* or, with `repositoryId` null, from any repository of the organization. A
* `caller` workflow narrows it to one calling workflow, and an
* `environment` to the jobs that run in that GitHub environment.
*/
function githubReusable(input) {
	const claims = {
		repository_owner_id: input.ownerId,
		...input.repositoryId === null ? {} : { repository_id: input.repositoryId },
		ref: input.ref,
		event_name: started(input, "event", "events"),
		job_workflow_ref: input.called,
		job_workflow_sha: input.sha,
		...inEnvironment(input.environment)
	};
	if (input.caller !== void 0) claims.workflow_ref = workflowRef(input.caller.repository, input.caller.workflow, input.ref);
	return {
		profile: input.repositoryId === null ? "github-reusable-organization" : "github-reusable",
		claims
	};
}
/** A GitLab project's pipelines from any of `sources`, at a branch or tag. */
function gitlabProject(input) {
	return {
		profile: "gitlab",
		claims: {
			namespace_id: input.namespaceId,
			project_id: input.projectId,
			ref_type: input.refType,
			ref: input.ref,
			pipeline_source: started(input, "source", "sources")
		}
	};
}
/** What a field left out of a policy means. */
const POLICY_DEFAULTS = {
	keyAudience: false,
	sessionHours: 24,
	sessionDays: 30,
	overlapMinutes: 15,
	approve: false,
	onContention: "freeze",
	unsignedUploads: false
};
const SESSION_FIELDS = [
	"reads",
	"sources",
	"sessionHours",
	"unsignedUploads"
];
const KEY_AUDIENCE = [...SESSION_FIELDS, "keyAudience"];
/**
* The profiles whose caller picks the token's audience, so their binding's
* policy always says `keyAudience`: `checkPolicy` sets it, and refuses it off.
* A Vercel function picks one by exchanging its own token at
* `https://oidc.vercel.com/~token`, as `@vercel/oidc`'s
* `getVercelOidcToken({ audience })` does.
*/
const KEY_NAMING_PROFILES = [
	"github",
	"github-reusable",
	"github-reusable-organization",
	"gcp",
	"fly",
	"vercel"
];
/** The fields each profile's policy may hold. */
const POLICY_FIELDS = {
	github: KEY_AUDIENCE,
	"github-reusable": KEY_AUDIENCE,
	"github-reusable-organization": KEY_AUDIENCE,
	gitlab: SESSION_FIELDS,
	custom: KEY_AUDIENCE,
	kubernetes: SESSION_FIELDS,
	gcp: KEY_AUDIENCE,
	azure: [...SESSION_FIELDS, "audience"],
	fly: KEY_AUDIENCE,
	vercel: KEY_AUDIENCE,
	aws: SESSION_FIELDS,
	enrollment: [
		"reads",
		"sources",
		"replicas",
		"sessionDays",
		"overlapMinutes",
		"mintedBy",
		"approve",
		"onContention",
		"unsignedUploads"
	],
	cloudflare: ["reads"]
};
const UUID$1 = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A credential's name in the proxy's config: a minter's, a signer's, an upstream's. */
const CREDENTIAL_NAME = /^[a-z][a-z0-9-]{0,31}$/;
/** A service's name after `token:`, as a member names it. */
const SERVICE_NAME = /^[^\s\p{Cc}]{1,320}$/u;
function integer(value, name, min, max) {
	if (!Number.isSafeInteger(value) || value < min || value > max) throw new BindingInvalid(`${name} is a whole number from ${min} to ${max}`);
	return value;
}
function sortedUnique(values) {
	return [...new Set(values)].sort();
}
function uuidList(value, what, max) {
	if (!Array.isArray(value) || value.length > max || value.some((id) => typeof id !== "string" || !UUID$1.test(id.toLowerCase()))) throw new BindingInvalid(`${what} lists at most ${max} IDs`);
	return sortedUnique(value.map((id) => id.toLowerCase()));
}
function checkReads(value) {
	if (typeof value !== "object" || value === null || Array.isArray(value)) throw new BindingInvalid("reads maps environment IDs to { keys, mints }");
	const entries = Object.entries(value);
	if (entries.length > 64) throw new BindingInvalid(`reads names at most 64 environments`);
	const reads = {};
	const seen = /* @__PURE__ */ new Set();
	for (const [environment, entry] of entries) {
		const id = environment.toLowerCase();
		if (!UUID$1.test(id)) throw new BindingInvalid(`reads names environments by ID: ${environment} is none`);
		if (seen.has(id)) throw new BindingInvalid(`reads names ${id} twice`);
		seen.add(id);
		if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new BindingInvalid("each environment of reads is { keys, mints }");
		const { keys, mints, ...rest } = entry;
		if (Object.keys(rest).length > 0) throw new BindingInvalid(`each environment of reads holds keys and mints, not ${Object.keys(rest).join(", ")}`);
		const read = {};
		if (keys !== void 0) {
			const listed = keys === "*" ? "*" : uuidList(keys, "reads.keys", 256);
			if (listed === "*" || listed.length > 0) read.keys = listed;
		}
		if (mints !== void 0) {
			if (!Array.isArray(mints) || mints.length > 256 || mints.some((name) => typeof name !== "string" || !CREDENTIAL_NAME.test(name))) throw new BindingInvalid("reads.mints lists minters by name");
			if (mints.length > 0) read.mints = sortedUnique(mints);
		}
		if (read.keys !== void 0 || read.mints !== void 0) reads[id] = read;
	}
	return Object.keys(reads).length === 0 ? void 0 : reads;
}
/**
* Check a binding's policy against its profile and return it canonical:
* every field its profile allows, valid, those at their default left out,
* lists sorted and IDs in lower case, so that one policy has one spelling
* (`policyText`). `service` is the binding's own, `token:<name>`, which its
* `mintedBy` may not name: a session of the service would then mint codes
* for itself, and outlive every deploy. Throws `BindingInvalid`.
*/
function checkPolicy(profile, input, options) {
	if (input === void 0 || input === null) input = {};
	if (typeof input !== "object" || Array.isArray(input)) throw new BindingInvalid("a policy is an object");
	const given = input;
	const allowed = POLICY_FIELDS[profile];
	const extra = Object.keys(given).filter((name) => given[name] !== void 0 && !allowed.includes(name));
	if (extra.length > 0) throw new BindingInvalid(`a ${profile} binding's policy holds ${allowed.join(", ") || "nothing"}, not ${extra.join(", ")}`);
	const policy = {};
	if (given.audience !== void 0) {
		if (typeof given.audience !== "string" || given.audience === "" || given.audience.length > 400 || /\p{Cc}|^\s|\s$/u.test(given.audience)) throw new BindingInvalid("audience is the exact audience the platform puts in its tokens");
		policy.audience = given.audience;
	} else if (allowed.includes("audience")) throw new BindingInvalid(`a ${profile} binding names the audience its platform puts in its tokens: ${profile} lets no caller choose one`);
	if (given.keyAudience !== void 0 && typeof given.keyAudience !== "boolean") throw new BindingInvalid("keyAudience is true or false");
	if (KEY_NAMING_PROFILES.includes(profile)) {
		if (given.keyAudience === false) throw new BindingInvalid(`a ${profile} binding's tokens name the session's key in their audience: ${profile} lets its caller choose one, so a copied token works for no other key`);
		policy.keyAudience = true;
	} else if (given.keyAudience === true) policy.keyAudience = true;
	if (given.reads !== void 0) {
		const reads = checkReads(given.reads);
		if (reads !== void 0) policy.reads = reads;
	}
	if (given.sources !== void 0) {
		if (!Array.isArray(given.sources) || given.sources.length > 16) throw new BindingInvalid(`sources lists at most 16 CIDRs`);
		const sources = sortedUnique(given.sources.map((source) => {
			const block = typeof source === "string" ? parseCidr(source) : null;
			if (block === null) throw new BindingInvalid(`sources lists CIDRs, such as 162.220.232.0/24 or 2001:db8::/32: ${String(source)} is none`);
			return block.text;
		}));
		if (sources.length > 0) policy.sources = sources;
	}
	const number = (name, min, max) => {
		if (given[name] === void 0) return;
		const value = integer(given[name], name, min, max);
		if (name === "replicas" || value !== POLICY_DEFAULTS[name]) policy[name] = value;
	};
	number("sessionHours", 1, 168);
	number("sessionDays", 1, 90);
	number("overlapMinutes", 1, 60);
	number("replicas", 1, 64);
	if (profile === "enrollment" && policy.replicas === void 0) throw new BindingInvalid("an enrollment binding says how many replicas run, its replicas: a code admits twice that many sessions");
	if (given.mintedBy !== void 0) {
		const named = typeof given.mintedBy === "string" ? given.mintedBy.startsWith("token:") ? given.mintedBy : `token:${given.mintedBy}` : "";
		if (!SERVICE_NAME.test(named.slice(6))) throw new BindingInvalid("mintedBy names a service account");
		if (named === options.service) throw new BindingInvalid(`mintedBy names another service than ${shownMember(options.service)}: a session of its own would mint codes for itself`);
		policy.mintedBy = named;
	}
	for (const flag of ["approve", "unsignedUploads"]) {
		if (given[flag] === void 0) continue;
		if (typeof given[flag] !== "boolean") throw new BindingInvalid(`${flag} is true or false`);
		if (given[flag]) policy[flag] = true;
	}
	if (given.onContention !== void 0) {
		if (given.onContention !== "freeze" && given.onContention !== "alert") throw new BindingInvalid("onContention is freeze or alert");
		if (given.onContention === "alert") policy.onContention = "alert";
	}
	return policy;
}
function ipv4(text) {
	const parts = text.split(".");
	if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return null;
	return Uint8Array.from(parts.map(Number));
}
function ipv6(text) {
	const halves = text.toLowerCase().split("::");
	if (halves.length > 2) return null;
	const groups = halves.map((half) => half === "" ? [] : half.split(":"));
	if (groups.flat().some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
	const count = groups.flat().length;
	if (halves.length === 1 ? count !== 8 : count > 7) return null;
	const words = halves.length === 1 ? groups[0] : [
		...groups[0],
		...Array(8 - count).fill("0"),
		...groups[1]
	];
	const bytes = /* @__PURE__ */ new Uint8Array(16);
	words.forEach((word, i) => {
		const value = parseInt(word, 16);
		bytes[2 * i] = value >> 8;
		bytes[2 * i + 1] = value & 255;
	});
	return bytes;
}
/** An address, IPv4 dotted or IPv6 in hex groups; null for anything else. */
function parseAddress(text) {
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(text);
	if (mapped !== null) return parseAddress(mapped[1]);
	const v4 = ipv4(text);
	if (v4 !== null) return {
		version: 4,
		bytes: v4
	};
	const v6 = text.includes(":") ? ipv6(text) : null;
	return v6 === null ? null : {
		version: 6,
		bytes: v6
	};
}
/** IPv6 as RFC 5952 writes it: lower case, no leading zeros, the longest run of two or more zero groups as `::`, the first of equals. */
function ipv6Text(bytes) {
	const words = Array.from({ length: 8 }, (_, i) => bytes[2 * i] << 8 | bytes[2 * i + 1]);
	let best = {
		at: -1,
		length: 0
	};
	for (let i = 0; i < 8;) {
		if (words[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && words[j] === 0) j++;
		if (j - i > best.length) best = {
			at: i,
			length: j - i
		};
		i = j;
	}
	const hexes = words.map((word) => word.toString(16));
	if (best.length < 2) return hexes.join(":");
	return `${hexes.slice(0, best.at).join(":")}::${hexes.slice(best.at + best.length).join(":")}`;
}
/**
* A CIDR, `162.220.232.0/24` or `2001:db8::/32`, as its one spelling; null
* for anything else, a block with host bits set included, since
* `162.220.232.5/24` most likely means another block than it says.
*/
function parseCidr(text) {
	const slash = text.indexOf("/");
	if (slash < 0 || !/^(0|[1-9][0-9]{0,2})$/.test(text.slice(slash + 1))) return null;
	const address = parseAddress(text.slice(0, slash));
	const bits = Number(text.slice(slash + 1));
	if (address === null || bits > address.bytes.length * 8) return null;
	for (let bit = bits; bit < address.bytes.length * 8; bit++) if (address.bytes[bit >> 3] >> 7 - (bit & 7) & 1) return null;
	const shown = address.version === 4 ? Array.from(address.bytes).join(".") : ipv6Text(address.bytes);
	return {
		...address,
		bits,
		text: `${shown}/${bits}`
	};
}
//#endregion
//#region src/trust.ts
/**
* `coffre trust` and `coffre untrust`: which CI runs may sign in as a
* service account by OIDC, the ID token their platform signs
* (docs/design/oidc.md).
*
*   coffre trust api-deploy --github acme/api --workflow deploy.yml --branch main
*
* builds the binding's claims from flags, looks up the IDs it names when
* not given, and shows what the server would save: the claims in full, the
* issuer and the keys it names. `--apply` saves it.
*
* A workload's binding (docs/design/workload-access.md, section 4) is made
* the same way, by its platform's flag, and carries a policy: what its
* key-bound sessions may read, where from, and for how long.
*
*   coffre trust ingest --aws arn:aws:iam::671742253563:role/ingest-task
*   coffre trust api-prod --enrollment --replicas 2 --source 162.220.232.0/24 --minted-by deploy
*/
/** `coffre trust`'s flags, as `parseArgs` reads them. */
const TRUST_OPTIONS = {
	github: { type: "string" },
	workflow: { type: "string" },
	reusable: { type: "string" },
	sha: { type: "string" },
	"any-repository": { type: "boolean" },
	"github-environment": { type: "string" },
	gitlab: { type: "string" },
	"gitlab-url": { type: "string" },
	source: {
		type: "string",
		multiple: true
	},
	issuer: { type: "string" },
	claim: {
		type: "string",
		multiple: true
	},
	branch: { type: "string" },
	tag: { type: "string" },
	event: {
		type: "string",
		multiple: true
	},
	"repository-id": { type: "string" },
	"owner-id": { type: "string" },
	"project-id": { type: "string" },
	"namespace-id": { type: "string" },
	aws: { type: "string" },
	"role-id": { type: "string" },
	kubernetes: { type: "string" },
	uid: { type: "string" },
	gcp: { type: "string" },
	azure: { type: "boolean" },
	tenant: { type: "string" },
	object: { type: "string" },
	audience: { type: "string" },
	fly: { type: "string" },
	"org-id": { type: "string" },
	"app-id": { type: "string" },
	vercel: { type: "string" },
	"vercel-environment": { type: "string" },
	enrollment: { type: "boolean" },
	cloudflare: { type: "boolean" },
	workload: { type: "boolean" },
	reads: {
		type: "string",
		multiple: true
	},
	"session-hours": { type: "string" },
	"unsigned-uploads": { type: "boolean" },
	replicas: { type: "string" },
	"minted-by": { type: "string" },
	approve: { type: "boolean" },
	"session-days": { type: "string" },
	"overlap-minutes": { type: "string" },
	"on-contention": { type: "string" },
	scope: {
		type: "string",
		multiple: true
	},
	label: { type: "string" },
	replace: {
		type: "string",
		multiple: true
	},
	"jwks-file": { type: "string" },
	"replace-keys": { type: "boolean" },
	apply: {
		type: "boolean",
		default: false
	}
};
const TRUST_USAGE = `usage: coffre trust <service>                       its trust bindings
       coffre trust <service> --github <owner>/<repo> --workflow <file> (--branch <b> | --tag <t>)
                    [--event push,workflow_dispatch,schedule,release,pull_request,workflow_run]
                    [--github-environment <name>]
       coffre trust <service> --github <owner>/<repo> --reusable <owner>/<repo>/.github/workflows/<file>@<ref>
                    --sha <commit> (--branch <b> | --tag <t>) [--event …] [--github-environment <name>]
       coffre trust <service> --github <owner> --reusable … --any-repository
       coffre trust <service> --gitlab <group>/<project> (--branch <b> | --tag <t>)
                    [--source push,web,schedule] [--gitlab-url <url>]
       coffre trust <service> --issuer <url> --claim sub=<subject> [--claim <name>=<value> …]
       coffre trust <service> --issuer <iss> --jwks-file <path> --claim sub=<subject> [--claim …]
       coffre trust <service> --issuer <iss> --replace-keys --jwks-file <path>
         IDs, when the lookup cannot see a private repository, owner or project:
                    [--repository-id <n> --owner-id <n>] [--project-id <n> --namespace-id <n>]
         [--scope <path>=<role>,…] [--label <text>] [--replace <binding-id>] [--apply]
         --scope is what its runs reach, as market/dev=developer: at most what the account holds,
         all of it unless told, and nothing it is given later
         --event and --source take one or more, push alone unless told; a pull request matches
         by the branch it merges into
         --github-environment takes only the jobs that run in that GitHub environment, under its
         protection rules
         --claim names a nested claim by its path: kubernetes.io.serviceaccount.uid=<uid>
         --jwks-file uploads the issuer's public keys, a JWKS, for an issuer coffre cannot fetch them
         from, such as a private Kubernetes cluster's (kubectl get --raw /openid/v1/jwks): then
         --issuer is any string its tokens name, and coffre asks it nothing
         --replace-keys gives every binding of the service on --issuer the keys of --jwks-file, as
         when the issuer rotates its keys: a set that holds the old and the new takes tokens of both
       coffre untrust <service> <binding-id> [--apply]   shows the CI runs it would cut off; --apply removes it
A service account, service:<name>, signs in by OIDC this way, its CI's ID token matched by a trust
binding, with no stored secret; or, for CI without OIDC, with a bearer token: coffre tokens issue <service>.

A workload signs in for a key-bound session, by its platform's proof:
       coffre trust <service> --aws arn:aws:iam::<account>:role/<name> [--role-id AROA…]
       coffre trust <service> --kubernetes <namespace>/<service-account> [--issuer <url>] [--uid <uid>]
                    [--jwks-file <path>] [--claim <name>=<value> …]
       coffre trust <service> --gcp <service-account-email | unique-id> [--claim …]
       coffre trust <service> --azure --tenant <tenant-id> --object <object-id> --audience <app-id-uri>
       coffre trust <service> --azure --tenant <tenant-id> --object <object-id> --audience <the API's client ID>
                    --issuer https://login.microsoftonline.com/<tenant-id>/v2.0   for an API that takes v2 tokens
                    [--claim …]
       coffre trust <service> --fly <organization> --org-id <id> --app-id <id> [--claim …]
       coffre trust <service> --vercel <team> --owner-id team_… --project-id prj_…
                    [--vercel-environment production] [--issuer https://oidc.vercel.com] [--claim …]
       coffre trust <service> --enrollment --replicas <n> [--minted-by <service>] [--approve]
                    [--session-days 30] [--overlap-minutes 15] [--on-contention freeze|alert]
       coffre trust <service> --cloudflare
       coffre trust <service> (--github … | --gitlab … | --issuer …) --workload
         and, for any of them:
                    [--reads <project>/<env>=<KEY>,… | <project>/<env>=*] [--source <cidr> …]
                    [--session-hours 24] [--unsigned-uploads]
         --aws, --kubernetes and --gcp look up the IDs they bind with the aws, kubectl and gcloud you
         are signed in to; --role-id, --uid and a unique ID skip the lookup
         --reads lists the values its sessions may read, which its platform then holds: every other
         key they use through coffre, never read
         --source takes CIDRs its sessions must come from; with --gitlab, push, web and schedule
         remain pipeline sources
         --workload makes a CI run's binding one for a key-bound session; without it, --github,
         --gitlab and --issuer make one for /api/auth/oidc's five-minute bearer credential`;
/** A service account as the API names it, `token:api-deploy`, from `api-deploy`, `service:api-deploy` or `token:api-deploy`. */
function serviceMember(value) {
	const member = apiMember(value);
	return member.startsWith("token:") ? member : `token:${member}`;
}
/**
* A token's or a binding's scope, from `--scope market/dev=developer,market/prod=viewer`,
* repeated or a comma list; undefined, all its account holds, when not given.
* `admit --grant` takes places and roles the same way.
*/
function scopeFrom(values, flag = "--scope") {
	const pairs = listOf$2(values);
	if (pairs === void 0) return void 0;
	return Object.fromEntries(pairs.map((pair) => {
		const [path, role, ...rest] = pair.split("=");
		if (!path || role === void 0 || rest.length > 0 || !ROLE_ID.test(role)) throw new Error(`${flag} takes <project>[/<environment>]=<role>, a role \`coffre roles\` lists, such as viewer or developer; not "${pair}"`);
		return [path, role];
	}));
}
/** A token's or a binding's scope in words; null for one 0.4 made, not sealed yet, which reaches all its account holds. */
function reaches(scope) {
	return scope === null ? "all its account holds" : credentialScopeInWords(scope);
}
/** `push,workflow_dispatch` and `--event schedule`, as one list, each once. */
function listOf$2(values) {
	if (values === void 0) return void 0;
	return [...new Set(values.flatMap((value) => value.split(",")).map((value) => value.trim()).filter((value) => value !== ""))];
}
/**
* What the binding accepts, by the event (GitHub) or the pipeline source
* (GitLab) that started the run; the flag that adds the others the ref
* allows (a schedule runs on a branch, a release at a tag), short of those
* that run unreviewed code; and what each of those chosen exposes.
*/
function describeEvents(binding) {
	if (!binding.profile.startsWith("github") && binding.profile !== "gitlab") return null;
	const gitlab = binding.profile === "gitlab";
	const chosen = claimValues(binding.claims[gitlab ? "pipeline_source" : "event_name"]);
	const tag = gitlab ? binding.claims.ref_type === "tag" : String(binding.claims.ref).startsWith("refs/tags/");
	const others = (gitlab ? GITLAB_PIPELINE_SOURCES : githubEventsAt(tag ? "tag" : "branch").filter((event) => EVENT_EXPOSURE[event] === void 0)).filter((value) => !chosen.includes(value));
	const [what, flag] = gitlab ? ["pipelines", "--source"] : ["runs", "--event"];
	const accepts = `Accepts ${what} started by ${listing(chosen)}.`;
	const lines = [others.length === 0 ? accepts : `${accepts} Not by ${listing(others, "or")}: add them with ${flag}, as ${flag} ${[...chosen, ...others].join(",")}.`];
	for (const event of chosen) if (EVENT_EXPOSURE[event] !== void 0) lines.push(`${event}: ${EVENT_EXPOSURE[event]}`);
	return lines.join("\n");
}
function listing(items, last = "and") {
	return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} ${last} ${items.at(-1)}`;
}
/** The flags that name a workload's platform, each its profile. */
const PLATFORMS = [
	"aws",
	"kubernetes",
	"gcp",
	"azure",
	"fly",
	"vercel",
	"enrollment",
	"cloudflare"
];
/** The flags only some platforms take, and which. */
const PLATFORM_ONLY = {
	"role-id": ["aws"],
	uid: ["kubernetes"],
	tenant: ["azure"],
	object: ["azure"],
	audience: ["azure"],
	"org-id": ["fly"],
	"app-id": ["fly"],
	"vercel-environment": ["vercel"],
	"owner-id": ["github", "vercel"],
	"project-id": ["gitlab", "vercel"]
};
/** The flags that say which CI runs a binding takes, which no workload's platform has. */
const CI_ONLY = [
	"workflow",
	"reusable",
	"sha",
	"any-repository",
	"github-environment",
	"gitlab-url",
	"branch",
	"tag",
	"event",
	"repository-id",
	"namespace-id"
];
/** Each policy flag, by the field it sets. */
const POLICY_FLAGS = {
	reads: "reads",
	source: "sources",
	"session-hours": "sessionHours",
	"unsigned-uploads": "unsignedUploads",
	replicas: "replicas",
	"minted-by": "mintedBy",
	approve: "approve",
	"session-days": "sessionDays",
	"overlap-minutes": "overlapMinutes",
	"on-contention": "onContention"
};
/**
* The binding the flags describe, its IDs looked up where they were not
* given: one, whatever the events (GitHub) or pipeline sources (GitLab) it
* names; `push` unless told. A workload's platform, or `--workload`, makes
* one with a policy, for a key-bound session. Throws a sentence.
*/
async function bindingFrom(flags, lookup, options = {}) {
	const platforms = PLATFORMS.filter((name) => flags[name] !== void 0 && flags[name] !== false);
	const named = [...platforms, ...["github", "gitlab"].filter((name) => flags[name] !== void 0)];
	if (named.length === 0 && flags.issuer === void 0) throw new Error(`name one of --github, --gitlab or --issuer, or a workload's platform: ${PLATFORMS.map((name) => `--${name}`).join(", ")}`);
	if (named.length > 1) throw new Error(`name one platform, not ${named.map((name) => `--${name}`).join(" and ")}`);
	const kind = named[0] ?? "issuer";
	for (const [flag, kinds] of Object.entries(PLATFORM_ONLY)) if (flags[flag] !== void 0 && !kinds.includes(kind)) throw new Error(`--${flag} is ${kinds.map((name) => `--${name}`).join(" or ")}'s`);
	if (flags.issuer !== void 0 && named.length > 0 && ![
		"kubernetes",
		"azure",
		"vercel"
	].includes(kind)) throw new Error(`--issuer names a custom binding's issuer, or a cluster's, a tenant's or a team's: --${kind} names its own`);
	const given = listOf$2(flags.source);
	const cidrs = given?.filter((value) => /[./:]/.test(value));
	const pipelines = given?.filter((value) => !/[./:]/.test(value));
	for (const cidr of cidrs ?? []) if (parseCidr(cidr) === null) throw new Error(`--source takes CIDRs, such as 162.220.232.0/24 or 2001:db8::/32: ${cidr} is none`);
	const policy = policyFrom(flags, cidrs);
	if (platforms.length === 1) {
		if (flags.workload === true) throw new Error(`--${kind} makes a workload's binding: --workload is for --github, --gitlab and --issuer`);
		const ci = CI_ONLY.find((flag) => flags[flag] !== void 0);
		if (ci !== void 0) throw new Error(`--${ci} says which CI runs a --github or --gitlab binding takes: --${kind} has none`);
		if (pipelines !== void 0 && pipelines.length > 0) throw new Error(`--source takes CIDRs, such as 162.220.232.0/24: ${pipelines.join(", ")} is none`);
		const binding = await platformBinding(kind, flags, options.platforms ?? platformLookup());
		return checked(binding, {
			...binding.policy,
			...policy
		}, options.service);
	}
	const events = listOf$2(flags.event);
	if (flags.github === void 0 && events !== void 0) throw new Error("--event is a GitHub run's: --source names a GitLab pipeline's");
	if (flags.github === void 0 && flags["github-environment"] !== void 0) throw new Error("--github-environment narrows a GitHub binding: name the repository with --github");
	if (flags.gitlab === void 0 && pipelines !== void 0 && pipelines.length > 0) throw new Error(`--source is a GitLab pipeline's, or a CIDR: ${pipelines.join(", ")} is neither`);
	for (const event of events ?? []) if (!GITHUB_EVENTS.includes(event)) throw new Error(`--event takes ${GITHUB_EVENTS.join(", ")}, not ${event}`);
	for (const source of pipelines ?? []) if (!GITLAB_PIPELINE_SOURCES.includes(source)) throw new Error(`--source takes ${GITLAB_PIPELINE_SOURCES.join(", ")}, or CIDRs, not ${source}`);
	const binding = flags.github !== void 0 ? await github$1(flags, events ?? ["push"], lookup) : flags.gitlab !== void 0 ? await gitlab(flags, pipelines !== void 0 && pipelines.length > 0 ? pipelines : ["push"], lookup) : custom(flags);
	if (flags.workload === true) return checked(binding, policy ?? {}, options.service);
	if (policy !== void 0) {
		const flag = Object.entries(POLICY_FLAGS).find(([, field]) => policy[field] !== void 0)[0];
		throw new Error(`--${flag} is a key-bound session's: add --workload, for a binding that signs in at /api/auth/workload`);
	}
	return binding;
}
/** The policy the flags give, `reads` by path and key name; undefined when they give none. */
function policyFrom(flags, sources) {
	const policy = {};
	const whole = (flag) => {
		const value = flags[flag];
		if (value === void 0) return void 0;
		if (!/^\d{1,6}$/.test(value)) throw new Error(`--${flag} takes a whole number, not ${value}`);
		return Number(value);
	};
	if (flags.reads !== void 0) policy.reads = readsFrom(flags.reads);
	if (sources !== void 0 && sources.length > 0) policy.sources = sources;
	for (const flag of [
		"session-hours",
		"replicas",
		"session-days",
		"overlap-minutes"
	]) {
		const value = whole(flag);
		if (value !== void 0) policy[POLICY_FLAGS[flag]] = value;
	}
	if (flags["minted-by"] !== void 0) policy.mintedBy = serviceMember(flags["minted-by"]);
	if (flags.approve === true) policy.approve = true;
	if (flags["unsigned-uploads"] === true) policy.unsignedUploads = true;
	const contention = flags["on-contention"];
	if (contention !== void 0) {
		if (contention !== "freeze" && contention !== "alert") throw new Error(`--on-contention takes freeze or alert, not ${contention}`);
		policy.onContention = contention;
	}
	return Object.keys(policy).length === 0 ? void 0 : policy;
}
/**
* `--reads market/prod=STRIPE_WEBHOOK_SECRET,DATABASE_URL`, repeated, or
* `market/prod=*` for every key of it, by path and name: the server finds
* their IDs, which the binding keeps, so that a rename moves nothing.
*/
function readsFrom(values) {
	const reads = {};
	for (const value of values) {
		const at = value.indexOf("=");
		const [path, list] = at < 0 ? [value, ""] : [value.slice(0, at), value.slice(at + 1)];
		const keys = list.split(",").map((key) => key.trim()).filter((key) => key !== "");
		if (!/^[^/=\s]+\/[^/=\s]+$/.test(path) || keys.length === 0) throw new Error(`--reads takes <project>/<environment>=<KEY>,<KEY>, or <project>/<environment>=* for every key of it; not "${value}"`);
		if (Object.hasOwn(reads, path)) throw new Error(`--reads names ${path} twice: list its keys once, comma-separated`);
		if (keys.includes("*") && keys.length > 1) throw new Error(`--reads ${path}=* reads every key of it: name keys, or *, not both`);
		reads[path] = keys.includes("*") ? "*" : [...new Set(keys)].sort();
	}
	return reads;
}
/**
* A workload's binding with its policy, checked here as far as the CLI
* can: each flag is one the profile's policy takes, and every field but
* `reads`, which names keys only the server can find, as `checkPolicy`
* checks it.
*/
function checked(binding, policy, service) {
	const allowed = POLICY_FIELDS[binding.profile];
	for (const [flag, field] of Object.entries(POLICY_FLAGS)) if (policy[field] !== void 0 && !allowed.includes(field)) {
		const takes = Object.entries(POLICY_FLAGS).filter(([, each]) => allowed.includes(each)).map(([name]) => `--${name}`);
		throw new Error(`${/^[aeiou]/.test(binding.profile) ? "an" : "a"} ${binding.profile} binding takes ${takes.join(", ") || "no policy flag"}, not --${flag}`);
	}
	try {
		checkPolicy(binding.profile, {
			...policy,
			reads: void 0
		}, { service: service ?? "" });
	} catch (error) {
		if (error instanceof BindingInvalid) throw new Error(error.message);
		throw error;
	}
	return {
		...binding,
		policy
	};
}
/** The claims `--claim` adds, to narrow a binding. */
function claimsFrom(flags) {
	const claims = {};
	for (const pair of flags.claim ?? []) {
		const at = pair.indexOf("=");
		if (at <= 0) throw new Error(`--claim takes <name>=<value>, not "${pair}"`);
		claims[pair.slice(0, at)] = pair.slice(at + 1);
	}
	return claims;
}
const ROLE_ARN = /^arn:aws:iam::(\d{12}):role\/(?:[\w+=,.@-]+\/)*([\w+=,.@-]{1,64})$/;
const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
/** A Kubernetes service account's name, a DNS subdomain, as its tokens' `sub` names it. */
const DNS_SUBDOMAIN = /^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/;
/** A Google service account's email: none begins with `-`, which gcloud would read as a flag. */
const GOOGLE_ACCOUNT = /^[a-z0-9][a-z0-9-]*@[a-z0-9][a-z0-9.-]*\.gserviceaccount\.com$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A workload's binding, by its platform's flags: IDs given, or looked up with its CLI. */
async function platformBinding(platform, flags, lookup) {
	const extra = claimsFrom(flags);
	/** The platform's claims, and those `--claim` adds: never one the platform's flags set, which would be dropped. */
	const claimed = (own) => {
		const taken = Object.keys(extra).find((name) => Object.hasOwn(own, name));
		if (taken !== void 0) throw new Error(`--${platform} sets ${taken} from its own flags: --claim adds other claims`);
		return {
			...extra,
			...own
		};
	};
	const required = (flag, what) => {
		const value = flags[flag];
		if (typeof value !== "string" || value === "") throw new Error(`--${platform} names ${what}: --${flag} <${what.split(" ").at(-1)}>`);
		return value;
	};
	switch (platform) {
		case "aws": {
			if (Object.keys(extra).length > 0) throw new Error("an aws binding names the role alone: its proof carries no other claim");
			const arn = ROLE_ARN.exec(flags.aws);
			if (arn === null) throw new Error(`--aws takes a role's ARN, arn:aws:iam::<account>:role/<name>, not ${flags.aws}`);
			const [, account, name] = arn;
			let roleId = flags["role-id"];
			if (roleId === void 0) {
				const found = await lookup.awsRole(name);
				if (found.arn !== flags.aws) throw new Error(`aws iam get-role finds ${found.arn}, not ${flags.aws}: sign in to the role's account, or add --role-id <AROA…>`);
				roleId = found.roleId;
			}
			return {
				profile: "aws",
				issuer: null,
				claims: {
					account,
					role_id: roleId
				}
			};
		}
		case "kubernetes": {
			const [namespace, name, ...rest] = flags.kubernetes.split("/");
			if (!namespace || !name || rest.length > 0 || !DNS_LABEL.test(namespace) || !DNS_SUBDOMAIN.test(name)) throw new Error(`--kubernetes takes <namespace>/<service-account>, not ${flags.kubernetes}`);
			const issuer = flags.issuer ?? await lookup.kubernetesIssuer();
			const uid = flags.uid ?? await lookup.kubernetesUid(namespace, name);
			return {
				profile: "kubernetes",
				issuer,
				claims: claimed({
					sub: `system:serviceaccount:${namespace}:${name}`,
					"kubernetes.io.serviceaccount.uid": uid
				})
			};
		}
		case "gcp": {
			const account = flags.gcp;
			const sub = /^\d+$/.test(account) ? account : GOOGLE_ACCOUNT.test(account) ? await lookup.gcpUniqueId(account) : null;
			if (sub === null) throw new Error(`--gcp takes a service account's email or unique ID, not ${account}`);
			return {
				profile: "gcp",
				issuer: GOOGLE_ISSUER,
				claims: claimed({ sub })
			};
		}
		case "azure": {
			const tenant = required("tenant", "the managed identity's tenant ID");
			const object = required("object", "the managed identity's object ID");
			const audience = required("audience", "the application ID URI Entra mints its tokens for, the resource's audience");
			return {
				profile: "azure",
				issuer: flags.issuer ?? `https://sts.windows.net/${tenant}/`,
				claims: claimed({
					tid: tenant,
					oid: object
				}),
				policy: { audience }
			};
		}
		case "fly": {
			if (!DNS_LABEL.test(flags.fly)) throw new Error(`--fly takes the organization's slug, as its tokens' issuer names it, not ${flags.fly}`);
			const orgId = required("org-id", "the organization's ID");
			const appId = required("app-id", "the app's ID");
			return {
				profile: "fly",
				issuer: `https://oidc.fly.io/${flags.fly}`,
				claims: claimed({
					org_id: orgId,
					app_id: appId
				})
			};
		}
		case "vercel": {
			if (!DNS_LABEL.test(flags.vercel)) throw new Error(`--vercel takes the team's slug, as its tokens' issuer names it, not ${flags.vercel}`);
			const claims = claimed({
				owner_id: required("owner-id", "the team's ID, from .vercel/project.json's orgId"),
				project_id: required("project-id", "the project's ID, from .vercel/project.json's projectId"),
				environment: flags["vercel-environment"] ?? "production"
			});
			return {
				profile: "vercel",
				issuer: flags.issuer ?? `https://oidc.vercel.com/${flags.vercel}`,
				claims
			};
		}
		case "enrollment":
		case "cloudflare":
			if (Object.keys(extra).length > 0) throw new Error(`a ${platform} binding names no claims: its proof carries none`);
			return {
				profile: platform,
				issuer: null,
				claims: {}
			};
	}
}
/** The platforms' CLIs, as the person running `coffre trust` is signed in to them. */
function platformLookup() {
	return {
		async awsRole(name) {
			const instead = "add --role-id <AROA…>";
			const [roleId, arn] = parsed(await run$1("aws", [
				"iam",
				"get-role",
				`--role-name=${name}`,
				"--query",
				"Role.[RoleId,Arn]",
				"--output",
				"json"
			], instead), "aws iam get-role", instead);
			if (typeof roleId !== "string" || !/^AROA[A-Z0-9]+$/.test(roleId) || typeof arn !== "string") throw new Error(`aws iam get-role answered no role ID and ARN; ${instead}`);
			return {
				roleId,
				arn
			};
		},
		async kubernetesIssuer() {
			const instead = "add --issuer, the cluster's service account issuer";
			const { issuer } = parsed(await run$1("kubectl", [
				"get",
				"--raw",
				"/.well-known/openid-configuration"
			], instead), "kubectl get --raw", instead) ?? {};
			if (typeof issuer !== "string" || issuer === "") throw new Error(`the cluster's discovery names no issuer; ${instead}`);
			return issuer;
		},
		async kubernetesUid(namespace, name) {
			const instead = "add --uid <uid>";
			const uid = (await run$1("kubectl", [
				"get",
				"serviceaccount",
				name,
				"--namespace",
				namespace,
				"--output",
				"jsonpath={.metadata.uid}"
			], instead)).trim();
			if (!UUID.test(uid)) throw new Error(`kubectl answered no service account UID; ${instead}`);
			return uid;
		},
		async gcpUniqueId(email) {
			const instead = "name it by its unique ID: --gcp <digits>";
			const id = (await run$1("gcloud", [
				"iam",
				"service-accounts",
				"describe",
				email,
				"--format=value(uniqueId)"
			], instead)).trim();
			if (!/^\d+$/.test(id)) throw new Error(`gcloud answered no unique ID; ${instead}`);
			return id;
		}
	};
}
/** A platform CLI's JSON, or a sentence saying what to add instead. */
function parsed(out, what, instead) {
	try {
		return JSON.parse(out);
	} catch {
		throw new Error(`${what} answered what is not JSON; ${instead}`);
	}
}
/** A platform CLI's output, or a sentence saying what to add instead. */
function run$1(command, args, instead) {
	return new Promise((resolve, reject) => {
		execFile(command, args, {
			encoding: "utf8",
			timeout: 3e4,
			maxBuffer: 1048576
		}, (error, stdout, stderr) => {
			if (error === null) {
				resolve(stdout);
				return;
			}
			const what = `${command} ${args.slice(0, 2).join(" ")}`;
			const why = error.code === "ENOENT" ? `${command} is not installed here` : error.killed ? `${what} did not answer within 30 s` : `${what} failed${stderr.trim() === "" ? "" : `: ${stderr.trim().split("\n")[0].slice(0, 200)}`}`;
			reject(/* @__PURE__ */ new Error(`${why}; ${instead}`));
		});
	});
}
function refFrom(flags, form) {
	if (flags.branch === void 0 === (flags.tag === void 0)) throw new Error("name one of --branch or --tag");
	const type = flags.branch !== void 0 ? "branch" : "tag";
	const name = flags.branch ?? flags.tag;
	return {
		ref: form === "name" ? name : fullRef(type, name),
		type
	};
}
async function github$1(flags, events, lookup) {
	const { ref } = refFrom(flags, "full");
	const environment = flags["github-environment"];
	/** IDs given, or looked up: then the name as GitHub spells it, as its tokens do. */
	const found = async (name, ids, flagsToAdd) => {
		try {
			const answer = await lookup({ github: name });
			if (!("github" in answer)) throw new Error("not a GitHub repository or owner");
			return answer;
		} catch (error) {
			if (!(error instanceof CoffreError && error.status === 404)) throw error;
			throw new Error(`GitHub shows coffre nothing of ${name}: it is private, or not there. Get its IDs with\n  gh api ${name.includes("/") ? "repos" : "users"}/${name} --jq '${ids}'\nand add ${flagsToAdd}, to this coffre trust.`);
		}
	};
	const repository = async () => {
		if (flags["repository-id"] !== void 0 && flags["owner-id"] !== void 0) return {
			github: flags.github,
			repositoryId: flags["repository-id"],
			ownerId: flags["owner-id"]
		};
		const answer = await found(flags.github, "\"--repository-id \\(.id) --owner-id \\(.owner.id)\"", "the two flags it prints, --repository-id <n> --owner-id <n>");
		if (!("repositoryId" in answer)) throw new Error(`--github takes <owner>/<repo>, not ${flags.github}`);
		return answer;
	};
	if (flags.reusable !== void 0) {
		if (flags.sha === void 0) throw new Error("a reusable workflow is trusted at one commit: --sha <commit>");
		const called = {
			ref,
			events,
			called: flags.reusable,
			sha: flags.sha,
			environment
		};
		if (flags["any-repository"] === true) {
			const owner = flags.github.split("/")[0];
			const ownerId = flags["owner-id"] ?? (await found(owner, "\"--owner-id \\(.id)\"", "the flag it prints, --owner-id <n>")).ownerId;
			const caller = flags.workflow === void 0 ? void 0 : {
				repository: flags.github,
				workflow: flags.workflow
			};
			return {
				...githubReusable({
					...called,
					caller,
					repositoryId: null,
					ownerId
				}),
				issuer: null
			};
		}
		const { github: name, repositoryId, ownerId } = await repository();
		const caller = flags.workflow === void 0 ? void 0 : {
			repository: name,
			workflow: flags.workflow
		};
		return {
			...githubReusable({
				...called,
				caller,
				repositoryId,
				ownerId
			}),
			issuer: null
		};
	}
	if (flags.workflow === void 0) throw new Error("name the workflow file: --workflow deploy.yml");
	const { github: name, repositoryId, ownerId } = await repository();
	return {
		...githubWorkflow({
			repository: name,
			repositoryId,
			ownerId,
			workflow: flags.workflow,
			ref,
			events,
			environment
		}),
		issuer: null
	};
}
async function gitlab(flags, sources, lookup) {
	const project = flags.gitlab;
	const { ref, type } = refFrom(flags, "name");
	let ids;
	if (flags["project-id"] !== void 0 && flags["namespace-id"] !== void 0) ids = {
		projectId: flags["project-id"],
		namespaceId: flags["namespace-id"]
	};
	else {
		let found;
		try {
			found = await lookup({
				gitlab: project,
				gitlabUrl: flags["gitlab-url"]
			});
		} catch (error) {
			if (!(error instanceof CoffreError && error.status === 404)) throw error;
			const host = flags["gitlab-url"] === void 0 ? "" : ` --hostname ${new URL(flags["gitlab-url"]).host}`;
			throw new Error(`GitLab shows coffre nothing of ${project}: it is private, or not there. Get its IDs with\n  glab api${host} projects/${encodeURIComponent(project)} | jq -r '"--project-id \\(.id) --namespace-id \\(.namespace.id)"'\nand add the two flags it prints, --project-id <n> --namespace-id <n>, to this coffre trust.`);
		}
		if (!("projectId" in found)) throw new Error("not a GitLab project");
		ids = found;
	}
	return {
		...gitlabProject({
			namespaceId: ids.namespaceId,
			projectId: ids.projectId,
			refType: type,
			ref,
			sources
		}),
		issuer: flags["gitlab-url"] ?? null
	};
}
function custom(flags) {
	return {
		profile: "custom",
		issuer: flags.issuer,
		claims: claimsFrom(flags)
	};
}
/**
* The JWKS `--jwks-file` holds, as the API takes it; the server checks each
* key. Throws a sentence.
*/
function keySetFrom(text, path) {
	let value;
	try {
		value = JSON.parse(text);
	} catch {
		throw new Error(`${path} is not JSON: --jwks-file takes the issuer's key set, { "keys": [ … ] }`);
	}
	const keys = value?.keys;
	if (!Array.isArray(keys)) throw new Error(`${path} is no key set: --jwks-file takes { "keys": [ … ] }, as kubectl get --raw /openid/v1/jwks prints it`);
	return { keys };
}
/** Where a binding's keys come from: the URL coffre fetches them from, or those uploaded with it, by `kid` (or thumbprint) and algorithm. */
function keysLine(binding) {
	if (binding.keys == null) return binding.jwksUri;
	return `uploaded: ${binding.keys.map((key) => `${key.kid ?? `thumbprint ${key.thumbprint}`} (${key.alg})`).join(", ")}`;
}
/** A binding, or a plan for one, as lines: what it trusts, every claim in full, and a workload's policy. */
function describeBinding(binding) {
	const width = Math.max(0, ...Object.keys(binding.claims).map((name) => name.length));
	const claims = Object.entries(binding.claims).map(([name, value], i) => `  ${i === 0 ? "claims " : "       "}  ${name.padEnd(width)}  ${claimValues(value).join(", ")}`);
	const signer = Object.values(PROFILE_URNS).includes(binding.issuer) ? [] : [`  issuer   ${binding.issuer}`, `  keys     ${keysLine(binding)}`];
	return [
		`  profile  ${binding.profile}`,
		...signer,
		...claims,
		`  reaches  ${reaches(binding.scope)}`,
		...policyLines(binding.profile, binding.policy ?? null)
	];
}
/**
* A workload binding's policy, a line for each thing it says, and what
* each costs: a key listed in `reads` is a value its platform then holds.
*/
function policyLines(profile, policy) {
	if (policy === null) return [];
	const uploads = policy.unsignedUploads === true ? "; streamed uploads no digest binds go through" : "";
	const sessions = profile === "enrollment" ? `  sessions key-bound, each renewed every 30 s and ended at its code's expiry, ${policy.sessionDays ?? 30} days after minting${uploads}` : profile === "cloudflare" ? null : `  sessions key-bound, at most ${policy.sessionHours ?? 24} h from each proof${uploads}`;
	const lines = sessions === null ? [] : [sessions];
	if (policy.audience !== void 0) lines.push(`  audience ${policy.audience}`);
	else if (policy.keyAudience === true || KEY_NAMING_PROFILES.includes(profile)) lines.push("  audience names the session's key: <publicUrl>#jkt=<thumbprint>");
	const reads = Object.entries(policy.reads ?? {});
	if (reads.length === 0) lines.push("  reads    nothing: every secret value is used through coffre, never read");
	for (const [i, [place, keys]] of reads.entries()) lines.push(`  ${i === 0 ? "reads   " : "        "} ${place}: ${keys === "*" ? "every key, those made later included" : keys.join(", ")}, exposed if ${profile} is breached`);
	if (policy.sources !== void 0) lines.push(`  from     ${policy.sources.join(", ")}`);
	if (profile === "enrollment") {
		const minted = policy.mintedBy === void 0 ? "its managers" : `its managers and ${shownMember$1(policy.mintedBy)}`;
		lines.push(`  codes    minted by ${minted}, ${policy.sessionDays ?? 30} days each; up to ${2 * (policy.replicas ?? 1)} sessions of ${policy.replicas} replica${policy.replicas === 1 ? "" : "s"}`);
		lines.push(`           ${policy.onContention === "alert" ? "alerts" : "freezes"} when a copy contends past ${policy.overlapMinutes ?? 15} minutes of overlap${policy.approve === true ? "; each session waits for approval" : ""}`);
	}
	return lines;
}
/**
* What `coffre trust --replace-keys` would do, or did: the keys, and each
* binding on the issuer a new one replaces, as the server planned it or, once
* saved, as it answered, whatever changed between the two.
*/
function describeKeys(member, plan, saved) {
	const replaced = saved?.replaced ?? plan.replaces;
	const count = replaced.length === 1 ? "binding" : `${replaced.length} bindings`;
	return `${[
		saved === null ? `Would give ${shownMember$1(member)}'s ${count} on ${plan.issuer} these keys, each replaced by a binding the same but for them:` : `Gave ${shownMember$1(member)}'s ${count} on ${plan.issuer} these keys:`,
		`  keys     ${keysLine(plan)}`,
		...replaced.map((id, i) => saved === null ? `  replaces ${id}` : `  ${saved.bindings[i].id} replaces ${id}`),
		...[withheldLine(plan.withheld)].flatMap((unread) => unread === null ? [] : [`  ${unread}`]),
		saved === null ? "Credentials those bindings issued, five minutes each at most, would end at once." : "Credentials the bindings replaced issued have ended."
	].join("\n")}\n`;
}
function describePlan(member, plan, applied) {
	const [who, how] = plan.policy == null ? ["CI runs", "by OIDC"] : [runsOf(plan), "for key-bound sessions"];
	const lines = [applied === null ? `Would trust ${who} to sign in as ${shownMember$1(member)}, ${how}:` : `Trusted ${who} to sign in as ${shownMember$1(member)}, ${how}, binding ${applied.id}:`];
	lines.push(...describeBinding(plan));
	for (const replaced of plan.replaces) lines.push(`  replaces ${replaced.id}${replaced.why === "keys_moved" ? ": the issuer moved its keys" : ""}`);
	const unread = withheldLine(plan.withheld);
	if (unread !== null) lines.push(`  ${unread}`);
	return `${lines.join("\n")}\n`;
}
/**
* What a service's new token or binding will not read, as the server said
* (`withheld`): the sensitive values of these places, which only one an
* Owner of their project issues reads. Null when there are none.
*/
function withheldLine(withheld) {
	if (withheld === void 0 || withheld.length === 0) return null;
	return `reads no sensitive value of ${withheld.join(", ")}: only one an Owner of ${withheld.length === 1 ? "its project" : "their projects"} issues does`;
}
/** `refs/heads/main` as `branch main`, `refs/tags/v1` as `tag v1`; anything else as it is. */
function refName(ref) {
	const [, kind, name] = /^refs\/(heads|tags)\/(.+)$/.exec(ref) ?? [];
	return kind === void 0 ? ref : `${kind === "heads" ? "branch" : "tag"} ${name}`;
}
/**
* The CI runs a binding lets sign in, in a sentence, from its claims: the
* platform, the repository or project, the workflow, the ref. Bindings keep
* IDs where a name could change hands; a name is shown where a claim has one.
*/
function runsOf(binding) {
	const claims = binding.claims;
	const on = (ref, how) => {
		const into = claimValues(how).includes("pull_request") ? " or a pull request into it" : "";
		return [
			ref === void 0 ? null : `on ${refName(ref)}${into}`,
			how === void 0 ? null : `by ${listing(claimValues(how), "or")}`,
			claims.environment === void 0 || binding.profile === "custom" ? null : `in environment ${claims.environment}`
		].filter(Boolean).join(", ");
	};
	/** `acme/api/.github/workflows/deploy.yml@refs/heads/main` as its repository and workflow file. */
	const workflow = (ref) => /^([^/]+\/[^/]+)\/(?:\.github\/workflows\/)?(.+)@/.exec(ref);
	switch (binding.profile) {
		case "github": {
			const [, repository, file] = workflow(claims.workflow_ref ?? "") ?? [];
			return `GitHub Actions runs of ${repository ?? `repository ${claims.repository_id}`}'s workflow ${file ?? "(any)"}, ${on(claims.ref, binding.claims.event_name)}`;
		}
		case "github-reusable":
		case "github-reusable-organization": {
			const [, repository, file] = workflow(claims.workflow_ref ?? "") ?? [];
			const callers = binding.profile === "github-reusable-organization" ? `any repository of owner ${claims.repository_owner_id}` : repository === void 0 ? `repository ${claims.repository_id}` : `${repository}'s workflow ${file}`;
			const sha = claims.job_workflow_sha === void 0 ? "" : ` at commit ${claims.job_workflow_sha.slice(0, 12)}`;
			return `GitHub Actions runs of ${callers} that call the reusable workflow ${claims.job_workflow_ref}${sha}, ${on(claims.ref, binding.claims.event_name)}`;
		}
		case "gitlab": {
			const ref = claims.ref === void 0 ? void 0 : `${claims.ref_type === "tag" ? "refs/tags" : "refs/heads"}/${claims.ref}`;
			const where = binding.issuer === "https://gitlab.com" ? "" : ` on ${binding.issuer}`;
			return `GitLab pipelines of project ${claims.project_id} (namespace ${claims.namespace_id})${where}, ${on(ref, binding.claims.pipeline_source)}`;
		}
		case "custom": return `runs whose ID token, from ${binding.issuer}, says ${Object.entries(claims).map(([name, value]) => `${name}=${value}`).join(", ")}`;
		case "aws": return `AWS workloads running as role ${claims.role_id} of account ${claims.account}`;
		case "kubernetes": {
			const [, namespace, name] = /^system:serviceaccount:([^:]+):(.+)$/.exec(claims.sub ?? "") ?? [];
			return `pods of service account ${namespace}/${name} (UID ${claims["kubernetes.io.serviceaccount.uid"]}) of the cluster ${binding.issuer}`;
		}
		case "gcp": return `Google Cloud workloads running as service account ${claims.sub}`;
		case "azure": return `Azure workloads of managed identity ${claims.oid} in tenant ${claims.tid}`;
		case "fly": return `Fly Machines of app ${claims.app_id} in organization ${claims.org_id}`;
		case "vercel": return `Vercel functions of project ${claims.project_id} of team ${claims.owner_id}, in ${claims.environment}`;
		case "enrollment": return "workloads enrolled with a code minted for this binding";
		case "cloudflare": return "Workers that call it through a service binding's props";
		default: {
			const says = Object.entries(claims).map(([name, value]) => `${name}=${value}`).join(", ");
			return `${binding.profile} workloads${says === "" ? "" : ` whose proof says ${says}`}`;
		}
	}
}
/** What `coffre untrust` shows: the binding, the runs it would cut off, and, unless done, how to do it. */
function describeRemoval(service, binding, removed) {
	const member = shownMember$1(service);
	const used = binding.lastUsedAt === null ? "never used" : `last used ${binding.lastUsedAt.slice(0, 16).replace("T", " ")}`;
	const head = `${binding.id}${binding.label === null ? "" : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`;
	const runs = runsOf(binding);
	return [
		removed ? `Removed ${member}'s trust binding ${head}` : `Would remove ${member}'s trust binding ${head}`,
		...describeBinding(binding),
		removed ? `${runs.charAt(0).toUpperCase()}${runs.slice(1)} can no longer sign in as ${member}, and the credentials they hold have ended.` : `${runs.charAt(0).toUpperCase()}${runs.slice(1)} would no longer sign in as ${member}, and the credentials they hold would end at once.\nNothing changed. Re-run with --apply to remove it.`
	].join("\n") + "\n";
}
function describeBindings(member, bindings) {
	if (bindings.length === 0) return `${shownMember$1(member)} trusts no CI runs or workloads: none signs in as it by OIDC or a platform's proof\n`;
	return `${bindings.map((binding) => {
		const used = binding.lastUsedAt === null ? "never used" : `last used ${binding.lastUsedAt.slice(0, 16).replace("T", " ")}`;
		return [`${binding.id}${binding.label === null ? "" : `  ${binding.label}`}  (added by ${binding.createdBy} ${binding.createdAt.slice(0, 10)}, ${used})`, ...describeBinding(binding)].join("\n");
	}).join("\n\n")}\n`;
}
//#endregion
//#region ../client/dist/dpop.js
/**
* The signing half of a workload's proofs (docs/design/workload-access.md,
* section 5.1): DPoP (RFC 9449) with two claims of coffre's own, `hdr` and
* `req`, which sign the request's headers, query and body as well as its
* method and URL. The SDK and the server run this one canonicalization, so
* what a workload signs is exactly what coffre recomputes and forwards;
* the server's verifier is `verifyProof` in `@coffre/core/identity`.
*
* WebCrypto only, and no dependency, like the rest of the client.
*
* A proof is a compact JWS:
*
*   { "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
*   { "jti": "pA6p8w2Yb3fQe1kHn0S9qg", "htm": "POST", "htu": "https://secrets.acme.example/use/stripe/v1/charges",
*     "iat": 1792805400, "ath": "fUHy…", "nonce": "g1.7Hq2…",
*     "hdr": "content-type idempotency-key", "req": "kq9V…" }
*/
/** The longest proof, in characters, which the verifier refuses past and the signer never makes. */
const MAX_PROOF_LENGTH = 2048;
/**
* Headers a proof never signs, so neither forwards: those the transport
* owns and an intermediary may rewrite, the credentials of the request to
* coffre itself, and cookies. Coffre sets the transport's own on the way out.
*/
const UNSIGNED_HEADERS = /* @__PURE__ */ new Set([
	"accept-encoding",
	"authorization",
	"connection",
	"content-length",
	"cookie",
	"dpop",
	"host",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade"
]);
const ENCODER$1 = new TextEncoder();
/** Bytes as base64url, without padding. */
function base64url(bytes) {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sha256(data) {
	const bytes = typeof data === "string" ? ENCODER$1.encode(data) : data;
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
function hex$1(bytes) {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
/** The key's RFC 7638 thumbprint, `jkt`: base64url SHA-256 of its required members in this order, 43 characters. */
async function thumbprint(jwk) {
	return base64url(await sha256(JSON.stringify({
		crv: jwk.crv,
		kty: jwk.kty,
		x: jwk.x,
		y: jwk.y
	})));
}
/** A new key for a process: P-256, its private half never exportable, never written anywhere. */
async function generateProofKey() {
	const pair = await crypto.subtle.generateKey({
		name: "ECDSA",
		namedCurve: "P-256"
	}, false, ["sign", "verify"]);
	const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
	return {
		privateKey: pair.privateKey,
		jwk: {
			kty,
			crv,
			x,
			y
		}
	};
}
/** A method, as RFC 9110 writes one: a token, of any length the proof's own limit leaves. */
const METHOD_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** RFC 3986's unreserved characters, which an escape never needs. */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
/**
* A URL as `htu` names it: scheme and host lowercased, no default port, no
* user, query or fragment, and its path as Cloudflare's zones normalize an
* incoming one by default, in their order: an escaped unreserved character
* decoded and every other escape's hex in upper case (RFC 3986, section
* 6.2.2), `\` made `/`, runs of `/` merged, then dot segments removed.
* Both sides sign this form, so a zone's normalization changes nothing, and
* a mismatch fails closed. Idempotent. Throws on a URL that is not http or
* https, and on a `%` that two hex digits do not follow, which would let
* two paths read as one.
*
*   canonicalHtu('HTTPS://Secrets.Acme.Example:443//use/%7estripe/a%2fb?x=1')
*     === 'https://secrets.acme.example/use/~stripe/a%2Fb'
*   canonicalHtu('https://secrets.acme.example/hello//../path')
*     === 'https://secrets.acme.example/path'
*/
function canonicalHtu(input) {
	const url = new URL(String(input));
	if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError(`a proof signs an http or https URL, not ${url.protocol}`);
	const raw = typeof input === "string" ? /^[^:/\\?#]+:[/\\]{2,}[^/\\?#]*([^?#]*)/.exec(input)?.[1] ?? url.pathname : url.pathname;
	if (/%(?![0-9A-Fa-f]{2})/.test(raw)) throw new TypeError("a URL a proof signs escapes a character with % and two hex digits, never a lone %");
	const merged = raw.replace(/%([0-9A-Fa-f]{2})/g, (_, code) => {
		const char = String.fromCharCode(parseInt(code, 16));
		return UNRESERVED.test(char) ? char : `%${code.toUpperCase()}`;
	}).replace(/\\/g, "/").replace(/\/{2,}/g, "/");
	return `${url.protocol}//${url.host}${new URL(withoutDotSegments(merged.startsWith("/") ? merged : `/${merged}`), url.origin).pathname}`;
}
/** RFC 3986's `remove_dot_segments` (section 5.2.4), on an absolute path. */
function withoutDotSegments(path) {
	const kept = [];
	const parts = path.split("/").slice(1);
	parts.forEach((part, i) => {
		if (part !== "." && part !== "..") kept.push(part);
		else {
			if (part === "..") kept.pop();
			if (i === parts.length - 1) kept.push("");
		}
	});
	return `/${kept.join("/")}`;
}
/**
* A method as `htm` names it, and the Fetch API sends it: one of DELETE,
* GET, HEAD, OPTIONS, POST and PUT in upper case, whatever case it was
* given in, and any other exactly as given. Methods are case-sensitive
* (RFC 9110, section 9.1), so `patch` is not `PATCH`, and a proof signs one.
*/
function fetchMethod(method) {
	if (!METHOD_TOKEN.test(method)) throw new TypeError(`${JSON.stringify(method)} is no HTTP method: a method is a token (RFC 9110, section 9.1)`);
	const upper = method.toUpperCase();
	return [
		"DELETE",
		"GET",
		"HEAD",
		"OPTIONS",
		"POST",
		"PUT"
	].includes(upper) ? upper : method;
}
/** The SHA-256 of a buffered body, in hex, as a canonical request's last line holds it. */
async function bodyDigest(body) {
	return hex$1(await sha256(body));
}
/**
* The most a body that declares its digest carries (`Content-Digest`),
* which coffre streams and `coffre serve` holds while it hashes it: 95 MiB,
* 99,614,720 bytes, under the 100 MB (decimal) Cloudflare takes in a
* request on Free and Pro zones, so a body near it gets coffre's answer and
* not the zone's.
*/
const MAX_DIGESTED_BODY = 99614720;
/** A body's `Content-Digest` (RFC 9530) from its SHA-256 in hex, as the SDK and `coffre serve` send it: `sha-256=:<base64>:`. */
function contentDigest(sha256) {
	if (!SHA256_HEX.test(sha256)) throw new TypeError("a Content-Digest is made from a SHA-256 in hex");
	return `sha-256=:${btoa(String.fromCharCode(...sha256.match(/../g).map((pair) => parseInt(pair, 16))))}:`;
}
/**
* The SHA-256 a `Content-Digest` declares, in hex, as a body's line takes
* it: its `sha-256` member's, among any others (RFC 9530 lets one header
* name several algorithms). Null for one with no `sha-256` member, an app's
* own `sha-512` say, which declares nothing to coffre. Throws on a
* `sha-256` member that is no SHA-256 (32 bytes, as base64 between colons),
* or one named twice: such a header binds no body, and stands for none.
*
*   declaredDigest('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:')   'e3b0c442…7852b855'
*   declaredDigest('sha-512=:z4PhNX7v…:')                                     null
*/
function declaredDigest(header) {
	const members = header.split(",").map((member) => member.trim()).filter((member) => /^sha-256(?:[=;]|$)/.test(member));
	if (members.length === 0) return null;
	const base64 = members.length === 1 ? /^sha-256=:([A-Za-z0-9+/]{43}=):$/.exec(members[0])?.[1] : void 0;
	const bytes = base64 === void 0 ? null : Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
	if (bytes === null || btoa(String.fromCharCode(...bytes)) !== base64) throw new TypeError("Content-Digest declares a body's SHA-256 once, as sha-256=:<44 characters of base64>:");
	return hex$1(bytes);
}
/** `ath`: base64url SHA-256 of the session token the proof is sent with. */
async function tokenDigest(token) {
	return base64url(await sha256(token));
}
/**
* A canonical request's last line for a body no digest binds: a streamed
* upload whose SigV4 `x-amz-content-sha256` is `UNSIGNED-PAYLOAD` or
* `STREAMING-…`. Coffre takes it only through a credential that says
* `unsignedUploads`, whose page notes what that leaves open.
*/
const UNSIGNED_BODY = "UNSIGNED-PAYLOAD";
const SHA256_HEX = /^[0-9a-f]{64}$/;
/**
* A body's line in `req` (section 5.1), one rule for the SDK and coffre,
* each from what it knows of the body:
*
* - `declared`: its `x-amz-content-sha256`, given only through a credential
*   `sigv4` signs; else the SHA-256 its `Content-Digest` declares
*   (`declaredDigest`); null when it sets neither.
* - `length`: its bytes as known: those read, a stream's `content-length`,
*   or null for a stream of no stated length.
*
* A body of no bytes signs the empty body's digest, whatever it declares.
* One that declares a hash signs it, which S3, or coffre for a
* `Content-Digest`, checks against the bytes, so it may stream: 64
* lower-case hex digits, or `UNSIGNED_BODY` for any other value, which only
* an `x-amz-content-sha256` can be. Every other body signs its bytes'
* digest (`bytes`, none for none).
*
*   bodyLine({ declared: null, length: 6, bytes })                       bodyDigest(bytes)
*   bodyLine({ declared: 'UNSIGNED-PAYLOAD', length: 0 })                bodyDigest('')
*   bodyLine({ declared: 'UNSIGNED-PAYLOAD', length: null })             UNSIGNED_BODY
*   bodyLine({ declared: '9f86…0f00a08', length: 4 })                     '9f86…0f00a08'
*/
async function bodyLine(body) {
	if (body.declared !== null && body.length !== 0) return SHA256_HEX.test(body.declared) ? body.declared : UNSIGNED_BODY;
	return bodyDigest(body.bytes ?? /* @__PURE__ */ new Uint8Array());
}
/**
* What `req` signs, one line each:
*
*   <the path as sent, as the WHATWG parser writes it: every slash and escape kept>
*   <the raw query string as sent, without "?", or empty>
*   <name>:<value>    for each header `hdr` names, in its order, its value as received
*   <the body's SHA-256, in lower-case hex>
*
* `htu` signs the path as a zone normalizes it, so a proof still holds
* behind one; this line signs it as it goes upstream, so `/use/s3/a/b` and
* `/use/s3/a//b`, one object and another to S3, are two requests. A path a
* zone changed fails closed. The body's line is its buffered bytes' digest
* (`bodyDigest`), or, for a body that declares one (`bodyLine`), the 64 hex
* digits its `Content-Digest` declares, which coffre checks against the
* bytes as they stream, or, through a credential `sigv4` signs, those its
* `x-amz-content-sha256` declares, which S3 checks; any other value of the
* latter is `UNSIGNED_BODY`. A
* header sent several times is one value, joined by `, `, as `Headers`
* gives it. No line holds a line break, so no two requests read as one;
* throws on one that does, or on a body line that is neither.
*/
function canonicalRequest(request) {
	const lines = [
		request.path,
		request.query,
		...request.headers.map(([name, value]) => `${name}:${value}`)
	];
	if (lines.some((line) => /[\r\n]/.test(line))) throw new TypeError("a signed request holds no line break in its path, query or headers");
	if (!SHA256_HEX.test(request.body) && request.body !== "UNSIGNED-PAYLOAD") throw new TypeError("a signed request's body is a SHA-256 in hex, or UNSIGNED_BODY");
	return `${lines.map((line) => `${line}\n`).join("")}${request.body}`;
}
/** The path and the query a URL sends, as `canonicalRequest` signs them. */
function sentTarget(url) {
	const parsed = new URL(String(url));
	return {
		path: parsed.pathname,
		query: parsed.search.slice(1)
	};
}
/** `req`: base64url SHA-256 of the canonical request. */
async function requestDigest(request) {
	return base64url(await sha256(canonicalRequest(request)));
}
/** The headers a proof signs from what the app set: every one but `UNSIGNED_HEADERS`, lowercased, in `Headers`' order. */
function signedHeaders(headers) {
	return [...new Headers(headers)].filter(([name]) => !UNSIGNED_HEADERS.has(name));
}
/**
* A proof for one request, signed by `key`.
*
* - `token` adds `ath`, for a request made with a session; the exchange has none.
* - `nonce` is the gate's newest, from the last answer's `DPoP-Nonce`.
* - `content` adds `hdr` and `req`: the headers the app set, and the body's
*   line (`bodyLine`: its bytes' digest, the one it declares, or
*   `UNSIGNED_BODY`).
*   Whatever it names is all coffre forwards.
*/
async function createProof(key, request) {
	const header = {
		typ: "dpop+jwt",
		alg: "ES256",
		jwk: {
			kty: key.jwk.kty,
			crv: key.jwk.crv,
			x: key.jwk.x,
			y: key.jwk.y
		}
	};
	const claims = {
		jti: request.jti ?? base64url(crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(16))),
		htm: fetchMethod(request.method),
		htu: canonicalHtu(request.url),
		iat: request.iat ?? Math.floor(Date.now() / 1e3)
	};
	if (request.token !== void 0) claims.ath = await tokenDigest(request.token);
	if (request.nonce !== void 0) claims.nonce = request.nonce;
	if (request.content !== void 0) {
		const headers = signedHeaders(request.content.headers);
		if (headers.length > 32) throw new TypeError(`a proof signs at most 32 headers: this request sets ${headers.length}`);
		claims.hdr = headers.map(([name]) => name).join(" ");
		claims.req = await requestDigest({
			...sentTarget(request.url),
			headers,
			body: request.content.body
		});
	}
	const input = `${base64url(ENCODER$1.encode(JSON.stringify(header)))}.${base64url(ENCODER$1.encode(JSON.stringify(claims)))}`;
	if (input.length + 87 > 2048) throw new TypeError(`a proof is at most ${MAX_PROOF_LENGTH} characters: this request's URL or headers are too long to sign`);
	const signature = await crypto.subtle.sign({
		name: "ECDSA",
		hash: "SHA-256"
	}, key.privateKey, ENCODER$1.encode(input));
	return `${input}.${base64url(new Uint8Array(signature))}`;
}
//#endregion
//#region ../client/dist/workload-BvUQrGIB.js
/** `<audience>#jkt=<thumbprint>`: an audience only this key can use (section 4.2). */
function keyAudience(context) {
	return `${context.audience}#jkt=${context.jkt}`;
}
const env = () => globalThis.process?.env ?? {};
async function json$1(response, what) {
	const body = await response.json().catch(() => null);
	if (!response.ok || body === null || typeof body !== "object") throw new Error(`${what} answered ${response.status}`);
	return body;
}
/** The token a platform answered, or why not. */
function tokenOf(body, field, what) {
	const token = body[field];
	if (typeof token !== "string" || token === "") throw new Error(`${what} gave no token`);
	return token;
}
/** The default projected token's path, as docs/workloads.md mounts it. */
const KUBERNETES_TOKEN = "/var/run/secrets/coffre/token";
/**
* A Kubernetes projected service account token, read from its file before
* each exchange: the pod spec's `serviceAccountToken` with coffre's URL as
* its `audience`. Such a token is spent once used, so a file still holding
* the token this process exchanged last is never sent again: the proof
* waits for the kubelet's next, which it writes at 80% of the token's life,
* watching the file for up to 10 minutes. That is the normal renewal in a
* long-running pod (the session re-proves at 90% of its life, and the
* kubelet's next volume sync can land after that), and so is the other
* case: a restarted process finds the token an earlier one used, which the
* exchange says (`replayed`), and `spent()` waits the same way.
*/
function kubernetes(path = KUBERNETES_TOKEN) {
	/** The token this process sent last. */
	let last = null;
	const read = async () => (await (await import("node:fs/promises")).readFile(path, "utf8")).trim();
	/** The file's next token once it differs from `last`, polled every second, or null after 10 minutes. */
	const next = async ({ log, signal }) => {
		log(`coffre: the token at ${path} is already used; waiting for the next one (up to 10 minutes)`);
		for (const end = Date.now() + 6e5; Date.now() < end;) {
			await sleep$1(1e3);
			signal?.throwIfAborted();
			const now = await read().catch(() => last);
			if (now !== last && now !== "") return now;
		}
		return null;
	};
	return {
		name: "kubernetes",
		kind: "oidc",
		prove: async (context) => {
			const token = await read().catch((error) => {
				throw new Error(`no projected service account token at ${path} (${error.code ?? error.message}): mount one whose audience is coffre's URL`);
			});
			const fresh = token === last || token === "" ? await next(context) : token;
			if (fresh === null) throw new Error(`the kubelet wrote no new token at ${path} in 10 minutes: check the projected volume and its expirationSeconds`);
			return { oidc: last = fresh };
		},
		spent: async (context) => await next(context) !== null
	};
}
/** A region as STS's regional hosts name one, in the commercial partition: the exchange takes no other. */
const REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
/**
* A `GetCallerIdentity` request, signed with the workload's own role
* credentials, for coffre to send STS (section 4.3). The credentials never
* leave: coffre gets the URL, the headers and the body, and the signature
* covers `x-coffre-key`, so the proof works with this session's key only.
*
* The credentials are the given ones, an AWS SDK provider's
* (`aws({ credentials: fromNodeProviderChain() })`), or else, in order, the
* environment's, the ECS container endpoint's, or EC2's instance metadata
* (IMDSv2). The region is `AWS_REGION`'s, for its regional STS host, unless
* given; without one, the global host.
*/
function aws(options = {}) {
	return {
		name: "aws",
		kind: "aws",
		prove: async (context) => {
			const given = options.credentials;
			const credentials = given === void 0 ? await awsCredentials(context.fetch) : typeof given === "function" ? await given() : given;
			const region = options.region ?? env().AWS_REGION ?? env().AWS_DEFAULT_REGION;
			if (region !== void 0 && (!REGION.test(region) || region.includes("-gov-"))) throw new Error(`aws(): ${region} is no commercial AWS region`);
			const url = region === void 0 ? "https://sts.amazonaws.com/" : `https://sts.${region}.amazonaws.com/`;
			const body = "Action=GetCallerIdentity&Version=2011-06-15";
			const headers = {
				"content-type": "application/x-www-form-urlencoded; charset=utf-8",
				host: new URL(url).host,
				"x-amz-date": amzDate(/* @__PURE__ */ new Date()),
				"x-coffre-audience": context.audience,
				"x-coffre-key": context.jkt
			};
			if (credentials.sessionToken) headers["x-amz-security-token"] = credentials.sessionToken;
			headers.authorization = await sigv4({
				method: "POST",
				url,
				headers,
				body,
				region: region ?? "us-east-1",
				service: "sts",
				credentials
			});
			return { aws: {
				url,
				headers,
				body
			} };
		}
	};
}
/** The environment's, the ECS container endpoint's, or IMDSv2's role credentials, as the AWS SDK's default chain finds them. */
async function awsCredentials(fetchImpl) {
	const vars = env();
	if (vars.AWS_ACCESS_KEY_ID && vars.AWS_SECRET_ACCESS_KEY) return {
		accessKeyId: vars.AWS_ACCESS_KEY_ID,
		secretAccessKey: vars.AWS_SECRET_ACCESS_KEY,
		sessionToken: vars.AWS_SESSION_TOKEN || void 0
	};
	const container = vars.AWS_CONTAINER_CREDENTIALS_FULL_URI ?? (vars.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ? `http://169.254.170.2${vars.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}` : void 0);
	if (container !== void 0) {
		const at = new URL(container);
		if (at.protocol !== "https:" && !/^(127(\.\d{1,3}){3}|localhost|\[::1\]|169\.254\.170\.(2|23)|\[fd00:ec2::23\])$/.test(at.hostname)) throw new Error(`aws(): AWS_CONTAINER_CREDENTIALS_FULL_URI names ${at.host}, which is neither https nor this machine nor the container agent's`);
		const file = vars.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE;
		const authorization = file ? (await (await import("node:fs/promises")).readFile(file, "utf8")).trim() : vars.AWS_CONTAINER_AUTHORIZATION_TOKEN;
		const body = await json$1(await fetchImpl(container, { headers: authorization ? { authorization } : {} }), "the ECS credentials endpoint");
		return {
			accessKeyId: tokenOf(body, "AccessKeyId", "ECS"),
			secretAccessKey: tokenOf(body, "SecretAccessKey", "ECS"),
			sessionToken: body.Token
		};
	}
	const imds = "http://169.254.169.254/latest";
	const session = await fetchImpl(`${imds}/api/token`, {
		method: "PUT",
		headers: { "x-aws-ec2-metadata-token-ttl-seconds": "300" },
		signal: AbortSignal.timeout(2e3)
	}).catch(() => null);
	if (session === null || !session.ok) throw new Error("aws(): no role credentials here: none in the environment, no ECS credentials endpoint, and no EC2 instance metadata");
	const headers = { "x-aws-ec2-metadata-token": await session.text() };
	const role = (await (await fetchImpl(`${imds}/meta-data/iam/security-credentials/`, { headers })).text()).trim().split("\n")[0];
	if (!role) throw new Error("aws(): this instance has no instance profile: give it a role");
	const body = await json$1(await fetchImpl(`${imds}/meta-data/iam/security-credentials/${role}`, { headers }), "EC2 instance metadata");
	return {
		accessKeyId: tokenOf(body, "AccessKeyId", "IMDS"),
		secretAccessKey: tokenOf(body, "SecretAccessKey", "IMDS"),
		sessionToken: body.Token
	};
}
/** `20261024T013000Z`, SigV4's time. */
function amzDate(date) {
	return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}
const ENCODER = new TextEncoder();
async function hmac(key, data) {
	const imported = await crypto.subtle.importKey("raw", key, {
		name: "HMAC",
		hash: "SHA-256"
	}, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", imported, ENCODER.encode(data)));
}
async function sha256Hex(data) {
	return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", ENCODER.encode(data))));
}
function hex(bytes) {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
/** RFC 3986's encoding, as SigV4 writes a query: everything but the unreserved characters escaped. */
const awsEncode = (text) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
/**
* The `authorization` header AWS Signature Version 4 gives a request, every
* header given signed (`host` and `x-amz-date` among them). Exported for its
* test, against AWS's own documented example.
*/
async function sigv4(request) {
	const url = new URL(request.url);
	const names = Object.keys(request.headers).map((name) => name.toLowerCase()).sort();
	const value = (name) => Object.entries(request.headers).find(([given]) => given.toLowerCase() === name)[1].trim().replace(/\s+/g, " ");
	const query = [...url.searchParams].map(([name, v]) => `${awsEncode(name)}=${awsEncode(v)}`).sort().join("&");
	const canonical = [
		request.method,
		url.pathname,
		query,
		...names.map((name) => `${name}:${value(name)}`),
		"",
		names.join(";"),
		await sha256Hex(request.body)
	].join("\n");
	const time = value("x-amz-date");
	const scope = `${time.slice(0, 8)}/${request.region}/${request.service}/aws4_request`;
	const toSign = [
		"AWS4-HMAC-SHA256",
		time,
		scope,
		await sha256Hex(canonical)
	].join("\n");
	let key = ENCODER.encode(`AWS4${request.credentials.secretAccessKey}`);
	for (const part of [
		time.slice(0, 8),
		request.region,
		request.service,
		"aws4_request"
	]) key = await hmac(key, part);
	return `AWS4-HMAC-SHA256 Credential=${request.credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(";")}, Signature=${hex(await hmac(key, toSign))}`;
}
/** Google Cloud's metadata server's ID token for the default service account, its audience naming the key: Cloud Run, GKE, GCE. */
function gcp() {
	return {
		name: "gcp",
		kind: "oidc",
		prove: async (context) => {
			const url = new URL("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity");
			url.searchParams.set("audience", keyAudience(context));
			url.searchParams.set("format", "full");
			const response = await context.fetch(url.href, { headers: { "metadata-flavor": "Google" } });
			if (!response.ok) throw new Error(`Google's metadata server gave no ID token (status ${response.status})`);
			return { oidc: (await response.text()).trim() };
		}
	};
}
/**
* An Azure managed identity's token for coffre's Entra application, its
* `audience` (`api://coffre-acme`): from App Service's and Functions'
* identity endpoint, or else IMDS. `clientId` picks a user-assigned
* identity. Entra mints only for a registered audience, so the token cannot
* name the key, and repeats until it expires (section 4.2).
*/
function azure(options) {
	return {
		name: "azure",
		kind: "oidc",
		prove: async ({ fetch: fetchImpl }) => {
			const vars = env();
			const service = vars.IDENTITY_ENDPOINT && vars.IDENTITY_HEADER;
			const url = new URL(service ? vars.IDENTITY_ENDPOINT : "http://169.254.169.254/metadata/identity/oauth2/token");
			url.searchParams.set("api-version", service ? "2019-08-01" : "2018-02-01");
			url.searchParams.set("resource", options.audience);
			if (options.clientId !== void 0) url.searchParams.set("client_id", options.clientId);
			const headers = service ? { "x-identity-header": vars.IDENTITY_HEADER } : { metadata: "true" };
			return { oidc: tokenOf(await json$1(await fetchImpl(url.href, { headers }), "Azure's identity endpoint"), "access_token", "Azure") };
		}
	};
}
/** A Fly Machine's OIDC token, from its `/.fly/api` socket, its audience naming the key. */
function fly(socketPath = "/.fly/api") {
	return {
		name: "fly",
		kind: "oidc",
		prove: async (context) => {
			const { request } = await import("node:http");
			const body = JSON.stringify({ aud: keyAudience(context) });
			return { oidc: await new Promise((resolve, reject) => {
				const asked = request({
					socketPath,
					path: "/v1/tokens/oidc",
					method: "POST",
					signal: context.signal,
					headers: {
						"content-type": "application/json",
						"content-length": ENCODER.encode(body).length
					}
				}, (answer) => {
					let text = "";
					answer.setEncoding("utf8");
					answer.on("data", (chunk) => text += chunk);
					answer.on("end", () => answer.statusCode === 200 ? resolve(text.trim()) : reject(/* @__PURE__ */ new Error(`Fly's API gave no OIDC token (status ${answer.statusCode})`)));
				});
				asked.on("error", (error) => reject(/* @__PURE__ */ new Error(`no Fly API at ${socketPath}: ${error.message}`)));
				asked.end(body);
			}) };
		}
	};
}
/**
* A Vercel function's OIDC token, exchanged at Vercel for one whose audience
* names the key, as `@vercel/oidc` does, asked afresh for each proof. The
* function's own token is the file `VERCEL_OIDC_TOKEN_FILE` names, or else
* `VERCEL_OIDC_TOKEN`, unless given: per request, from the
* `x-vercel-oidc-token` header, as `vercel(() => headers.get(…))`.
*/
function vercel(token) {
	return {
		name: "vercel",
		kind: "oidc",
		prove: async (context) => {
			const file = env().VERCEL_OIDC_TOKEN_FILE;
			const own = typeof token === "function" ? await token() : token ?? (file ? (await (await import("node:fs/promises")).readFile(file, "utf8")).trim() : env().VERCEL_OIDC_TOKEN);
			if (!own) throw new Error("vercel(): no OIDC token: turn on OIDC federation for the project, or pass the request's x-vercel-oidc-token");
			return { oidc: tokenOf(await json$1(await context.fetch("https://oidc.vercel.com/~token", {
				method: "POST",
				headers: {
					"content-type": "application/json",
					accept: "application/json"
				},
				body: JSON.stringify({
					token: own,
					aud: keyAudience(context)
				})
			}), "Vercel's token exchange"), "token", "Vercel") };
		}
	};
}
/** A GitHub Actions job's ID token, from its runner, its audience naming the key: the job needs `permissions: id-token: write`. */
function github() {
	return {
		name: "github",
		kind: "oidc",
		prove: async (context) => {
			const vars = env();
			const [url, bearer] = [vars.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), vars.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
			if (!url || !bearer) throw new Error("github(): this job has no ID token: give it `permissions: id-token: write`");
			const request = new URL(url);
			request.searchParams.set("audience", keyAudience(context));
			return { oidc: tokenOf(await json$1(await context.fetch(request.href, { headers: {
				authorization: `bearer ${bearer}`,
				accept: "application/json"
			} }), "GitHub's runner"), "value", "GitHub") };
		}
	};
}
/**
* Any other ID token, as given, or asked for at each exchange: GitLab's
* `id_tokens` entry, whose `aud` is coffre's URL, or a custom issuer's. A
* token is spent once used, so a given string proves one session.
*/
function oidc(token, name = "oidc") {
	return {
		name,
		kind: "oidc",
		prove: async () => ({ oidc: typeof token === "function" ? await token() : token })
	};
}
/**
* An enrollment code (section 4.4), on a platform that signs nothing:
* Railway, Render, a VM. Once given, the code leaves `process.env`, under
* whatever name held it, so the app's own dumps of its environment no
* longer show it; the platform's store still holds it.
*/
function enrollment(code) {
	if (code === void 0 || !code.startsWith("coffre_enr_")) throw new Error("enrollment(): no enrollment code: CI sets one each deploy, from `coffre enroll <service>`");
	const vars = globalThis.process?.env;
	for (const [name, value] of Object.entries(vars ?? {})) if (value === code) delete vars[name];
	return {
		name: "enrollment",
		kind: "enrollment",
		prove: async () => ({ enrollment: code })
	};
}
const sleep$1 = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/**
* A workload's session with coffre (docs/design/workload-access.md, section
* 9.1): it proves who it is once, gets a session bound to a key that never
* leaves this process, and from then on uses its credentials through coffre,
* every request signed. The app holds no secret that works anywhere else.
*
*   import { workload, enrollment } from '@coffre/client/workload';
*
*   const coffre = await workload({ url: 'https://secrets.acme.example', service: 'api-prod', proof: enrollment(process.env.COFFRE_ENROLL) });
*   const openai = new OpenAI({ apiKey: 'coffre', baseURL: coffre.url('openai'), fetch: coffre.fetch });
*   const charge = await coffre.credential('stripe').fetch('/v1/charges', { method: 'POST', body: new URLSearchParams({ amount: '2000' }) });
*
* What it does for the app, so the app does nothing:
*
*   - a P-256 key made here, non-extractable; the key, the session's token
*     and the gate's nonce live in this closure only, never on disk or in
*     the environment;
*   - the exchange, retried while an enrollment code is `full` (5 minutes)
*     or its session awaits approval (10), and after a spent projected token,
*     once the kubelet writes the next;
*   - renewal at half-life, every 30 seconds for an enrollment session, whose
*     expiry is its liveness, and none for a session already at its hard end
*     (a projected token's), which only a new proof outlives; a fresh proof, with the same key, before the
*     session's hard end, `notAfter`; and a new session whenever the old one
*     is lost (revoked, frozen, expired while the process slept);
*   - each request under `<url>/use/` signed whole (method, URL, query, the
*     headers it was given, the body), with the newest nonce, and sent again
*     once if the gate asks for a fresh one;
*   - logout on `close()`, and on SIGTERM.
*/
const dispatch = (nonces) => ({
	seq: ++nonces.sent,
	at: Date.now()
});
/** How long a nonce is taken as fresh, for a request that cannot be sent again (a stream, a WebSocket's upgrade): under the 2 minutes it lasts. */
const FRESH_NONCE_MS = 1e5;
/** How long the exchange waits out a full enrollment code, and a session awaiting approval. */
const FULL_MS = 3e5;
const PENDING_MS = 6e5;
/** An enrollment session renews every 30 seconds: its expiry, 90 seconds past its last renewal, is its liveness. */
const ENROLLMENT_RENEW_MS = 3e4;
/** Refusals no new proof can change: the code was superseded by a newer deploy's. */
const FINAL = /* @__PURE__ */ new Set(["superseded"]);
/** How long a logout may take: a process stopping waits no longer for it. */
const LOGOUT_MS = 3e3;
/** The redirects fetch follows, and how many it follows at most. */
const REDIRECTS = /* @__PURE__ */ new Set([
	301,
	302,
	303,
	307,
	308
]);
const MOST_REDIRECTS = 20;
/** Each session's SIGTERM handler: a process whose every handler is one of these ends on SIGTERM once they have logged out. */
const TERMINATING = /* @__PURE__ */ new WeakSet();
/** What `upgradeHeaders` and `upgradeRefused` reach, for each workload: its own, never on the object. */
const UPGRADES = /* @__PURE__ */ new WeakMap();
/**
* Sign in as `service`, with `proof`, and hold the session for as long as
* the process runs. Rejects if the first exchange is refused.
*/
async function workload(options) {
	const url = new URL(options.url);
	if (url.protocol !== "https:" && !(url.protocol === "http:" && /^(localhost|127(\.\d{1,3}){3}|\[::1\])$/.test(url.hostname))) throw new TypeError(`workload() talks to coffre over https, or http on this machine: not ${url.origin}`);
	const origin = url.origin;
	const base = options.fetch ?? ((input, init) => fetch(input, init));
	const log = options.log ?? ((line) => console.error(line));
	const key = await generateProofKey();
	/** Aborted by `close()`: an exchange, its waits and its proof's stop with it. */
	const lifetime = new AbortController();
	const proofFetch = (input, init = {}) => base(input, {
		...init,
		signal: init.signal ? anySignal([init.signal, lifetime.signal]) : lifetime.signal
	});
	const context = {
		audience: origin,
		jkt: await thumbprint(key.jwk),
		fetch: proofFetch,
		log,
		signal: lifetime.signal
	};
	const nonces = {
		value: void 0,
		at: 0,
		seq: 0,
		sent: 0
	};
	const enrolled = options.proof.kind === "enrollment";
	const api = apiOf({
		origin,
		base,
		key,
		nonces
	});
	/** How long the last exchange refused was told to wait before asking again (`Retry-After`): the least a retry waits. */
	let toldToWait = 0;
	/** Trade a fresh proof for a session, waiting out what the design says to wait out; throws a refusal, with the server's words. */
	const exchange = async () => {
		const start = Date.now();
		toldToWait = 0;
		const said = /* @__PURE__ */ new Set();
		const say = (line) => void (said.has(line) || (said.add(line), log(line)));
		for (;;) {
			lifetime.signal.throwIfAborted();
			const proof = await options.proof.prove(context);
			const url = `${origin}/api/auth/workload`;
			const sent = dispatch(nonces);
			const response = await base(url, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					accept: "application/json",
					dpop: await createProof(key, {
						method: "POST",
						url
					})
				},
				body: JSON.stringify({
					service: options.service,
					proof
				}),
				signal: lifetime.signal,
				redirect: "error"
			});
			note(nonces, response, sent);
			const body = await response.json().catch(() => null);
			const [expiresAt, notAfter] = [Date.parse(String(body?.expiresAt)), Date.parse(String(body?.notAfter))];
			if (response.status === 200 && typeof body?.token === "string" && Number.isFinite(expiresAt) && Number.isFinite(notAfter)) {
				const places = Array.isArray(body.places) ? body.places.filter((place) => typeof place === "string") : [];
				return {
					token: body.token,
					expiresAt,
					notAfter,
					places,
					issuedAt: Date.now()
				};
			}
			const reason = typeof body?.reason === "string" ? body.reason : void 0;
			if (response.status === 202 && Date.now() - start < PENDING_MS) {
				say(`coffre: ${options.service}'s session waits for a person to approve it${typeof body?.approve === "string" ? `, at ${body.approve}` : ""}`);
				await sleep(5e3, lifetime.signal);
				continue;
			}
			if (response.status === 429 && reason === "full" && Date.now() - start < FULL_MS) {
				say(`coffre: ${options.service}'s enrollment code holds all the sessions it admits; waiting for one to end, up to 5 minutes`);
				await sleep(retryAfter(response, 3e4), lifetime.signal);
				continue;
			}
			if (reason === "replayed" && options.proof.spent !== void 0 && await options.proof.spent(context)) continue;
			toldToWait = retryAfter(response, 0);
			throw refusal(response.status, body, `${origin} would not sign ${options.service} in with its ${options.proof.name} proof`);
		}
	};
	let session = await exchange();
	if (options.place !== void 0 && !session.places.includes(options.place)) throw new Error(`${options.service} reaches ${session.places.join(", ") || "no environment"}, not ${options.place}`);
	/** The environments of the newest session, kept while a lost one is proved again. */
	let places = session.places;
	/**
	* Every session proved and not past its hard end: a new proof leaves the
	* old one to finish its requests, and close() ends them all, their
	* children with them. Not pruned by their expiry, which a renewal answered
	* late may have pushed on: a session already ended answers 401, which is
	* an end too.
	*/
	let roots = [session];
	let closed = false;
	/** The exchange in flight, which requests without a session wait for; and why the last one failed, while none holds. */
	let attempt = null;
	let failure = null;
	/** A refusal no new proof can change (a superseded code, a proof given once and spent), once seen. */
	let final = null;
	let tries = 0;
	/** The renewal in flight for each session: one each, so that an old session's renewal answered late takes no new session's turn. */
	const renewals = /* @__PURE__ */ new WeakMap();
	const timers = {
		renew: void 0,
		prove: void 0,
		retry: void 0
	};
	const at = (which, when, run) => {
		clearTimeout(timers[which]);
		if (closed) return;
		timers[which] = setTimeout(() => void run(), Math.max(0, when - Date.now()));
		timers[which].unref?.();
	};
	/** Renew at half-life, or every 30 seconds for an enrollment, while the session's end can still move: one already at its hard end, as a projected token's is, only the next proof replaces. */
	const planRenewal = (held) => {
		if (held.expiresAt >= held.notAfter) return clearTimeout(timers.renew);
		const now = Date.now();
		at("renew", enrolled ? now + ENROLLMENT_RENEW_MS : now + Math.max(1e3, (held.expiresAt - now) / 2), renew);
	};
	/** Renew as `planRenewal` says; prove again at 90% of the way to `notAfter`. */
	const plan = (held) => {
		planRenewal(held);
		if (!enrolled) at("prove", held.notAfter - (held.notAfter - held.issuedAt) / 10, () => prove().catch(() => void 0));
	};
	/** A new session, with a fresh proof and the same key: requests in flight finish on the old one. Retried with backoff while it fails, unless it cannot change. */
	const prove = () => {
		if (final !== null) return Promise.reject(final);
		attempt ??= exchange().then((next) => {
			if (closed) {
				logout$1(api, next.token).catch(() => void 0);
				throw new Error(`${options.service}'s session with coffre is closed`);
			}
			session = next;
			places = next.places;
			roots = [...roots.filter((root) => root.notAfter > Date.now()), next];
			failure = null;
			tries = 0;
			plan(next);
			return next;
		}).catch((error) => {
			failure = error;
			const spent = error instanceof CoffreError && error.reason === "replayed" && options.proof.spent === void 0;
			if (spent) log(`coffre: ${options.service}'s ${options.proof.name} proof was spent, and it gives no fresh one: the session ends at its expiry`);
			if (spent || error instanceof CoffreError && FINAL.has(error.reason ?? "")) final = error;
			else if (!closed) at("retry", Date.now() + Math.max(backoff(tries++), toldToWait * (1 + Math.random() / 2)), () => prove().catch(() => void 0));
			throw error;
		}).finally(() => attempt = null);
		return attempt;
	};
	/** Push the session's expiry on; a session coffre no longer renews is lost, and proved again. */
	const renew = () => {
		const held = session;
		if (held === null || closed) return Promise.resolve();
		const running = renewals.get(held);
		if (running !== void 0) return running;
		const renewal = (async () => {
			try {
				const { response, body } = await api("/api/auth/workload/renew", held.token);
				if (response.ok && typeof body?.expiresAt === "string") {
					held.expiresAt = Date.parse(body.expiresAt);
					if (session === held) planRenewal(held);
					return;
				}
				if (response.status !== 401 && response.status !== 403 || askedNonce(response)) throw new Error(`renewal answered ${response.status}`);
				if (session === held) lose();
			} catch {
				if (session !== held) return;
				if (Date.now() >= held.expiresAt) return lose();
				at("renew", Math.min(Date.now() + (enrolled ? 5e3 : 3e4), held.expiresAt), renew);
			}
		})().finally(() => renewals.delete(held));
		renewals.set(held, renewal);
		return renewal;
	};
	const lose = () => {
		if (closed) return;
		session = null;
		clearTimeout(timers.renew);
		clearTimeout(timers.prove);
		prove().catch(() => void 0);
	};
	/** The session to sign with: the one held, the exchange in flight, or, while exchanges fail, why. */
	const current = async () => {
		if (closed) throw new Error(`${options.service}'s session with coffre is closed`);
		if (session !== null && Date.now() < session.expiresAt - 5e3) return session;
		if (attempt !== null) return attempt;
		if (failure !== null) throw failure;
		return prove();
	};
	plan(session);
	const signals = globalThis.process;
	let closing = null;
	const close = () => closing ??= (async () => {
		closed = true;
		lifetime.abort();
		for (const timer of Object.values(timers)) clearTimeout(timer);
		session = null;
		try {
			const failed = (await Promise.allSettled(roots.filter((root) => root.notAfter > Date.now()).map((root) => logout$1(api, root.token)))).find((each) => each.status === "rejected");
			if (failed !== void 0) throw failed.reason;
		} finally {
			signals?.off?.("SIGTERM", onTerm);
			TERMINATING.delete(onTerm);
		}
	})();
	const onTerm = () => {
		const alone = signals.listeners("SIGTERM").every((listener) => TERMINATING.has(listener));
		close().catch(() => void 0).finally(() => alone && signals.listenerCount("SIGTERM") === 0 && signals.kill(signals.pid, "SIGTERM"));
	};
	if (options.sigterm !== false) {
		TERMINATING.add(onTerm);
		signals?.on?.("SIGTERM", onTerm);
	}
	return surface({
		origin,
		base,
		key,
		nonces,
		api,
		service: options.service,
		place: options.place,
		current,
		places: () => places,
		refresh: renew,
		close
	});
}
function surface(core) {
	const { origin, key, nonces } = core;
	const under = (url) => {
		try {
			const parsed = new URL(url);
			return parsed.origin === origin && parsed.pathname.startsWith("/use/");
		} catch {
			return false;
		}
	};
	const fresh = async () => {
		if (Date.now() - nonces.at > FRESH_NONCE_MS) await core.refresh().catch(() => void 0);
	};
	/** A request under `/use/`, signed; or any other, as given. Redirects come back through here, so each hop is signed for itself. */
	const go = async (input, init, hops) => {
		const url = input instanceof Request ? input.url : input instanceof URL ? input.href : String(input);
		if (!under(url)) return core.base(input, init);
		const request = new Request(input, init);
		const own = request.headers.get("content-digest");
		const declared = request.headers.get("x-amz-content-sha256") ?? (own === null ? null : declaredDigest(own));
		const streamed = init?.body instanceof ReadableStream || input instanceof Request && init?.body === void 0;
		const stream = declared !== null && request.body !== null && streamed ? request.body : null;
		const bytes = stream === null && request.body !== null ? new Uint8Array(await request.arrayBuffer()) : null;
		const stated = request.headers.get("content-length");
		const length = stream === null ? bytes?.length ?? 0 : stated !== null && /^\d+$/.test(stated) ? Number(stated) : null;
		const line = await bodyLine({
			declared,
			length,
			bytes
		});
		const content = new Headers(request.headers);
		if (declared === null && own === null && length !== 0) content.set("content-digest", contentDigest(line));
		const send = async () => {
			const { token } = await core.current();
			const headers = new Headers(content);
			if (bytes !== null) headers.set("content-length", String(bytes.length));
			headers.set("authorization", `DPoP ${token}`);
			headers.set("dpop", await createProof(key, {
				method: request.method,
				url: request.url,
				token,
				nonce: nonces.value,
				content: {
					headers: content,
					body: line
				}
			}));
			const sent = dispatch(nonces);
			const response = await core.base(request.url, {
				method: request.method,
				headers,
				body: stream ?? bytes,
				signal: request.signal,
				redirect: "manual",
				...stream === null ? {} : { duplex: "half" }
			});
			note(nonces, response, sent);
			return response;
		};
		let response;
		if (stream !== null) {
			await fresh();
			response = await send();
		} else {
			response = await send();
			if (askedNonce(response)) {
				await response.body?.cancel();
				response = await send();
			}
		}
		const location = response.headers.get("location");
		if (request.redirect === "manual" || !REDIRECTS.has(response.status) || location === null) return response;
		await response.body?.cancel();
		if (request.redirect === "error") throw new TypeError(`fetch failed: ${request.url} redirects, and redirect is "error"`);
		if (hops >= MOST_REDIRECTS) throw new TypeError(`fetch failed: more than ${MOST_REDIRECTS} redirects`);
		const asGet = response.status === 303 && request.method !== "HEAD" || (response.status === 301 || response.status === 302) && request.method === "POST";
		if (!asGet && stream !== null) throw new TypeError(`fetch failed: ${request.url} redirects a streamed body, which cannot be sent again`);
		const next = new URL(location, request.url);
		const headers = new Headers(request.headers);
		if (asGet) for (const name of [
			"content-type",
			"content-length",
			"content-encoding",
			"content-language",
			"content-location",
			"content-digest"
		]) headers.delete(name);
		if (next.origin !== new URL(request.url).origin) for (const name of [
			"authorization",
			"cookie",
			"proxy-authorization"
		]) headers.delete(name);
		return go(next, {
			method: asGet ? "GET" : request.method,
			headers,
			body: asGet ? null : bytes,
			signal: request.signal,
			redirect: "follow"
		}, hops + 1);
	};
	const signed = (input, init) => go(input, init, 0);
	const placeOf = () => {
		const places = core.places();
		const place = core.place ?? (places.length === 1 ? places[0] : void 0);
		if (place === void 0) throw new Error(`${core.service} reaches ${places.join(", ") || "no environment"}: name the one to use, workload({ place })`);
		return place;
	};
	const placeUrl = () => `${origin}/use/${placeOf().split("/").map(encodeURIComponent).join("/")}`;
	const url = (name) => core.places().length === 1 ? `${origin}/use/${encodeURIComponent(name)}` : `${placeUrl()}/${encodeURIComponent(name)}`;
	/** What coffre makes with the environment's values, at the environment's URL: a signature, a verdict, a presigned URL, a minted child. */
	const compute = async (asked, what) => {
		const response = await signed(placeUrl(), {
			method: "POST",
			headers: {
				"content-type": "application/json",
				accept: "application/json"
			},
			body: JSON.stringify(asked)
		});
		const body = await response.json().catch(() => null);
		if (!response.ok || body === null) throw refusal(response.status, body, `coffre ${what} nothing`);
		return body;
	};
	const workload = {
		service: core.service,
		get places() {
			return core.places();
		},
		fetch: signed,
		url,
		credential: (name) => ({
			fetch: async (path, init) => {
				const base = url(name);
				const target = new URL(`${base}${path.startsWith("/") ? "" : "/"}${path}`);
				const under = new URL(base).pathname;
				if (target.pathname !== under && !target.pathname.startsWith(`${under}/`)) throw new TypeError(`${JSON.stringify(path)} leaves ${name}'s URL: a credential's fetch reaches its own upstream only`);
				return signed(target.href, init);
			},
			sign: async (message) => {
				const body = await compute({ sign: {
					credential: name,
					message: bytesOf(message)
				} }, "signed");
				if (typeof body.signature !== "string") throw new Error("coffre signed nothing");
				return body.signature;
			},
			verify: async (message, signature) => (await compute({ verify: {
				credential: name,
				message: bytesOf(message),
				signature
			} }, "verified")).valid === true,
			presign: async (path, options = {}) => {
				const body = await compute({ presign: {
					credential: name,
					path,
					...options
				} }, "presigned");
				if (typeof body.url !== "string" || typeof body.expiresAt !== "string") throw new Error("coffre presigned nothing");
				return {
					url: body.url,
					expiresAt: body.expiresAt
				};
			},
			mint: async () => await compute({ mint: { credential: name } }, "minted")
		}),
		read: async (name) => {
			const response = await signed(placeUrl(), { headers: { accept: "application/json" } });
			const body = await response.json().catch(() => null);
			if (!response.ok) throw refusal(response.status, body, `coffre answered no plan for ${placeOf()}`);
			const value = body?.values?.[name];
			if (typeof value === "string") return value;
			throw new CoffreError(403, "forbidden", `${core.service} reads no ${name} in ${placeOf()}: it reads plain values and those its binding lists in reads, and uses every other through coffre`, "use_only");
		},
		narrow: (async (options) => {
			const own = options.key === void 0 ? await generateProofKey() : null;
			const { token } = await core.current();
			const { key: given, expiresIn, label, ...constraints } = options;
			const { response, body } = await core.api("/api/auth/workload/narrow", token, {
				key: given ?? own.jwk,
				label,
				constraints,
				expiresIn
			});
			if (!response.ok || typeof body?.token !== "string" || typeof body.expiresAt !== "string") throw refusal(response.status, body, `coffre narrowed ${core.service} to nothing`);
			if (own === null) return {
				token: body.token,
				expiresAt: body.expiresAt
			};
			return child(core, own, body.token, Date.parse(body.expiresAt), options.places ?? core.places());
		}),
		close: core.close
	};
	UPGRADES.set(workload, {
		sign: async (target) => {
			await fresh();
			const { token } = await core.current();
			const url = target.replace(/^ws/, "http");
			return {
				authorization: `DPoP ${token}`,
				dpop: await createProof(key, {
					method: "GET",
					url,
					token,
					nonce: nonces.value
				})
			};
		},
		refused: () => nonces.at = 0
	});
	return workload;
}
/** A narrowed session in this process: its own key, no renewal, and its end its parent's or its own. */
function child(parent, key, token, expiresAt, places) {
	let closed = false;
	let closing = null;
	const held = {
		token,
		expiresAt,
		notAfter: expiresAt,
		places,
		issuedAt: Date.now()
	};
	const api = apiOf({
		origin: parent.origin,
		base: parent.base,
		key,
		nonces: parent.nonces
	});
	return surface({
		...parent,
		key,
		api,
		places: () => places,
		place: parent.place !== void 0 && places.includes(parent.place) ? parent.place : void 0,
		current: async () => {
			if (closed || Date.now() >= held.expiresAt) throw new Error(`this narrowed session of ${parent.service} has ended`);
			return held;
		},
		refresh: parent.refresh,
		close: () => closing ??= (async () => {
			closed = true;
			await logout$1(api, token);
		})()
	});
}
/**
* The headers that sign a WebSocket's upgrade to `url` (a tunnel's), made
* outside `coffre.fetch`: the session, and a proof of a GET at its `https`
* form with a nonce fresh enough that the gate takes it, since an upgrade
* refused cannot be told why and sent again.
*/
function upgradeHeaders(coffre, url) {
	const upgrade = UPGRADES.get(coffre);
	if (upgrade === void 0) throw new TypeError("upgradeHeaders takes a workload() session");
	return upgrade.sign(url);
}
/**
* Say that coffre refused an upgrade, or that it never opened: its nonce may
* be the gate's no longer, so the next upgrade, which cannot be sent again
* either, first asks for the newest.
*/
function upgradeRefused(coffre) {
	UPGRADES.get(coffre)?.refused();
}
/** Keep the gate's newest nonce: every answer from coffre carries it, and the newest is the one to a request sent last. */
function note(nonces, response, sent) {
	const nonce = response.headers.get("dpop-nonce");
	if (nonce !== null && nonce !== "" && sent.seq > nonces.seq) {
		nonces.value = nonce;
		nonces.at = sent.at;
		nonces.seq = sent.seq;
	}
}
/**
* Its proof signs the token and the newest nonce, and a body where there is
* one (`hdr` and `req`: narrow's, the key and the limits it gives a child),
* so no one who sees the request can make it say anything else; sent again
* once if the gate asks for a fresh nonce.
*/
function apiOf({ origin, base, key, nonces }) {
	return async (path, token, body, signal) => {
		const url = `${origin}${path}`;
		const json = body === void 0 ? void 0 : JSON.stringify(body);
		const headers = {
			accept: "application/json",
			...json === void 0 ? {} : { "content-type": "application/json" }
		};
		const content = json === void 0 ? void 0 : {
			headers,
			body: await bodyDigest(json)
		};
		const send = async () => {
			const sent = dispatch(nonces);
			const response = await base(url, {
				method: "POST",
				headers: {
					...headers,
					authorization: `DPoP ${token}`,
					dpop: await createProof(key, {
						method: "POST",
						url,
						token,
						nonce: nonces.value,
						content
					})
				},
				body: json,
				signal,
				redirect: "error"
			});
			note(nonces, response, sent);
			return response;
		};
		let response = await send();
		if (askedNonce(response)) {
			await response.body?.cancel();
			response = await send();
		}
		return {
			response,
			body: await response.json().catch(() => null)
		};
	};
}
/** End a session, waiting 3 seconds at most; rejects unless coffre says it ended, or had already (401). */
async function logout$1(api, token) {
	const { response, body } = await api("/api/auth/logout", token, void 0, AbortSignal.timeout(LOGOUT_MS));
	if (!response.ok && (response.status !== 401 || askedNonce(response))) throw refusal(response.status, body, "coffre did not end the session");
}
/**
* Whether coffre refused a proof for its nonce alone (RFC 9449, section 8): sent again once, with the nonce it gave. A
* workload's `fetch` does so itself, but for a stream, which it cannot read twice: whoever holds its bytes may.
*/
function askedNonce(response) {
	return response.status === 401 && /error="?use_dpop_nonce/.test(response.headers.get("www-authenticate") ?? "") && response.headers.has("dpop-nonce");
}
function refusal(status, body, what) {
	const reason = typeof body?.reason === "string" ? body.reason : void 0;
	const message = typeof body?.message === "string" ? body.message : `status ${status}`;
	return new CoffreError(status, typeof body?.error === "string" ? body.error : "refused", `${what}${reason === void 0 ? "" : ` (${reason})`}: ${message}`, reason);
}
/** `Retry-After`, in milliseconds, or `fallback`. */
function retryAfter(response, fallback) {
	const seconds = Number(response.headers.get("retry-after"));
	return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 300) * 1e3 : fallback;
}
/** 1, 2, 4… seconds, at most a minute, a little jittered so that a fleet's replicas spread out. */
function backoff(tries) {
	return Math.min(6e4, 1e3 * 2 ** tries) * (.75 + Math.random() / 2);
}
/** A message as coffre's `sign` and `verify` take it: a string's UTF-8, base64url. */
const bytesOf = (message) => base64url(typeof message === "string" ? new TextEncoder().encode(message) : message);
/** A signal that aborts with the first of `signals`: `AbortSignal.any`, where the runtime has it (Node 20.3 and later). */
function anySignal(signals) {
	if (typeof AbortSignal.any === "function") return AbortSignal.any(signals);
	const controller = new AbortController();
	for (const signal of signals) if (signal.aborted) controller.abort(signal.reason);
	else signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
	return controller.signal;
}
/** A wait that `signal` ends early, rejecting. */
const sleep = (ms, signal) => new Promise((resolve, reject) => {
	const timer = setTimeout(() => (signal.removeEventListener("abort", stop), resolve()), ms);
	const stop = () => (clearTimeout(timer), reject(signal.reason));
	signal.addEventListener("abort", stop, { once: true });
});
//#endregion
//#region src/manage.ts
const STDIO = {
	out: process.stdout,
	err: process.stderr
};
/** A command used wrongly: the CLI says why, then the command's usage, and exits 2. */
var UsageError = class extends Error {};
/** A check that ran and failed, `missing --check`: the CLI says why and exits 1, once what the command printed is out. */
var CheckFailed = class extends Error {};
/** Strict options and positionals, each positional named: too few or too many is a usage error. */
function parse(args, options, names, optional = 0) {
	const { values, positionals } = parseArgs({
		args,
		options,
		allowPositionals: true,
		strict: true
	});
	if (positionals.length > names.length) throw new UsageError(`too many arguments: ${positionals.slice(names.length).join(" ")}`);
	if (positionals.length < names.length - optional) throw new UsageError(`name ${listOf$1(names.slice(positionals.length))}`);
	return {
		values,
		positionals
	};
}
function listOf$1(names) {
	return names.length < 2 ? names.join("") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
}
const json = { json: {
	type: "boolean",
	default: false
} };
function asJson(io, value) {
	io.out.write(`${JSON.stringify(value, null, 2)}\n`);
}
/** `market` and `market/prod`, checked: a project, or a place with its environment. */
function place(text, environment) {
	const parts = text.split("/");
	if (parts.length !== (environment ? 2 : 1) || parts.some((part) => part === "")) throw new UsageError(environment ? `expected <project>/<environment>, not "${text}"` : `expected a project, not "${text}"`);
	return {
		project: parts[0],
		environment: parts[1]
	};
}
/** `market/prod/KEY`, checked. */
function secret(text) {
	const parts = text.split("/");
	if (parts.length !== 3 || parts.some((part) => part === "")) throw new UsageError(`expected <project>/<environment>/<KEY>, not "${text}"`);
	return text;
}
const day = (iso) => iso === null ? "never" : iso.slice(0, 10);
/**
* A grant is on a project or an environment: what reaches every project is
* a person's instance role, and `*` no project.
*/
function onAProject(project) {
	if (project === "*") throw new UsageError("grants are on a project or an environment: a person reaches every project by their instance role, `coffre admit <email> --role <role>`");
}
/**
* Someone's instance role in words: `Developer`, or `Developer, All projects · dev only`
* when a scope narrows it. Only those who run the instance are told the scope (null otherwise).
*/
function roleInWords(member) {
	const known = INSTANCE_ROLES[member.instanceRole];
	if (known === void 0) return String(member.instanceRole);
	const { name } = known;
	return member.scope === null || unscoped(member.scope) ? name : `${name}, ${scopeInWords(member.scope)}`;
}
async function projects(connect, args, io = STDIO) {
	const { values } = parse(args, json, []);
	const { projects: list } = await connect().projects.list();
	if (values.json) return asJson(io, list);
	for (const [folder, inFolder] of byFolder(list)) {
		const indent = folder === null ? "" : "  ";
		if (folder !== null) io.out.write(`${folder}/\n`);
		for (const project of inFolder) {
			const archived = project.archivedAt === null ? "" : " (archived)";
			io.out.write(`${indent}${project.slug}${archived}\n`);
			for (const environment of project.environments) {
				if (environment.details?.archivedAt) continue;
				const count = environment.details?.secretCount;
				const guarded = environment.protected === true ? "  protected" : "";
				io.out.write(`${indent}  ${environment.slug.padEnd(16)} ${count === null || count === void 0 ? "" : `${count} secrets`}${guarded}\n`);
			}
		}
	}
}
/** `--undo`: what reset and remove did, undone. */
const undo = { undo: {
	type: "boolean",
	default: false
} };
const naming = { name: { type: "string" } };
const renaming = {
	name: { type: "string" },
	slug: { type: "string" }
};
function nameIgnored(values, what, io) {
	if (values.name !== void 0) io.err.write(`coffre: --name is ignored: ${what === "project" ? "a" : "an"} ${what} goes by its slug\n`);
}
async function projectsCreate(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, naming, ["<project>"]);
	const { project } = place(positionals[0], false);
	nameIgnored(values, "project", io);
	const made = await connect().projects.create(project, { name: project });
	io.out.write(made.created ? `created ${made.project.slug}\n` : `${made.project.slug} exists already: nothing changed\n`);
}
async function environmentsCreate(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, naming, [`<project>/<environment>`]);
	const { project, environment } = place(positionals[0], true);
	nameIgnored(values, "environment", io);
	const made = await connect().environments.create(`${project}/${environment}`, { name: environment });
	const path = `${project}/${made.environment.slug}`;
	io.out.write(made.created ? `created ${path}\n` : `${path} exists already: nothing changed\n`);
}
/**
* `coffre fork market/prod staging`: a new environment beside it, with each
* live key's value and folder, and none of its history. Copying is a read,
* logged as one; running it again fills the environment if it stopped
* half way. With --inherit, nothing is copied or read: the fork reads its
* parent's keys live, but for those it sets or removes, and its readers
* need read on the parent for those (docs/design/forking.md).
*/
async function fork(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		...naming,
		reference: {
			type: "boolean",
			default: false
		},
		inherit: {
			type: "boolean",
			default: false
		}
	}, ["<project>/<environment>", "<new-environment>"]);
	const { project, environment: from } = place(positionals[0], true);
	const slug = positionals[1];
	if (slug.includes("/")) throw new UsageError(`name the new environment alone, as in staging, not "${slug}": it goes in ${project}`);
	if (values.reference && values.inherit) throw new UsageError("--reference or --inherit, not both: a fork holds references to its parent, or inherits from it");
	nameIgnored(values, "environment", io);
	const api = connect();
	if (values.inherit && (await api.secrets.list(`${project}/${from}`)).parents === void 0) throw new UsageError("this instance is older than forks that inherit (coffre 0.7): it would copy instead. Upgrade it, or fork without --inherit");
	const made = await api.environments.create(`${project}/${slug}`, {
		name: slug,
		from,
		...values.reference ? { references: true } : {},
		...values.inherit ? { inherit: true } : {}
	});
	if (values.inherit) {
		if (made.forked?.inherits !== true) throw new UsageError(`${project}/${made.environment.slug} was ${made.created ? "made" : "there already"}, but does not inherit from ${project}/${from}: check it with \`coffre list ${project}/${made.environment.slug}\``);
		io.out.write(`created ${project}/${made.environment.slug}, inheriting ${project}/${from}: nothing copied\n`);
		io.out.write(`  it reads ${from}'s keys as they change, but for those it sets or removes; its readers need read on ${from} for those\n`);
		return;
	}
	const { keys = 0, references = 0, copied = [] } = made.forked ?? {};
	const what = values.reference ? `${references} reference${references === 1 ? "" : "s"}${copied.length === 0 ? "" : `, and ${copied.length} copied: ${copied.join(", ")}, whose source you read only through ${from}`}` : "values copied, no history";
	io.out.write(`${made.created ? "created" : "filled"} ${project}/${made.environment.slug} from ${project}/${from}: ${keys} key${keys === 1 ? "" : "s"}, ${what}\n`);
	if (values.reference && references > 0) io.out.write(`  whoever reads ${project}/${made.environment.slug} reads those values through them, as they change\n`);
}
/**
* `coffre personal market`: its members' personal configs, for whoever
* manages its environments: whose, of what, and their key names, never a
* value. Each slug is what `coffre environments delete` takes.
*/
async function personal(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, json, ["<project>"]);
	const { project } = place(positionals[0], false);
	const { configs } = await connect().environments.personal(project);
	if (values.json) return asJson(io, configs);
	if (configs.length === 0) return void io.out.write(`no personal config in ${project}\n`);
	for (const config of configs) {
		const keys = config.keys.length === 0 ? "no keys" : config.keys.join(", ");
		io.out.write(`${project}/${config.of}@${shownMember$1(config.owner).replace(/^user:/, "")}\t${project}/${config.slug}${config.archived ? "	(archived)" : ""}\n  ${keys}\n`);
	}
}
/** The patch `--slug` makes, or null for `--name` alone, which a script from before 0.6.2 may pass: nothing to change. */
function renamed(values, what, io) {
	nameIgnored(values, what, io);
	if (values.slug !== void 0) return { slug: values.slug };
	if (values.name !== void 0) return null;
	throw new UsageError("give it a new --slug");
}
async function projectsRename(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, renaming, ["<project>"]);
	const { project } = place(positionals[0], false);
	const patch = renamed(values, "project", io);
	if (patch === null) return;
	const { project: now } = await connect().projects.update(project, patch);
	io.out.write(`${project} is now ${now.slug}\n`);
}
async function environmentsRename(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, renaming, ["<project>/<environment>"]);
	const { project, environment } = place(positionals[0], true);
	const patch = renamed(values, "environment", io);
	if (patch === null) return;
	const { environment: now } = await connect().environments.update(`${project}/${environment}`, patch);
	io.out.write(`${project}/${environment} is now ${project}/${now.slug}\n`);
	if (now.slug !== environment) io.out.write(`  instance roles scoped to ${environment} no longer reach it; those scoped to ${now.slug} do\n`);
}
async function projectsArchive(connect, args, archived, io = STDIO) {
	const { positionals } = parse(args, {}, ["<project>"]);
	const { project } = place(positionals[0], false);
	await connect().projects.update(project, { archived });
	io.out.write(archived ? `archived ${project}: \`coffre projects unarchive ${project}\` brings it back\n` : `unarchived ${project}\n`);
}
async function environmentsArchive(connect, args, archived, io = STDIO) {
	const { positionals } = parse(args, {}, ["<project>/<environment>"]);
	const { project, environment } = place(positionals[0], true);
	const path = `${project}/${environment}`;
	await connect().environments.update(path, { archived });
	io.out.write(archived ? `archived ${path}: \`coffre environments unarchive ${path}\` brings it back\n` : `unarchived ${path}\n`);
}
/**
* An archived project or environment deleted for good: first shown, what it
* would erase and revoke, then, with --apply, deleted. Asked again after a
* deletion cut off partway, it finishes it.
*/
async function placeDelete(connect, args, environment, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, [environment ? "<project>/<environment>" : "<project>"]);
	const where = place(positionals[0], environment);
	const path = environment ? `${where.project}/${where.environment}` : where.project;
	const api = connect();
	const places = environment ? api.environments : api.projects;
	if (!values.apply) {
		io.out.write(describeDeletion((await places.previewDelete(path)).deletion, false));
		return;
	}
	io.out.write(describeDeletion((await places.delete(path)).deletion, true));
}
/** What a deletion takes, before or after: what it erases, revokes and keeps. */
function describeDeletion(deletion, done) {
	const { path, tombstone, environments, keys, versions, grants, stranded } = deletion;
	const count = (n, one) => `${n} ${one}${n === 1 ? "" : "s"}`;
	const where = environments.length === 0 ? "" : `, in ${environments.join(", ")}`;
	const revoked = grants.map((grant) => `${shownMember$1(grant.member)} (${grant.role} on ${grant.place})`);
	const lines = [
		done ? `deleted ${path}, for good:` : `would delete ${path}, for good:`,
		`  erased: ${count(versions, "version")}${where}`,
		`  revoked: ${count(grants.length, "grant")}${revoked.length === 0 ? "" : `, ${revoked.join(", ")}`}`,
		...deletion.references.length === 0 ? [] : [`  ended: ${count(deletion.references.length, "reference")}, ${deletion.references.map((reference) => `${reference.holder} → ${reference.source}`).join(", ")}`],
		`  kept, names only: ${tombstone} and its ${count(keys, "key")}, for the audit log`,
		`  ${path.split("/").at(-1)} ${done ? "is" : "would be"} free to use again`
	];
	for (const member of stranded) {
		const offboard = member.startsWith("token:") ? `coffre offboard ${serviceName(member)} --service` : `coffre offboard ${member.slice(5)}`;
		lines.push(`  ${shownMember$1(member)} ${done ? "holds" : "would hold"} nothing anywhere: \`${offboard}\` removes them`);
	}
	if (!done) lines.push("Backups taken before the deletion still hold the encrypted values.", "Nothing changed. Re-run with --apply to delete it.");
	return `${lines.join("\n")}\n`;
}
async function renameSecret(connect, args, io = STDIO) {
	const { positionals } = parse(args, {}, ["<project>/<environment>/<KEY>", "<NEW_KEY>"]);
	const path = secret(positionals[0]);
	const { key } = await connect().secrets.rename(path, positionals[1]);
	io.out.write(`${path} is now ${path.slice(0, path.lastIndexOf("/"))}/${key}, its versions with it\n`);
}
async function archiveSecret(connect, args, archived, io = STDIO) {
	const { positionals } = parse(args, {}, ["<project>/<environment>/<KEY>"]);
	const path = secret(positionals[0]);
	await connect().secrets.update(path, { archived });
	io.out.write(archived ? `archived ${path}: \`coffre unarchive ${path}\` brings it back\n` : `unarchived ${path}\n`);
}
/**
* `coffre reset market/prod-eu/KEY`: in a fork, the key reads its parent's
* value again; its own is archived, with its history. --undo serves it again.
*/
async function resetSecret(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, undo, ["<project>/<environment>/<KEY>"]);
	const path = secret(positionals[0]);
	const { from } = await connect().secrets.inherit(path, !values.undo);
	const project = path.slice(0, path.indexOf("/"));
	io.out.write(values.undo ? `${path} overrides ${project}/${from} again, with the value it had\n` : `${path} reads ${project}/${from}'s value again; its own is kept: \`coffre reset ${path} --undo\` serves it again\n`);
}
/**
* `coffre remove market/prod-eu/KEY`: in a fork, it does without its
* parent's key, a dismissal, which the missing keys list too. --undo
* inherits it again.
*/
async function removeSecret(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, undo, ["<project>/<environment>/<KEY>"]);
	const path = secret(positionals[0]);
	const environment = path.slice(0, path.lastIndexOf("/"));
	const key = path.slice(path.lastIndexOf("/") + 1);
	const api = connect();
	const { parents } = await api.secrets.list(environment);
	if (parents === void 0 || parents.length === 0) throw new UsageError(`${environment} inherits from no environment: \`coffre archive ${path}\` takes a key out of it`);
	const { keys } = await api.environments.dismiss(environment, { [key]: values.undo ? null : true });
	if (keys[key] === "unchanged") return void io.out.write(`${path} was ${values.undo ? "not removed" : "removed"} already\n`);
	io.out.write(values.undo ? `${environment} inherits ${key} again, unless it holds its own\n` : `${environment} does without its parent's ${key}: \`coffre remove ${path} --undo\` inherits it again\n`);
}
/** `coffre references market/prod`: what it lends and what it holds, and who reads through each. */
async function references(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, json, ["<project>[/<environment>[/<KEY>]]"]);
	const { references: list } = await connect().references.list(positionals[0]);
	if (values.json) return asJson(io, list);
	if (list.length === 0) return void io.out.write(`no reference into or out of ${positionals[0]}\n`);
	for (const reference of list) {
		const state = reference.state === "live" ? "" : `  (${reference.state.replace("_", " ")})`;
		io.out.write(`${reference.holder} → ${reference.source}${state}\n`);
		io.out.write(`  made by ${shownMember$1(reference.createdBy).replace(/^user:/, "")} on ${reference.createdAt.slice(0, 10)}\n`);
		if (reference.readers !== null) io.out.write(`  read through by ${reference.readers.length === 0 ? "no one by a grant" : reference.readers.map((reader) => shownMember$1(reader).replace(/^user:/, "")).join(", ")}\n`);
	}
}
/**
* `coffre references break billing/prod/DATABASE_URL`: who would stop
* reading the source through it, and with --apply, the break. Whoever writes
* the holder may, and whoever manages the source's project's access.
*/
async function referencesBreak(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<project>/<environment>/<KEY>"]);
	const path = secret(positionals[0]);
	const api = connect();
	if (!values.apply) {
		const [reference] = (await api.references.list(path)).references.filter((each) => each.holder === path);
		if (reference === void 0) return void io.out.write(`${path} is no reference you can see\n`);
		const readers = reference.readers === null ? "whoever reads its environment" : reference.readers.map((reader) => shownMember$1(reader).replace(/^user:/, "")).join(", ") || "no one by a grant";
		io.out.write(`${path} reads ${reference.source}, made by ${shownMember$1(reference.createdBy).replace(/^user:/, "")} on ${reference.createdAt.slice(0, 10)}\n`);
		io.out.write(`breaking it stops ${readers} reading it there, and a run of its environment refuses until ${path.split("/")[2]} gets a value\n`);
		io.out.write("Nothing changed. Re-run with --apply to break it.\n");
		return;
	}
	const { reference } = await api.references.break(path);
	io.out.write(`broke ${reference.holder}: it no longer reads ${reference.source}\n`);
}
/**
* `coffre missing market/dev`: the keys its sibling environments have and it
* lacks, by name, whether you read them or not. With --check, a gate for CI:
* it fails when one is missing, and a dismissed key never fails it.
*/
async function missing(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		...json,
		dismissed: {
			type: "boolean",
			default: false
		},
		check: {
			type: "boolean",
			default: false
		}
	}, ["<project>/<environment>"]);
	if (values.check && values.dismissed) throw new UsageError("--check fails on the missing keys, --dismissed lists the others: one or the other");
	const { project, environment } = place(positionals[0], true);
	const path = `${project}/${environment}`;
	const result = await connect().environments.missing(path);
	const hint = `\`coffre set ${path}/<KEY>\` adds one; \`coffre missing dismiss ${path}/<KEY>\`, or --all, says it is not needed`;
	const incomplete = () => {
		const count = result.missing.length;
		return new CheckFailed(`${path} lacks ${count === 1 ? "a key" : `${count} keys`} its sibling environments have: ${hint}`);
	};
	if (values.json) {
		asJson(io, values.dismissed ? result.dismissed : result.missing);
		if (values.check && result.missing.length > 0) throw incomplete();
		return;
	}
	if (values.dismissed) {
		if (result.dismissed.length === 0) return void io.out.write(`nothing dismissed in ${path}\n`);
		for (const key of result.dismissed) io.out.write(`${key.key.padEnd(28)} in ${key.in.join(", ")}; dismissed by ${key.dismissedBy} on ${key.dismissedAt.slice(0, 10)}\n`);
		return;
	}
	if (result.missing.length === 0) {
		io.out.write(`${path} has every key of its sibling environments${result.dismissed.length === 0 ? "" : `, but ${result.dismissed.length} dismissed: --dismissed lists them`}\n`);
		return;
	}
	for (const key of result.missing) io.out.write(`${key.key.padEnd(28)} in ${key.in.join(", ")}\n`);
	if (values.check) throw incomplete();
	io.out.write(`\n${hint}\n`);
}
/** `coffre missing dismiss market/dev/KEY` (or `market/dev --all`), and `restore`: for the whole team, logged. */
async function missingDismiss(connect, args, dismiss, io = STDIO) {
	const { values, positionals } = parse(args, dismiss ? { all: {
		type: "boolean",
		default: false
	} } : {}, ["<project>/<environment>[/<KEY>]"]);
	const parts = positionals[0].split("/");
	const all = values.all === true;
	if (parts.length !== (all ? 2 : 3) || parts.some((part) => part === "")) throw new UsageError(all ? `--all takes <project>/<environment>, not "${positionals[0]}"` : `expected <project>/<environment>/<KEY>, not "${positionals[0]}"`);
	const path = parts.slice(0, 2).join("/");
	const api = connect();
	const keys = all ? (await api.environments.missing(path)).missing.map((key) => key.key) : [parts[2]];
	if (keys.length === 0) return void io.out.write(`nothing missing from ${path} to dismiss\n`);
	const { keys: outcomes } = await api.environments.dismiss(path, Object.fromEntries(keys.map((key) => [key, dismiss ? true : null])));
	for (const key of keys) {
		const outcome = outcomes[key];
		io.out.write(outcome === "unchanged" ? `${key} was ${dismiss ? "dismissed" : "not dismissed"} already\n` : `${outcome} ${key} in ${path}\n`);
	}
}
/**
* `coffre version market/prod`: a version of what reading it would open,
* which changes whenever a read would. No value is read and nothing is
* logged, so a script may poll it, and read only once it changed.
*/
async function version(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, json, ["<project>/<environment>"]);
	const { project, environment } = place(positionals[0], true);
	const result = await connect().environments.version(`${project}/${environment}`);
	if (values.json) return asJson(io, result);
	io.out.write(`${result.version}\n`);
}
/** `coffre move acme Clients`, `coffre move market/prod/STRIPE_KEY stripe`, or `--none` for out of its folder. */
async function move(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { none: {
		type: "boolean",
		default: false
	} }, ["<project> | <project>/<environment>/<KEY>", "<folder>"], 1);
	const [target, given] = positionals;
	if (values.none === (given !== void 0)) throw new UsageError(values.none ? "a folder, or --none, not both" : "name a folder, or --none for out of its folder");
	const folder = given ?? null;
	const api = connect();
	if (target.includes("/")) {
		const path = secret(target);
		await api.secrets.update(path, { folder });
		io.out.write(folder === null ? `${path} is in no folder now\n` : `${path} is in ${folder}/ now\n`);
		return;
	}
	const { project } = place(target, false);
	await api.projects.update(project, { folder });
	io.out.write(folder === null ? `${project} is in no folder now\n` : `${project} is in ${folder}/ now\n`);
}
/**
* What a folder command is about: the projects' folders, or, when its first
* argument is a `<project>/<environment>`, that environment's key folders.
* A folder's name has no `/`, so the two cannot be mistaken.
*/
function folderScope(positionals, folders) {
	const environment = positionals.length > folders ? positionals[0] : null;
	if (environment !== null) place(environment, true);
	const names = positionals.slice(environment === null ? 0 : 1);
	for (const name of names) if (name.includes("/")) throw new UsageError(`a folder's name has no /, so "${name}" is none: an environment's key folders are \`coffre folders <project>/<environment> …\``);
	return {
		environment,
		names
	};
}
/** Each folder and what is filed in it, by name: the projects', or an environment's keys. */
async function foldersIn(api, environment) {
	const filed = environment === null ? (await api.projects.list()).projects.map((project) => ({
		name: project.slug,
		folder: project.folder
	})) : (await api.secrets.list(environment)).keys.map((key) => ({
		name: key.key,
		folder: key.folder
	}));
	const folders = /* @__PURE__ */ new Map();
	for (const { name, folder } of filed) if (folder !== null) folders.set(folder, [...folders.get(folder) ?? [], name]);
	return [...folders].sort(([a], [b]) => a.localeCompare(b)).map(([folder, items]) => ({
		folder,
		items
	}));
}
/** `coffre folders [<project>/<environment>]`: each folder, and what is in it. */
async function folders(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, json, ["<project>/<environment>"], 1);
	const { environment } = folderScope(positionals, 0);
	const listed = await foldersIn(connect(), environment);
	if (values.json) return asJson(io, listed.map(({ folder, items }) => environment === null ? {
		folder,
		projects: items
	} : {
		folder,
		keys: items
	}));
	if (listed.length === 0) {
		io.out.write(environment === null ? "No project is in a folder. `coffre move <project> <folder>` files one, and makes the folder.\n" : `No key of ${environment} is in a folder. \`coffre move ${environment}/<KEY> <folder>\` files one, and makes the folder.\n`);
		return;
	}
	const width = Math.max(...listed.map(({ folder }) => folder.length)) + 1;
	for (const { folder, items } of listed) io.out.write(`${`${folder}/`.padEnd(width)}  ${items.join(", ")}\n`);
}
/** `coffre folders rename [<project>/<environment>] <folder> <new-folder>`: everything in it, re-filed. */
async function foldersRename(connect, args, io = STDIO) {
	const { positionals } = parse(args, {}, [
		"<project>/<environment>",
		"<folder>",
		"<new-folder>"
	], 1);
	const { environment, names } = folderScope(positionals, 2);
	const [folder, name] = names;
	const api = connect();
	const { moved } = environment === null ? await api.folders.rename(folder, name) : await api.folders.renameKeys(environment, folder, name);
	io.out.write(`${folder}/ is ${name}/ now${environment === null ? "" : ` in ${environment}`}: ${moved.join(", ")}\n`);
}
/**
* `coffre folders remove [<project>/<environment>] <folder> [--apply]`:
* everything out of it, each staying where it is, in no folder. More than
* one item is shown first; --apply does it.
*/
async function foldersRemove(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<project>/<environment>", "<folder>"], 1);
	const { environment, names } = folderScope(positionals, 1);
	const folder = names[0];
	const api = connect();
	const items = (await foldersIn(api, environment)).find((each) => each.folder === folder)?.items ?? [];
	const what = environment === null ? "project" : "key";
	if (items.length > 1 && !values.apply) {
		io.out.write(`would take ${items.length} ${what}s out of ${folder}/${environment === null ? "" : ` in ${environment}`}: ${items.join(", ")}. Each stays where it is, in no folder.\nNothing changed. Re-run with --apply to remove it.\n`);
		return;
	}
	const { moved } = environment === null ? await api.folders.remove(folder) : await api.folders.removeKeys(environment, folder);
	io.out.write(`${moved.join(", ")} ${moved.length === 1 ? "is" : "are"} in no folder now; ${folder}/ is gone\n`);
}
/** A name that says it is a service account's: `service:deploy`, or `token:deploy` as before. */
const SERVICE = /^(?:service|token):/;
/**
* A member as the API names it, `user:ada@acme.example` or `token:deploy`,
* from what was typed: a `service:` name, or --service, is a service account.
*/
function memberOf(name, service) {
	if (SERVICE.test(name)) return apiMember(name);
	return service ? serviceMember(name) : name.startsWith("user:") ? name : `user:${name}`;
}
/** A filter from its two flags, `--projects a,b` or `--except-projects a,b`; neither leaves it out. */
function filterOf(values, what) {
	const [only, except] = [values[what], values[`except-${what}`]];
	if (only !== void 0 && except !== void 0) throw new UsageError(`--${what} or --except-${what}, not both`);
	const list = (text) => text.split(",").map((name) => name.trim()).filter((name) => name !== "");
	if (only !== void 0) return { only: list(only) };
	if (except !== void 0) return { except: list(except) };
}
const SCOPE_FLAGS = {
	projects: { type: "string" },
	"except-projects": { type: "string" },
	environments: { type: "string" },
	"except-environments": { type: "string" }
};
/**
* `coffre admit ada@acme.example --role developer --environments dev`: a
* member, and for a person, their instance role and where it applies,
* every project and environment unless the scope flags narrow it. A
* service account takes its first grants with it, `--grant market/dev=developer`,
* in one call: refused, it is not admitted either.
*/
async function admit(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		service: {
			type: "boolean",
			default: false
		},
		role: { type: "string" },
		grant: {
			type: "string",
			multiple: true
		},
		...SCOPE_FLAGS
	}, ["<principal>"]);
	const name = positionals[0];
	const service = values.service || SERVICE.test(name);
	const role = values.role;
	let access;
	try {
		access = scopeFrom(values.grant, "--grant");
	} catch (error) {
		throw new UsageError(error.message);
	}
	if (access !== void 0 && (!service || role !== void 0)) throw new UsageError("--grant comes with a service account, and no --role: a person is granted once a member, coffre grant");
	if (role !== void 0 && !isInstanceRole(role)) throw new UsageError(`no instance role "${role}": member, auditor, developer, admin or owner`);
	const [projects, environments] = [filterOf(values, "projects"), filterOf(values, "environments")];
	const scoped = projects !== void 0 || environments !== void 0;
	if (scoped && role === void 0) throw new UsageError("a scope goes with a role: add --role");
	if (service && role !== void 0 && role !== "member") throw new UsageError("a service account holds project grants only: drop --role, then coffre grant");
	const who = memberOf(name, service);
	const result = await connect().members.add(who, access !== void 0 ? { access } : role === void 0 ? {} : {
		role,
		...scoped ? { scope: {
			...projects && { projects },
			...environments && { environments }
		} } : {}
	});
	const as = result.instanceRole === "member" ? "" : ` as ${roleInWords(result)}`;
	const shown = shownMember$1(result.member);
	const granted = access === void 0 ? "" : `, holding ${Object.entries(access).map(([place, held]) => `${held} on ${place}`).join(", ")}`;
	io.out.write(result.created ? `admitted ${shown}${as}${granted}\n` : `${shown} is a member${as}${role === void 0 && access === void 0 ? " already" : " now"}${granted}\n`);
	if (service && result.created && access === void 0) {
		const bare = serviceName(who);
		io.out.write(`  next: coffre grant <project> ${bare} --role viewer [--env <env>] --service,\n        then let its CI sign in by OIDC, coffre trust ${bare} --github … --apply,\n        or, for CI without OIDC, give it a bearer token, coffre tokens issue ${bare}\n`);
	}
}
/**
* `coffre settings`: the instance's settings. With `service-accounts` and
* the scope flags, where people set up service accounts themselves, which
* those who run the instance set: `--except-environments prod` keeps prod's
* to an Admin whose scope takes prod in. No flag is everywhere again.
*/
async function settings(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		...json,
		...SCOPE_FLAGS
	}, ["service-accounts"], 0);
	const api = connect();
	const [projects, environments] = [filterOf(values, "projects"), filterOf(values, "environments")];
	if (positionals[0] === void 0 && (projects !== void 0 || environments !== void 0)) throw new UsageError("the scope flags set one setting: coffre settings service-accounts --except-environments prod");
	if (positionals[0] !== void 0 && positionals[0] !== "service-accounts") throw new UsageError(`no setting "${positionals[0]}": service-accounts`);
	const result = positionals[0] === void 0 ? await api.settings.get() : await api.settings.set({ serviceAccounts: {
		...projects && { projects },
		...environments && { environments }
	} });
	if (values.json) return asJson(io, result);
	io.out.write(`service accounts, set up by anyone who holds access in: ${scopeInWords(result.serviceAccounts)}\n`);
}
async function revoke(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		env: { type: "string" },
		service: {
			type: "boolean",
			default: false
		}
	}, ["<project>", "<principal>"]);
	const [project, name] = positionals;
	onAProject(project);
	const scope = values.env === void 0 ? project : `${project}/${values.env}`;
	const who = memberOf(name, values.service);
	const { changes } = await connect().access.set(who, { [scope]: null });
	io.out.write(changes[scope] === "revoked" ? `revoked ${shownMember$1(who)}'s grant on ${scope}\n` : `${shownMember$1(who)} held no grant on ${scope}: nothing changed\n`);
}
/** What sets a role apart in a list: one an Owner made, or edited, or nobody edits. */
function marks(role) {
	const said = [role.fixed ? "fixed" : role.builtin ? role.edited ? "edited" : "" : "custom"].filter((mark) => mark !== "");
	return said.length === 0 ? "" : `  [${said.join(", ")}]`;
}
/** A column of permissions, `read, use`: a secret's without its prefix, the rest whole. */
function column(permissions) {
	return permissions.length === 0 ? "nothing" : permissions.map((permission) => permission.replace(/^secret\./, "")).join(", ");
}
/**
* `coffre roles`: every role, as the instance defines it, in its two
* columns: what it holds where nothing is protected, and in a protected
* environment, where a person holds the second (docs/design/roles.md).
* `coffre roles developer` says one, permission by permission.
*/
async function roles(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		...json,
		instance: {
			type: "boolean",
			default: false
		}
	}, ["<role>"], 1);
	const listed = await connect().roles.list();
	if (values.json) return asJson(io, positionals[0] === void 0 ? listed : roleNamed(listed, positionals[0], values.instance));
	if (positionals[0] !== void 0) {
		const role = roleNamed(listed, positionals[0], values.instance);
		io.out.write(`${role.id}  ${role.name}${marks(role)}${role.description === "" ? "" : `  ${role.description}`}\n`);
		const width = Math.max(...role.permissions.map((permission) => permission.length), 0) + 2;
		for (const permission of role.permissions) {
			const wide = PROJECT_ONLY_PERMISSIONS.includes(permission);
			io.out.write(`  ${permission.padEnd(width)}yes${wide ? "   on the project" : `   protected: ${role.protected.includes(permission) ? "yes" : "no"}`}\n`);
		}
		if (role.permissions.length === 0) io.out.write("  nothing\n");
		return;
	}
	const width = Math.max(...[...listed.instanceRoles, ...listed.roles].map((role) => column(role.permissions).length));
	const line = (role, project) => {
		const where = project ? role.assignableToEnvironment ? "project or env" : "project only" : "";
		return `  ${role.id.padEnd(16)} ${(project ? `[${where}]` : "").padEnd(project ? 17 : 0)}${column(role.permissions).padEnd(width)}  protected: ${column(role.protected)}${marks(role)}\n`;
	};
	io.out.write("Instance roles, a person's across every project in their scope (coffre admit --role):\n");
	for (const role of listed.instanceRoles) io.out.write(line(role, false));
	io.out.write("\nProject roles, a grant on a project or an environment (coffre grant --role):\n");
	for (const role of listed.roles) io.out.write(line(role, true));
	io.out.write("\nIn a protected environment a person holds the protected column; a service account, the other.\n");
	if (listed.editable) io.out.write("You edit them: coffre roles set <role> …, coffre roles reset <role>.\n");
}
function roleNamed(listed, id, instance) {
	const found = (instance ? listed.instanceRoles : listed.roles).find((role) => role.id === id);
	if (found === void 0) throw new UsageError(`no ${instance ? "instance " : ""}role "${id}": \`coffre roles\` lists them`);
	return found;
}
/** `read,use`, or `none`: permissions as a flag takes them, a secret's by its short name too. */
function permissionsFrom(text, flag) {
	if (text.trim() === "" || text.trim() === "none") return [];
	return [...new Set(text.split(",").map((word) => word.trim()).filter((word) => word !== "").map((word) => word.includes(".") ? word : `secret.${word}`))].map((permission) => {
		if (!/^[a-z]+\.[a-z]+$/.test(permission)) throw new UsageError(`${flag} takes permissions, as secret.read,secret.use or read,use; not "${permission}"`);
		return permission;
	});
}
const roleFlags = {
	name: { type: "string" },
	description: { type: "string" },
	permissions: { type: "string" },
	protected: { type: "string" },
	instance: {
		type: "boolean",
		default: false
	},
	apply: {
		type: "boolean",
		default: false
	}
};
/**
* `coffre roles set developer --protected use,write,read`: a role defined,
* a built-in one edited or one an Owner makes, by an Owner of the whole
* instance. What the flags leave out stays as it is; a new role holds
* nothing it is not given. Says what it would do to everyone it reaches
* first, and with --apply does it.
*/
async function rolesSet(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, roleFlags, ["<role>"]);
	const id = positionals[0];
	if (values.name === void 0 && values.description === void 0 && values.permissions === void 0 && values.protected === void 0) throw new UsageError("say what changes: --name, --description, --permissions or --protected");
	const api = connect();
	const listed = await api.roles.list();
	const current = (values.instance ? listed.instanceRoles : listed.roles).find((role) => role.id === id);
	if (current === void 0 && values.instance) throw new UsageError(`no instance role "${id}": an Owner makes project roles`);
	const permissions = values.permissions === void 0 ? current?.permissions ?? [] : permissionsFrom(values.permissions, "--permissions");
	const definition = {
		name: values.name ?? current?.name ?? id,
		description: values.description ?? current?.description ?? "",
		permissions,
		protected: values.protected === void 0 ? (current?.protected ?? []).filter((permission) => permissions.includes(permission)) : permissionsFrom(values.protected, "--protected")
	};
	const which = { instance: values.instance };
	const { sentence, revision } = await api.roles.preview(id, definition, which);
	const what = `${current === void 0 ? "a new role" : id}: ${column(definition.permissions)}, protected: ${column(definition.protected)}`;
	if (!values.apply) {
		io.out.write(`${what}\n  ${sentence}\nNothing changed. Re-run with --apply to save it.\n`);
		return;
	}
	await api.roles.set(id, definition, {
		...which,
		revision
	});
	io.out.write(`saved ${what}\n  ${sentence}\n`);
}
/**
* `coffre roles reset developer`: a built-in role back as it ships, what
* that does shown first, and with --apply done. `coffre roles remove`
* deletes one an Owner made.
*/
async function rolesReset(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		instance: roleFlags.instance,
		apply: roleFlags.apply
	}, ["<role>"]);
	const id = positionals[0];
	const api = connect();
	const role = roleNamed(await api.roles.list(), id, values.instance);
	if (!role.builtin) throw new UsageError(`${id} is one an Owner made: \`coffre roles remove ${id}\` deletes it`);
	if (!role.edited) return void io.out.write(`${id} is as it ships: nothing to reset\n`);
	const which = { instance: values.instance };
	const { sentence, revision } = await api.roles.previewReset(id, which);
	if (!values.apply) {
		io.out.write(`${id} back as it ships: ${column(role.default?.permissions ?? [])}, protected: ${column(role.default?.protected ?? [])}\n  ${sentence}\nNothing changed. Re-run with --apply to reset it.\n`);
		return;
	}
	await api.roles.reset(id, {
		...which,
		revision
	});
	io.out.write(`reset ${id}, as it ships\n  ${sentence}\n`);
}
/** `coffre roles remove release-manager`: a role an Owner made, deleted, once no grant names it. */
async function rolesRemove(connect, args, io = STDIO) {
	const { positionals } = parse(args, {}, ["<role>"]);
	const id = positionals[0];
	const api = connect();
	if (roleNamed(await api.roles.list(), id, false).builtin) throw new UsageError(`${id} ships with coffre, and stays: \`coffre roles reset ${id}\` puts it back as it ships`);
	await api.roles.reset(id);
	io.out.write(`removed ${id}\n`);
}
/**
* `coffre environments protect market/prod`: a person holds their role's
* protected column there (docs/design/roles.md); whoever manages the
* project's environments protects one, and only an Owner of the project,
* or of the whole instance, unprotects it.
*/
async function environmentsProtect(connect, args, on, io = STDIO) {
	const { positionals } = parse(args, {}, ["<project>/<environment>"]);
	const { project, environment } = place(positionals[0], true);
	const path = `${project}/${environment}`;
	const { environment: now } = await connect().environments.protect(path, on);
	io.out.write(now.protected ? `${path} is protected: each role holds there what its protected column says, for people; service accounts as before\n` : `${path} is not protected: each role holds there what it holds anywhere\n`);
}
/**
* Whose tokens a command is about: a service account's, named, or, with no
* name, the person's own personal tokens, which act as them.
*/
async function tokenHolder(api, named) {
	if (named !== void 0) return {
		member: serviceMember(named),
		personal: false
	};
	const { principal } = await api.me();
	if (principal.type !== "user") throw new UsageError("a service account holds no personal token: name the service, coffre tokens <service>");
	return {
		member: `user:${principal.id}`,
		personal: true
	};
}
/** When a token ends: its day for a service's, which last days; to the minute, in UTC, for a personal one, which lasts hours. */
function ends(iso, personal) {
	return personal ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : day(iso);
}
async function tokens(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, json, ["<service>"], 1);
	const api = connect();
	const { member, personal } = await tokenHolder(api, positionals[0]);
	const { tokens: list } = await api.tokens.list(member);
	if (values.json) return asJson(io, list);
	if (list.length === 0) io.out.write(personal ? "you hold no personal token: coffre tokens issue --label <label> --scope <project>/<environment>=<role>\n" : `${shownMember$1(member)} holds no bearer token: coffre tokens issue ${serviceName(member)}\n`);
	for (const token of list) io.out.write(`${token.id}  …${token.hint}  ${(token.label ?? "-").padEnd(16)}  expires ${ends(token.expiresAt, personal)}  last used ${day(token.lastUsedAt)}  reaches ${reaches(token.scope)}\n`);
}
/** A personal token's lifetime when `--expires-in` is left out: an hour. */
const PERSONAL_MINUTES = 60;
/**
* What `--expires-in` takes: `30m`, `4h`, `2d`, or a number alone, which
* is days, as a service token's always was. A service token lasts whole
* days, 1 to 366, 90 unless told; a personal token a minute to a week, an
* hour unless told. In days for a service token, in minutes for a personal one.
*/
function lifetime(text, personal) {
	if (text === void 0) return personal ? PERSONAL_MINUTES : 90;
	const match = /^(\d+)([mhd]?)$/.exec(text.trim());
	const count = match === null ? NaN : Number(match[1]);
	const unit = match?.[2] || "d";
	if (!personal) {
		if (unit !== "d" || !Number.isInteger(count) || count < 1 || count > 366) throw new UsageError(`--expires-in takes days for a service token, 1 to 366, as 90 or 90d; not "${text}"`);
		return count;
	}
	const minutes = count * {
		m: 1,
		h: 60,
		d: 1440
	}[unit];
	if (!Number.isInteger(minutes) || minutes < 1 || minutes > 10080) throw new UsageError(`--expires-in takes a personal token's lifetime, a minute to ${MAX_PERSONAL_TOKEN_MINUTES / 1440} days, as 30m, 4h or 2d; not "${text}"`);
	return minutes;
}
/**
* A new token, once: on stdout, or written to a file made for it, 0600, and
* never one already there. The file is made before the token is, so a path
* that cannot be written costs no token. With no service named, a personal
* token, acting as you within `--scope`, which it must say, as `--label`
* must: every entry it makes names it.
*/
async function tokensIssue(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, {
		"expires-in": { type: "string" },
		label: { type: "string" },
		scope: {
			type: "string",
			multiple: true
		},
		"output-file": { type: "string" }
	}, ["<service>"], 1);
	const personal = positionals[0] === void 0;
	const expiresIn = lifetime(values["expires-in"], personal);
	let scope;
	try {
		scope = scopeFrom(values.scope);
	} catch (error) {
		throw new UsageError(error.message);
	}
	if (personal && (values.label === void 0 || values.label.trim() === "")) throw new UsageError("a personal token needs --label, which every entry it makes names: --label cursor-agent");
	if (personal && scope === void 0) throw new UsageError("a personal token needs --scope, what it reaches of what you hold: --scope market/dev=viewer");
	const path = values["output-file"];
	const api = connect();
	const { member } = await tokenHolder(api, positionals[0]);
	let fd = null;
	if (path !== void 0) try {
		fd = openSync(path, "wx", 384);
	} catch (error) {
		const code = error.code;
		throw new Error(code === "EEXIST" ? `${path} exists already: the token goes only into a new file` : `cannot make ${path}: ${code ?? String(error)}`);
	}
	const unmake = () => {
		if (fd === null) return;
		closeSync(fd);
		rmSync(path, { force: true });
		fd = null;
	};
	process.once("exit", unmake);
	let issued;
	try {
		issued = await api.tokens.issue(member, personal ? {
			label: values.label.trim(),
			expiresInMinutes: expiresIn,
			scope
		} : {
			expiresInDays: expiresIn,
			label: values.label ?? null,
			...scope === void 0 ? {} : { scope }
		});
	} catch (error) {
		unmake();
		throw error;
	} finally {
		process.off("exit", unmake);
	}
	const about = personal ? `your personal token ${issued.id} "${values.label.trim()}", acting as you on ${reaches(issued.scope)}, until ${ends(issued.expiresAt, true)}` : `${shownMember$1(member)}'s bearer token ${issued.id}, reaching ${reaches(issued.scope)}, until ${day(issued.expiresAt)}`;
	const unread = withheldLine(issued.withheld);
	if (fd !== null) {
		writeSync(fd, `${issued.token}\n`);
		closeSync(fd);
		io.out.write(`wrote ${about}, to ${path}, readable by you alone\n`);
	} else {
		io.out.write(`${issued.token}\n`);
		if (io.err.isTTY) io.err.write(`coffre: ${about}. It is shown this once\n`);
	}
	if (unread !== null) io.err.write(`coffre: it ${unread}\n`);
}
async function tokensRevoke(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<service>", "<id>"], 1);
	const [named, id] = positionals.length === 1 ? [void 0, positionals[0]] : [positionals[0], positionals[1]];
	const api = connect();
	const { member, personal } = await tokenHolder(api, named);
	const token = (await api.tokens.list(member)).tokens.find((entry) => entry.id === id);
	if (token === void 0) throw new Error(personal ? `you hold no personal token ${id}: \`coffre tokens\` lists them` : `${shownMember$1(member)} holds no bearer token ${id}: \`coffre tokens ${serviceName(member)}\` lists them`);
	const what = `${personal ? "your personal token" : `${shownMember$1(member)}'s bearer token`} ${id}, …${token.hint}${token.label === null ? "" : ` "${token.label}"`}, last used ${day(token.lastUsedAt)}`;
	if (!values.apply) {
		io.out.write(`would revoke ${what}: whatever uses it stops at once.\nNothing changed. Re-run with --apply to revoke it.\n`);
		return;
	}
	await api.tokens.revoke(member, id);
	io.out.write(`revoked ${what}\n`);
}
/**
* A trust binding removed: first shown, with the CI runs it would cut off,
* then, with --apply, removed. The credentials it issued end with it.
*/
async function untrust(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<service>", "<binding-id>"]);
	const service = serviceMember(positionals[0]);
	const id = positionals[1];
	const api = connect();
	const binding = (await api.bindings.list(service)).bindings.find((entry) => entry.id === id);
	if (binding === void 0) throw new Error(`${shownMember$1(service)} has no trust binding ${id}: \`coffre trust ${serviceName(service)}\` lists them`);
	if (!values.apply) {
		io.out.write(describeRemoval(service, binding, false));
		return;
	}
	await api.bindings.remove(service, id);
	io.out.write(describeRemoval(service, binding, true));
}
async function sessions(connect, args, io = STDIO) {
	const { values } = parse(args, json, []);
	const { sessions: list } = await connect().sessions.list();
	if (values.json) return asJson(io, list);
	for (const session of list) {
		const label = session.label ?? session.provider ?? "";
		io.out.write(`${session.current ? "*" : " "} ${session.id}  ${session.kind.padEnd(7)}  …${session.hint}  ${label.padEnd(24)}  last used ${day(session.lastUsedAt)}  ends ${day(session.expiresAt)}\n`);
	}
}
async function sessionsRevoke(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<id>"]);
	const id = positionals[0];
	const api = connect();
	const session = (await api.sessions.list()).sessions.find((entry) => entry.id === id);
	if (session === void 0) throw new Error(`you have no session ${id}: \`coffre sessions\` lists them`);
	const what = `your ${session.kind} session ${id}${session.label === null ? "" : `, "${session.label}"`}, last used ${day(session.lastUsedAt)}`;
	const current = session.current ? ": the one this command runs with, so this CLI signs out too" : "";
	if (!values.apply) {
		io.out.write(`would sign out ${what}${current}.\nNothing changed. Re-run with --apply to sign it out.\n`);
		return;
	}
	await api.sessions.revoke(id);
	io.out.write(`signed out ${what}${current}\n`);
}
/** What `apps` says where the deployment serves no MCP, as `GET /me` reports its configuration. */
const MCP_OFF = "MCP is off on this instance: no app connects here. Its deployment's signin({ mcp }) turns it on (docs/mcp.md)";
/** The MCP clients you connected: Account › Connected apps. */
async function apps(connect, args, io = STDIO) {
	const { values } = parse(args, json, []);
	const api = connect();
	if (!(await api.me()).features.mcp) {
		if (values.json) return asJson(io, []);
		io.out.write(`${MCP_OFF}\n`);
		return;
	}
	const { apps: list } = await api.apps.list();
	if (values.json) return asJson(io, list);
	for (const app of list) {
		const name = `${app.name}${app.registration === "dcr" ? " (unverified)" : ""}`;
		io.out.write(`${app.id}  ${name.padEnd(28)}  ${(app.host ?? "-").padEnd(24)}  ${app.scopes.join(" ").padEnd(16)}  last used ${day(app.lastUsedAt)}  ends ${day(app.expiresAt)}\n`);
	}
}
async function appsRevoke(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<id>"]);
	const id = positionals[0];
	const api = connect();
	if (!(await api.me()).features.mcp) throw new Error(MCP_OFF);
	const app = (await api.apps.list()).apps.find((entry) => entry.id === id);
	if (app === void 0) throw new Error(`you have no connected app ${id}: \`coffre apps\` lists them`);
	const what = `${app.name}${app.host === null ? "" : ` (${app.host})`}, connected ${day(app.createdAt)}, last used ${day(app.lastUsedAt)}`;
	if (!values.apply) {
		io.out.write(`would disconnect ${what}: it would stop working at once.\nNothing changed. Re-run with --apply to disconnect it.\n`);
		return;
	}
	await api.apps.disconnect(id);
	io.out.write(`disconnected ${what}\n`);
}
async function identities(connect, args, io = STDIO) {
	const { values } = parse(args, json, []);
	const { identities: list } = await connect().identities.list();
	if (values.json) return asJson(io, list);
	for (const identity of list) io.out.write(`${identity.id}  ${identity.provider.padEnd(10)}  ${(identity.email ?? "-").padEnd(32)}  last sign-in ${day(identity.lastSignInAt)}\n`);
}
async function identitiesUnlink(connect, args, io = STDIO) {
	const { values, positionals } = parse(args, { apply: {
		type: "boolean",
		default: false
	} }, ["<id>"]);
	const id = positionals[0];
	const api = connect();
	const identity = (await api.identities.list()).identities.find((entry) => entry.id === id);
	if (identity === void 0) throw new Error(`you have no linked account ${id}: \`coffre identities\` lists them`);
	const what = `your ${identity.provider} account${identity.email === null ? "" : ` ${identity.email}`} (${id})`;
	if (!values.apply) {
		io.out.write(`would unlink ${what}: it would no longer sign you in, and its sessions would end.\nNothing changed. Re-run with --apply to unlink it.\n`);
		return;
	}
	await api.identities.unlink(id);
	io.out.write(`unlinked ${what}, and ended its sessions\n`);
}
//#endregion
//#region src/environments.ts
/** The environments named, `market/prod auth/prod`, each checked, none twice. */
function environmentPaths(positionals) {
	if (positionals.length === 0) throw new UsageError("name an environment: <project>/<environment>");
	for (const [i, path] of positionals.entries()) {
		const parts = path.split("/");
		if (parts.length !== 2 || parts.some((part) => part === "")) throw new UsageError(`expected <project>/<environment>, not "${path}"`);
		if (positionals.indexOf(path) !== i) throw new UsageError(`${path} is named twice`);
	}
	return [...positionals];
}
/**
* What `export --keys` names, words apart by spaces or lines: a key by its
* name, `DATABASE_URL`, or the keys that start with a prefix, `STRIPE_*`.
* Never every key: `coffre run` hands them all to one process.
*/
function keyPatterns(text) {
	const patterns = text.split(/\s+/).filter((word) => word !== "");
	if (patterns.length === 0) throw new UsageError("--keys names the keys to export: --keys \"DATABASE_URL STRIPE_*\"");
	for (const pattern of patterns) {
		if (pattern === "*") throw new UsageError("--keys names keys, or the keys a prefix starts, STRIPE_*, never all of them: `coffre run <project>/<environment> -- <command>` hands every key to one process");
		if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}\*?$/.test(pattern)) throw new UsageError(`--keys takes key names, or a prefix and *, as STRIPE_*, not "${pattern}"`);
	}
	return [...new Set(patterns)];
}
/** Whether `key` is one `pattern` names (`keyPatterns`). */
function keyNamed(pattern, key) {
	return pattern.endsWith("*") ? key.startsWith(pattern.slice(0, -1)) : key === pattern;
}
/**
* The keys two of the environments both define, by the pair, said in a
* line without a value: `deploy/prod and auth/prod both define API_URL and
* TOKEN`. Null when each key is in one environment only.
*/
function clash(environments) {
	const first = /* @__PURE__ */ new Map();
	const shared = /* @__PURE__ */ new Map();
	for (const [path, keys] of environments) for (const key of keys) {
		const at = first.get(key);
		if (at === void 0) {
			first.set(key, path);
			continue;
		}
		const pair = `${at} and ${path}`;
		shared.set(pair, [...shared.get(pair) ?? [], key]);
	}
	if (shared.size === 0) return null;
	return [...shared].map(([pair, keys]) => `${pair} both define ${listOf(keys.sort())}`).join("; ");
}
/** `a`, `a and b`, `a, b and c`. */
function listOf(items) {
	return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}
//#endregion
//#region src/secret.ts
/**
* One secret: typed at a hidden prompt on a terminal, or the whole of stdin,
* trimmed. Empty is refused, saying where it was looked for.
*/
async function readSecret(asked) {
	if (process.stdin.isTTY) {
		const value = await hiddenLine(process.stdin, process.stderr, style(process.stderr), `${asked.label}:`, asked.hint);
		if (value === "") throw new Error(`no ${lower(asked.label)} given`);
		return value;
	}
	const value = readFileSync(0, "utf8").trim();
	if (value === "") throw new Error(`no ${lower(asked.label)}: none came on stdin, and there is no terminal to ask on`);
	return value;
}
function lower(label) {
	return label.charAt(0).toLowerCase() + label.slice(1);
}
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/constants.js
var require_constants = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const BINARY_TYPES = [
		"nodebuffer",
		"arraybuffer",
		"fragments"
	];
	const hasBlob = typeof Blob !== "undefined";
	if (hasBlob) BINARY_TYPES.push("blob");
	module.exports = {
		BINARY_TYPES,
		CLOSE_TIMEOUT: 3e4,
		EMPTY_BUFFER: Buffer.alloc(0),
		GUID: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
		hasBlob,
		kForOnEventAttribute: Symbol("kIsForOnEventAttribute"),
		kListener: Symbol("kListener"),
		kStatusCode: Symbol("status-code"),
		kWebSocket: Symbol("websocket"),
		NOOP: () => {}
	};
}));
//#endregion
//#region \0absent:bufferutil
var require__absent_bufferutil = /* @__PURE__ */ __commonJSMin((() => {
	throw new Error("bufferutil is not in the Action's CLI");
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/buffer-util.js
var require_buffer_util = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { EMPTY_BUFFER } = require_constants();
	const FastBuffer = Buffer[Symbol.species];
	/**
	* Merges an array of buffers into a new buffer.
	*
	* @param {Buffer[]} list The array of buffers to concat
	* @param {Number} totalLength The total length of buffers in the list
	* @return {Buffer} The resulting buffer
	* @public
	*/
	function concat(list, totalLength) {
		if (list.length === 0) return EMPTY_BUFFER;
		if (list.length === 1) return list[0];
		const target = Buffer.allocUnsafe(totalLength);
		let offset = 0;
		for (let i = 0; i < list.length; i++) {
			const buf = list[i];
			target.set(buf, offset);
			offset += buf.length;
		}
		if (offset < totalLength) return new FastBuffer(target.buffer, target.byteOffset, offset);
		return target;
	}
	/**
	* Masks a buffer using the given mask.
	*
	* @param {Buffer} source The buffer to mask
	* @param {Buffer} mask The mask to use
	* @param {Buffer} output The buffer where to store the result
	* @param {Number} offset The offset at which to start writing
	* @param {Number} length The number of bytes to mask.
	* @public
	*/
	function _mask(source, mask, output, offset, length) {
		for (let i = 0; i < length; i++) output[offset + i] = source[i] ^ mask[i & 3];
	}
	/**
	* Unmasks a buffer using the given mask.
	*
	* @param {Buffer} buffer The buffer to unmask
	* @param {Buffer} mask The mask to use
	* @public
	*/
	function _unmask(buffer, mask) {
		for (let i = 0; i < buffer.length; i++) buffer[i] ^= mask[i & 3];
	}
	/**
	* Converts a buffer to an `ArrayBuffer`.
	*
	* @param {Buffer} buf The buffer to convert
	* @return {ArrayBuffer} Converted buffer
	* @public
	*/
	function toArrayBuffer(buf) {
		if (buf.length === buf.buffer.byteLength) return buf.buffer;
		return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
	}
	/**
	* Converts `data` to a `Buffer`.
	*
	* @param {*} data The data to convert
	* @return {Buffer} The buffer
	* @throws {TypeError}
	* @public
	*/
	function toBuffer(data) {
		toBuffer.readOnly = true;
		if (Buffer.isBuffer(data)) return data;
		let buf;
		if (data instanceof ArrayBuffer) buf = new FastBuffer(data);
		else if (ArrayBuffer.isView(data)) buf = new FastBuffer(data.buffer, data.byteOffset, data.byteLength);
		else {
			buf = Buffer.from(data);
			toBuffer.readOnly = false;
		}
		return buf;
	}
	module.exports = {
		concat,
		mask: _mask,
		toArrayBuffer,
		toBuffer,
		unmask: _unmask
	};
	/* istanbul ignore else  */
	if (!process.env.WS_NO_BUFFER_UTIL) try {
		const bufferUtil = require__absent_bufferutil();
		module.exports.mask = function(source, mask, output, offset, length) {
			if (length < 48) _mask(source, mask, output, offset, length);
			else bufferUtil.mask(source, mask, output, offset, length);
		};
		module.exports.unmask = function(buffer, mask) {
			if (buffer.length < 32) _unmask(buffer, mask);
			else bufferUtil.unmask(buffer, mask);
		};
	} catch (e) {}
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/limiter.js
var require_limiter = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const kDone = Symbol("kDone");
	const kRun = Symbol("kRun");
	/**
	* A very simple job queue with adjustable concurrency. Adapted from
	* https://github.com/STRML/async-limiter
	*/
	var Limiter = class {
		/**
		* Creates a new `Limiter`.
		*
		* @param {Number} [concurrency=Infinity] The maximum number of jobs allowed
		*     to run concurrently
		*/
		constructor(concurrency) {
			this[kDone] = () => {
				this.pending--;
				this[kRun]();
			};
			this.concurrency = concurrency || Infinity;
			this.jobs = [];
			this.pending = 0;
		}
		/**
		* Adds a job to the queue.
		*
		* @param {Function} job The job to run
		* @public
		*/
		add(job) {
			this.jobs.push(job);
			this[kRun]();
		}
		/**
		* Removes a job from the queue and runs it if possible.
		*
		* @private
		*/
		[kRun]() {
			if (this.pending === this.concurrency) return;
			if (this.jobs.length) {
				const job = this.jobs.shift();
				this.pending++;
				job(this[kDone]);
			}
		}
	};
	module.exports = Limiter;
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/permessage-deflate.js
var require_permessage_deflate = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const zlib = __require("node:zlib");
	const bufferUtil = require_buffer_util();
	const Limiter = require_limiter();
	const { kStatusCode } = require_constants();
	const FastBuffer = Buffer[Symbol.species];
	const TRAILER = Buffer.from([
		0,
		0,
		255,
		255
	]);
	const kPerMessageDeflate = Symbol("permessage-deflate");
	const kTotalLength = Symbol("total-length");
	const kCallback = Symbol("callback");
	const kBuffers = Symbol("buffers");
	const kError = Symbol("error");
	let zlibLimiter;
	/**
	* permessage-deflate implementation.
	*/
	var PerMessageDeflate = class {
		/**
		* Creates a PerMessageDeflate instance.
		*
		* @param {Object} [options] Configuration options
		* @param {(Boolean|Number)} [options.clientMaxWindowBits] Advertise support
		*     for, or request, a custom client window size
		* @param {Boolean} [options.clientNoContextTakeover=false] Advertise/
		*     acknowledge disabling of client context takeover
		* @param {Number} [options.concurrencyLimit=10] The number of concurrent
		*     calls to zlib
		* @param {Boolean} [options.isServer=false] Create the instance in either
		*     server or client mode
		* @param {Number} [options.maxPayload=0] The maximum allowed message length
		* @param {(Boolean|Number)} [options.serverMaxWindowBits] Request/confirm the
		*     use of a custom server window size
		* @param {Boolean} [options.serverNoContextTakeover=false] Request/accept
		*     disabling of server context takeover
		* @param {Number} [options.threshold=1024] Size (in bytes) below which
		*     messages should not be compressed if context takeover is disabled
		* @param {Object} [options.zlibDeflateOptions] Options to pass to zlib on
		*     deflate
		* @param {Object} [options.zlibInflateOptions] Options to pass to zlib on
		*     inflate
		*/
		constructor(options) {
			this._options = options || {};
			this._threshold = this._options.threshold !== void 0 ? this._options.threshold : 1024;
			this._maxPayload = this._options.maxPayload | 0;
			this._isServer = !!this._options.isServer;
			this._deflate = null;
			this._inflate = null;
			this.params = null;
			if (!zlibLimiter) {
				const concurrency = this._options.concurrencyLimit !== void 0 ? this._options.concurrencyLimit : 10;
				zlibLimiter = new Limiter(concurrency);
			}
		}
		/**
		* @type {String}
		*/
		static get extensionName() {
			return "permessage-deflate";
		}
		/**
		* Create an extension negotiation offer.
		*
		* @return {Object} Extension parameters
		* @public
		*/
		offer() {
			const params = {};
			if (this._options.serverNoContextTakeover) params.server_no_context_takeover = true;
			if (this._options.clientNoContextTakeover) params.client_no_context_takeover = true;
			if (this._options.serverMaxWindowBits) params.server_max_window_bits = this._options.serverMaxWindowBits;
			if (this._options.clientMaxWindowBits) params.client_max_window_bits = this._options.clientMaxWindowBits;
			else if (this._options.clientMaxWindowBits == null) params.client_max_window_bits = true;
			return params;
		}
		/**
		* Accept an extension negotiation offer/response.
		*
		* @param {Array} configurations The extension negotiation offers/reponse
		* @return {Object} Accepted configuration
		* @public
		*/
		accept(configurations) {
			configurations = this.normalizeParams(configurations);
			this.params = this._isServer ? this.acceptAsServer(configurations) : this.acceptAsClient(configurations);
			return this.params;
		}
		/**
		* Releases all resources used by the extension.
		*
		* @public
		*/
		cleanup() {
			if (this._inflate) {
				this._inflate.close();
				this._inflate = null;
			}
			if (this._deflate) {
				const callback = this._deflate[kCallback];
				this._deflate.close();
				this._deflate = null;
				if (callback) callback(/* @__PURE__ */ new Error("The deflate stream was closed while data was being processed"));
			}
		}
		/**
		*  Accept an extension negotiation offer.
		*
		* @param {Array} offers The extension negotiation offers
		* @return {Object} Accepted configuration
		* @private
		*/
		acceptAsServer(offers) {
			const opts = this._options;
			const accepted = offers.find((params) => {
				if (opts.serverNoContextTakeover === false && params.server_no_context_takeover || params.server_max_window_bits && (opts.serverMaxWindowBits === false || typeof opts.serverMaxWindowBits === "number" && opts.serverMaxWindowBits > params.server_max_window_bits) || typeof opts.clientMaxWindowBits === "number" && (typeof params.client_max_window_bits === "number" ? opts.clientMaxWindowBits > params.client_max_window_bits : !params.client_max_window_bits)) return false;
				return true;
			});
			if (!accepted) throw new Error("None of the extension offers can be accepted");
			if (opts.serverNoContextTakeover) accepted.server_no_context_takeover = true;
			if (opts.clientNoContextTakeover) accepted.client_no_context_takeover = true;
			if (typeof opts.serverMaxWindowBits === "number") accepted.server_max_window_bits = opts.serverMaxWindowBits;
			if (typeof opts.clientMaxWindowBits === "number") accepted.client_max_window_bits = opts.clientMaxWindowBits;
			else if (accepted.client_max_window_bits === true || opts.clientMaxWindowBits === false) delete accepted.client_max_window_bits;
			return accepted;
		}
		/**
		* Accept the extension negotiation response.
		*
		* @param {Array} response The extension negotiation response
		* @return {Object} Accepted configuration
		* @private
		*/
		acceptAsClient(response) {
			const params = response[0];
			if (this._options.clientNoContextTakeover === false && params.client_no_context_takeover) throw new Error("Unexpected parameter \"client_no_context_takeover\"");
			if (!params.client_max_window_bits) {
				if (typeof this._options.clientMaxWindowBits === "number") params.client_max_window_bits = this._options.clientMaxWindowBits;
			} else if (this._options.clientMaxWindowBits === false || typeof this._options.clientMaxWindowBits === "number" && params.client_max_window_bits > this._options.clientMaxWindowBits) throw new Error("Unexpected or invalid parameter \"client_max_window_bits\"");
			return params;
		}
		/**
		* Normalize parameters.
		*
		* @param {Array} configurations The extension negotiation offers/reponse
		* @return {Array} The offers/response with normalized parameters
		* @private
		*/
		normalizeParams(configurations) {
			configurations.forEach((params) => {
				Object.keys(params).forEach((key) => {
					let value = params[key];
					if (value.length > 1) throw new Error(`Parameter "${key}" must have only a single value`);
					value = value[0];
					if (key === "client_max_window_bits") {
						if (value !== true) {
							const num = +value;
							if (!Number.isInteger(num) || num < 8 || num > 15) throw new TypeError(`Invalid value for parameter "${key}": ${value}`);
							value = num;
						} else if (!this._isServer) throw new TypeError(`Invalid value for parameter "${key}": ${value}`);
					} else if (key === "server_max_window_bits") {
						const num = +value;
						if (!Number.isInteger(num) || num < 8 || num > 15) throw new TypeError(`Invalid value for parameter "${key}": ${value}`);
						value = num;
					} else if (key === "client_no_context_takeover" || key === "server_no_context_takeover") {
						if (value !== true) throw new TypeError(`Invalid value for parameter "${key}": ${value}`);
					} else throw new Error(`Unknown parameter "${key}"`);
					params[key] = value;
				});
			});
			return configurations;
		}
		/**
		* Decompress data. Concurrency limited.
		*
		* @param {Buffer} data Compressed data
		* @param {Boolean} fin Specifies whether or not this is the last fragment
		* @param {Function} callback Callback
		* @public
		*/
		decompress(data, fin, callback) {
			zlibLimiter.add((done) => {
				this._decompress(data, fin, (err, result) => {
					done();
					callback(err, result);
				});
			});
		}
		/**
		* Compress data. Concurrency limited.
		*
		* @param {(Buffer|String)} data Data to compress
		* @param {Boolean} fin Specifies whether or not this is the last fragment
		* @param {Function} callback Callback
		* @public
		*/
		compress(data, fin, callback) {
			zlibLimiter.add((done) => {
				this._compress(data, fin, (err, result) => {
					done();
					callback(err, result);
				});
			});
		}
		/**
		* Decompress data.
		*
		* @param {Buffer} data Compressed data
		* @param {Boolean} fin Specifies whether or not this is the last fragment
		* @param {Function} callback Callback
		* @private
		*/
		_decompress(data, fin, callback) {
			const endpoint = this._isServer ? "client" : "server";
			if (!this._inflate) {
				const key = `${endpoint}_max_window_bits`;
				const windowBits = typeof this.params[key] !== "number" ? zlib.Z_DEFAULT_WINDOWBITS : this.params[key];
				this._inflate = zlib.createInflateRaw({
					...this._options.zlibInflateOptions,
					windowBits
				});
				this._inflate[kPerMessageDeflate] = this;
				this._inflate[kTotalLength] = 0;
				this._inflate[kBuffers] = [];
				this._inflate.on("error", inflateOnError);
				this._inflate.on("data", inflateOnData);
			}
			this._inflate[kCallback] = callback;
			this._inflate.write(data);
			if (fin) this._inflate.write(TRAILER);
			this._inflate.flush(() => {
				const err = this._inflate[kError];
				if (err) {
					this._inflate.close();
					this._inflate = null;
					callback(err);
					return;
				}
				const data = bufferUtil.concat(this._inflate[kBuffers], this._inflate[kTotalLength]);
				if (this._inflate._readableState.endEmitted) {
					this._inflate.close();
					this._inflate = null;
				} else {
					this._inflate[kTotalLength] = 0;
					this._inflate[kBuffers] = [];
					if (fin && this.params[`${endpoint}_no_context_takeover`]) this._inflate.reset();
				}
				callback(null, data);
			});
		}
		/**
		* Compress data.
		*
		* @param {(Buffer|String)} data Data to compress
		* @param {Boolean} fin Specifies whether or not this is the last fragment
		* @param {Function} callback Callback
		* @private
		*/
		_compress(data, fin, callback) {
			const endpoint = this._isServer ? "server" : "client";
			if (!this._deflate) {
				const key = `${endpoint}_max_window_bits`;
				const windowBits = typeof this.params[key] !== "number" ? zlib.Z_DEFAULT_WINDOWBITS : this.params[key];
				this._deflate = zlib.createDeflateRaw({
					...this._options.zlibDeflateOptions,
					windowBits
				});
				this._deflate[kTotalLength] = 0;
				this._deflate[kBuffers] = [];
				this._deflate.on("data", deflateOnData);
			}
			this._deflate[kCallback] = callback;
			this._deflate.write(data);
			this._deflate.flush(zlib.Z_SYNC_FLUSH, () => {
				if (!this._deflate) return;
				let data = bufferUtil.concat(this._deflate[kBuffers], this._deflate[kTotalLength]);
				if (fin) data = new FastBuffer(data.buffer, data.byteOffset, data.length - 4);
				this._deflate[kCallback] = null;
				this._deflate[kTotalLength] = 0;
				this._deflate[kBuffers] = [];
				if (fin && this.params[`${endpoint}_no_context_takeover`]) this._deflate.reset();
				callback(null, data);
			});
		}
	};
	module.exports = PerMessageDeflate;
	/**
	* The listener of the `zlib.DeflateRaw` stream `'data'` event.
	*
	* @param {Buffer} chunk A chunk of data
	* @private
	*/
	function deflateOnData(chunk) {
		this[kBuffers].push(chunk);
		this[kTotalLength] += chunk.length;
	}
	/**
	* The listener of the `zlib.InflateRaw` stream `'data'` event.
	*
	* @param {Buffer} chunk A chunk of data
	* @private
	*/
	function inflateOnData(chunk) {
		this[kTotalLength] += chunk.length;
		if (this[kPerMessageDeflate]._maxPayload < 1 || this[kTotalLength] <= this[kPerMessageDeflate]._maxPayload) {
			this[kBuffers].push(chunk);
			return;
		}
		this[kError] = /* @__PURE__ */ new RangeError("Max payload size exceeded");
		this[kError].code = "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
		this[kError][kStatusCode] = 1009;
		this.removeListener("data", inflateOnData);
		this.reset();
	}
	/**
	* The listener of the `zlib.InflateRaw` stream `'error'` event.
	*
	* @param {Error} err The emitted error
	* @private
	*/
	function inflateOnError(err) {
		this[kPerMessageDeflate]._inflate = null;
		if (this[kError]) {
			this[kCallback](this[kError]);
			return;
		}
		err[kStatusCode] = 1007;
		this[kCallback](err);
	}
}));
//#endregion
//#region \0absent:utf-8-validate
var require__absent_utf_8_validate = /* @__PURE__ */ __commonJSMin((() => {
	throw new Error("utf-8-validate is not in the Action's CLI");
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/validation.js
var require_validation = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { isUtf8 } = __require("node:buffer");
	const { hasBlob } = require_constants();
	const tokenChars = [
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		1,
		0,
		1,
		1,
		1,
		1,
		1,
		0,
		0,
		1,
		1,
		0,
		1,
		1,
		0,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		0,
		0,
		0,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		1,
		0,
		1,
		0,
		1,
		0
	];
	/**
	* Checks if a status code is allowed in a close frame.
	*
	* @param {Number} code The status code
	* @return {Boolean} `true` if the status code is valid, else `false`
	* @public
	*/
	function isValidStatusCode(code) {
		return code >= 1e3 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006 || code >= 3e3 && code <= 4999;
	}
	/**
	* Checks if a given buffer contains only correct UTF-8.
	* Ported from https://www.cl.cam.ac.uk/%7Emgk25/ucs/utf8_check.c by
	* Markus Kuhn.
	*
	* @param {Buffer} buf The buffer to check
	* @return {Boolean} `true` if `buf` contains only correct UTF-8, else `false`
	* @public
	*/
	function _isValidUTF8(buf) {
		const len = buf.length;
		let i = 0;
		while (i < len) if ((buf[i] & 128) === 0) i++;
		else if ((buf[i] & 224) === 192) {
			if (i + 1 === len || (buf[i + 1] & 192) !== 128 || (buf[i] & 254) === 192) return false;
			i += 2;
		} else if ((buf[i] & 240) === 224) {
			if (i + 2 >= len || (buf[i + 1] & 192) !== 128 || (buf[i + 2] & 192) !== 128 || buf[i] === 224 && (buf[i + 1] & 224) === 128 || buf[i] === 237 && (buf[i + 1] & 224) === 160) return false;
			i += 3;
		} else if ((buf[i] & 248) === 240) {
			if (i + 3 >= len || (buf[i + 1] & 192) !== 128 || (buf[i + 2] & 192) !== 128 || (buf[i + 3] & 192) !== 128 || buf[i] === 240 && (buf[i + 1] & 240) === 128 || buf[i] === 244 && buf[i + 1] > 143 || buf[i] > 244) return false;
			i += 4;
		} else return false;
		return true;
	}
	/**
	* Determines whether a value is a `Blob`.
	*
	* @param {*} value The value to be tested
	* @return {Boolean} `true` if `value` is a `Blob`, else `false`
	* @private
	*/
	function isBlob(value) {
		return hasBlob && typeof value === "object" && typeof value.arrayBuffer === "function" && typeof value.type === "string" && typeof value.stream === "function" && (value[Symbol.toStringTag] === "Blob" || value[Symbol.toStringTag] === "File");
	}
	module.exports = {
		isBlob,
		isValidStatusCode,
		isValidUTF8: _isValidUTF8,
		tokenChars
	};
	if (isUtf8) module.exports.isValidUTF8 = function(buf) {
		return buf.length < 24 ? _isValidUTF8(buf) : isUtf8(buf);
	};
	else if (!process.env.WS_NO_UTF_8_VALIDATE) try {
		const isValidUTF8 = require__absent_utf_8_validate();
		module.exports.isValidUTF8 = function(buf) {
			return buf.length < 32 ? _isValidUTF8(buf) : isValidUTF8(buf);
		};
	} catch (e) {}
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/receiver.js
var require_receiver = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { Writable } = __require("node:stream");
	const PerMessageDeflate = require_permessage_deflate();
	const { BINARY_TYPES, EMPTY_BUFFER, kStatusCode, kWebSocket } = require_constants();
	const { concat, toArrayBuffer, unmask } = require_buffer_util();
	const { isValidStatusCode, isValidUTF8 } = require_validation();
	const FastBuffer = Buffer[Symbol.species];
	const GET_INFO = 0;
	const GET_PAYLOAD_LENGTH_16 = 1;
	const GET_PAYLOAD_LENGTH_64 = 2;
	const GET_MASK = 3;
	const GET_DATA = 4;
	const INFLATING = 5;
	const DEFER_EVENT = 6;
	/**
	* HyBi Receiver implementation.
	*
	* @extends Writable
	*/
	var Receiver = class extends Writable {
		/**
		* Creates a Receiver instance.
		*
		* @param {Object} [options] Options object
		* @param {Boolean} [options.allowSynchronousEvents=true] Specifies whether
		*     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
		*     multiple times in the same tick
		* @param {String} [options.binaryType=nodebuffer] The type for binary data
		* @param {Object} [options.extensions] An object containing the negotiated
		*     extensions
		* @param {Boolean} [options.isServer=false] Specifies whether to operate in
		*     client or server mode
		* @param {Number} [options.maxBufferedChunks=0] The maximum number of
		*     buffered data chunks
		* @param {Number} [options.maxFragments=0] The maximum number of message
		*     fragments
		* @param {Number} [options.maxPayload=0] The maximum allowed message length
		* @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
		*     not to skip UTF-8 validation for text and close messages
		*/
		constructor(options = {}) {
			super();
			this._allowSynchronousEvents = options.allowSynchronousEvents !== void 0 ? options.allowSynchronousEvents : true;
			this._binaryType = options.binaryType || BINARY_TYPES[0];
			this._extensions = options.extensions || {};
			this._isServer = !!options.isServer;
			this._maxBufferedChunks = options.maxBufferedChunks | 0;
			this._maxFragments = options.maxFragments | 0;
			this._maxPayload = options.maxPayload | 0;
			this._skipUTF8Validation = !!options.skipUTF8Validation;
			this[kWebSocket] = void 0;
			this._bufferedBytes = 0;
			this._buffers = [];
			this._compressed = false;
			this._payloadLength = 0;
			this._mask = void 0;
			this._fragmented = 0;
			this._masked = false;
			this._fin = false;
			this._opcode = 0;
			this._totalPayloadLength = 0;
			this._messageLength = 0;
			this._numFragments = 0;
			this._fragments = [];
			this._errored = false;
			this._loop = false;
			this._state = GET_INFO;
		}
		/**
		* Implements `Writable.prototype._write()`.
		*
		* @param {Buffer} chunk The chunk of data to write
		* @param {String} encoding The character encoding of `chunk`
		* @param {Function} cb Callback
		* @private
		*/
		_write(chunk, encoding, cb) {
			if (this._opcode === 8 && this._state == GET_INFO) return cb();
			if (this._maxBufferedChunks > 0 && this._buffers.length >= this._maxBufferedChunks) {
				cb(this.createError(RangeError, "Too many buffered chunks", false, 1008, "WS_ERR_TOO_MANY_BUFFERED_PARTS"));
				return;
			}
			this._bufferedBytes += chunk.length;
			this._buffers.push(chunk);
			this.startLoop(cb);
		}
		/**
		* Consumes `n` bytes from the buffered data.
		*
		* @param {Number} n The number of bytes to consume
		* @return {Buffer} The consumed bytes
		* @private
		*/
		consume(n) {
			this._bufferedBytes -= n;
			if (n === this._buffers[0].length) return this._buffers.shift();
			if (n < this._buffers[0].length) {
				const buf = this._buffers[0];
				this._buffers[0] = new FastBuffer(buf.buffer, buf.byteOffset + n, buf.length - n);
				return new FastBuffer(buf.buffer, buf.byteOffset, n);
			}
			const dst = Buffer.allocUnsafe(n);
			do {
				const buf = this._buffers[0];
				const offset = dst.length - n;
				if (n >= buf.length) dst.set(this._buffers.shift(), offset);
				else {
					dst.set(new Uint8Array(buf.buffer, buf.byteOffset, n), offset);
					this._buffers[0] = new FastBuffer(buf.buffer, buf.byteOffset + n, buf.length - n);
				}
				n -= buf.length;
			} while (n > 0);
			return dst;
		}
		/**
		* Starts the parsing loop.
		*
		* @param {Function} cb Callback
		* @private
		*/
		startLoop(cb) {
			this._loop = true;
			do
				switch (this._state) {
					case GET_INFO:
						this.getInfo(cb);
						break;
					case GET_PAYLOAD_LENGTH_16:
						this.getPayloadLength16(cb);
						break;
					case GET_PAYLOAD_LENGTH_64:
						this.getPayloadLength64(cb);
						break;
					case GET_MASK:
						this.getMask();
						break;
					case GET_DATA:
						this.getData(cb);
						break;
					case INFLATING:
					case DEFER_EVENT:
						this._loop = false;
						return;
				}
			while (this._loop);
			if (!this._errored) cb();
		}
		/**
		* Reads the first two bytes of a frame.
		*
		* @param {Function} cb Callback
		* @private
		*/
		getInfo(cb) {
			if (this._bufferedBytes < 2) {
				this._loop = false;
				return;
			}
			const buf = this.consume(2);
			if ((buf[0] & 48) !== 0) {
				cb(this.createError(RangeError, "RSV2 and RSV3 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_2_3"));
				return;
			}
			const compressed = (buf[0] & 64) === 64;
			if (compressed && !this._extensions[PerMessageDeflate.extensionName]) {
				cb(this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1"));
				return;
			}
			this._fin = (buf[0] & 128) === 128;
			this._opcode = buf[0] & 15;
			this._payloadLength = buf[1] & 127;
			if (this._opcode === 0) {
				if (compressed) {
					cb(this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1"));
					return;
				}
				if (!this._fragmented) {
					cb(this.createError(RangeError, "invalid opcode 0", true, 1002, "WS_ERR_INVALID_OPCODE"));
					return;
				}
				this._opcode = this._fragmented;
			} else if (this._opcode === 1 || this._opcode === 2) {
				if (this._fragmented) {
					cb(this.createError(RangeError, `invalid opcode ${this._opcode}`, true, 1002, "WS_ERR_INVALID_OPCODE"));
					return;
				}
				this._compressed = compressed;
			} else if (this._opcode > 7 && this._opcode < 11) {
				if (!this._fin) {
					cb(this.createError(RangeError, "FIN must be set", true, 1002, "WS_ERR_EXPECTED_FIN"));
					return;
				}
				if (compressed) {
					cb(this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1"));
					return;
				}
				if (this._payloadLength > 125 || this._opcode === 8 && this._payloadLength === 1) {
					cb(this.createError(RangeError, `invalid payload length ${this._payloadLength}`, true, 1002, "WS_ERR_INVALID_CONTROL_PAYLOAD_LENGTH"));
					return;
				}
			} else {
				cb(this.createError(RangeError, `invalid opcode ${this._opcode}`, true, 1002, "WS_ERR_INVALID_OPCODE"));
				return;
			}
			if (!this._fin && !this._fragmented) this._fragmented = this._opcode;
			this._masked = (buf[1] & 128) === 128;
			if (this._isServer) {
				if (!this._masked) {
					cb(this.createError(RangeError, "MASK must be set", true, 1002, "WS_ERR_EXPECTED_MASK"));
					return;
				}
			} else if (this._masked) {
				cb(this.createError(RangeError, "MASK must be clear", true, 1002, "WS_ERR_UNEXPECTED_MASK"));
				return;
			}
			if (this._payloadLength === 126) this._state = GET_PAYLOAD_LENGTH_16;
			else if (this._payloadLength === 127) this._state = GET_PAYLOAD_LENGTH_64;
			else this.haveLength(cb);
		}
		/**
		* Gets extended payload length (7+16).
		*
		* @param {Function} cb Callback
		* @private
		*/
		getPayloadLength16(cb) {
			if (this._bufferedBytes < 2) {
				this._loop = false;
				return;
			}
			this._payloadLength = this.consume(2).readUInt16BE(0);
			this.haveLength(cb);
		}
		/**
		* Gets extended payload length (7+64).
		*
		* @param {Function} cb Callback
		* @private
		*/
		getPayloadLength64(cb) {
			if (this._bufferedBytes < 8) {
				this._loop = false;
				return;
			}
			const buf = this.consume(8);
			const num = buf.readUInt32BE(0);
			if (num > Math.pow(2, 21) - 1) {
				cb(this.createError(RangeError, "Unsupported WebSocket frame: payload length > 2^53 - 1", false, 1009, "WS_ERR_UNSUPPORTED_DATA_PAYLOAD_LENGTH"));
				return;
			}
			this._payloadLength = num * Math.pow(2, 32) + buf.readUInt32BE(4);
			this.haveLength(cb);
		}
		/**
		* Payload length has been read.
		*
		* @param {Function} cb Callback
		* @private
		*/
		haveLength(cb) {
			if (this._payloadLength && this._opcode < 8) {
				this._totalPayloadLength += this._payloadLength;
				if (this._totalPayloadLength > this._maxPayload && this._maxPayload > 0) {
					cb(this.createError(RangeError, "Max payload size exceeded", false, 1009, "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH"));
					return;
				}
			}
			if (this._masked) this._state = GET_MASK;
			else this._state = GET_DATA;
		}
		/**
		* Reads mask bytes.
		*
		* @private
		*/
		getMask() {
			if (this._bufferedBytes < 4) {
				this._loop = false;
				return;
			}
			this._mask = this.consume(4);
			this._state = GET_DATA;
		}
		/**
		* Reads data bytes.
		*
		* @param {Function} cb Callback
		* @private
		*/
		getData(cb) {
			let data = EMPTY_BUFFER;
			if (this._payloadLength) {
				if (this._bufferedBytes < this._payloadLength) {
					this._loop = false;
					return;
				}
				data = this.consume(this._payloadLength);
				if (this._masked && (this._mask[0] | this._mask[1] | this._mask[2] | this._mask[3]) !== 0) unmask(data, this._mask);
			}
			if (this._opcode > 7) {
				this.controlMessage(data, cb);
				return;
			}
			if (this._maxFragments > 0 && ++this._numFragments > this._maxFragments) {
				cb(this.createError(RangeError, "Too many message fragments", false, 1008, "WS_ERR_TOO_MANY_BUFFERED_PARTS"));
				return;
			}
			if (this._compressed) {
				this._state = INFLATING;
				this.decompress(data, cb);
				return;
			}
			if (data.length) {
				this._messageLength = this._totalPayloadLength;
				this._fragments.push(data);
			}
			this.dataMessage(cb);
		}
		/**
		* Decompresses data.
		*
		* @param {Buffer} data Compressed data
		* @param {Function} cb Callback
		* @private
		*/
		decompress(data, cb) {
			this._extensions[PerMessageDeflate.extensionName].decompress(data, this._fin, (err, buf) => {
				if (err) return cb(err);
				if (buf.length) {
					this._messageLength += buf.length;
					if (this._messageLength > this._maxPayload && this._maxPayload > 0) {
						cb(this.createError(RangeError, "Max payload size exceeded", false, 1009, "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH"));
						return;
					}
					this._fragments.push(buf);
				}
				this.dataMessage(cb);
				if (this._state === GET_INFO) this.startLoop(cb);
			});
		}
		/**
		* Handles a data message.
		*
		* @param {Function} cb Callback
		* @private
		*/
		dataMessage(cb) {
			if (!this._fin) {
				this._state = GET_INFO;
				return;
			}
			const messageLength = this._messageLength;
			const fragments = this._fragments;
			this._totalPayloadLength = 0;
			this._messageLength = 0;
			this._fragmented = 0;
			this._numFragments = 0;
			this._fragments = [];
			if (this._opcode === 2) {
				let data;
				if (this._binaryType === "nodebuffer") data = concat(fragments, messageLength);
				else if (this._binaryType === "arraybuffer") data = toArrayBuffer(concat(fragments, messageLength));
				else if (this._binaryType === "blob") data = new Blob(fragments);
				else data = fragments;
				if (this._allowSynchronousEvents) {
					this.emit("message", data, true);
					this._state = GET_INFO;
				} else {
					this._state = DEFER_EVENT;
					setImmediate(() => {
						this.emit("message", data, true);
						this._state = GET_INFO;
						this.startLoop(cb);
					});
				}
			} else {
				const buf = concat(fragments, messageLength);
				if (!this._skipUTF8Validation && !isValidUTF8(buf)) {
					cb(this.createError(Error, "invalid UTF-8 sequence", true, 1007, "WS_ERR_INVALID_UTF8"));
					return;
				}
				if (this._state === INFLATING || this._allowSynchronousEvents) {
					this.emit("message", buf, false);
					this._state = GET_INFO;
				} else {
					this._state = DEFER_EVENT;
					setImmediate(() => {
						this.emit("message", buf, false);
						this._state = GET_INFO;
						this.startLoop(cb);
					});
				}
			}
		}
		/**
		* Handles a control message.
		*
		* @param {Buffer} data Data to handle
		* @return {(Error|RangeError|undefined)} A possible error
		* @private
		*/
		controlMessage(data, cb) {
			if (this._opcode === 8) {
				if (data.length === 0) {
					this._loop = false;
					this.emit("conclude", 1005, EMPTY_BUFFER);
					this.end();
				} else {
					const code = data.readUInt16BE(0);
					if (!isValidStatusCode(code)) {
						cb(this.createError(RangeError, `invalid status code ${code}`, true, 1002, "WS_ERR_INVALID_CLOSE_CODE"));
						return;
					}
					const buf = new FastBuffer(data.buffer, data.byteOffset + 2, data.length - 2);
					if (!this._skipUTF8Validation && !isValidUTF8(buf)) {
						cb(this.createError(Error, "invalid UTF-8 sequence", true, 1007, "WS_ERR_INVALID_UTF8"));
						return;
					}
					this._loop = false;
					this.emit("conclude", code, buf);
					this.end();
				}
				this._state = GET_INFO;
				return;
			}
			if (this._allowSynchronousEvents) {
				this.emit(this._opcode === 9 ? "ping" : "pong", data);
				this._state = GET_INFO;
			} else {
				this._state = DEFER_EVENT;
				setImmediate(() => {
					this.emit(this._opcode === 9 ? "ping" : "pong", data);
					this._state = GET_INFO;
					this.startLoop(cb);
				});
			}
		}
		/**
		* Builds an error object.
		*
		* @param {function(new:Error|RangeError)} ErrorCtor The error constructor
		* @param {String} message The error message
		* @param {Boolean} prefix Specifies whether or not to add a default prefix to
		*     `message`
		* @param {Number} statusCode The status code
		* @param {String} errorCode The exposed error code
		* @return {(Error|RangeError)} The error
		* @private
		*/
		createError(ErrorCtor, message, prefix, statusCode, errorCode) {
			this._loop = false;
			this._errored = true;
			const err = new ErrorCtor(prefix ? `Invalid WebSocket frame: ${message}` : message);
			Error.captureStackTrace(err, this.createError);
			err.code = errorCode;
			err[kStatusCode] = statusCode;
			return err;
		}
	};
	module.exports = Receiver;
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/sender.js
var require_sender = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { Duplex: Duplex$3 } = __require("node:stream");
	const { randomFillSync } = __require("node:crypto");
	const { types: { isUint8Array } } = __require("node:util");
	const PerMessageDeflate = require_permessage_deflate();
	const { EMPTY_BUFFER, kWebSocket, NOOP } = require_constants();
	const { isBlob, isValidStatusCode } = require_validation();
	const { mask: applyMask, toBuffer } = require_buffer_util();
	const kByteLength = Symbol("kByteLength");
	const maskBuffer = Buffer.alloc(4);
	const RANDOM_POOL_SIZE = 8192;
	let randomPool;
	let randomPoolPointer = RANDOM_POOL_SIZE;
	const DEFAULT = 0;
	const DEFLATING = 1;
	const GET_BLOB_DATA = 2;
	module.exports = class Sender {
		/**
		* Creates a Sender instance.
		*
		* @param {Duplex} socket The connection socket
		* @param {Object} [extensions] An object containing the negotiated extensions
		* @param {Function} [generateMask] The function used to generate the masking
		*     key
		*/
		constructor(socket, extensions, generateMask) {
			this._extensions = extensions || {};
			if (generateMask) {
				this._generateMask = generateMask;
				this._maskBuffer = Buffer.alloc(4);
			}
			this._socket = socket;
			this._firstFragment = true;
			this._compress = false;
			this._bufferedBytes = 0;
			this._queue = [];
			this._state = DEFAULT;
			this.onerror = NOOP;
			this[kWebSocket] = void 0;
		}
		/**
		* Frames a piece of data according to the HyBi WebSocket protocol.
		*
		* @param {(Buffer|String)} data The data to frame
		* @param {Object} options Options object
		* @param {Boolean} [options.fin=false] Specifies whether or not to set the
		*     FIN bit
		* @param {Function} [options.generateMask] The function used to generate the
		*     masking key
		* @param {Boolean} [options.mask=false] Specifies whether or not to mask
		*     `data`
		* @param {Buffer} [options.maskBuffer] The buffer used to store the masking
		*     key
		* @param {Number} options.opcode The opcode
		* @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
		*     modified
		* @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
		*     RSV1 bit
		* @return {(Buffer|String)[]} The framed data
		* @public
		*/
		static frame(data, options) {
			let mask;
			let merge = false;
			let offset = 2;
			let skipMasking = false;
			if (options.mask) {
				mask = options.maskBuffer || maskBuffer;
				if (options.generateMask) options.generateMask(mask);
				else {
					if (randomPoolPointer === RANDOM_POOL_SIZE) {
						/* istanbul ignore else  */
						if (randomPool === void 0) randomPool = Buffer.alloc(RANDOM_POOL_SIZE);
						randomFillSync(randomPool, 0, RANDOM_POOL_SIZE);
						randomPoolPointer = 0;
					}
					mask[0] = randomPool[randomPoolPointer++];
					mask[1] = randomPool[randomPoolPointer++];
					mask[2] = randomPool[randomPoolPointer++];
					mask[3] = randomPool[randomPoolPointer++];
				}
				skipMasking = (mask[0] | mask[1] | mask[2] | mask[3]) === 0;
				offset = 6;
			}
			let dataLength;
			if (typeof data === "string") {
				if ((!options.mask || skipMasking) && options[kByteLength] !== void 0) dataLength = options[kByteLength];
				else {
					data = Buffer.from(data);
					dataLength = data.length;
				}
			} else {
				dataLength = data.length;
				merge = options.mask && options.readOnly && !skipMasking;
			}
			let payloadLength = dataLength;
			if (dataLength >= 65536) {
				offset += 8;
				payloadLength = 127;
			} else if (dataLength > 125) {
				offset += 2;
				payloadLength = 126;
			}
			const target = Buffer.allocUnsafe(merge ? dataLength + offset : offset);
			target[0] = options.fin ? options.opcode | 128 : options.opcode;
			if (options.rsv1) target[0] |= 64;
			target[1] = payloadLength;
			if (payloadLength === 126) target.writeUInt16BE(dataLength, 2);
			else if (payloadLength === 127) {
				target[2] = target[3] = 0;
				target.writeUIntBE(dataLength, 4, 6);
			}
			if (!options.mask) return [target, data];
			target[1] |= 128;
			target[offset - 4] = mask[0];
			target[offset - 3] = mask[1];
			target[offset - 2] = mask[2];
			target[offset - 1] = mask[3];
			if (skipMasking) return [target, data];
			if (merge) {
				applyMask(data, mask, target, offset, dataLength);
				return [target];
			}
			applyMask(data, mask, data, 0, dataLength);
			return [target, data];
		}
		/**
		* Sends a close message to the other peer.
		*
		* @param {Number} [code] The status code component of the body
		* @param {(String|Buffer)} [data] The message component of the body
		* @param {Boolean} [mask=false] Specifies whether or not to mask the message
		* @param {Function} [cb] Callback
		* @public
		*/
		close(code, data, mask, cb) {
			let buf;
			if (code === void 0) buf = EMPTY_BUFFER;
			else if (typeof code !== "number" || !isValidStatusCode(code)) throw new TypeError("First argument must be a valid error code number");
			else if (data === void 0 || !data.length) {
				buf = Buffer.allocUnsafe(2);
				buf.writeUInt16BE(code, 0);
			} else {
				const length = Buffer.byteLength(data);
				if (length > 123) throw new RangeError("The message must not be greater than 123 bytes");
				buf = Buffer.allocUnsafe(2 + length);
				buf.writeUInt16BE(code, 0);
				if (typeof data === "string") buf.write(data, 2);
				else if (isUint8Array(data)) buf.set(data, 2);
				else throw new TypeError("Second argument must be a string or a Uint8Array");
			}
			const options = {
				[kByteLength]: buf.length,
				fin: true,
				generateMask: this._generateMask,
				mask,
				maskBuffer: this._maskBuffer,
				opcode: 8,
				readOnly: false,
				rsv1: false
			};
			if (this._state !== DEFAULT) this.enqueue([
				this.dispatch,
				buf,
				false,
				options,
				cb
			]);
			else this.sendFrame(Sender.frame(buf, options), cb);
		}
		/**
		* Sends a ping message to the other peer.
		*
		* @param {*} data The message to send
		* @param {Boolean} [mask=false] Specifies whether or not to mask `data`
		* @param {Function} [cb] Callback
		* @public
		*/
		ping(data, mask, cb) {
			let byteLength;
			let readOnly;
			if (typeof data === "string") {
				byteLength = Buffer.byteLength(data);
				readOnly = false;
			} else if (isBlob(data)) {
				byteLength = data.size;
				readOnly = false;
			} else {
				data = toBuffer(data);
				byteLength = data.length;
				readOnly = toBuffer.readOnly;
			}
			if (byteLength > 125) throw new RangeError("The data size must not be greater than 125 bytes");
			const options = {
				[kByteLength]: byteLength,
				fin: true,
				generateMask: this._generateMask,
				mask,
				maskBuffer: this._maskBuffer,
				opcode: 9,
				readOnly,
				rsv1: false
			};
			if (isBlob(data)) {
				if (this._state !== DEFAULT) this.enqueue([
					this.getBlobData,
					data,
					false,
					options,
					cb
				]);
				else this.getBlobData(data, false, options, cb);
			} else if (this._state !== DEFAULT) this.enqueue([
				this.dispatch,
				data,
				false,
				options,
				cb
			]);
			else this.sendFrame(Sender.frame(data, options), cb);
		}
		/**
		* Sends a pong message to the other peer.
		*
		* @param {*} data The message to send
		* @param {Boolean} [mask=false] Specifies whether or not to mask `data`
		* @param {Function} [cb] Callback
		* @public
		*/
		pong(data, mask, cb) {
			let byteLength;
			let readOnly;
			if (typeof data === "string") {
				byteLength = Buffer.byteLength(data);
				readOnly = false;
			} else if (isBlob(data)) {
				byteLength = data.size;
				readOnly = false;
			} else {
				data = toBuffer(data);
				byteLength = data.length;
				readOnly = toBuffer.readOnly;
			}
			if (byteLength > 125) throw new RangeError("The data size must not be greater than 125 bytes");
			const options = {
				[kByteLength]: byteLength,
				fin: true,
				generateMask: this._generateMask,
				mask,
				maskBuffer: this._maskBuffer,
				opcode: 10,
				readOnly,
				rsv1: false
			};
			if (isBlob(data)) {
				if (this._state !== DEFAULT) this.enqueue([
					this.getBlobData,
					data,
					false,
					options,
					cb
				]);
				else this.getBlobData(data, false, options, cb);
			} else if (this._state !== DEFAULT) this.enqueue([
				this.dispatch,
				data,
				false,
				options,
				cb
			]);
			else this.sendFrame(Sender.frame(data, options), cb);
		}
		/**
		* Sends a data message to the other peer.
		*
		* @param {*} data The message to send
		* @param {Object} options Options object
		* @param {Boolean} [options.binary=false] Specifies whether `data` is binary
		*     or text
		* @param {Boolean} [options.compress=false] Specifies whether or not to
		*     compress `data`
		* @param {Boolean} [options.fin=false] Specifies whether the fragment is the
		*     last one
		* @param {Boolean} [options.mask=false] Specifies whether or not to mask
		*     `data`
		* @param {Function} [cb] Callback
		* @public
		*/
		send(data, options, cb) {
			const perMessageDeflate = this._extensions[PerMessageDeflate.extensionName];
			let opcode = options.binary ? 2 : 1;
			let rsv1 = options.compress;
			let byteLength;
			let readOnly;
			if (typeof data === "string") {
				byteLength = Buffer.byteLength(data);
				readOnly = false;
			} else if (isBlob(data)) {
				byteLength = data.size;
				readOnly = false;
			} else {
				data = toBuffer(data);
				byteLength = data.length;
				readOnly = toBuffer.readOnly;
			}
			if (this._firstFragment) {
				this._firstFragment = false;
				if (rsv1 && perMessageDeflate && perMessageDeflate.params[perMessageDeflate._isServer ? "server_no_context_takeover" : "client_no_context_takeover"]) rsv1 = byteLength >= perMessageDeflate._threshold;
				this._compress = rsv1;
			} else {
				rsv1 = false;
				opcode = 0;
			}
			if (options.fin) this._firstFragment = true;
			const opts = {
				[kByteLength]: byteLength,
				fin: options.fin,
				generateMask: this._generateMask,
				mask: options.mask,
				maskBuffer: this._maskBuffer,
				opcode,
				readOnly,
				rsv1
			};
			if (isBlob(data)) {
				if (this._state !== DEFAULT) this.enqueue([
					this.getBlobData,
					data,
					this._compress,
					opts,
					cb
				]);
				else this.getBlobData(data, this._compress, opts, cb);
			} else if (this._state !== DEFAULT) this.enqueue([
				this.dispatch,
				data,
				this._compress,
				opts,
				cb
			]);
			else this.dispatch(data, this._compress, opts, cb);
		}
		/**
		* Gets the contents of a blob as binary data.
		*
		* @param {Blob} blob The blob
		* @param {Boolean} [compress=false] Specifies whether or not to compress
		*     the data
		* @param {Object} options Options object
		* @param {Boolean} [options.fin=false] Specifies whether or not to set the
		*     FIN bit
		* @param {Function} [options.generateMask] The function used to generate the
		*     masking key
		* @param {Boolean} [options.mask=false] Specifies whether or not to mask
		*     `data`
		* @param {Buffer} [options.maskBuffer] The buffer used to store the masking
		*     key
		* @param {Number} options.opcode The opcode
		* @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
		*     modified
		* @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
		*     RSV1 bit
		* @param {Function} [cb] Callback
		* @private
		*/
		getBlobData(blob, compress, options, cb) {
			this._bufferedBytes += options[kByteLength];
			this._state = GET_BLOB_DATA;
			blob.arrayBuffer().then((arrayBuffer) => {
				if (this._socket.destroyed) {
					const err = /* @__PURE__ */ new Error("The socket was closed while the blob was being read");
					process.nextTick(callCallbacks, this, err, cb);
					return;
				}
				this._bufferedBytes -= options[kByteLength];
				const data = toBuffer(arrayBuffer);
				if (!compress) {
					this._state = DEFAULT;
					this.sendFrame(Sender.frame(data, options), cb);
					this.dequeue();
				} else this.dispatch(data, compress, options, cb);
			}).catch((err) => {
				process.nextTick(onError, this, err, cb);
			});
		}
		/**
		* Dispatches a message.
		*
		* @param {(Buffer|String)} data The message to send
		* @param {Boolean} [compress=false] Specifies whether or not to compress
		*     `data`
		* @param {Object} options Options object
		* @param {Boolean} [options.fin=false] Specifies whether or not to set the
		*     FIN bit
		* @param {Function} [options.generateMask] The function used to generate the
		*     masking key
		* @param {Boolean} [options.mask=false] Specifies whether or not to mask
		*     `data`
		* @param {Buffer} [options.maskBuffer] The buffer used to store the masking
		*     key
		* @param {Number} options.opcode The opcode
		* @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
		*     modified
		* @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
		*     RSV1 bit
		* @param {Function} [cb] Callback
		* @private
		*/
		dispatch(data, compress, options, cb) {
			if (!compress) {
				this.sendFrame(Sender.frame(data, options), cb);
				return;
			}
			const perMessageDeflate = this._extensions[PerMessageDeflate.extensionName];
			this._bufferedBytes += options[kByteLength];
			this._state = DEFLATING;
			perMessageDeflate.compress(data, options.fin, (_, buf) => {
				if (this._socket.destroyed) {
					const err = /* @__PURE__ */ new Error("The socket was closed while data was being compressed");
					callCallbacks(this, err, cb);
					return;
				}
				this._bufferedBytes -= options[kByteLength];
				this._state = DEFAULT;
				options.readOnly = false;
				this.sendFrame(Sender.frame(buf, options), cb);
				this.dequeue();
			});
		}
		/**
		* Executes queued send operations.
		*
		* @private
		*/
		dequeue() {
			while (this._state === DEFAULT && this._queue.length) {
				const params = this._queue.shift();
				this._bufferedBytes -= params[3][kByteLength];
				Reflect.apply(params[0], this, params.slice(1));
			}
		}
		/**
		* Enqueues a send operation.
		*
		* @param {Array} params Send operation parameters.
		* @private
		*/
		enqueue(params) {
			this._bufferedBytes += params[3][kByteLength];
			this._queue.push(params);
		}
		/**
		* Sends a frame.
		*
		* @param {(Buffer | String)[]} list The frame to send
		* @param {Function} [cb] Callback
		* @private
		*/
		sendFrame(list, cb) {
			if (list.length === 2) {
				this._socket.cork();
				this._socket.write(list[0]);
				this._socket.write(list[1], cb);
				this._socket.uncork();
			} else this._socket.write(list[0], cb);
		}
	};
	/**
	* Calls queued callbacks with an error.
	*
	* @param {Sender} sender The `Sender` instance
	* @param {Error} err The error to call the callbacks with
	* @param {Function} [cb] The first callback
	* @private
	*/
	function callCallbacks(sender, err, cb) {
		if (typeof cb === "function") cb(err);
		for (let i = 0; i < sender._queue.length; i++) {
			const params = sender._queue[i];
			const callback = params[params.length - 1];
			if (typeof callback === "function") callback(err);
		}
	}
	/**
	* Handles a `Sender` error.
	*
	* @param {Sender} sender The `Sender` instance
	* @param {Error} err The error
	* @param {Function} [cb] The first pending callback
	* @private
	*/
	function onError(sender, err, cb) {
		callCallbacks(sender, err, cb);
		sender.onerror(err);
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/event-target.js
var require_event_target = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { kForOnEventAttribute, kListener } = require_constants();
	const kCode = Symbol("kCode");
	const kData = Symbol("kData");
	const kError = Symbol("kError");
	const kMessage = Symbol("kMessage");
	const kReason = Symbol("kReason");
	const kTarget = Symbol("kTarget");
	const kType = Symbol("kType");
	const kWasClean = Symbol("kWasClean");
	/**
	* Class representing an event.
	*/
	var Event = class {
		/**
		* Create a new `Event`.
		*
		* @param {String} type The name of the event
		* @throws {TypeError} If the `type` argument is not specified
		*/
		constructor(type) {
			this[kTarget] = null;
			this[kType] = type;
		}
		/**
		* @type {*}
		*/
		get target() {
			return this[kTarget];
		}
		/**
		* @type {String}
		*/
		get type() {
			return this[kType];
		}
	};
	Object.defineProperty(Event.prototype, "target", { enumerable: true });
	Object.defineProperty(Event.prototype, "type", { enumerable: true });
	/**
	* Class representing a close event.
	*
	* @extends Event
	*/
	var CloseEvent = class extends Event {
		/**
		* Create a new `CloseEvent`.
		*
		* @param {String} type The name of the event
		* @param {Object} [options] A dictionary object that allows for setting
		*     attributes via object members of the same name
		* @param {Number} [options.code=0] The status code explaining why the
		*     connection was closed
		* @param {String} [options.reason=''] A human-readable string explaining why
		*     the connection was closed
		* @param {Boolean} [options.wasClean=false] Indicates whether or not the
		*     connection was cleanly closed
		*/
		constructor(type, options = {}) {
			super(type);
			this[kCode] = options.code === void 0 ? 0 : options.code;
			this[kReason] = options.reason === void 0 ? "" : options.reason;
			this[kWasClean] = options.wasClean === void 0 ? false : options.wasClean;
		}
		/**
		* @type {Number}
		*/
		get code() {
			return this[kCode];
		}
		/**
		* @type {String}
		*/
		get reason() {
			return this[kReason];
		}
		/**
		* @type {Boolean}
		*/
		get wasClean() {
			return this[kWasClean];
		}
	};
	Object.defineProperty(CloseEvent.prototype, "code", { enumerable: true });
	Object.defineProperty(CloseEvent.prototype, "reason", { enumerable: true });
	Object.defineProperty(CloseEvent.prototype, "wasClean", { enumerable: true });
	/**
	* Class representing an error event.
	*
	* @extends Event
	*/
	var ErrorEvent = class extends Event {
		/**
		* Create a new `ErrorEvent`.
		*
		* @param {String} type The name of the event
		* @param {Object} [options] A dictionary object that allows for setting
		*     attributes via object members of the same name
		* @param {*} [options.error=null] The error that generated this event
		* @param {String} [options.message=''] The error message
		*/
		constructor(type, options = {}) {
			super(type);
			this[kError] = options.error === void 0 ? null : options.error;
			this[kMessage] = options.message === void 0 ? "" : options.message;
		}
		/**
		* @type {*}
		*/
		get error() {
			return this[kError];
		}
		/**
		* @type {String}
		*/
		get message() {
			return this[kMessage];
		}
	};
	Object.defineProperty(ErrorEvent.prototype, "error", { enumerable: true });
	Object.defineProperty(ErrorEvent.prototype, "message", { enumerable: true });
	/**
	* Class representing a message event.
	*
	* @extends Event
	*/
	var MessageEvent = class extends Event {
		/**
		* Create a new `MessageEvent`.
		*
		* @param {String} type The name of the event
		* @param {Object} [options] A dictionary object that allows for setting
		*     attributes via object members of the same name
		* @param {*} [options.data=null] The message content
		*/
		constructor(type, options = {}) {
			super(type);
			this[kData] = options.data === void 0 ? null : options.data;
		}
		/**
		* @type {*}
		*/
		get data() {
			return this[kData];
		}
	};
	Object.defineProperty(MessageEvent.prototype, "data", { enumerable: true });
	module.exports = {
		CloseEvent,
		ErrorEvent,
		Event,
		EventTarget: {
			/**
			* Register an event listener.
			*
			* @param {String} type A string representing the event type to listen for
			* @param {(Function|Object)} handler The listener to add
			* @param {Object} [options] An options object specifies characteristics about
			*     the event listener
			* @param {Boolean} [options.once=false] A `Boolean` indicating that the
			*     listener should be invoked at most once after being added. If `true`,
			*     the listener would be automatically removed when invoked.
			* @public
			*/
			addEventListener(type, handler, options = {}) {
				for (const listener of this.listeners(type)) if (!options[kForOnEventAttribute] && listener[kListener] === handler && !listener[kForOnEventAttribute]) return;
				let wrapper;
				if (type === "message") wrapper = function onMessage(data, isBinary) {
					const event = new MessageEvent("message", { data: isBinary ? data : data.toString() });
					event[kTarget] = this;
					callListener(handler, this, event);
				};
				else if (type === "close") wrapper = function onClose(code, message) {
					const event = new CloseEvent("close", {
						code,
						reason: message.toString(),
						wasClean: this._closeFrameReceived && this._closeFrameSent
					});
					event[kTarget] = this;
					callListener(handler, this, event);
				};
				else if (type === "error") wrapper = function onError(error) {
					const event = new ErrorEvent("error", {
						error,
						message: error.message
					});
					event[kTarget] = this;
					callListener(handler, this, event);
				};
				else if (type === "open") wrapper = function onOpen() {
					const event = new Event("open");
					event[kTarget] = this;
					callListener(handler, this, event);
				};
				else return;
				wrapper[kForOnEventAttribute] = !!options[kForOnEventAttribute];
				wrapper[kListener] = handler;
				if (options.once) this.once(type, wrapper);
				else this.on(type, wrapper);
			},
			/**
			* Remove an event listener.
			*
			* @param {String} type A string representing the event type to remove
			* @param {(Function|Object)} handler The listener to remove
			* @public
			*/
			removeEventListener(type, handler) {
				for (const listener of this.listeners(type)) if (listener[kListener] === handler && !listener[kForOnEventAttribute]) {
					this.removeListener(type, listener);
					break;
				}
			}
		},
		MessageEvent
	};
	/**
	* Call an event listener
	*
	* @param {(Function|Object)} listener The listener to call
	* @param {*} thisArg The value to use as `this`` when calling the listener
	* @param {Event} event The event to pass to the listener
	* @private
	*/
	function callListener(listener, thisArg, event) {
		if (typeof listener === "object" && listener.handleEvent) listener.handleEvent.call(listener, event);
		else listener.call(thisArg, event);
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/extension.js
var require_extension = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { tokenChars } = require_validation();
	/**
	* Adds an offer to the map of extension offers or a parameter to the map of
	* parameters.
	*
	* @param {Object} dest The map of extension offers or parameters
	* @param {String} name The extension or parameter name
	* @param {(Object|Boolean|String)} elem The extension parameters or the
	*     parameter value
	* @private
	*/
	function push(dest, name, elem) {
		if (dest[name] === void 0) dest[name] = [elem];
		else dest[name].push(elem);
	}
	/**
	* Parses the `Sec-WebSocket-Extensions` header into an object.
	*
	* @param {String} header The field value of the header
	* @return {Object} The parsed object
	* @public
	*/
	function parse(header) {
		const offers = Object.create(null);
		let params = Object.create(null);
		let mustUnescape = false;
		let isEscaping = false;
		let inQuotes = false;
		let extensionName;
		let paramName;
		let start = -1;
		let code = -1;
		let end = -1;
		let i = 0;
		for (; i < header.length; i++) {
			code = header.charCodeAt(i);
			if (extensionName === void 0) {
				if (end === -1 && tokenChars[code] === 1) {
					if (start === -1) start = i;
				} else if (i !== 0 && (code === 32 || code === 9)) {
					if (end === -1 && start !== -1) end = i;
				} else if (code === 59 || code === 44) {
					if (start === -1) throw new SyntaxError(`Unexpected character at index ${i}`);
					if (end === -1) end = i;
					const name = header.slice(start, end);
					if (code === 44) {
						push(offers, name, params);
						params = Object.create(null);
					} else extensionName = name;
					start = end = -1;
				} else throw new SyntaxError(`Unexpected character at index ${i}`);
			} else if (paramName === void 0) {
				if (end === -1 && tokenChars[code] === 1) {
					if (start === -1) start = i;
				} else if (code === 32 || code === 9) {
					if (end === -1 && start !== -1) end = i;
				} else if (code === 59 || code === 44) {
					if (start === -1) throw new SyntaxError(`Unexpected character at index ${i}`);
					if (end === -1) end = i;
					push(params, header.slice(start, end), true);
					if (code === 44) {
						push(offers, extensionName, params);
						params = Object.create(null);
						extensionName = void 0;
					}
					start = end = -1;
				} else if (code === 61 && start !== -1 && end === -1) {
					paramName = header.slice(start, i);
					start = end = -1;
				} else throw new SyntaxError(`Unexpected character at index ${i}`);
			} else if (isEscaping) {
				if (tokenChars[code] !== 1) throw new SyntaxError(`Unexpected character at index ${i}`);
				if (start === -1) start = i;
				else if (!mustUnescape) mustUnescape = true;
				isEscaping = false;
			} else if (inQuotes) {
				if (tokenChars[code] === 1) {
					if (start === -1) start = i;
				} else if (code === 34 && start !== -1) {
					inQuotes = false;
					end = i;
				} else if (code === 92) isEscaping = true;
				else throw new SyntaxError(`Unexpected character at index ${i}`);
			} else if (code === 34 && header.charCodeAt(i - 1) === 61) inQuotes = true;
			else if (end === -1 && tokenChars[code] === 1) {
				if (start === -1) start = i;
			} else if (start !== -1 && (code === 32 || code === 9)) {
				if (end === -1) end = i;
			} else if (code === 59 || code === 44) {
				if (start === -1) throw new SyntaxError(`Unexpected character at index ${i}`);
				if (end === -1) end = i;
				let value = header.slice(start, end);
				if (mustUnescape) {
					value = value.replace(/\\/g, "");
					mustUnescape = false;
				}
				push(params, paramName, value);
				if (code === 44) {
					push(offers, extensionName, params);
					params = Object.create(null);
					extensionName = void 0;
				}
				paramName = void 0;
				start = end = -1;
			} else throw new SyntaxError(`Unexpected character at index ${i}`);
		}
		if (start === -1 || inQuotes || code === 32 || code === 9) throw new SyntaxError("Unexpected end of input");
		if (end === -1) end = i;
		const token = header.slice(start, end);
		if (extensionName === void 0) push(offers, token, params);
		else {
			if (paramName === void 0) push(params, token, true);
			else if (mustUnescape) push(params, paramName, token.replace(/\\/g, ""));
			else push(params, paramName, token);
			push(offers, extensionName, params);
		}
		return offers;
	}
	/**
	* Builds the `Sec-WebSocket-Extensions` header field value.
	*
	* @param {Object} extensions The map of extensions and parameters to format
	* @return {String} A string representing the given object
	* @public
	*/
	function format(extensions) {
		return Object.keys(extensions).map((extension) => {
			let configurations = extensions[extension];
			if (!Array.isArray(configurations)) configurations = [configurations];
			return configurations.map((params) => {
				return [extension].concat(Object.keys(params).map((k) => {
					let values = params[k];
					if (!Array.isArray(values)) values = [values];
					return values.map((v) => v === true ? k : `${k}=${v}`).join("; ");
				})).join("; ");
			}).join(", ");
		}).join(", ");
	}
	module.exports = {
		format,
		parse
	};
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/websocket.js
var require_websocket = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const EventEmitter$1 = __require("node:events");
	const https = __require("node:https");
	const http$2 = __require("node:http");
	const net = __require("node:net");
	const tls = __require("node:tls");
	const { randomBytes: randomBytes$2, createHash: createHash$2 } = __require("node:crypto");
	const { Duplex: Duplex$2, Readable: Readable$1 } = __require("node:stream");
	const { URL: URL$1 } = __require("node:url");
	const PerMessageDeflate = require_permessage_deflate();
	const Receiver = require_receiver();
	const Sender = require_sender();
	const { isBlob } = require_validation();
	const { BINARY_TYPES, CLOSE_TIMEOUT, EMPTY_BUFFER, GUID, kForOnEventAttribute, kListener, kStatusCode, kWebSocket, NOOP } = require_constants();
	const { EventTarget: { addEventListener, removeEventListener } } = require_event_target();
	const { format, parse } = require_extension();
	const { toBuffer } = require_buffer_util();
	const kAborted = Symbol("kAborted");
	const protocolVersions = [8, 13];
	const readyStates = [
		"CONNECTING",
		"OPEN",
		"CLOSING",
		"CLOSED"
	];
	const subprotocolRegex = /^[!#$%&'*+\-.0-9A-Z^_`|a-z~]+$/;
	/**
	* Class representing a WebSocket.
	*
	* @extends EventEmitter
	*/
	var WebSocket = class WebSocket extends EventEmitter$1 {
		/**
		* Create a new `WebSocket`.
		*
		* @param {(String|URL)} address The URL to which to connect
		* @param {(String|String[])} [protocols] The subprotocols
		* @param {Object} [options] Connection options
		*/
		constructor(address, protocols, options) {
			super();
			this._binaryType = BINARY_TYPES[0];
			this._closeCode = 1006;
			this._closeFrameReceived = false;
			this._closeFrameSent = false;
			this._closeMessage = EMPTY_BUFFER;
			this._closeTimer = null;
			this._errorEmitted = false;
			this._extensions = {};
			this._paused = false;
			this._protocol = "";
			this._readyState = WebSocket.CONNECTING;
			this._receiver = null;
			this._sender = null;
			this._socket = null;
			if (address !== null) {
				this._bufferedAmount = 0;
				this._isServer = false;
				this._redirects = 0;
				if (protocols === void 0) protocols = [];
				else if (!Array.isArray(protocols)) {
					if (typeof protocols === "object" && protocols !== null) {
						options = protocols;
						protocols = [];
					} else protocols = [protocols];
				}
				initAsClient(this, address, protocols, options);
			} else {
				this._autoPong = options.autoPong;
				this._closeTimeout = options.closeTimeout;
				this._isServer = true;
			}
		}
		/**
		* For historical reasons, the custom "nodebuffer" type is used by the default
		* instead of "blob".
		*
		* @type {String}
		*/
		get binaryType() {
			return this._binaryType;
		}
		set binaryType(type) {
			if (!BINARY_TYPES.includes(type)) return;
			this._binaryType = type;
			if (this._receiver) this._receiver._binaryType = type;
		}
		/**
		* @type {Number}
		*/
		get bufferedAmount() {
			if (!this._socket) return this._bufferedAmount;
			return this._socket._writableState.length + this._sender._bufferedBytes;
		}
		/**
		* @type {String}
		*/
		get extensions() {
			return Object.keys(this._extensions).join();
		}
		/**
		* @type {Boolean}
		*/
		get isPaused() {
			return this._paused;
		}
		/**
		* @type {Function}
		*/
		/* istanbul ignore next */
		get onclose() {
			return null;
		}
		/**
		* @type {Function}
		*/
		/* istanbul ignore next */
		get onerror() {
			return null;
		}
		/**
		* @type {Function}
		*/
		/* istanbul ignore next */
		get onopen() {
			return null;
		}
		/**
		* @type {Function}
		*/
		/* istanbul ignore next */
		get onmessage() {
			return null;
		}
		/**
		* @type {String}
		*/
		get protocol() {
			return this._protocol;
		}
		/**
		* @type {Number}
		*/
		get readyState() {
			return this._readyState;
		}
		/**
		* @type {String}
		*/
		get url() {
			return this._url;
		}
		/**
		* Set up the socket and the internal resources.
		*
		* @param {Duplex} socket The network socket between the server and client
		* @param {Buffer} head The first packet of the upgraded stream
		* @param {Object} options Options object
		* @param {Boolean} [options.allowSynchronousEvents=false] Specifies whether
		*     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
		*     multiple times in the same tick
		* @param {Function} [options.generateMask] The function used to generate the
		*     masking key
		* @param {Number} [options.maxBufferedChunks=0] The maximum number of
		*     buffered data chunks
		* @param {Number} [options.maxFragments=0] The maximum number of message
		*     fragments
		* @param {Number} [options.maxPayload=0] The maximum allowed message size
		* @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
		*     not to skip UTF-8 validation for text and close messages
		* @private
		*/
		setSocket(socket, head, options) {
			const receiver = new Receiver({
				allowSynchronousEvents: options.allowSynchronousEvents,
				binaryType: this.binaryType,
				extensions: this._extensions,
				isServer: this._isServer,
				maxBufferedChunks: options.maxBufferedChunks,
				maxFragments: options.maxFragments,
				maxPayload: options.maxPayload,
				skipUTF8Validation: options.skipUTF8Validation
			});
			const sender = new Sender(socket, this._extensions, options.generateMask);
			this._receiver = receiver;
			this._sender = sender;
			this._socket = socket;
			receiver[kWebSocket] = this;
			sender[kWebSocket] = this;
			socket[kWebSocket] = this;
			receiver.on("conclude", receiverOnConclude);
			receiver.on("drain", receiverOnDrain);
			receiver.on("error", receiverOnError);
			receiver.on("message", receiverOnMessage);
			receiver.on("ping", receiverOnPing);
			receiver.on("pong", receiverOnPong);
			sender.onerror = senderOnError;
			if (socket.setTimeout) socket.setTimeout(0);
			if (socket.setNoDelay) socket.setNoDelay();
			if (head.length > 0) socket.unshift(head);
			socket.on("close", socketOnClose);
			socket.on("data", socketOnData);
			socket.on("end", socketOnEnd);
			socket.on("error", socketOnError);
			this._readyState = WebSocket.OPEN;
			this.emit("open");
		}
		/**
		* Emit the `'close'` event.
		*
		* @private
		*/
		emitClose() {
			if (!this._socket) {
				this._readyState = WebSocket.CLOSED;
				this.emit("close", this._closeCode, this._closeMessage);
				return;
			}
			if (this._extensions[PerMessageDeflate.extensionName]) this._extensions[PerMessageDeflate.extensionName].cleanup();
			this._receiver.removeAllListeners();
			this._readyState = WebSocket.CLOSED;
			this.emit("close", this._closeCode, this._closeMessage);
		}
		/**
		* Start a closing handshake.
		*
		*          +----------+   +-----------+   +----------+
		*     - - -|ws.close()|-->|close frame|-->|ws.close()|- - -
		*    |     +----------+   +-----------+   +----------+     |
		*          +----------+   +-----------+         |
		* CLOSING  |ws.close()|<--|close frame|<--+-----+       CLOSING
		*          +----------+   +-----------+   |
		*    |           |                        |   +---+        |
		*                +------------------------+-->|fin| - - - -
		*    |         +---+                      |   +---+
		*     - - - - -|fin|<---------------------+
		*              +---+
		*
		* @param {Number} [code] Status code explaining why the connection is closing
		* @param {(String|Buffer)} [data] The reason why the connection is
		*     closing
		* @public
		*/
		close(code, data) {
			if (this.readyState === WebSocket.CLOSED) return;
			if (this.readyState === WebSocket.CONNECTING) {
				abortHandshake(this, this._req, "WebSocket was closed before the connection was established");
				return;
			}
			if (this.readyState === WebSocket.CLOSING) {
				if (this._closeFrameSent && (this._closeFrameReceived || this._receiver._writableState.errorEmitted)) this._socket.end();
				return;
			}
			this._readyState = WebSocket.CLOSING;
			this._sender.close(code, data, !this._isServer, (err) => {
				if (err) return;
				this._closeFrameSent = true;
				if (this._closeFrameReceived || this._receiver._writableState.errorEmitted) this._socket.end();
			});
			setCloseTimer(this);
		}
		/**
		* Pause the socket.
		*
		* @public
		*/
		pause() {
			if (this.readyState === WebSocket.CONNECTING || this.readyState === WebSocket.CLOSED) return;
			this._paused = true;
			this._socket.pause();
		}
		/**
		* Send a ping.
		*
		* @param {*} [data] The data to send
		* @param {Boolean} [mask] Indicates whether or not to mask `data`
		* @param {Function} [cb] Callback which is executed when the ping is sent
		* @public
		*/
		ping(data, mask, cb) {
			if (this.readyState === WebSocket.CONNECTING) throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
			if (typeof data === "function") {
				cb = data;
				data = mask = void 0;
			} else if (typeof mask === "function") {
				cb = mask;
				mask = void 0;
			}
			if (typeof data === "number") data = data.toString();
			if (this.readyState !== WebSocket.OPEN) {
				sendAfterClose(this, data, cb);
				return;
			}
			if (mask === void 0) mask = !this._isServer;
			this._sender.ping(data || EMPTY_BUFFER, mask, cb);
		}
		/**
		* Send a pong.
		*
		* @param {*} [data] The data to send
		* @param {Boolean} [mask] Indicates whether or not to mask `data`
		* @param {Function} [cb] Callback which is executed when the pong is sent
		* @public
		*/
		pong(data, mask, cb) {
			if (this.readyState === WebSocket.CONNECTING) throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
			if (typeof data === "function") {
				cb = data;
				data = mask = void 0;
			} else if (typeof mask === "function") {
				cb = mask;
				mask = void 0;
			}
			if (typeof data === "number") data = data.toString();
			if (this.readyState !== WebSocket.OPEN) {
				sendAfterClose(this, data, cb);
				return;
			}
			if (mask === void 0) mask = !this._isServer;
			this._sender.pong(data || EMPTY_BUFFER, mask, cb);
		}
		/**
		* Resume the socket.
		*
		* @public
		*/
		resume() {
			if (this.readyState === WebSocket.CONNECTING || this.readyState === WebSocket.CLOSED) return;
			this._paused = false;
			if (!this._receiver._writableState.needDrain) this._socket.resume();
		}
		/**
		* Send a data message.
		*
		* @param {*} data The message to send
		* @param {Object} [options] Options object
		* @param {Boolean} [options.binary] Specifies whether `data` is binary or
		*     text
		* @param {Boolean} [options.compress] Specifies whether or not to compress
		*     `data`
		* @param {Boolean} [options.fin=true] Specifies whether the fragment is the
		*     last one
		* @param {Boolean} [options.mask] Specifies whether or not to mask `data`
		* @param {Function} [cb] Callback which is executed when data is written out
		* @public
		*/
		send(data, options, cb) {
			if (this.readyState === WebSocket.CONNECTING) throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
			if (typeof options === "function") {
				cb = options;
				options = {};
			}
			if (typeof data === "number") data = data.toString();
			if (this.readyState !== WebSocket.OPEN) {
				sendAfterClose(this, data, cb);
				return;
			}
			const opts = {
				binary: typeof data !== "string",
				mask: !this._isServer,
				compress: true,
				fin: true,
				...options
			};
			if (!this._extensions[PerMessageDeflate.extensionName]) opts.compress = false;
			this._sender.send(data || EMPTY_BUFFER, opts, cb);
		}
		/**
		* Forcibly close the connection.
		*
		* @public
		*/
		terminate() {
			if (this.readyState === WebSocket.CLOSED) return;
			if (this.readyState === WebSocket.CONNECTING) {
				abortHandshake(this, this._req, "WebSocket was closed before the connection was established");
				return;
			}
			if (this._socket) {
				this._readyState = WebSocket.CLOSING;
				this._socket.destroy();
			}
		}
	};
	/**
	* @constant {Number} CONNECTING
	* @memberof WebSocket
	*/
	Object.defineProperty(WebSocket, "CONNECTING", {
		enumerable: true,
		value: readyStates.indexOf("CONNECTING")
	});
	/**
	* @constant {Number} CONNECTING
	* @memberof WebSocket.prototype
	*/
	Object.defineProperty(WebSocket.prototype, "CONNECTING", {
		enumerable: true,
		value: readyStates.indexOf("CONNECTING")
	});
	/**
	* @constant {Number} OPEN
	* @memberof WebSocket
	*/
	Object.defineProperty(WebSocket, "OPEN", {
		enumerable: true,
		value: readyStates.indexOf("OPEN")
	});
	/**
	* @constant {Number} OPEN
	* @memberof WebSocket.prototype
	*/
	Object.defineProperty(WebSocket.prototype, "OPEN", {
		enumerable: true,
		value: readyStates.indexOf("OPEN")
	});
	/**
	* @constant {Number} CLOSING
	* @memberof WebSocket
	*/
	Object.defineProperty(WebSocket, "CLOSING", {
		enumerable: true,
		value: readyStates.indexOf("CLOSING")
	});
	/**
	* @constant {Number} CLOSING
	* @memberof WebSocket.prototype
	*/
	Object.defineProperty(WebSocket.prototype, "CLOSING", {
		enumerable: true,
		value: readyStates.indexOf("CLOSING")
	});
	/**
	* @constant {Number} CLOSED
	* @memberof WebSocket
	*/
	Object.defineProperty(WebSocket, "CLOSED", {
		enumerable: true,
		value: readyStates.indexOf("CLOSED")
	});
	/**
	* @constant {Number} CLOSED
	* @memberof WebSocket.prototype
	*/
	Object.defineProperty(WebSocket.prototype, "CLOSED", {
		enumerable: true,
		value: readyStates.indexOf("CLOSED")
	});
	[
		"binaryType",
		"bufferedAmount",
		"extensions",
		"isPaused",
		"protocol",
		"readyState",
		"url"
	].forEach((property) => {
		Object.defineProperty(WebSocket.prototype, property, { enumerable: true });
	});
	[
		"open",
		"error",
		"close",
		"message"
	].forEach((method) => {
		Object.defineProperty(WebSocket.prototype, `on${method}`, {
			enumerable: true,
			get() {
				for (const listener of this.listeners(method)) if (listener[kForOnEventAttribute]) return listener[kListener];
				return null;
			},
			set(handler) {
				for (const listener of this.listeners(method)) if (listener[kForOnEventAttribute]) {
					this.removeListener(method, listener);
					break;
				}
				if (typeof handler !== "function") return;
				this.addEventListener(method, handler, { [kForOnEventAttribute]: true });
			}
		});
	});
	WebSocket.prototype.addEventListener = addEventListener;
	WebSocket.prototype.removeEventListener = removeEventListener;
	module.exports = WebSocket;
	/**
	* Initialize a WebSocket client.
	*
	* @param {WebSocket} websocket The client to initialize
	* @param {(String|URL)} address The URL to which to connect
	* @param {Array} protocols The subprotocols
	* @param {Object} [options] Connection options
	* @param {Boolean} [options.allowSynchronousEvents=true] Specifies whether any
	*     of the `'message'`, `'ping'`, and `'pong'` events can be emitted multiple
	*     times in the same tick
	* @param {Boolean} [options.autoPong=true] Specifies whether or not to
	*     automatically send a pong in response to a ping
	* @param {Number} [options.closeTimeout=30000] Duration in milliseconds to wait
	*     for the closing handshake to finish after `websocket.close()` is called
	* @param {Function} [options.finishRequest] A function which can be used to
	*     customize the headers of each http request before it is sent
	* @param {Boolean} [options.followRedirects=false] Whether or not to follow
	*     redirects
	* @param {Function} [options.generateMask] The function used to generate the
	*     masking key
	* @param {Number} [options.handshakeTimeout] Timeout in milliseconds for the
	*     handshake request
	* @param {Number} [options.maxBufferedChunks=262144] The maximum number of
	*     buffered data chunks
	* @param {Number} [options.maxFragments=16384] The maximum number of message
	*     fragments
	* @param {Number} [options.maxPayload=104857600] The maximum allowed message
	*     size
	* @param {Number} [options.maxRedirects=10] The maximum number of redirects
	*     allowed
	* @param {String} [options.origin] Value of the `Origin` or
	*     `Sec-WebSocket-Origin` header
	* @param {(Boolean|Object)} [options.perMessageDeflate=true] Enable/disable
	*     permessage-deflate
	* @param {Number} [options.protocolVersion=13] Value of the
	*     `Sec-WebSocket-Version` header
	* @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
	*     not to skip UTF-8 validation for text and close messages
	* @private
	*/
	function initAsClient(websocket, address, protocols, options) {
		const opts = {
			allowSynchronousEvents: true,
			autoPong: true,
			closeTimeout: CLOSE_TIMEOUT,
			protocolVersion: protocolVersions[1],
			maxBufferedChunks: 262144,
			maxFragments: 16384,
			maxPayload: 104857600,
			skipUTF8Validation: false,
			perMessageDeflate: true,
			followRedirects: false,
			maxRedirects: 10,
			...options,
			socketPath: void 0,
			hostname: void 0,
			protocol: void 0,
			timeout: void 0,
			method: "GET",
			host: void 0,
			path: void 0,
			port: void 0
		};
		websocket._autoPong = opts.autoPong;
		websocket._closeTimeout = opts.closeTimeout;
		if (!protocolVersions.includes(opts.protocolVersion)) throw new RangeError(`Unsupported protocol version: ${opts.protocolVersion} (supported versions: ${protocolVersions.join(", ")})`);
		let parsedUrl;
		if (address instanceof URL$1) parsedUrl = address;
		else try {
			parsedUrl = new URL$1(address);
		} catch {
			throw new SyntaxError(`Invalid URL: ${address}`);
		}
		if (parsedUrl.protocol === "http:") parsedUrl.protocol = "ws:";
		else if (parsedUrl.protocol === "https:") parsedUrl.protocol = "wss:";
		websocket._url = parsedUrl.href;
		const isSecure = parsedUrl.protocol === "wss:";
		const isIpcUrl = parsedUrl.protocol === "ws+unix:";
		let invalidUrlMessage;
		if (parsedUrl.protocol !== "ws:" && !isSecure && !isIpcUrl) invalidUrlMessage = "The URL's protocol must be one of \"ws:\", \"wss:\", \"http:\", \"https:\", or \"ws+unix:\"";
		else if (isIpcUrl && !parsedUrl.pathname) invalidUrlMessage = "The URL's pathname is empty";
		else if (parsedUrl.hash) invalidUrlMessage = "The URL contains a fragment identifier";
		if (invalidUrlMessage) {
			const err = new SyntaxError(invalidUrlMessage);
			if (websocket._redirects === 0) throw err;
			else {
				emitErrorAndClose(websocket, err);
				return;
			}
		}
		const defaultPort = isSecure ? 443 : 80;
		const key = randomBytes$2(16).toString("base64");
		const request = isSecure ? https.request : http$2.request;
		const protocolSet = /* @__PURE__ */ new Set();
		let perMessageDeflate;
		opts.createConnection = opts.createConnection || (isSecure ? tlsConnect : netConnect);
		opts.defaultPort = opts.defaultPort || defaultPort;
		opts.port = parsedUrl.port || defaultPort;
		opts.host = parsedUrl.hostname.startsWith("[") ? parsedUrl.hostname.slice(1, -1) : parsedUrl.hostname;
		opts.headers = {
			...opts.headers,
			"Sec-WebSocket-Version": opts.protocolVersion,
			"Sec-WebSocket-Key": key,
			Connection: "Upgrade",
			Upgrade: "websocket"
		};
		opts.path = parsedUrl.pathname + parsedUrl.search;
		opts.timeout = opts.handshakeTimeout;
		if (opts.perMessageDeflate) {
			perMessageDeflate = new PerMessageDeflate({
				...opts.perMessageDeflate,
				isServer: false,
				maxPayload: opts.maxPayload
			});
			opts.headers["Sec-WebSocket-Extensions"] = format({ [PerMessageDeflate.extensionName]: perMessageDeflate.offer() });
		}
		if (protocols.length) {
			for (const protocol of protocols) {
				if (typeof protocol !== "string" || !subprotocolRegex.test(protocol) || protocolSet.has(protocol)) throw new SyntaxError("An invalid or duplicated subprotocol was specified");
				protocolSet.add(protocol);
			}
			opts.headers["Sec-WebSocket-Protocol"] = protocols.join(",");
		}
		if (opts.origin) {
			if (opts.protocolVersion < 13) opts.headers["Sec-WebSocket-Origin"] = opts.origin;
			else opts.headers.Origin = opts.origin;
		}
		if (parsedUrl.username || parsedUrl.password) opts.auth = `${parsedUrl.username}:${parsedUrl.password}`;
		if (isIpcUrl) {
			const parts = opts.path.split(":");
			opts.socketPath = parts[0];
			opts.path = parts[1];
		}
		let req;
		if (opts.followRedirects) {
			if (websocket._redirects === 0) {
				websocket._originalIpc = isIpcUrl;
				websocket._originalSecure = isSecure;
				websocket._originalHostOrSocketPath = isIpcUrl ? opts.socketPath : parsedUrl.host;
				const headers = options && options.headers;
				options = {
					...options,
					headers: {}
				};
				if (headers) for (const [key, value] of Object.entries(headers)) options.headers[key.toLowerCase()] = value;
			} else if (websocket.listenerCount("redirect") === 0) {
				const isSameHost = isIpcUrl ? websocket._originalIpc ? opts.socketPath === websocket._originalHostOrSocketPath : false : websocket._originalIpc ? false : parsedUrl.host === websocket._originalHostOrSocketPath;
				if (!isSameHost || websocket._originalSecure && !isSecure) {
					delete opts.headers.authorization;
					delete opts.headers.cookie;
					if (!isSameHost) delete opts.headers.host;
					opts.auth = void 0;
				}
			}
			if (opts.auth && !options.headers.authorization) options.headers.authorization = "Basic " + Buffer.from(opts.auth).toString("base64");
			req = websocket._req = request(opts);
			if (websocket._redirects) websocket.emit("redirect", websocket.url, req);
		} else req = websocket._req = request(opts);
		if (opts.timeout) req.on("timeout", () => {
			abortHandshake(websocket, req, "Opening handshake has timed out");
		});
		req.on("error", (err) => {
			if (req === null || req[kAborted]) return;
			req = websocket._req = null;
			emitErrorAndClose(websocket, err);
		});
		req.on("response", (res) => {
			const location = res.headers.location;
			const statusCode = res.statusCode;
			if (location && opts.followRedirects && statusCode >= 300 && statusCode < 400) {
				if (++websocket._redirects > opts.maxRedirects) {
					abortHandshake(websocket, req, "Maximum redirects exceeded");
					return;
				}
				req.abort();
				let addr;
				try {
					addr = new URL$1(location, address);
				} catch (e) {
					emitErrorAndClose(websocket, /* @__PURE__ */ new SyntaxError(`Invalid URL: ${location}`));
					return;
				}
				initAsClient(websocket, addr, protocols, options);
			} else if (!websocket.emit("unexpected-response", req, res)) abortHandshake(websocket, req, `Unexpected server response: ${res.statusCode}`);
		});
		req.on("upgrade", (res, socket, head) => {
			websocket.emit("upgrade", res);
			if (websocket.readyState !== WebSocket.CONNECTING) return;
			req = websocket._req = null;
			const upgrade = res.headers.upgrade;
			if (upgrade === void 0 || upgrade.toLowerCase() !== "websocket") {
				abortHandshake(websocket, socket, "Invalid Upgrade header");
				return;
			}
			const digest = createHash$2("sha1").update(key + GUID).digest("base64");
			if (res.headers["sec-websocket-accept"] !== digest) {
				abortHandshake(websocket, socket, "Invalid Sec-WebSocket-Accept header");
				return;
			}
			const serverProt = res.headers["sec-websocket-protocol"];
			let protError;
			if (serverProt !== void 0) {
				if (!protocolSet.size) protError = "Server sent a subprotocol but none was requested";
				else if (!protocolSet.has(serverProt)) protError = "Server sent an invalid subprotocol";
			} else if (protocolSet.size) protError = "Server sent no subprotocol";
			if (protError) {
				abortHandshake(websocket, socket, protError);
				return;
			}
			if (serverProt) websocket._protocol = serverProt;
			const secWebSocketExtensions = res.headers["sec-websocket-extensions"];
			if (secWebSocketExtensions !== void 0) {
				if (!perMessageDeflate) {
					abortHandshake(websocket, socket, "Server sent a Sec-WebSocket-Extensions header but no extension was requested");
					return;
				}
				let extensions;
				try {
					extensions = parse(secWebSocketExtensions);
				} catch (err) {
					abortHandshake(websocket, socket, "Invalid Sec-WebSocket-Extensions header");
					return;
				}
				const extensionNames = Object.keys(extensions);
				if (extensionNames.length !== 1 || extensionNames[0] !== PerMessageDeflate.extensionName) {
					abortHandshake(websocket, socket, "Server indicated an extension that was not requested");
					return;
				}
				try {
					perMessageDeflate.accept(extensions[PerMessageDeflate.extensionName]);
				} catch (err) {
					abortHandshake(websocket, socket, "Invalid Sec-WebSocket-Extensions header");
					return;
				}
				websocket._extensions[PerMessageDeflate.extensionName] = perMessageDeflate;
			}
			websocket.setSocket(socket, head, {
				allowSynchronousEvents: opts.allowSynchronousEvents,
				generateMask: opts.generateMask,
				maxBufferedChunks: opts.maxBufferedChunks,
				maxFragments: opts.maxFragments,
				maxPayload: opts.maxPayload,
				skipUTF8Validation: opts.skipUTF8Validation
			});
		});
		if (opts.finishRequest) opts.finishRequest(req, websocket);
		else req.end();
	}
	/**
	* Emit the `'error'` and `'close'` events.
	*
	* @param {WebSocket} websocket The WebSocket instance
	* @param {Error} The error to emit
	* @private
	*/
	function emitErrorAndClose(websocket, err) {
		websocket._readyState = WebSocket.CLOSING;
		websocket._errorEmitted = true;
		websocket.emit("error", err);
		websocket.emitClose();
	}
	/**
	* Create a `net.Socket` and initiate a connection.
	*
	* @param {Object} options Connection options
	* @return {net.Socket} The newly created socket used to start the connection
	* @private
	*/
	function netConnect(options) {
		options.path = options.socketPath;
		return net.connect(options);
	}
	/**
	* Create a `tls.TLSSocket` and initiate a connection.
	*
	* @param {Object} options Connection options
	* @return {tls.TLSSocket} The newly created socket used to start the connection
	* @private
	*/
	function tlsConnect(options) {
		options.path = void 0;
		if (!options.servername && options.servername !== "") options.servername = net.isIP(options.host) ? "" : options.host;
		return tls.connect(options);
	}
	/**
	* Abort the handshake and emit an error.
	*
	* @param {WebSocket} websocket The WebSocket instance
	* @param {(http.ClientRequest|net.Socket|tls.Socket)} stream The request to
	*     abort or the socket to destroy
	* @param {String} message The error message
	* @private
	*/
	function abortHandshake(websocket, stream, message) {
		websocket._readyState = WebSocket.CLOSING;
		const err = new Error(message);
		Error.captureStackTrace(err, abortHandshake);
		if (stream.setHeader) {
			stream[kAborted] = true;
			stream.abort();
			if (stream.socket && !stream.socket.destroyed) stream.socket.destroy();
			process.nextTick(emitErrorAndClose, websocket, err);
		} else {
			stream.destroy(err);
			stream.once("error", websocket.emit.bind(websocket, "error"));
			stream.once("close", websocket.emitClose.bind(websocket));
		}
	}
	/**
	* Handle cases where the `ping()`, `pong()`, or `send()` methods are called
	* when the `readyState` attribute is `CLOSING` or `CLOSED`.
	*
	* @param {WebSocket} websocket The WebSocket instance
	* @param {*} [data] The data to send
	* @param {Function} [cb] Callback
	* @private
	*/
	function sendAfterClose(websocket, data, cb) {
		if (data) {
			const length = isBlob(data) ? data.size : toBuffer(data).length;
			if (websocket._socket) websocket._sender._bufferedBytes += length;
			else websocket._bufferedAmount += length;
		}
		if (cb) {
			const err = /* @__PURE__ */ new Error(`WebSocket is not open: readyState ${websocket.readyState} (${readyStates[websocket.readyState]})`);
			process.nextTick(cb, err);
		}
	}
	/**
	* The listener of the `Receiver` `'conclude'` event.
	*
	* @param {Number} code The status code
	* @param {Buffer} reason The reason for closing
	* @private
	*/
	function receiverOnConclude(code, reason) {
		const websocket = this[kWebSocket];
		websocket._closeFrameReceived = true;
		websocket._closeMessage = reason;
		websocket._closeCode = code;
		if (websocket._socket[kWebSocket] === void 0) return;
		websocket._socket.removeListener("data", socketOnData);
		process.nextTick(resume, websocket._socket);
		if (code === 1005) websocket.close();
		else websocket.close(code, reason);
	}
	/**
	* The listener of the `Receiver` `'drain'` event.
	*
	* @private
	*/
	function receiverOnDrain() {
		const websocket = this[kWebSocket];
		if (!websocket.isPaused) websocket._socket.resume();
	}
	/**
	* The listener of the `Receiver` `'error'` event.
	*
	* @param {(RangeError|Error)} err The emitted error
	* @private
	*/
	function receiverOnError(err) {
		const websocket = this[kWebSocket];
		if (websocket._socket[kWebSocket] !== void 0) {
			websocket._socket.removeListener("data", socketOnData);
			process.nextTick(resume, websocket._socket);
			websocket.close(err[kStatusCode]);
		}
		if (!websocket._errorEmitted) {
			websocket._errorEmitted = true;
			websocket.emit("error", err);
		}
	}
	/**
	* The listener of the `Receiver` `'finish'` event.
	*
	* @private
	*/
	function receiverOnFinish() {
		this[kWebSocket].emitClose();
	}
	/**
	* The listener of the `Receiver` `'message'` event.
	*
	* @param {Buffer|ArrayBuffer|Buffer[])} data The message
	* @param {Boolean} isBinary Specifies whether the message is binary or not
	* @private
	*/
	function receiverOnMessage(data, isBinary) {
		this[kWebSocket].emit("message", data, isBinary);
	}
	/**
	* The listener of the `Receiver` `'ping'` event.
	*
	* @param {Buffer} data The data included in the ping frame
	* @private
	*/
	function receiverOnPing(data) {
		const websocket = this[kWebSocket];
		if (websocket._autoPong) websocket.pong(data, !this._isServer, NOOP);
		websocket.emit("ping", data);
	}
	/**
	* The listener of the `Receiver` `'pong'` event.
	*
	* @param {Buffer} data The data included in the pong frame
	* @private
	*/
	function receiverOnPong(data) {
		this[kWebSocket].emit("pong", data);
	}
	/**
	* Resume a readable stream
	*
	* @param {Readable} stream The readable stream
	* @private
	*/
	function resume(stream) {
		stream.resume();
	}
	/**
	* The `Sender` error event handler.
	*
	* @param {Error} The error
	* @private
	*/
	function senderOnError(err) {
		const websocket = this[kWebSocket];
		if (websocket.readyState === WebSocket.CLOSED) return;
		if (websocket.readyState === WebSocket.OPEN) {
			websocket._readyState = WebSocket.CLOSING;
			setCloseTimer(websocket);
		}
		this._socket.end();
		if (!websocket._errorEmitted) {
			websocket._errorEmitted = true;
			websocket.emit("error", err);
		}
	}
	/**
	* Set a timer to destroy the underlying raw socket of a WebSocket.
	*
	* @param {WebSocket} websocket The WebSocket instance
	* @private
	*/
	function setCloseTimer(websocket) {
		websocket._closeTimer = setTimeout(websocket._socket.destroy.bind(websocket._socket), websocket._closeTimeout);
	}
	/**
	* The listener of the socket `'close'` event.
	*
	* @private
	*/
	function socketOnClose() {
		const websocket = this[kWebSocket];
		this.removeListener("close", socketOnClose);
		this.removeListener("data", socketOnData);
		this.removeListener("end", socketOnEnd);
		websocket._readyState = WebSocket.CLOSING;
		if (!this._readableState.endEmitted && !websocket._closeFrameReceived && !websocket._receiver._writableState.errorEmitted && this._readableState.length !== 0) {
			const chunk = this.read(this._readableState.length);
			websocket._receiver.write(chunk);
		}
		websocket._receiver.end();
		this[kWebSocket] = void 0;
		clearTimeout(websocket._closeTimer);
		if (websocket._receiver._writableState.finished || websocket._receiver._writableState.errorEmitted) websocket.emitClose();
		else {
			websocket._receiver.on("error", receiverOnFinish);
			websocket._receiver.on("finish", receiverOnFinish);
		}
	}
	/**
	* The listener of the socket `'data'` event.
	*
	* @param {Buffer} chunk A chunk of data
	* @private
	*/
	function socketOnData(chunk) {
		if (!this[kWebSocket]._receiver.write(chunk)) this.pause();
	}
	/**
	* The listener of the socket `'end'` event.
	*
	* @private
	*/
	function socketOnEnd() {
		const websocket = this[kWebSocket];
		websocket._readyState = WebSocket.CLOSING;
		websocket._receiver.end();
		this.end();
	}
	/**
	* The listener of the socket `'error'` event.
	*
	* @private
	*/
	function socketOnError() {
		const websocket = this[kWebSocket];
		this.removeListener("error", socketOnError);
		this.on("error", NOOP);
		if (websocket) {
			websocket._readyState = WebSocket.CLOSING;
			this.destroy();
		}
	}
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/stream.js
var require_stream = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	require_websocket();
	const { Duplex: Duplex$1 } = __require("node:stream");
	/**
	* Emits the `'close'` event on a stream.
	*
	* @param {Duplex} stream The stream.
	* @private
	*/
	function emitClose(stream) {
		stream.emit("close");
	}
	/**
	* The listener of the `'end'` event.
	*
	* @private
	*/
	function duplexOnEnd() {
		if (!this.destroyed && this._writableState.finished) this.destroy();
	}
	/**
	* The listener of the `'error'` event.
	*
	* @param {Error} err The error
	* @private
	*/
	function duplexOnError(err) {
		this.removeListener("error", duplexOnError);
		this.destroy();
		if (this.listenerCount("error") === 0) this.emit("error", err);
	}
	/**
	* Wraps a `WebSocket` in a duplex stream.
	*
	* @param {WebSocket} ws The `WebSocket` to wrap
	* @param {Object} [options] The options for the `Duplex` constructor
	* @return {Duplex} The duplex stream
	* @public
	*/
	function createWebSocketStream(ws, options) {
		let terminateOnDestroy = true;
		const duplex = new Duplex$1({
			...options,
			autoDestroy: false,
			emitClose: false,
			objectMode: false,
			writableObjectMode: false
		});
		ws.on("message", function message(msg, isBinary) {
			const data = !isBinary && duplex._readableState.objectMode ? msg.toString() : msg;
			if (!duplex.push(data)) ws.pause();
		});
		ws.once("error", function error(err) {
			if (duplex.destroyed) return;
			terminateOnDestroy = false;
			duplex.destroy(err);
		});
		ws.once("close", function close() {
			if (duplex.destroyed) return;
			duplex.push(null);
		});
		duplex._destroy = function(err, callback) {
			if (ws.readyState === ws.CLOSED) {
				callback(err);
				process.nextTick(emitClose, duplex);
				return;
			}
			let called = false;
			ws.once("error", function error(err) {
				called = true;
				callback(err);
			});
			ws.once("close", function close() {
				if (!called) callback(err);
				process.nextTick(emitClose, duplex);
			});
			if (terminateOnDestroy) ws.terminate();
		};
		duplex._final = function(callback) {
			if (ws.readyState === ws.CONNECTING) {
				ws.once("open", function open() {
					duplex._final(callback);
				});
				return;
			}
			if (ws._socket === null) return;
			if (ws._socket._writableState.finished) {
				callback();
				if (duplex._readableState.endEmitted) duplex.destroy();
			} else {
				ws._socket.once("finish", function finish() {
					callback();
				});
				ws.close();
			}
		};
		duplex._read = function() {
			if (ws.isPaused) ws.resume();
		};
		duplex._write = function(chunk, encoding, callback) {
			if (ws.readyState === ws.CONNECTING) {
				ws.once("open", function open() {
					duplex._write(chunk, encoding, callback);
				});
				return;
			}
			ws.send(chunk, callback);
		};
		duplex.on("end", duplexOnEnd);
		duplex.on("error", duplexOnError);
		return duplex;
	}
	module.exports = createWebSocketStream;
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/subprotocol.js
var require_subprotocol = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const { tokenChars } = require_validation();
	/**
	* Parses the `Sec-WebSocket-Protocol` header into a set of subprotocol names.
	*
	* @param {String} header The field value of the header
	* @return {Set} The subprotocol names
	* @public
	*/
	function parse(header) {
		const protocols = /* @__PURE__ */ new Set();
		let start = -1;
		let end = -1;
		let i = 0;
		for (; i < header.length; i++) {
			const code = header.charCodeAt(i);
			if (end === -1 && tokenChars[code] === 1) {
				if (start === -1) start = i;
			} else if (i !== 0 && (code === 32 || code === 9)) {
				if (end === -1 && start !== -1) end = i;
			} else if (code === 44) {
				if (start === -1) throw new SyntaxError(`Unexpected character at index ${i}`);
				if (end === -1) end = i;
				const protocol = header.slice(start, end);
				if (protocols.has(protocol)) throw new SyntaxError(`The "${protocol}" subprotocol is duplicated`);
				protocols.add(protocol);
				start = end = -1;
			} else throw new SyntaxError(`Unexpected character at index ${i}`);
		}
		if (start === -1 || end !== -1) throw new SyntaxError("Unexpected end of input");
		const protocol = header.slice(start, i);
		if (protocols.has(protocol)) throw new SyntaxError(`The "${protocol}" subprotocol is duplicated`);
		protocols.add(protocol);
		return protocols;
	}
	module.exports = { parse };
}));
//#endregion
//#region ../../node_modules/.pnpm/ws@8.21.3/node_modules/ws/lib/websocket-server.js
var require_websocket_server = /* @__PURE__ */ __commonJSMin(((exports, module) => {
	const EventEmitter = __require("node:events");
	const http$1 = __require("node:http");
	const { Duplex } = __require("node:stream");
	const { createHash: createHash$1 } = __require("node:crypto");
	const extension = require_extension();
	const PerMessageDeflate = require_permessage_deflate();
	const subprotocol = require_subprotocol();
	const WebSocket = require_websocket();
	const { CLOSE_TIMEOUT, GUID, kWebSocket } = require_constants();
	const keyRegex = /^[+/0-9A-Za-z]{22}==$/;
	const RUNNING = 0;
	const CLOSING = 1;
	const CLOSED = 2;
	/**
	* Class representing a WebSocket server.
	*
	* @extends EventEmitter
	*/
	var WebSocketServer = class extends EventEmitter {
		/**
		* Create a `WebSocketServer` instance.
		*
		* @param {Object} options Configuration options
		* @param {Boolean} [options.allowSynchronousEvents=true] Specifies whether
		*     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
		*     multiple times in the same tick
		* @param {Boolean} [options.autoPong=true] Specifies whether or not to
		*     automatically send a pong in response to a ping
		* @param {Number} [options.backlog=511] The maximum length of the queue of
		*     pending connections
		* @param {Boolean} [options.clientTracking=true] Specifies whether or not to
		*     track clients
		* @param {Number} [options.closeTimeout=30000] Duration in milliseconds to
		*     wait for the closing handshake to finish after `websocket.close()` is
		*     called
		* @param {Function} [options.handleProtocols] A hook to handle protocols
		* @param {String} [options.host] The hostname where to bind the server
		* @param {Number} [options.maxBufferedChunks=262144] The maximum number of
		*     buffered data chunks
		* @param {Number} [options.maxFragments=16384] The maximum number of message
		*     fragments
		* @param {Number} [options.maxPayload=104857600] The maximum allowed message
		*     size
		* @param {Boolean} [options.noServer=false] Enable no server mode
		* @param {String} [options.path] Accept only connections matching this path
		* @param {(Boolean|Object)} [options.perMessageDeflate=false] Enable/disable
		*     permessage-deflate
		* @param {Number} [options.port] The port where to bind the server
		* @param {(http.Server|https.Server)} [options.server] A pre-created HTTP/S
		*     server to use
		* @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
		*     not to skip UTF-8 validation for text and close messages
		* @param {Function} [options.verifyClient] A hook to reject connections
		* @param {Function} [options.WebSocket=WebSocket] Specifies the `WebSocket`
		*     class to use. It must be the `WebSocket` class or class that extends it
		* @param {Function} [callback] A listener for the `listening` event
		*/
		constructor(options, callback) {
			super();
			options = {
				allowSynchronousEvents: true,
				autoPong: true,
				maxBufferedChunks: 262144,
				maxFragments: 16384,
				maxPayload: 104857600,
				skipUTF8Validation: false,
				perMessageDeflate: false,
				handleProtocols: null,
				clientTracking: true,
				closeTimeout: CLOSE_TIMEOUT,
				verifyClient: null,
				noServer: false,
				backlog: null,
				server: null,
				host: null,
				path: null,
				port: null,
				WebSocket,
				...options
			};
			if (options.port == null && !options.server && !options.noServer || options.port != null && (options.server || options.noServer) || options.server && options.noServer) throw new TypeError("One and only one of the \"port\", \"server\", or \"noServer\" options must be specified");
			if (options.port != null) {
				this._server = http$1.createServer((req, res) => {
					const body = http$1.STATUS_CODES[426];
					res.writeHead(426, {
						"Content-Length": body.length,
						"Content-Type": "text/plain"
					});
					res.end(body);
				});
				this._server.listen(options.port, options.host, options.backlog, callback);
			} else if (options.server) this._server = options.server;
			if (this._server) {
				const emitConnection = this.emit.bind(this, "connection");
				this._removeListeners = addListeners(this._server, {
					listening: this.emit.bind(this, "listening"),
					error: this.emit.bind(this, "error"),
					upgrade: (req, socket, head) => {
						this.handleUpgrade(req, socket, head, emitConnection);
					}
				});
			}
			if (options.perMessageDeflate === true) options.perMessageDeflate = {};
			if (options.clientTracking) {
				this.clients = /* @__PURE__ */ new Set();
				this._shouldEmitClose = false;
			}
			this.options = options;
			this._state = RUNNING;
		}
		/**
		* Returns the bound address, the address family name, and port of the server
		* as reported by the operating system if listening on an IP socket.
		* If the server is listening on a pipe or UNIX domain socket, the name is
		* returned as a string.
		*
		* @return {(Object|String|null)} The address of the server
		* @public
		*/
		address() {
			if (this.options.noServer) throw new Error("The server is operating in \"noServer\" mode");
			if (!this._server) return null;
			return this._server.address();
		}
		/**
		* Stop the server from accepting new connections and emit the `'close'` event
		* when all existing connections are closed.
		*
		* @param {Function} [cb] A one-time listener for the `'close'` event
		* @public
		*/
		close(cb) {
			if (this._state === CLOSED) {
				if (cb) this.once("close", () => {
					cb(/* @__PURE__ */ new Error("The server is not running"));
				});
				process.nextTick(emitClose, this);
				return;
			}
			if (cb) this.once("close", cb);
			if (this._state === CLOSING) return;
			this._state = CLOSING;
			if (this.options.noServer || this.options.server) {
				if (this._server) {
					this._removeListeners();
					this._removeListeners = this._server = null;
				}
				if (this.clients) {
					if (!this.clients.size) process.nextTick(emitClose, this);
					else this._shouldEmitClose = true;
				} else process.nextTick(emitClose, this);
			} else {
				const server = this._server;
				this._removeListeners();
				this._removeListeners = this._server = null;
				server.close(() => {
					emitClose(this);
				});
			}
		}
		/**
		* See if a given request should be handled by this server instance.
		*
		* @param {http.IncomingMessage} req Request object to inspect
		* @return {Boolean} `true` if the request is valid, else `false`
		* @public
		*/
		shouldHandle(req) {
			if (this.options.path) {
				const index = req.url.indexOf("?");
				if ((index !== -1 ? req.url.slice(0, index) : req.url) !== this.options.path) return false;
			}
			return true;
		}
		/**
		* Handle a HTTP Upgrade request.
		*
		* @param {http.IncomingMessage} req The request object
		* @param {Duplex} socket The network socket between the server and client
		* @param {Buffer} head The first packet of the upgraded stream
		* @param {Function} cb Callback
		* @public
		*/
		handleUpgrade(req, socket, head, cb) {
			socket.on("error", socketOnError);
			const key = req.headers["sec-websocket-key"];
			const upgrade = req.headers.upgrade;
			const version = +req.headers["sec-websocket-version"];
			if (req.method !== "GET") {
				abortHandshakeOrEmitwsClientError(this, req, socket, 405, "Invalid HTTP method");
				return;
			}
			if (upgrade === void 0 || upgrade.toLowerCase() !== "websocket") {
				abortHandshakeOrEmitwsClientError(this, req, socket, 400, "Invalid Upgrade header");
				return;
			}
			if (key === void 0 || !keyRegex.test(key)) {
				abortHandshakeOrEmitwsClientError(this, req, socket, 400, "Missing or invalid Sec-WebSocket-Key header");
				return;
			}
			if (version !== 13 && version !== 8) {
				abortHandshakeOrEmitwsClientError(this, req, socket, 400, "Missing or invalid Sec-WebSocket-Version header", { "Sec-WebSocket-Version": "13, 8" });
				return;
			}
			if (!this.shouldHandle(req)) {
				abortHandshake(socket, 400);
				return;
			}
			const secWebSocketProtocol = req.headers["sec-websocket-protocol"];
			let protocols = /* @__PURE__ */ new Set();
			if (secWebSocketProtocol !== void 0) try {
				protocols = subprotocol.parse(secWebSocketProtocol);
			} catch (err) {
				abortHandshakeOrEmitwsClientError(this, req, socket, 400, "Invalid Sec-WebSocket-Protocol header");
				return;
			}
			const secWebSocketExtensions = req.headers["sec-websocket-extensions"];
			const extensions = {};
			if (this.options.perMessageDeflate && secWebSocketExtensions !== void 0) {
				const perMessageDeflate = new PerMessageDeflate({
					...this.options.perMessageDeflate,
					isServer: true,
					maxPayload: this.options.maxPayload
				});
				try {
					const offers = extension.parse(secWebSocketExtensions);
					if (offers[PerMessageDeflate.extensionName]) {
						perMessageDeflate.accept(offers[PerMessageDeflate.extensionName]);
						extensions[PerMessageDeflate.extensionName] = perMessageDeflate;
					}
				} catch (err) {
					abortHandshakeOrEmitwsClientError(this, req, socket, 400, "Invalid or unacceptable Sec-WebSocket-Extensions header");
					return;
				}
			}
			if (this.options.verifyClient) {
				const info = {
					origin: req.headers[`${version === 8 ? "sec-websocket-origin" : "origin"}`],
					secure: !!(req.socket.authorized || req.socket.encrypted),
					req
				};
				if (this.options.verifyClient.length === 2) {
					this.options.verifyClient(info, (verified, code, message, headers) => {
						if (!verified) return abortHandshake(socket, code || 401, message, headers);
						this.completeUpgrade(extensions, key, protocols, req, socket, head, cb);
					});
					return;
				}
				if (!this.options.verifyClient(info)) return abortHandshake(socket, 401);
			}
			this.completeUpgrade(extensions, key, protocols, req, socket, head, cb);
		}
		/**
		* Upgrade the connection to WebSocket.
		*
		* @param {Object} extensions The accepted extensions
		* @param {String} key The value of the `Sec-WebSocket-Key` header
		* @param {Set} protocols The subprotocols
		* @param {http.IncomingMessage} req The request object
		* @param {Duplex} socket The network socket between the server and client
		* @param {Buffer} head The first packet of the upgraded stream
		* @param {Function} cb Callback
		* @throws {Error} If called more than once with the same socket
		* @private
		*/
		completeUpgrade(extensions, key, protocols, req, socket, head, cb) {
			if (!socket.readable || !socket.writable) return socket.destroy();
			if (socket[kWebSocket]) throw new Error("server.handleUpgrade() was called more than once with the same socket, possibly due to a misconfiguration");
			if (this._state > RUNNING) return abortHandshake(socket, 503);
			const headers = [
				"HTTP/1.1 101 Switching Protocols",
				"Upgrade: websocket",
				"Connection: Upgrade",
				`Sec-WebSocket-Accept: ${createHash$1("sha1").update(key + GUID).digest("base64")}`
			];
			const ws = new this.options.WebSocket(null, void 0, this.options);
			if (protocols.size) {
				const protocol = this.options.handleProtocols ? this.options.handleProtocols(protocols, req) : protocols.values().next().value;
				if (protocol) {
					headers.push(`Sec-WebSocket-Protocol: ${protocol}`);
					ws._protocol = protocol;
				}
			}
			if (extensions[PerMessageDeflate.extensionName]) {
				const params = extensions[PerMessageDeflate.extensionName].params;
				const value = extension.format({ [PerMessageDeflate.extensionName]: [params] });
				headers.push(`Sec-WebSocket-Extensions: ${value}`);
				ws._extensions = extensions;
			}
			this.emit("headers", headers, req);
			socket.write(headers.concat("\r\n").join("\r\n"));
			socket.removeListener("error", socketOnError);
			ws.setSocket(socket, head, {
				allowSynchronousEvents: this.options.allowSynchronousEvents,
				maxBufferedChunks: this.options.maxBufferedChunks,
				maxFragments: this.options.maxFragments,
				maxPayload: this.options.maxPayload,
				skipUTF8Validation: this.options.skipUTF8Validation
			});
			if (this.clients) {
				this.clients.add(ws);
				ws.on("close", () => {
					this.clients.delete(ws);
					if (this._shouldEmitClose && !this.clients.size) process.nextTick(emitClose, this);
				});
			}
			cb(ws, req);
		}
	};
	module.exports = WebSocketServer;
	/**
	* Add event listeners on an `EventEmitter` using a map of <event, listener>
	* pairs.
	*
	* @param {EventEmitter} server The event emitter
	* @param {Object.<String, Function>} map The listeners to add
	* @return {Function} A function that will remove the added listeners when
	*     called
	* @private
	*/
	function addListeners(server, map) {
		for (const event of Object.keys(map)) server.on(event, map[event]);
		return function removeListeners() {
			for (const event of Object.keys(map)) server.removeListener(event, map[event]);
		};
	}
	/**
	* Emit a `'close'` event on an `EventEmitter`.
	*
	* @param {EventEmitter} server The event emitter
	* @private
	*/
	function emitClose(server) {
		server._state = CLOSED;
		server.emit("close");
	}
	/**
	* Handle socket errors.
	*
	* @private
	*/
	function socketOnError() {
		this.destroy();
	}
	/**
	* Close the connection when preconditions are not fulfilled.
	*
	* @param {Duplex} socket The socket of the upgrade request
	* @param {Number} code The HTTP response status code
	* @param {String} [message] The HTTP response body
	* @param {Object} [headers] Additional HTTP response headers
	* @private
	*/
	function abortHandshake(socket, code, message, headers) {
		message = message || http$1.STATUS_CODES[code];
		headers = {
			Connection: "close",
			"Content-Type": "text/html",
			"Content-Length": Buffer.byteLength(message),
			...headers
		};
		socket.once("finish", socket.destroy);
		socket.end(`HTTP/1.1 ${code} ${http$1.STATUS_CODES[code]}\r\n` + Object.keys(headers).map((h) => `${h}: ${headers[h]}`).join("\r\n") + "\r\n\r\n" + message);
	}
	/**
	* Emit a `'wsClientError'` event on a `WebSocketServer` if there is at least
	* one listener for it, otherwise call `abortHandshake()`.
	*
	* @param {WebSocketServer} server The WebSocket server
	* @param {http.IncomingMessage} req The request object
	* @param {Duplex} socket The socket of the upgrade request
	* @param {Number} code The HTTP response status code
	* @param {String} message The HTTP response body
	* @param {Object} [headers] The HTTP response headers
	* @private
	*/
	function abortHandshakeOrEmitwsClientError(server, req, socket, code, message, headers) {
		if (server.listenerCount("wsClientError")) {
			const err = new Error(message);
			Error.captureStackTrace(err, abortHandshakeOrEmitwsClientError);
			server.emit("wsClientError", err, socket, req);
		} else abortHandshake(socket, code, message, headers);
	}
}));
require_stream();
require_extension();
require_permessage_deflate();
require_receiver();
require_sender();
require_subprotocol();
var import_websocket = /* @__PURE__ */ __toESM(require_websocket(), 1);
require_websocket_server();
//#endregion
//#region src/tunnels.ts
/** How much one side may hold for the other before it stops reading: a few COPY chunks. */
const HIGH_WATER = 1048576;
/**
* Credit flow, asked for in a header (on Workers, whose WebSockets have no
* back-pressure: packages/server/src/cloudflare-sockets.ts): each side
* counts back what it took, in text messages, each the bytes taken from
* binary messages since its last, and sends at most `WINDOW` bytes the
* other has not counted. coffre's first message says whether it paces: a
* count, `0`, before any byte, or a byte, from a coffre on Node, which
* reads its socket only as fast as it writes and ignores the counts. Until
* it says, the listener holds the app to the window; it counts back
* whatever coffre it reaches.
*/
const FLOW = "coffre-tunnel-flow";
const WINDOW = 1048576;
/** How much the app takes before the listener counts it back: well under the window. */
const COUNT_EVERY = 131072;
/**
* How often an open connection says it is there, idle or not: a count,
* which reaches coffre's end, so that a psql left at its prompt outlives
* Cloudflare's idle timeout (100 seconds), and keeps its Durable Object;
* and a ping, whose pong must come before the next, or the connection is
* gone, as when a laptop's network changes without a word.
*/
const KEEPALIVE_MS = 3e4;
/**
* How long coffre has to answer the upgrade: a coffre that does not is gone,
* and both ends close, rather than wait forever on it. Longer than coffre's
* own 15 s wait for a turn and 45 s to admit (cloudflare-sockets.ts,
* socket-admission.ts), so that its refusal for taking too long is the one said.
*/
const HANDSHAKE_MS = 7e4;
/**
* A listener, on a port of its own (or at `address`, a sidecar's), for as
* long as the run lasts; and the URL the app connects with. Its connections
* are a person's run's, by `handle`, or a workload's, signed by its session.
* `keepaliveMs` and `handshakeMs` are for tests.
*/
async function listen(tunnel, as, { keepaliveMs = KEEPALIVE_MS, handshakeMs = HANDSHAKE_MS, address = {
	host: "127.0.0.1",
	port: 0
} } = {}) {
	const sockets = /* @__PURE__ */ new Set();
	/** The refusals said already, by status and reason: once each for the run, however many connections a pool retries. */
	const said = /* @__PURE__ */ new Set();
	const server = createServer$1((socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
		const ws = new import_websocket.default(tunnel.url, {
			headers: {
				...typeof as === "string" ? { authorization: `Bearer ${as}` } : {},
				[FLOW]: "credit"
			},
			handshakeTimeout: handshakeMs,
			finishRequest: signed(as, tunnel.url)
		});
		carry(socket, ws, keepaliveMs);
		ws.on("unexpected-response", (request, response) => {
			if (typeof as !== "string") upgradeRefused(as);
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => body = (body + chunk).slice(0, 1e3));
			response.on("end", () => {
				let message = body.trim();
				try {
					message = JSON.parse(body).message ?? message;
				} catch {}
				const refusal = `(${response.statusCode})${message === "" ? "" : `: ${message}`}`;
				if (!said.has(refusal)) {
					said.add(refusal);
					process.stderr.write(`coffre: the tunnel for ${tunnel.key} was refused ${refusal}\n`);
				}
				request.destroy();
				socket.destroy();
			});
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(address.port, address.host, () => resolve());
	});
	server.unref();
	const { port } = server.address();
	return {
		url: `postgres://app${typeof as === "string" ? `:${encodeURIComponent(as)}` : ""}@${address.host.includes(":") ? `[${address.host}]` : address.host}:${port}/app?sslmode=disable`,
		close: () => {
			for (const socket of sockets) socket.destroy();
			server.close();
		}
	};
}
/**
* One app connection, carried over its WebSocket to coffre: each side reads
* only as fast as the other takes, by credit with a coffre that paces, and
* the keepalive. Exported for its properties (tunnel-properties.test.ts).
*/
function carry(socket, ws, keepaliveMs) {
	socket.pause();
	/** Whether coffre paces: unknown until its first message says. */
	let pacing = null;
	/** Bytes sent that coffre has not counted, and bytes the app took that the listener has not. */
	let uncounted = 0;
	let taken = 0;
	/** Bytes coffre sent that the listener has not counted back: a coffre that paces keeps them under a window. */
	let owed = 0;
	let answered = true;
	const held = () => ws.bufferedAmount >= HIGH_WATER || pacing !== false && uncounted >= WINDOW;
	const count = () => {
		if (ws.readyState !== import_websocket.default.OPEN) return;
		ws.send(String(taken), () => void 0);
		owed -= taken;
		taken = 0;
	};
	ws.on("open", () => socket.resume());
	ws.on("pong", () => answered = true);
	const keepalive = setInterval(() => {
		if (ws.readyState !== import_websocket.default.OPEN) return;
		if (!answered && !ws.isPaused) return ws.terminate();
		answered = false;
		ws.ping();
		count();
	}, keepaliveMs);
	keepalive.unref();
	socket.on("data", (chunk) => {
		uncounted += chunk.length;
		ws.send(chunk, { binary: true }, () => {
			if (!held()) socket.resume();
		});
		if (held()) socket.pause();
	});
	ws.on("message", (data, binary) => {
		if (!binary) {
			const text = data.toString();
			const counted = Number(text);
			if (pacing === false || !/^\d{1,10}$/.test(text) || counted > uncounted) return ws.terminate();
			pacing = true;
			uncounted -= counted;
			if (!held()) socket.resume();
			return;
		}
		if (pacing === null) {
			pacing = false;
			if (!held()) socket.resume();
		}
		owed += data.length;
		if (pacing === true && owed > 2 * WINDOW) return ws.terminate();
		if (socket.destroyed) return;
		if (!socket.write(data, () => {
			taken += data.length;
			if (taken >= COUNT_EVERY) count();
		}) && pacing === false) ws.pause();
	});
	socket.on("drain", () => ws.resume());
	ws.on("close", () => {
		clearInterval(keepalive);
		socket.destroy();
	});
	ws.on("error", () => socket.destroy());
	socket.on("close", () => {
		clearInterval(keepalive);
		ws.close();
	});
	socket.on("error", () => ws.terminate());
}
/**
* How a workload's upgrade is sent: its session and a proof, signed as the
* request goes, since a proof is made fresh for each. A handle's needs
* nothing more than its header.
*/
function signed(as, url) {
	if (typeof as === "string") return void 0;
	return (request) => {
		upgradeHeaders(as, url).then((headers) => {
			for (const [name, value] of Object.entries(headers)) request.setHeader(name, value);
			request.end();
		}, (error) => request.destroy(error));
	};
}
//#endregion
//#region src/workload.ts
/**
* A CI run signing in as a service, with the ID token its platform signs
* for it (docs/design/oidc.md), and no bearer token: `coffre --service
* api-deploy …` for one command, or `coffre login <url> --service
* api-deploy` for the commands after it. The CLI takes the run's ID token,
* trades it at `POST /api/auth/oidc` for a credential that lasts five
* minutes, and keeps that credential in memory, or, after a login, in the
* session it saves, which lasts as long. A token is spent once used, so on
* GitHub each exchange asks the runner for a fresh one.
*/
/**
* The run's ID token, for `audience`, this instance's URL: the one
* `coffre login --service <name> --id-token` asked for (GitLab's
* `id_tokens`, or any issuer's), or GitHub's runner's, asked for a fresh
* one, when the job has `permissions: id-token: write`.
*/
async function idToken(given, runner, audience, fetchImpl) {
	if (given) return given;
	const [url, bearer] = [runner.ACTIONS_ID_TOKEN_REQUEST_URL?.trim(), runner.ACTIONS_ID_TOKEN_REQUEST_TOKEN?.trim()];
	if (url && bearer) {
		const request = new URL(url);
		request.searchParams.set("audience", audience);
		const response = await fetchImpl(request.href, { headers: {
			authorization: `bearer ${bearer}`,
			accept: "application/json"
		} });
		const body = await response.json().catch(() => null);
		if (!response.ok || typeof body?.value !== "string") throw new Error(`GitHub did not give this job an ID token (status ${response.status})`);
		return body.value;
	}
	throw new Error(`--service signs in with the run's ID token, and there is none: on GitHub Actions, give the job \`permissions: id-token: write\`; elsewhere, pipe it to \`coffre login <url> --service <name> --id-token\` (GitLab: an \`id_tokens\` entry whose aud is ${audience})`);
}
/** An exchange the instance refused, or could not answer: its status, its body's code and reason, and its `Retry-After`. */
var ExchangeFailed = class extends Error {
	status;
	body;
	retryAfter;
	constructor(message, status, body, retryAfter) {
		super(message);
		this.status = status;
		this.body = body;
		this.retryAfter = retryAfter;
	}
};
/** Trade an ID token for a credential of `service`, or throw `ExchangeFailed` saying why the instance refused. */
async function exchange(origin, service, token, fetchImpl) {
	const response = await fetchImpl(`${origin}/api/auth/oidc`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			accept: "application/json"
		},
		body: JSON.stringify({
			service,
			token
		})
	});
	const body = await response.json().catch(() => null);
	if (response.ok && typeof body?.token === "string" && typeof body.expiresAt === "string") return {
		token: body.token,
		expiresAt: body.expiresAt
	};
	const why = typeof body?.message === "string" ? body.message : `status ${response.status}`;
	throw new ExchangeFailed(`${origin} would not sign this run in as ${service}${typeof body?.reason === "string" ? ` (${body.reason})` : ""}: ${why}`, response.status, body, response.headers.get("retry-after"));
}
/**
* Key-bound, the same CLI (docs/design/workload-access.md, sections 6.3 and
* 9.3): `coffre serve` and `coffre --service <name> run` sign in at
* `POST /api/auth/workload` with a platform's proof, and hold a session bound
* to a key that lives in the CLI's memory alone. The app reaches its
* credentials through a local listener, which forwards what it sends,
* signed, and its databases through tunnels that sign their upgrades.
*/
/** The proofs `--proof` names. Each secret one (an enrollment code, an ID token) is read from stdin, never an argument. */
const PROOFS = "kubernetes[:<file>], aws, gcp, azure:<audience>, fly, vercel, github, enrollment or oidc";
/** A `--proof`, as `@coffre/client/workload` proves it; none, in a GitHub Actions job, is the job's ID token. */
async function proofOf(spec, runner) {
	if (spec === void 0) {
		if (runner.ACTIONS_ID_TOKEN_REQUEST_URL && runner.ACTIONS_ID_TOKEN_REQUEST_TOKEN) return github();
		throw new UsageError(`name the platform's proof: --proof ${PROOFS}`);
	}
	const [kind, rest] = spec.split(/:(.*)/s);
	switch (kind) {
		case "kubernetes": return kubernetes(rest || void 0);
		case "aws": return aws();
		case "gcp": return gcp();
		case "azure":
			if (!rest) throw new UsageError("--proof azure:<audience> names coffre's Entra application: azure:api://coffre-acme");
			return azure({ audience: rest });
		case "fly": return fly();
		case "vercel": return vercel();
		case "github": return github();
		case "enrollment": return enrollment(await readSecret({
			label: "Enrollment code",
			hint: "coffre_enr_…, from `coffre enroll <service>`; piped in, as printf %s \"$COFFRE_ENROLL\" | coffre …"
		}));
		case "oidc": return oidc(await readSecret({
			label: "ID token",
			hint: "the platform's ID token for this instance: GitLab's id_tokens entry, or a custom issuer's"
		}));
	}
	throw new UsageError(`--proof ${spec}: a proof is one of ${PROOFS}`);
}
function addressOf(text, flag) {
	if (text.startsWith("unix:") && text.length > 5) return { path: text.slice(5) };
	const match = /^(?:\[([0-9a-fA-F:.]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(text);
	const port = Number(match?.[3]);
	if (match === null || port > 65535) throw new UsageError(`${flag} ${text}: an address is <host>:<port>, [<ipv6>]:<port> or unix:<path>`);
	return {
		host: match[1] ?? match[2],
		port
	};
}
/**
* Headers no request carries on to coffre: the transport's, the app's
* credentials for the listener, which the session's replace, and a
* person's handle header, which `credential(name)` sends empty here.
*/
const DROPPED = /* @__PURE__ */ new Set([
	...UNSIGNED_HEADERS,
	"expect",
	"x-coffre-handle"
]);
/** Headers no answer carries back: the transport's, and what fetch undid (a body it decompressed is no longer its encoding). */
const UNANSWERED = /* @__PURE__ */ new Set([
	"connection",
	"content-encoding",
	"content-length",
	"keep-alive",
	"transfer-encoding",
	"dpop-nonce"
]);
/**
* A local listener that forwards each request under `/use/` to coffre,
* signed by the session, as the app sent it: its method, path, query, headers
* and body. The app's config names it (`OPENAI_BASE_URL=http://127.0.0.1:7300/use/openai`),
* and coffre writes no URL into the app's environment (R14). On a Unix
* socket, only the socket's owner may connect.
*/
async function forwarder(coffre, origin, address) {
	const server = createServer((req, res) => {
		const answer = (status, error, message) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify({
			error,
			message
		}));
		let target;
		try {
			target = new URL(req.url ?? "/", origin);
		} catch {
			return answer(400, "bad_request", "this request names no URL");
		}
		if (target.origin !== origin || !target.pathname.startsWith("/use/")) return answer(404, "not_found", "this listener forwards /use/… to coffre, and nothing else");
		const gone = new AbortController();
		res.on("close", () => gone.abort());
		(async () => {
			const headers = new Headers();
			for (let i = 0; i < req.rawHeaders.length; i += 2) if (!DROPPED.has(req.rawHeaders[i].toLowerCase())) headers.append(req.rawHeaders[i], req.rawHeaders[i + 1]);
			const method = req.method ?? "GET";
			let body;
			let again = false;
			if (method !== "GET" && method !== "HEAD") {
				const length = req.headers["content-length"];
				if (headers.has("x-amz-content-sha256")) {
					if (length !== void 0) headers.set("content-length", length);
					const stream = Readable.toWeb(req);
					body = () => stream;
				} else {
					const tooLarge = () => answer(413, "too_large", `a request's body through coffre is at most ${MAX_DIGESTED_BODY / 1024 / 1024} MiB, under the 100 MB a Cloudflare zone takes`);
					if (Number(length ?? 0) > 99614720) return tooLarge();
					const own = headers.get("content-digest");
					let declared;
					try {
						declared = own === null ? null : declaredDigest(own);
					} catch (error) {
						return answer(400, "bad_request", error.message);
					}
					const chunks = [];
					const hash = createHash("sha256");
					let size = 0;
					for await (const chunk of req) {
						size += chunk.length;
						if (size > 99614720) return tooLarge();
						hash.update(chunk);
						chunks.push(chunk);
					}
					const sha256 = hash.digest("hex");
					if (declared !== null && declared !== sha256) return answer(400, "bad_request", "the body is not what its Content-Digest says");
					const ours = contentDigest(sha256);
					if (own === null) headers.set("content-digest", ours);
					else if (declared === null) headers.set("content-digest", `${own}, ${ours}`);
					headers.set("content-length", String(size));
					again = true;
					body = () => {
						let next = 0;
						return new ReadableStream({ pull: (out) => next < chunks.length ? out.enqueue(chunks[next++]) : out.close() });
					};
				}
			}
			const send = () => coffre.fetch(target.href, {
				method,
				headers,
				body: body?.(),
				redirect: "manual",
				signal: gone.signal,
				...body === void 0 ? {} : { duplex: "half" }
			});
			let response = await send();
			if (again && askedNonce(response)) {
				await response.body?.cancel();
				response = await send();
			}
			const back = [...response.headers].filter(([name]) => !UNANSWERED.has(name) && name !== "set-cookie");
			const location = back.find(([name]) => name === "location");
			if (location !== void 0) {
				const to = URL.canParse(location[1], target.href) ? new URL(location[1], target.href) : null;
				if (to !== null && to.origin === origin && to.pathname.startsWith("/use/")) location[1] = `${to.pathname}${to.search}${to.hash}`;
			}
			for (const cookie of response.headers.getSetCookie()) back.push(["set-cookie", cookie]);
			res.writeHead(response.status, back);
			if (response.body === null) res.end();
			else await pipeline(Readable.fromWeb(response.body), res);
		})().catch((error) => {
			if (gone.signal.aborted) return;
			if (res.headersSent) return res.destroy();
			answer(502, "bad_gateway", `coffre did not answer: ${error instanceof Error ? error.message : String(error)}`);
		});
	});
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		if ("path" in address) {
			const umask = process.umask(127);
			server.listen(address.path, () => resolve());
			process.umask(umask);
		} else server.listen(address.port, address.host, () => resolve());
	});
	if ("path" in address) chmodSync(address.path, 384);
	const bound = server.address();
	return {
		url: "path" in address ? `unix:${address.path}` : `http://${address.host.includes(":") ? `[${address.host}]` : address.host}:${bound.port}`,
		close: () => (server.closeAllConnections(), server.close())
	};
}
/**
* Sign `service` in key-bound, and make what its command gets: each place's
* plan, values the session may read (plain ones, and those its binding
* lists in `reads`), `COFFRE_CREDENTIALS` naming each credential at a local
* listener, and a tunnel listener for each database. Null where the
* instance has no key-bound sessions yet, which the bearer exchange serves.
*/
async function keyBound(origin, service, proof, positionals, log, fetchImpl) {
	const coffre = await workload({
		url: origin,
		service,
		proof,
		log,
		sigterm: false,
		fetch: fetchImpl
	}).catch((error) => {
		if (error instanceof CoffreError && (error.status === 404 || error.status === 501)) return null;
		throw error;
	});
	if (coffre === null) return null;
	const opened = [];
	const close = async () => {
		for (const each of opened) each.close();
		await coffre.close();
	};
	const signals = [
		"SIGTERM",
		"SIGINT",
		"SIGHUP"
	];
	const stopped = (signal) => {
		for (const each of signals) process.off(each, stopped);
		close().catch(() => void 0).finally(() => process.kill(process.pid, signal));
	};
	for (const each of signals) process.on(each, stopped);
	try {
		const places = positionals.length === 0 ? [...coffre.places] : environmentPaths(positionals);
		const outside = places.filter((place) => !coffre.places.includes(place));
		if (outside.length > 0) throw new Error(`${service}'s session reaches ${listOf(coffre.places)}, not ${listOf(outside)}`);
		const local = await forwarder(coffre, origin, {
			host: "127.0.0.1",
			port: 0
		});
		opened.push(local);
		const plans = [];
		for (const place of places) {
			const response = await coffre.fetch(`${origin}/use/${place.split("/").map(encodeURIComponent).join("/")}`, { headers: { accept: "application/json" } });
			const plan = await response.json().catch(() => null);
			if (!response.ok || plan === null) throw new Error(`${origin} gave ${service} no plan for ${place} (${response.status})${typeof plan?.message === "string" ? `: ${plan.message}` : ""}`);
			plans.push([place, plan]);
		}
		for (const [place, plan] of plans) if (plan.tunnels !== void 0 && (typeof plan.tunnels !== "object" || Array.isArray(plan.tunnels))) throw new Error(`${origin}'s plan for ${place} names its tunnels without the key each URL goes in: coffre run needs { <name>: { key, url } }; coffre serve --tunnel <name>=<address> needs none`);
		const values = (plan) => Object.entries(plan.values ?? {}).filter((entry) => typeof entry[1] === "string");
		const tunnels = (plan) => Object.entries(plan.tunnels ?? {}).filter((entry) => typeof entry[1].key === "string" && typeof entry[1].url === "string");
		const names = (list) => Array.isArray(list) ? list.filter((name) => typeof name === "string") : [];
		const shared = clash(plans.map(([place, plan]) => [place, [...values(plan).map(([key]) => key), ...tunnels(plan).map(([, tunnel]) => tunnel.key)]]));
		if (shared !== null) throw new Error(`${shared}: a key comes from one environment only`);
		const twice = clash(plans.map(([place, plan]) => [place, names(plan.credentials)]));
		if (twice !== null) throw new Error(`${twice}: a credential comes from one environment only; run with the one it should be`);
		const env = {};
		const credentials = {};
		for (const [place, plan] of plans) {
			for (const [key, value] of values(plan)) Object.defineProperty(env, key, {
				value,
				enumerable: true,
				writable: true,
				configurable: true
			});
			for (const name of names(plan.credentials)) credentials[name] = `${local.url}/use/${place}/${name}`;
			for (const [, tunnel] of tunnels(plan)) {
				const listener = await listen(tunnel, coffre);
				opened.push(listener);
				Object.defineProperty(env, tunnel.key, {
					value: listener.url,
					enumerable: true,
					writable: true,
					configurable: true
				});
			}
			const left = [.../* @__PURE__ */ new Set([...names(plan.left), ...names(plan.useOnly)])];
			if (left.length > 0) log(`coffre: ${place}: ${listOf(left)} ${left.length === 1 ? "is" : "are"} used through coffre now; list ${left.length === 1 ? "it" : "them"} in the binding's reads if this job must hold ${left.length === 1 ? "it" : "them"}`);
		}
		env.COFFRE_CREDENTIALS = JSON.stringify(credentials);
		env.COFFRE_HANDLE = "";
		log(`coffre: ${service}, key-bound, in ${listOf(places)}: ${Object.keys(credentials).length === 0 ? "no credential" : `${listOf(Object.keys(credentials).sort())} through ${local.url}/use`}`);
		return {
			places,
			env,
			close
		};
	} catch (error) {
		await close();
		throw error;
	} finally {
		for (const each of signals) process.off(each, stopped);
	}
}
//#endregion
//#region src/flags.ts
/**
* What the CLI is told, it is told on its command line, and it reads no
* COFFRE_* variable. Flags configure; a secret is never one, but asked for
* (`secret.ts`). The session flags come before the command, and say which
* coffre to talk to, and as which service, for that one command:
*
*   coffre --url https://coffre.example.com --service api-deploy export app/prod
*
* The credential itself is the session `coffre login` saved: a person's,
* or a CI run's, with a bearer token or an Access service token it asked
* for, or an ID token traded for a credential.
*/
/** The session flags, each overriding the saved session for one command, and `--verbose`, which says how each request went. */
const SESSION_OPTIONS = {
	url: { type: "string" },
	service: { type: "string" },
	"auth-mode": { type: "string" },
	verbose: { type: "boolean" }
};
/** The session flags each command takes, when not all of them: none where it talks to no instance. */
const TAKES = {
	init: [],
	keys: [],
	setup: [],
	update: [],
	migrate: [],
	use: [],
	roles: [],
	help: [],
	login: [
		"url",
		"auth-mode",
		"verbose"
	],
	logout: ["url", "verbose"],
	verify: [
		"url",
		"service",
		"auth-mode"
	]
};
/**
* A command's own flags that share a session flag's name: `coffre grant …
* --service` names a service's grant, `coffre login <url> --service <name>`
* the service a CI run signs in as, `coffre serve --service <name> --url
* <url>` the workload its sidecar holds a session of, and where.
*/
const OWN = {
	access: ["service"],
	admit: ["service"],
	grant: ["service"],
	revoke: ["service"],
	offboard: ["service"],
	login: ["service"],
	serve: ["service", "url"]
};
/**
* The commands that refuse any flag but theirs themselves, and say more: that
* an argument looks like a connection string, which the shell's history now
* holds.
*/
const SELF = /* @__PURE__ */ new Set(["setup", "migrate"]);
/**
* `coffre [session flags] <command> [args…]`, split. Throws, saying what to
* do, on a session flag that is malformed, misplaced after the command, or
* given to a command it does nothing for.
*/
function commandLine(argv) {
	let at = 0;
	for (; at < argv.length; at++) {
		const [name, value] = argv[at].startsWith("--") ? argv[at].slice(2).split(/=(.*)/s) : [];
		if (name === void 0 || !Object.hasOwn(SESSION_OPTIONS, name)) break;
		if (value === void 0 && SESSION_OPTIONS[name].type === "string") at++;
	}
	const session = { ...parseArgs({
		args: argv.slice(0, at),
		options: SESSION_OPTIONS,
		strict: true
	}).values };
	const [command, ...rest] = argv.slice(at);
	if (command === void 0 || command.startsWith("-")) return {
		session,
		command,
		rest
	};
	const own = OWN[command] ?? [];
	const end = rest.indexOf("--");
	for (const arg of SELF.has(command) ? [] : end === -1 ? rest : rest.slice(0, end)) {
		const name = arg.startsWith("--") ? arg.slice(2).split("=")[0] : "";
		if (Object.hasOwn(SESSION_OPTIONS, name) && !own.includes(name)) throw new Error(`--${name} is a session flag, which goes before the command: coffre --${name}${placeholder(name)} ${command} …`);
	}
	const takes = TAKES[command];
	const extra = takes === void 0 ? [] : Object.keys(session).filter((name) => !takes.includes(name));
	if (extra.length > 0) throw new Error(`${listed(extra.map((name) => `--${name}`), "and")} ${extra.length === 1 ? "does" : "do"} nothing for coffre ${command}`);
	return {
		session,
		command,
		rest
	};
}
function placeholder(name) {
	return {
		url: " <url>",
		service: " <name>",
		"auth-mode": " signin|cloudflare",
		verbose: ""
	}[name] ?? " …";
}
/**
* The session flags, trimmed. An empty one is refused, never read as left
* out: it is what an unset variable expands to, and left out would mean the
* saved session, another instance or another person than the script meant.
*/
function readSession(args) {
	for (const [name, value] of Object.entries(args)) if (typeof value === "string" && value.trim() === "") throw new Error(`--${name} is empty: an unset variable, perhaps`);
	return {
		url: args.url?.trim(),
		service: args.service?.trim(),
		authMode: args["auth-mode"]?.trim(),
		verbose: args.verbose === true
	};
}
//#endregion
//#region src/timings.ts
const stderr = (line) => void process.stderr.write(`coffre: ${line}\n`);
/**
* `fetchImpl`, each request said once answered: `POST /api/reveals: 200 in
* 1.2 s`, or `failed after 30.0 s`. `instance`, the origin whose paths are
* said; without it, every request is the instance's.
*/
function timed(fetchImpl, say, instance) {
	return async (input, init) => {
		const [method, url] = input instanceof Request ? [input.method, input.url] : [init?.method ?? "GET", String(input)];
		const at = new URL(url);
		const what = instance === void 0 || at.origin === instance ? requestLine(method, at) : `${method} ${at.host}`;
		const start = performance.now();
		try {
			const response = await fetchImpl(input, init);
			say(`${what}: ${response.status} in ${took(performance.now() - start)}`);
			return response;
		} catch (error) {
			say(`${what}: failed after ${took(performance.now() - start)} (${failure(error)})`);
			throw error;
		}
	};
}
/** A duration as a person reads it: `245 ms`, `15.8 s`. */
function took(ms) {
	return ms < 1e3 ? `${Math.round(ms)} ms` : `${(ms / 1e3).toFixed(1)} s`;
}
/** A request to the instance, as a line says it: `POST /api/reveals`; `POST /use/stripe/…`, the rest of its path the app's. */
function requestLine(method, url) {
	const proxied = /^\/use\/[^/]+\/./.exec(url.pathname);
	return `${method} ${proxied === null ? url.pathname : `${proxied[0].slice(0, -1)}…`}`;
}
/** What failed, by the network's code (`ECONNREFUSED`) or the error's kind (`TypeError`), never its message. */
function failure(error) {
	for (let cause = error; typeof cause === "object" && cause !== null; cause = cause.cause) {
		const { code } = cause;
		if (typeof code === "string" && /^[A-Z][A-Z0-9_]+$/.test(code)) return code;
	}
	return error instanceof Error ? error.name : "failed";
}
//#endregion
//#region ../core/dist/recipe.js
const ENCODINGS = [
	{
		id: "base62",
		name: "Letters and digits"
	},
	{
		id: "hex",
		name: "Hex"
	},
	{
		id: "base64",
		name: "Base64"
	},
	{
		id: "base64url",
		name: "Base64 URL"
	}
];
const CURVES = [
	"P-256",
	"P-384",
	"P-521"
];
const RECIPE_SYNTAX = "bytes:<1-256>[:base62|hex|base64|base64url], aes:<128|256>, ecdsa:<p-256|p-384|p-521> or ecdh:<curve>";
/**
* The recipe a text names, in any case: `bytes:32` is `bytes:32:base62`,
* `ECDSA:P-256` is `ecdsa:p-256`. Throws, saying what is wrong, for any
* other text.
*/
function parseRecipe(text) {
	const [kind, size, encoding, ...rest] = text.trim().toLowerCase().split(":");
	const wrong = (what) => /* @__PURE__ */ new Error(`${what}: a recipe is ${RECIPE_SYNTAX}`);
	if (text.length > 32) throw wrong(`"${text.slice(0, 32)}…" is too long`);
	switch (kind) {
		case "bytes": {
			if (rest.length > 0) break;
			const bytes = wholeNumber(size);
			if (bytes === null || bytes < 1 || bytes > 256) throw wrong(`bytes takes a length from 1 to 256, not "${size ?? ""}"`);
			const named = encoding ?? "base62";
			if (!ENCODINGS.some((each) => each.id === named)) throw wrong(`bytes are written as base62, hex, base64 or base64url, not "${named}"`);
			return {
				kind: "random",
				bytes,
				encoding: named
			};
		}
		case "aes":
			if (encoding !== void 0) break;
			if (size !== "128" && size !== "256") throw wrong(`an AES key is 128 or 256 bits, not "${size ?? ""}"`);
			return {
				kind: "aes",
				size: Number(size)
			};
		case "ecdsa":
		case "ecdh": {
			if (encoding !== void 0) break;
			const curve = CURVES.find((each) => each.toLowerCase() === size);
			if (curve === void 0) throw wrong(`${kind} takes the curve p-256, p-384 or p-521, not "${size ?? ""}"`);
			return {
				kind: "pair",
				algorithm: kind === "ecdsa" ? "ECDSA" : "ECDH",
				curve
			};
		}
	}
	throw wrong(`"${text}" is no recipe`);
}
/** A recipe as it is stored and shown: lowercase, every part named. */
function formatRecipe(recipe) {
	switch (recipe.kind) {
		case "random": return `bytes:${recipe.bytes}:${recipe.encoding}`;
		case "aes": return `aes:${recipe.size}`;
		case "pair": return `${recipe.algorithm.toLowerCase()}:${recipe.curve.toLowerCase()}`;
	}
}
/** A recipe in words, for a confirmation or a listing: "32 random bytes as 64 hex characters". */
function describeRecipe(recipe) {
	switch (recipe.kind) {
		case "random": return `${`${recipe.bytes} random ${recipe.bytes === 1 ? "byte" : "bytes"}`} as ${encodedLength(recipe.encoding, recipe.bytes)} ${{
			base62: "letters and digits",
			hex: "hex characters",
			base64: "base64 characters",
			base64url: "base64 URL characters"
		}[recipe.encoding]}`;
		case "aes": return `a ${recipe.size}-bit AES-GCM key, raw, base64`;
		case "pair": return `an ${recipe.algorithm} ${recipe.curve} key pair: the private key PKCS #8, the public key SPKI, both base64`;
	}
}
/**
* How many characters carry `bytes` of entropy. Hex and base64 encode the
* bytes themselves; base62 draws whole characters, each worth log2(62) bits,
* so it takes as many as reach the same number of bits: 43 for 32 bytes.
* Base64 pads to a multiple of four; base64 URL leaves the padding off.
*/
function encodedLength(encoding, bytes) {
	switch (encoding) {
		case "hex": return bytes * 2;
		case "base64": return Math.ceil(bytes / 3) * 4;
		case "base64url": return Math.ceil(bytes * 8 / 6);
		case "base62": return Math.ceil(bytes * 8 / Math.log2(62));
	}
}
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/**
* The largest multiple of 62 a byte reaches: 248. A byte below it is taken
* modulo 62, and each of the 62 characters has four bytes that make it. The
* eight bytes from 248 up are thrown away, as taking them would make the
* first eight characters a little likelier than the rest.
*/
const BASE62_LIMIT = 248;
const randomBytes$1 = (bytes) => webCrypto().getRandomValues(bytes);
/** `length` characters of base62, each drawn uniformly by rejecting the bytes 248 to 255. */
function base62(length, random = randomBytes$1) {
	let out = "";
	while (out.length < length) for (const byte of random(new Uint8Array(length - out.length + 8))) {
		if (byte >= BASE62_LIMIT) continue;
		out += BASE62[byte % 62];
		if (out.length === length) break;
	}
	return out;
}
function randomValue(encoding, bytes, random = randomBytes$1) {
	if (encoding === "base62") return base62(encodedLength("base62", bytes), random);
	const drawn = random(new Uint8Array(bytes));
	if (encoding === "hex") return [...drawn].map((byte) => byte.toString(16).padStart(2, "0")).join("");
	const base64 = toBase64(drawn);
	return encoding === "base64" ? base64 : base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** A value made by the recipe, with the platform's CSPRNG. */
async function generate(recipe) {
	switch (recipe.kind) {
		case "random": return { value: randomValue(recipe.encoding, recipe.bytes) };
		case "aes": {
			const key = await subtle().generateKey({
				name: "AES-GCM",
				length: recipe.size
			}, true, ["encrypt", "decrypt"]);
			return { value: toBase64(await subtle().exportKey("raw", key)) };
		}
		case "pair": {
			const usages = recipe.algorithm === "ECDSA" ? ["sign", "verify"] : ["deriveBits"];
			const pair = await subtle().generateKey({
				name: recipe.algorithm,
				namedCurve: recipe.curve
			}, true, usages);
			return {
				value: toBase64(await subtle().exportKey("pkcs8", pair.privateKey)),
				publicKey: toBase64(await subtle().exportKey("spki", pair.publicKey))
			};
		}
	}
}
/**
* A value made by the recipe for `key`, as a write sends it, and for a key
* pair its public key beside it, under `publicKey` or the name that follows
* from the private key's (`publicKeyName`). The two halves name each other.
*/
async function generateWrite(key, recipe, publicKey) {
	const text = formatRecipe(recipe);
	const made = await generate(recipe);
	if (recipe.kind !== "pair") return { [key]: {
		value: made.value,
		generated: { recipe: text }
	} };
	const pair = {
		private: key,
		public: publicKey ?? publicKeyName(key)
	};
	return {
		[pair.private]: {
			value: made.value,
			generated: {
				recipe: text,
				pair
			}
		},
		[pair.public]: {
			value: made.publicKey,
			generated: {
				recipe: text,
				pair
			}
		}
	};
}
/**
* The next value of a key by the recipe its current one was made by, as a
* listing says it: a key pair's either half makes the pair again, whole,
* under the names its halves have now. Each key says the version it
* replaces, by the id `versionIdOf` gives as listed, and the server refuses
* the write (409) if any has changed since: renamed, archived, typed over
* or regenerated meanwhile. A regenerate addresses keys by name, and
* without that it could write a name that no longer holds the pair.
*/
async function regenerateWrite(key, generated, versionIdOf) {
	const recipe = parseRecipe(generated.recipe);
	if (recipe.kind === "pair" && generated.pair === void 0) throw new Error(`${key}: ${generated.recipe} makes a key pair, and no pair is named`);
	const write = recipe.kind === "pair" ? await generateWrite(generated.pair.private, recipe, generated.pair.public) : await generateWrite(key, recipe);
	for (const [name, entry] of Object.entries(write)) {
		const version = versionIdOf(name);
		if (version === null) throw new Error(`${name} is not listed with a version to regenerate`);
		entry.replaces = version;
	}
	return write;
}
/**
* The name a key pair's public key gets beside its private key's:
* `JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`, any other name gains `_PUBLIC`.
*/
function publicKeyName(privateName) {
	const name = privateName.trim();
	if (name === "") return "";
	if (/PRIVATE/.test(name)) return name.replace(/PRIVATE/g, "PUBLIC");
	if (/private/.test(name)) return name.replace(/private/g, "public");
	return `${name}_PUBLIC`;
}
function wholeNumber(text) {
	return text !== void 0 && /^\d{1,4}$/.test(text) ? Number(text) : null;
}
/** Web Crypto's keys need a secure context: HTTPS, or the machine's own address. */
function subtle() {
	if (globalThis.crypto?.subtle === void 0) throw new Error("This page is not served over HTTPS, so the browser makes no keys here.");
	return globalThis.crypto.subtle;
}
function webCrypto() {
	if (globalThis.crypto?.getRandomValues === void 0) throw new Error("This runtime has no Web Crypto to draw random bytes from.");
	return globalThis.crypto;
}
function toBase64(bytes) {
	let binary = "";
	for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
	return btoa(binary);
}
//#endregion
//#region src/generate.ts
/**
* Values the CLI makes for `coffre set --generate` and `coffre regenerate`:
* made here, with the platform's CSPRNG, by the recipe the pages use too
* (`@coffre/core/recipe`), and sent with it, so the next one is made the
* same way. Nothing here prints a value: what is said is the recipe, the
* keys and their versions.
*/
/** A key's name, as the server takes it: `secretKey` in `@coffre/core/schemas`, without loading zod here. */
const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** The recipe `--generate` names, or a usage error that says the syntax. */
function recipeFlag(text) {
	try {
		return parseRecipe(text);
	} catch (error) {
		throw new UsageError(`--generate: ${error.message}`);
	}
}
/**
* The patch that writes a value made by the recipe to `key`, and for a key
* pair its public key to `publicKey`, or the name it follows from the
* private key's: `JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`.
*/
async function generatedPatch(key, recipe, publicKey) {
	if (recipe.kind !== "pair") {
		if (publicKey !== void 0) throw new UsageError(`--public-key names a key pair's public key, and this recipe makes one value`);
		return generateWrite(key, recipe);
	}
	const publicName = publicKey ?? publicKeyName(key);
	if (!KEY_NAME.test(publicName)) throw new UsageError(`--public-key: "${publicName}" is no key name: letters, digits and underscores`);
	if (publicName === key) throw new UsageError(`a key pair's two keys need different names: --public-key names the other`);
	return generateWrite(key, recipe, publicName);
}
/**
* What regenerating `key` writes, from its environment's listing: a new
* value by its recipe, and for a key pair's either half, the pair whole,
* under the names it has now. A key with no recipe says how it gets one:
* a plain error, as the key is what is wrong, not the command.
*/
async function regeneratedPatch(path, key, listed) {
	const entry = listed.find((each) => each.key === key);
	if (entry === void 0) throw new Error(`${path} has no key ${key}`);
	if (entry.archived) throw new Error(`${path}/${key} is archived: unarchive it before regenerating it`);
	if (entry.generated === void 0) throw new Error(`this instance is older than recipes (coffre 0.7) and keeps none to regenerate by: upgrade it`);
	if (entry.generated === null) throw new Error(`${path}/${key} has no recipe: its value was typed, or written by hand since it was generated. \`coffre set ${path}/${key} --generate <recipe>\` gives it one`);
	return regenerateWrite(key, entry.generated, (name) => listed.find((each) => each.key === name && !each.archived)?.versionId ?? null);
}
/**
* What a generated write says, a line per key: its version and how it was
* made, never its value. `{ JWT_PRIVATE_KEY: 3, JWT_PUBLIC_KEY: 3 }` for a
* pair says which half each holds.
*/
function generatedLines(patch, versions, verb) {
	return Object.entries(patch).map(([key, { generated }]) => {
		const version = versions[key] ?? "?";
		const recipe = parseRecipe(generated.recipe);
		if (recipe.kind !== "pair" || generated.pair === void 0) return `${key} ${verb} as version ${version}: ${describeRecipe(recipe)} (${generated.recipe})`;
		const [half, other] = key === generated.pair.private ? ["private", generated.pair.public] : ["public", generated.pair.private];
		return `${key} ${verb} as version ${version}: the ${half} key of a new ${recipe.algorithm} ${recipe.curve} pair with ${other} (${generated.recipe})`;
	});
}
//#endregion
//#region src/commands.ts
const P = "<project>/<environment>";
const SECTIONS = [
	{
		title: "New deployment",
		entries: [
			{
				command: "init",
				usage: ["init --workers [<dir>]"],
				about: ["two Cloudflare Workers: the app and its vault"]
			},
			{
				command: "init",
				usage: ["init --node [<dir>]"],
				about: ["a Node server, and its vault beside it"]
			},
			{
				command: "setup",
				usage: ["setup [--reset-passwords] [--rotate-deploy-token] [--json]"],
				about: [
					"its database logins, migrations and keys in one go,",
					"shown once on a screen of their own; on Workers,",
					"Cloudflare too, and deploys on every push to GitHub;",
					"in an empty directory, the deployment first"
				]
			},
			{
				command: "keys",
				usage: ["keys [--json]"],
				about: ["the app key, vault key and vault ID alone, shown the same way"]
			}
		]
	},
	{
		title: "Upgrade",
		entries: [{
			command: "update",
			usage: ["update [--yes]"],
			about: ["this CLI, and in a deployment, its coffre packages"]
		}, {
			command: "migrate",
			usage: ["migrate [--yes] [--backup-login <role>]"],
			about: [
				"in a deployment's folder, its database to the schema of",
				"the version it pins; asks for the owner's connection",
				"string (piped in, and --yes, without a terminal, to apply);",
				"--backup-login grants that existing role coffre_backup,",
				"which reads every row for pg_dump, on every run; coffre",
				"never makes the role, nor revokes it when the flag is left off"
			]
		}]
	},
	{
		title: "Backup",
		entries: [{
			command: "backup",
			usage: ["backup [<file>]"],
			about: ["the database, with pg_dump, as the backup login, and a", "manifest of what it holds beside it"]
		}, {
			command: "restore",
			usage: ["restore <dump> [--keys]"],
			about: ["into an empty database, then checked against its", "manifest; with --keys, every value opened too"]
		}]
	},
	{
		title: "Session",
		entries: [
			{
				command: "login",
				usage: ["login [<url>] [--no-browser]"],
				about: ["sign in; use <url> in this directory and below,", "and by default"]
			},
			{
				command: "login",
				usage: ["login <url> --token"],
				about: ["a CI run's or a script's sign-in: a bearer or personal", "token, asked for or piped in"]
			},
			{
				command: "login",
				usage: ["login <url> --access-client-id <id>"],
				about: ["the same, behind Cloudflare Access: its secret asked for"]
			},
			{
				command: "login",
				usage: ["login <url> --service <name> [--id-token]"],
				about: ["the same, as a service account, by OIDC, the run's ID token:", "GitHub's runner gives it; elsewhere, --id-token asks for it"]
			},
			{
				command: "logout",
				usage: ["logout [<url>]"]
			},
			{
				command: "whoami",
				usage: ["whoami [--json]"]
			},
			{
				command: "use",
				usage: ["use [<url>]"],
				about: ["list instances, or switch the default one"]
			},
			{
				command: "sessions",
				usage: ["sessions [--json]"],
				about: ["where you are signed in, this CLI's session among them"]
			},
			{
				command: "sessions revoke",
				usage: ["sessions revoke <id> [--apply]"],
				about: ["signs that session out"]
			},
			{
				command: "apps",
				usage: ["apps [--json]"],
				about: ["the MCP clients you connected, such as Claude"]
			},
			{
				command: "apps revoke",
				usage: ["apps revoke <id> [--apply]"],
				about: ["disconnects that app"]
			},
			{
				command: "tokens",
				usage: ["tokens [--json]"],
				about: ["your personal tokens, which act as you"]
			},
			{
				command: "tokens issue",
				usage: ["tokens issue --label <label> --scope <path>=<role>,…", "             [--expires-in <30m|4h|2d>] [--output-file <path>]"],
				about: [
					"a personal token, for a script or an agent: it acts as you",
					"on what --scope says, at most what you hold now and less",
					"whenever you hold less; never on access or sign-in. An hour",
					"unless told, a week at most; every entry it makes names it"
				]
			},
			{
				command: "tokens revoke",
				usage: ["tokens revoke <id> [--apply]"],
				about: ["ends that personal token; `coffre logout` with it, too"]
			},
			{
				command: "identities",
				usage: ["identities [--json]"],
				about: ["the accounts you sign in with"]
			},
			{
				command: "identities unlink",
				usage: ["identities unlink <id> [--apply]"],
				about: ["stops that account signing you in"]
			}
		]
	},
	{
		title: "Secrets",
		entries: [
			{
				command: "list",
				usage: [`list      ${P} [--older-than <days>d | --stale] [--json]`],
				about: [
					"keys, versions, who changed them and when; no secret value,",
					"a plain one as it is",
					"--stale: those unchanged past the instance's rotateAfterDays"
				]
			},
			{
				command: "get",
				usage: [`get       ${P}/<KEY>`]
			},
			{
				command: "set",
				usage: [`set       ${P}/<KEY>`],
				about: ["the value asked for, or piped in"]
			},
			{
				command: "set",
				usage: [`set       ${P}/<KEY> [value] --plain`],
				about: [
					"a value that is no secret, an account id: shown to whoever lists",
					"the environment, and given to its apps as it is; written again",
					"without --plain, it is a secret again. In <env>@me, shown to you",
					"alone, and a value written saying nothing takes the level of the",
					"key it overrides, then of your own"
				]
			},
			{
				command: "set",
				usage: [`set       ${P}/<KEY> --sensitive`],
				about: [
					"a value shown to nobody, Owners included: people's apps use it",
					"through the credential proxy, and service accounts read it;",
					"written again, it stays sensitive unless --secret says otherwise"
				]
			},
			{
				command: "mark",
				usage: [`mark      ${P}[/<KEY>] <plain|secret|sensitive>`],
				about: [
					"a key, or every value of the environment's own, made stricter, its",
					"value kept: plain to secret, secret to sensitive; looser takes the",
					"value written again, coffre set … --secret, but an Owner of the",
					"project makes a sensitive value secret in place, never shown to",
					"them by it. A reference or an inherited key at another level is",
					"left, and named, to mark where it is held"
				]
			},
			{
				command: "set",
				usage: [`set       ${P}/<KEY> --ref <project>/<environment>/<KEY>`],
				about: ["a reference: whoever reads its environment reads that", "secret's current value through it; you need read on it"]
			},
			{
				command: "set",
				usage: [`set       ${P}/<KEY> --generate <recipe> [--public-key <KEY>]`],
				about: [
					"a value made here and never shown, by a recipe: bytes:32,",
					"bytes:32:hex (or base64, base64url), aes:256, or a key pair,",
					"ecdsa:p-256 or ecdh:p-384, its public key in JWT_PUBLIC_KEY",
					"beside JWT_PRIVATE_KEY, or --public-key; kept, for regenerate"
				]
			},
			{
				command: "regenerate",
				usage: [`regenerate ${P}/<KEY>`],
				about: ["a new value by the recipe its value was made by, never shown;", "a key pair, both its keys at once"]
			},
			{
				command: "references",
				usage: ["references <project>[/<environment>[/<KEY>]] [--json]"],
				about: ["the references into and out of it, and who reads through them"]
			},
			{
				command: "references break",
				usage: [`references break ${P}/<KEY> [--apply]`],
				about: ["who would stop reading through it; --apply breaks it"]
			},
			{
				command: "run",
				usage: [`run       [--keep-existing] [--proof <proof>] ${P}... -- <command>`],
				about: [
					"several environments: their keys together, and a key in two",
					"of them stops it before anything is read; --keep-existing lets",
					"a variable already set in your shell, empty ones too, win",
					"over coffre's value for it; <environment>@me reads your",
					"personal config of it, or it while you have none; where the",
					"deployment generates, your own value of each key a recipe made,",
					"made once, in your personal config; as a --service, key-bound",
					"where the instance has it: --proof says how it proves itself (none:",
					"a GitHub Actions job's ID token), the environments are the session's",
					"unless named, and credentials go through a local listener"
				]
			},
			{
				command: "export",
				usage: [`export    ${P}... [--keys <KEY | PREFIX_*>...] [--format dotenv|json|shell|github]`, "          [--output-file <file> [--watch [--interval 60s] [--on-change <command>]]]"],
				about: [
					"several, as run takes them; --keys reads only the keys it",
					"names, each one some environment must hold, and github",
					"needs it; --output-file writes them to a file only you can",
					"read, which --watch keeps current: it asks their version",
					"each interval, reads only once it changed, and runs",
					"--on-change after each new file"
				]
			},
			{
				command: "version",
				usage: [`version   ${P} [--json]`],
				about: ["what reading it would open, as a version that changes", "whenever a read would; it reads no value, and is not logged"]
			},
			{
				command: "history",
				usage: [`history   ${P}/<KEY> [--json]`]
			},
			{
				command: "rollback",
				usage: [`rollback  ${P}/<KEY> <version>`]
			},
			{
				command: "import",
				usage: [`import    ${P} [--file .env] [--apply]`]
			},
			{
				command: "rename",
				usage: [`rename    ${P}/<KEY> <NEW_KEY>`],
				about: ["the key, with its versions"]
			},
			{
				command: "archive",
				usage: [`archive   ${P}/<KEY>`],
				about: ["out of reads, runs and exports; its versions kept"]
			},
			{
				command: "unarchive",
				usage: [`unarchive ${P}/<KEY>`]
			},
			{
				command: "reset",
				usage: [`reset     ${P}/<KEY> [--undo]`],
				about: ["in a fork, back to its parent's value; its own is kept,", "and --undo serves it again"]
			},
			{
				command: "remove",
				usage: [`remove    ${P}/<KEY> [--undo]`],
				about: ["in a fork, does without its parent's key; --undo inherits it", "again"]
			},
			{
				command: "move",
				usage: [`move      ${P}/<KEY> (<folder> | --none)`],
				about: ["into a folder, to arrange the list; nothing else changes"]
			},
			{
				command: "folders",
				usage: [`folders   ${P} [--json]`],
				about: ["its key folders, and the keys in each; move makes them"]
			},
			{
				command: "folders rename",
				usage: [`folders rename ${P} <folder> <new-folder>`],
				about: ["every key in it moves; onto an existing folder, the two merge"]
			},
			{
				command: "folders remove",
				usage: [`folders remove ${P} <folder> [--apply]`],
				about: ["every key out of it, into no folder; more than one is", "shown first"]
			},
			{
				command: "missing",
				usage: [`missing   ${P} [--dismissed | --check] [--json]`],
				about: [
					"keys its sibling environments have and it lacks, by name, read",
					"or not; --dismissed, those its team decided it does not need;",
					"--check exits 1 when one is missing, for CI"
				]
			},
			{
				command: "missing dismiss",
				usage: [`missing dismiss ${P}/<KEY>`, `missing dismiss ${P} --all`],
				about: ["for the whole team, logged; restore brings it back"]
			},
			{
				command: "missing restore",
				usage: [`missing restore ${P}/<KEY>`]
			}
		]
	},
	{
		title: "Projects",
		entries: [
			{
				command: "projects",
				usage: ["projects [--json]"],
				about: ["with their environments"]
			},
			{
				command: "projects create",
				usage: ["projects create <project>"]
			},
			{
				command: "projects rename",
				usage: ["projects rename <project> --slug <new-project>"]
			},
			{
				command: "projects archive",
				usage: ["projects archive <project>"],
				about: ["out of reach, and back with unarchive"]
			},
			{
				command: "projects unarchive",
				usage: ["projects unarchive <project>"]
			},
			{
				command: "projects delete",
				usage: ["projects delete <project> [--apply]"],
				about: ["an archived one, for good: what it erases and revokes;", "--apply deletes it, and frees its name"]
			},
			{
				command: "move",
				usage: ["move <project> (<folder> | --none)"],
				about: ["into a folder of projects"]
			},
			{
				command: "folders",
				usage: ["folders [--json]"],
				about: ["the folders of projects, and the projects in each"]
			},
			{
				command: "folders rename",
				usage: ["folders rename <folder> <new-folder>"],
				about: ["every project in it moves; you must manage each of them"]
			},
			{
				command: "folders remove",
				usage: ["folders remove <folder> [--apply]"],
				about: ["every project out of it, each staying where it is"]
			},
			{
				command: "environments create",
				usage: [`environments create ${P}`]
			},
			{
				command: "fork",
				usage: [`fork ${P} <new-environment> [--reference | --inherit]`],
				about: [
					"a new environment beside it, each key a copy of its value,",
					"without history; --reference makes each key a reference",
					"to its parent instead; --inherit copies nothing: it reads",
					"its parent's keys live, but for those it sets or removes"
				]
			},
			{
				command: "personal",
				usage: ["personal  <project> [--json]"],
				about: [
					"its members' personal configs, <environment>@me: whose, of",
					"what, and their key names, never values; `environments delete",
					"<project>/<slug>` deletes one, as its owner deletes <env>@me"
				]
			},
			{
				command: "environments rename",
				usage: [`environments rename ${P} --slug <new-environment>`]
			},
			{
				command: "environments archive",
				usage: [`environments archive ${P}`]
			},
			{
				command: "environments unarchive",
				usage: [`environments unarchive ${P}`]
			},
			{
				command: "environments delete",
				usage: [`environments delete ${P} [--apply]`],
				about: ["an archived one, for good, as a project"]
			},
			{
				command: "environments protect",
				usage: [`environments protect ${P}`],
				about: ["each role holds its protected column there, for people:", "managing the project's environments does it"]
			},
			{
				command: "environments unprotect",
				usage: [`environments unprotect ${P}`],
				about: ["an Owner of the project, or of the whole instance, only"]
			}
		]
	},
	{
		title: "Access",
		entries: [
			{
				command: "roles",
				usage: ["roles [<role>] [--instance] [--json]"],
				about: ["every role, in two columns: anywhere, and in a protected", "environment, where a person holds the second"]
			},
			{
				command: "roles set",
				usage: ["roles set <role> [--name <name>] [--description <text>]", "          [--permissions <a,b>] [--protected <a,b>] [--instance] [--apply]"],
				about: ["a role edited, or one made, by an Owner of the whole instance:", "what it would change for whom, and --apply saves it"]
			},
			{
				command: "roles reset",
				usage: ["roles reset <role> [--instance] [--apply]"],
				about: ["a built-in role back as it ships, shown first"]
			},
			{
				command: "roles remove",
				usage: ["roles remove <role>"],
				about: ["a role an Owner made, once no grant names it"]
			},
			{
				command: "access",
				usage: ["access [<project>[/<environment>] | <member> [--service]] [--json]"],
				about: ["the members, their instance roles and grants; who reaches", "a place; or what one member holds"]
			},
			{
				command: "admit",
				usage: [
					"admit <principal> [--service] [--role <role>]",
					"      [--projects <a,b> | --except-projects <a,b>]",
					"      [--environments <a,b> | --except-environments <a,b>]",
					"      [--grant <project>[/<env>]=<role>,…]"
				],
				about: [
					"a member: a person by their email, or a service account,",
					"service:<name> or --service. --role sets a person's",
					"instance role, member, auditor, developer, admin or owner,",
					"in every project and environment unless a scope flag",
					"narrows it; never your own. --grant gives a service",
					"account its first grants with it: refused, it is not added"
				]
			},
			{
				command: "grant",
				usage: ["grant <project> <principal> --role <role> [--env <env>] [--service]", "      [--expires YYYY-MM-DD]"],
				about: ["a member, admitted first: on a project, or one of its", "environments with --env"]
			},
			{
				command: "revoke",
				usage: ["revoke <project> <principal> [--env <env>] [--service]"],
				about: ["their grant there"]
			},
			{
				command: "offboard",
				usage: ["offboard <principal> [--service] [--apply]"],
				about: ["what removing them revokes, and what to rotate"]
			},
			{
				command: "settings",
				usage: ["settings [service-accounts [--projects <a,b> | --except-projects <a,b>]", "         [--environments <a,b> | --except-environments <a,b>]] [--json]"],
				about: [
					"the instance's settings; with service-accounts, where anyone",
					"who holds access sets one up, giving it at most what they",
					"hold: no flag is everywhere"
				]
			}
		]
	},
	{
		title: "Service accounts, for CI and other machines: admit, grant, then OIDC or a bearer token; anyone with access sets one up where `coffre settings` lets them",
		entries: [
			{
				command: "trust",
				usage: ["trust <service> [--github … | --gitlab … | --issuer …] [--apply]"],
				about: ["OIDC, no stored secret: the CI runs that may sign in as", "it, by their platform's ID token; `coffre trust` alone says how"]
			},
			{
				command: "untrust",
				usage: ["untrust <service> <binding-id> [--apply]"],
				about: ["the CI runs it would cut off; --apply removes it"]
			},
			{
				command: "tokens",
				usage: ["tokens <service> [--json]"],
				about: ["its bearer tokens, for CI without OIDC"]
			},
			{
				command: "tokens issue",
				usage: ["tokens issue <service> [--expires-in <days>] [--label <label>]", "             [--scope <path>=<role>,…] [--output-file <path>]"],
				about: [
					"a bearer token, on stdout or in a new 0600 file, shown once",
					"and kept nowhere; 90 days unless told. It reaches what --scope",
					"says, at most what the account holds, all of it unless told,",
					"and nothing the account is given later"
				]
			},
			{
				command: "tokens revoke",
				usage: ["tokens revoke <service> <id> [--apply]"]
			}
		]
	},
	{
		title: "Workloads: apps that use secrets through coffre, with a session bound to a key they never export",
		entries: [
			{
				command: "enroll",
				usage: ["enroll <service> [--binding <id>]"],
				about: ["an enrollment code, for one deploy of an app on a platform", "that signs nothing: printed once, for the platform to hold"]
			},
			{
				command: "enroll",
				usage: ["enroll <service> --promote <code-id> [--now]"],
				about: ["the binding's current code, once the deploy is up: older", "codes' sessions drain; --now ends them at once"]
			},
			{
				command: "enroll",
				usage: ["enroll <service> --list [--json]"],
				about: ["the binding's live codes, and what each reaches"]
			},
			{
				command: "approve",
				usage: ["approve <service> <session-id>"],
				about: ["a session its binding holds for a person to check"]
			},
			{
				command: "freeze",
				usage: ["freeze [<target> --reason <text>]"],
				about: [
					"every use under the target refused from its next request,",
					"its sessions and codes kept: instance, service:<name>,",
					"binding:<id>, session:<id> or credential:<path>/<name>;",
					"alone, what is frozen"
				]
			},
			{
				command: "unfreeze",
				usage: ["unfreeze <target>"],
				about: ["lifts it"]
			},
			{
				command: "serve",
				usage: ["serve --url <url> --service <name> --proof <proof> [--place <project>/<env>]", "      [--listen <address>] [--tunnel <name>=<address>]..."],
				about: [
					"a workload's sidecar: it holds the session and its key,",
					"and forwards what the app sends it, signed; --listen, 127.0.0.1:7300",
					"unless given, or unix:<path>; each --tunnel a Postgres listener;",
					"--proof kubernetes[:<file>], aws, gcp, azure:<audience>, fly,",
					"vercel, github, enrollment or oidc (those two read stdin); --place",
					"which of the session's environments its tunnels are in"
				]
			}
		]
	},
	{
		title: "Audit",
		entries: [{
			command: "audit",
			usage: ["audit [<path>] [--limit N] [--actor <id>] [--denied] [--detail] [--json]"],
			about: ["a project, environment or KEY: market/prod/DATABASE_URL lists", "who read or changed it, reads of several that listed it included"]
		}, {
			command: "audit accept-loss",
			usage: ["audit accept-loss <from> <to>"],
			about: ["as an owner of the whole instance: entries <from> to <to> are lost for", "good, a cut with no backup; the audit watch's finding stays logged"]
		}]
	},
	{
		title: "Verify",
		entries: [
			{
				command: "verify",
				usage: ["verify"],
				about: ["asks which of these, on a terminal"]
			},
			{
				command: "verify instance",
				usage: ["verify instance [<url>]"],
				about: ["the instance from outside: as no one, then as you, an", "admin or owner"]
			},
			{
				command: "verify keys",
				usage: ["verify keys [--vault-id <id>]"],
				about: ["the vault key and app key you keep, checked on this machine"]
			},
			{
				command: "verify log",
				usage: ["verify log"],
				about: ["the whole audit log, as an auditor, admin or owner of all of it"]
			},
			{
				command: "verify backup",
				usage: ["verify backup <dump> [--keys]"],
				about: ["a backup, restored into an empty scratch database and", "checked as restore does; needs no coffre role"]
			}
		]
	}
];
const ENTRIES = SECTIONS.flatMap(({ entries }) => entries);
const SESSION_FLAGS = `  Session flags, before the command: coffre [flags] <command>, for that command alone
    --url <url>                     which instance to talk to; else the one this directory is pinned
                                    to, by a login in it or above it, or its repository's coffre.json
                                    names, { "url": "https://…" }, whichever is nearer; else the default
    --service <name>                the service account a CI run signs in as, by OIDC: its ID token,
                                    which a trust binding accepts (coffre trust); on GitHub Actions, with
                                    \`permissions: id-token: write\`, nothing else
    --auth-mode signin|cloudflare   normally detected at login
    Without them, the session \`coffre login\` saved.
    --verbose                       each request on stderr: its method, path, status and time, and
                                    each time the CLI asks again; never a header, a body or a value

  A secret is asked for, at a hidden prompt, or piped in; never a flag or an argument:
    printf '%s' "$TOKEN" | coffre login https://coffre.example.com --token

  coffre <command> --help says more of each; coffre --version, which version this is.
`;
/** Where the line beside a synopsis starts. */
const COLUMN = 44;
/** An entry's lines, as `coffre help` shows them: the synopsis, and beside it or under it, what it does. */
function lines(entry) {
	const usage = entry.usage.map((line, i) => `    ${i === 0 ? "coffre " : "       "}${line}`);
	const about = entry.about ?? [];
	const last = usage.at(-1);
	if (about.length > 0 && last.length < 43) return [
		...usage.slice(0, -1),
		`${last.padEnd(COLUMN)}${about[0]}`,
		...about.slice(1).map((line) => `${" ".repeat(COLUMN)}${line}`)
	];
	return [...usage, ...about.map((line) => `${" ".repeat(COLUMN)}${line}`)];
}
/** `coffre help`. */
function usage() {
	return `coffre - secrets, with an audit log\n\n${SECTIONS.map(({ title, entries }) => [`  ${title}`, ...entries.flatMap(lines)].join("\n")).join("\n\n")}\n\n${SESSION_FLAGS}`;
}
/**
* What `argv` names: a command, its words the longest that match
* (`projects create` before `projects`), and the arguments after them; or a
* group of commands, `tokens` or `environments`, alone; or nothing.
*/
function lookup(argv) {
	for (let count = Math.min(argv.length, 2); count > 0; count--) {
		const words = argv.slice(0, count).join(" ");
		if (ENTRIES.some((entry) => entry.command === words)) return {
			command: words,
			args: argv.slice(count)
		};
	}
	const [first] = argv;
	return first !== void 0 && ENTRIES.some((entry) => entry.command.startsWith(`${first} `)) ? { group: first } : null;
}
/** `coffre <command> --help`: the command's entries, and those under it. */
function help(command) {
	return `usage:\n${ENTRIES.filter((entry) => entry.command === command || entry.command.startsWith(`${command} `)).flatMap(lines).join("\n")}\n`;
}
//#endregion
//#region src/enroll.ts
/** `coffre enroll <service> [--binding <id>] [--promote <code-id> [--now] | --list [--json]]`. */
async function enroll(args) {
	parse(args, {
		binding: { type: "string" },
		promote: { type: "string" },
		now: { type: "boolean" },
		list: { type: "boolean" },
		json: { type: "boolean" }
	}, ["<service>"]);
	throw new Error("coffre enroll is not built yet: docs/design/workload-access.md, PR 3, brings it");
}
/** `coffre approve <service> <session-id>`. */
async function approve(args) {
	parse(args, {}, ["<service>", "<session-id>"]);
	throw new Error("coffre approve is not built yet: docs/design/workload-access.md, PR 3, brings it");
}
//#endregion
//#region src/freeze.ts
/** `coffre freeze [<target> --reason <text>]`: alone, what is frozen. */
async function freeze(args) {
	parse(args, { reason: { type: "string" } }, ["<target>"], 1);
	throw new Error("coffre freeze is not built yet: docs/design/workload-access.md, PR 4, brings it");
}
/** `coffre unfreeze <target>`. */
async function unfreeze(args) {
	parse(args, {}, ["<target>"]);
	throw new Error("coffre unfreeze is not built yet: docs/design/workload-access.md, PR 4, brings it");
}
//#endregion
//#region ../client/dist/workload-postgres.js
/**
* The WebSocket URL of the tunnel `name`: always under its environment,
* `/use/<project>/<env>/<name>`, which coffre's tunnel route requires,
* where `url(name)` shortens a single place's to `/use/<name>`.
*/
function tunnelUrl(coffre, name) {
	const url = new URL(coffre.url(name));
	if (coffre.places.length === 1) url.pathname = `/use/${[...coffre.places[0].split("/"), name].map(encodeURIComponent).join("/")}`;
	return url.href.replace(/^http/, "ws");
}
//#endregion
//#region src/instance.ts
/**
* Which coffre the CLI talks to, and how it proves who you are there.
*
* One person often has several instances (a company's and their own), so
* sessions are kept per origin in one file, and `coffre login <url>` makes
* that origin the default one:
*
*   {
*     "version": 2,
*     "current": "https://coffre.example.com",
*     "instances": {
*       "https://coffre.example.com": { "mode": "signin", "token": "coffre_cli_…", … },
*       "https://coffre.acme.example": { "mode": "cloudflare", … }
*     }
*   }
*
* A CI run signs in the same way, with what `coffre login` asks it for: a
* bearer token (`--token`), an Access service token's secret
* (`--access-client-id`), or the credential its ID token buys
* (`--service`); each saved as the instance's session. The session flags
* pick another instance than the one a command would use, `--url`, or sign
* one command in as a service by its ID token, `--service` (`flags.ts`).
*
* `coffre login <url>` also pins the directory it ran in to that origin,
* for it and every directory below, in a file of its own beside the
* sessions (`Pins`). A repository can name its instance for everyone who
* clones it, in a `coffre.json` it commits (`parseRepoFile`). A command uses
* `--url`, else the nearest pinned directory or `coffre.json` above where it
* runs, a pin before a file in the same directory, else the default.
*/
/** What an agent does with `coffre login`, which waits for a person to approve a link: it must not block on it. */
const SIGN_IN_HINT = "agents: run the command in the background and provide the link it prints to the user";
/**
* A sign-in error: `message`, which names the command, and the hint under it.
* `mode`, how the instance signs in when that is known, from --auth-mode or a session signed in again:
* Cloudflare Access signs in with cloudflared, not a link, and gets no hint.
*/
function signInError(message, mode) {
	return mode === "cloudflare" ? message : `${message}\n${SIGN_IN_HINT}`;
}
/** `--auth-mode`, if it is one: a mode it is not is for the command to refuse, not for a hint to. */
function askedMode(raw) {
	try {
		return parseMode(raw);
	} catch {
		return;
	}
}
/** The file a repository names its instance in. */
const REPO_FILE = "coffre.json";
const MODES = ["signin", "cloudflare"];
const KINDS = [
	"token",
	"access",
	"run"
];
function emptyStore() {
	return {
		version: 2,
		current: null,
		instances: {}
	};
}
/**
* Read the credentials file. Anything unrecognised reads as empty: the worst
* case is one extra login, never a token sent to the wrong place.
*/
function parseStore(text) {
	let raw;
	try {
		raw = JSON.parse(text);
	} catch {
		return emptyStore();
	}
	if (typeof raw !== "object" || raw === null) return emptyStore();
	const candidate = raw;
	if (candidate.version !== 2 || typeof candidate.instances !== "object" || candidate.instances === null) return emptyStore();
	const instances = {};
	for (const [origin, session] of Object.entries(candidate.instances)) if (typeof session === "object" && session !== null && MODES.includes(session.mode) && (session.kind === void 0 || KINDS.includes(session.kind))) instances[origin] = session;
	return {
		version: 2,
		current: typeof candidate.current === "string" && candidate.current in instances ? candidate.current : null,
		instances
	};
}
function emptyPins() {
	return {
		version: 1,
		directories: {}
	};
}
/**
* Read the pins file. Unlike the sessions, one this CLI cannot read is an
* error, not an empty file: that would send a pinned directory's commands
* to the default instance.
*/
function parsePins(text) {
	let raw;
	try {
		raw = JSON.parse(text);
	} catch {
		throw new Error("it is not JSON");
	}
	const candidate = typeof raw === "object" && raw !== null ? raw : {};
	if (candidate.version !== 1 || typeof candidate.directories !== "object" || candidate.directories === null || Array.isArray(candidate.directories)) throw new Error("this CLI does not know its shape: a later coffre wrote it, perhaps");
	const directories = {};
	for (const [directory, origin] of Object.entries(candidate.directories)) {
		if (!isAbsolute(directory) || typeof origin !== "string") throw new Error(`it pins ${JSON.stringify(directory)} to ${JSON.stringify(origin)}`);
		directories[directory] = instanceOrigin(origin);
	}
	return {
		version: 1,
		directories
	};
}
/** Whether `directory` is `ancestor` or below it. */
function within(directory, ancestor) {
	const path = relative(ancestor, directory);
	return path === "" || path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}
/** The pin that applies in `directory`, a real path: the longest pinned one it is in. */
function pinFor(pins, directory) {
	let found = null;
	for (const [pinned, origin] of Object.entries(pins.directories)) if (within(directory, pinned) && (found === null || pinned.length > found.directory.length)) found = {
		directory: pinned,
		origin
	};
	return found;
}
/** Pin `directory` to `origin`. */
function withPin(pins, directory, origin) {
	return {
		version: 1,
		directories: {
			...pins.directories,
			[directory]: origin
		}
	};
}
/** Every pin to `origin` taken out, and the directories they pinned. */
function withoutPins(pins, origin) {
	const kept = Object.entries(pins.directories).filter(([, pinned]) => pinned !== origin);
	const unpinned = Object.entries(pins.directories).filter(([, pinned]) => pinned === origin).map(([directory]) => directory);
	return {
		pins: {
			version: 1,
			directories: Object.fromEntries(kept)
		},
		unpinned
	};
}
/**
* The origin a repository's `coffre.json` names, committed beside its code
* so that a clone uses its instance with no `--url` and no pin:
*
*   { "url": "https://coffre.acme.example" }
*
* Only that: a file anyone can commit picks where the CLI goes, never what
* it carries, which stays that instance's own session. So it holds no
* credential and nothing else, and its URL is an origin as written.
*/
function parseRepoFile(text) {
	let raw;
	try {
		raw = JSON.parse(text);
	} catch {
		throw new Error("it is not JSON");
	}
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error("expected { \"url\": \"https://…\" }");
	const others = Object.keys(raw).filter((key) => key !== "url");
	if (others.length > 0) throw new Error(`it holds only "url", never a credential or anything else: not ${others.map((key) => JSON.stringify(key)).join(", ")}`);
	const { url } = raw;
	if (typeof url !== "string") throw new Error("expected { \"url\": \"https://…\" }");
	const origin = instanceOrigin(url);
	if (origin !== url) throw new Error(`"url" is an origin, written as one: ${JSON.stringify(origin)}, not ${JSON.stringify(url)}`);
	return origin;
}
/**
* What names the instance in `directory`, a real path: walking up from it,
* the first directory pinned or holding a `coffre.json`, the pin first.
* Your home and the directories above it hold no project's `coffre.json`,
* as a login there pins nothing. `read` gives a file's text, or null if
* there is none; a file there that cannot be read or used is an error,
* never a reason to look further up.
*/
function localFor(pins, directory, home, read) {
	const pin = pinFor(pins, directory);
	for (let at = directory; !within(home, at) && !(pin !== null && within(pin.directory, at)); at = dirname(at)) {
		const path = join(at, REPO_FILE);
		const text = read(path);
		if (text !== null) try {
			return {
				origin: parseRepoFile(text),
				by: "file",
				directory: at
			};
		} catch (error) {
			throw new Error(`cannot use ${path}: ${error.message}`);
		}
		if (dirname(at) === at) break;
	}
	return pin === null ? null : {
		...pin,
		by: "pin"
	};
}
/**
* The instance a command means: `--url`, else the pin or `coffre.json` that
* applies where it runs, else the default. That instance is the one, signed
* in there or not: never another one's session in its place.
*/
function choose(flags, store, local) {
	if (flags.url !== void 0) return {
		origin: instanceOrigin(flags.url),
		by: "url"
	};
	if (local !== null) return {
		...local,
		origin: instanceOrigin(local.origin)
	};
	if (store.current !== null) return {
		origin: instanceOrigin(store.current),
		by: "default"
	};
	throw new Error(signInError("not signed in anywhere yet: run `coffre login <url>`", askedMode(flags.authMode)));
}
function parseMode(raw) {
	if (raw === void 0) return void 0;
	if (!MODES.includes(raw)) throw new Error(`--auth-mode must be one of ${MODES.join(", ")}, not "${raw}"`);
	return raw;
}
function isLoopback(hostname) {
	return hostname === "localhost" || hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}
/**
* Normalise what someone typed into an origin the CLI will send credentials
* to. Plain HTTP is refused except on this machine, where there is no wire to
* listen on. A bare host name means HTTPS, or HTTP for this machine:
* `coffre.example.com` and `127.0.0.1:3000` both do what they look like.
*/
function instanceOrigin(raw) {
	const value = raw.trim();
	const invalid = () => /* @__PURE__ */ new Error(`"${raw}" is not a coffre address; expected something like https://coffre.example.com`);
	let url;
	try {
		if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) url = new URL(value);
		else {
			url = new URL(`https://${value}`);
			if (isLoopback(url.hostname)) url.protocol = "http:";
		}
	} catch {
		throw invalid();
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") throw invalid();
	if (url.username !== "" || url.password !== "") throw new Error("the coffre address must not contain a user name or password");
	if (url.pathname !== "/" && url.pathname !== "" || url.search !== "" || url.hash !== "") throw new Error(`the coffre address must be an origin, like ${url.origin}, without a path`);
	if (url.protocol === "http:" && !isLoopback(url.hostname)) throw new Error(`refusing to send credentials over plain HTTP; use https://${url.host}`);
	return url.origin;
}
function isJsonContentType(value) {
	if (value === null) return false;
	const mediaType = value.split(";", 1)[0].trim().toLowerCase();
	return mediaType === "application/json" || mediaType.endsWith("+json");
}
/**
* How to sign in somewhere, from its answer to `GET /api/auth` without a
* credential. coffre says how it signs people in. Cloudflare Access, in front
* of it, turns the CLI away first, with a redirect to its own login page:
*
*   200 { signin: { providers: […] }, access: null }   → a device login
*   200 { signin: null, access: { … } }                 → cloudflared
*   302 Location: https://acme.cloudflareaccess.com/…   → cloudflared
*/
function loginMode(origin, status, body) {
	if (status >= 300 && status < 400) return "cloudflare";
	const auth = status === 200 && typeof body === "object" && body !== null ? body : null;
	if (auth?.signin) return "signin";
	if (auth?.access) return "cloudflare";
	if (status === 401 || status === 403) throw new Error(`${origin} turned the CLI away (status ${status}). If it is behind Cloudflare Access,\n  run \`coffre --auth-mode cloudflare login ${origin}\``);
	throw new Error(`${origin} does not look like coffre: GET /api/auth answered ${status}`);
}
/**
* Decide where the next request goes and what it carries, or explain why it
* cannot be sent. Pure, so every precedence rule is testable. A flag given
* is given: `readSession` refused an empty one, which falling back to the
* saved session would have taken for none.
*/
function resolveTarget(flags, store, local = null, now = /* @__PURE__ */ new Date()) {
	const explicitMode = parseMode(flags.authMode);
	const choice = choose(flags, store, local);
	const { origin } = choice;
	if (flags.service !== void 0) {
		if (explicitMode === "cloudflare") throw new Error("--service signs a CI run in with its ID token, which coffre's own sign-in takes: behind Cloudflare Access, use an Access service token");
		const named = apiMember(flags.service);
		return {
			origin,
			mode: "signin",
			by: "service",
			credential: {
				kind: "workload",
				service: named.startsWith("token:") ? named : `token:${named}`
			}
		};
	}
	const stored = store.instances[origin];
	const mode = explicitMode ?? stored?.mode ?? "signin";
	const relogin = `run \`coffre login ${origin}\``;
	if (stored === void 0 || stored.mode !== mode) {
		const named = choice.by === "file" ? ` (named by ${join(choice.directory, REPO_FILE)})` : "";
		throw new Error(signInError(`not signed in: ${relogin}${named}`, explicitMode));
	}
	const by = stored.kind ?? "person";
	if (mode === "cloudflare") {
		if (by !== "access") return {
			origin,
			mode,
			by,
			credential: { kind: "cloudflared" }
		};
		if (!stored.clientId || !stored.clientSecret) throw new Error(`not signed in: ${relogin}`);
		return {
			origin,
			mode,
			by,
			credential: {
				kind: "access-service-token",
				clientId: stored.clientId,
				clientSecret: stored.clientSecret
			}
		};
	}
	if (!stored.token) {
		const message = `not signed in: ${relogin}`;
		throw new Error(by === "person" ? signInError(message, "signin") : message);
	}
	if (stored.expiresAt && Date.parse(stored.expiresAt) <= now.getTime()) {
		const ended = `your session on ${origin} ended on ${stored.expiresAt.slice(0, 10)}: ${relogin}`;
		throw new Error(by === "run" ? `the credential this run's ID token bought on ${origin} lasted until ${stored.expiresAt.slice(11, 19)}: sign in again, \`coffre login ${origin} --service ${stored.principal?.id ?? "<name>"}\`` : by === "person" ? signInError(ended, "signin") : ended);
	}
	return {
		origin,
		mode,
		by,
		credential: {
			kind: "token",
			token: stored.token
		}
	};
}
/**
* The headers that carry a credential, per mode. coffre's own sign-in takes a
* standard bearer token. Cloudflare Access takes its user token, or a service
* token's id and secret, at the edge, and hands coffre its own assertion.
*/
function credentialHeaders(mode, credential, issued) {
	switch (credential.kind) {
		case "access-service-token": return {
			"cf-access-client-id": credential.clientId,
			"cf-access-client-secret": credential.clientSecret
		};
		case "cloudflared":
			if (!issued) throw new Error("cloudflared did not return a token");
			return { "cf-access-token": issued };
		case "workload":
			if (!issued) throw new Error("the run was not signed in: no credential was exchanged");
			return { authorization: `Bearer ${issued}` };
		case "token": return mode === "cloudflare" ? { "cf-access-token": credential.token } : { authorization: `Bearer ${credential.token}` };
	}
}
function withSession(store, origin, session) {
	return {
		version: 2,
		current: origin,
		instances: {
			...store.instances,
			[origin]: session
		}
	};
}
function withoutSession(store, origin) {
	const { [origin]: _removed, ...instances } = store.instances;
	return {
		version: 2,
		current: store.current === origin ? Object.keys(instances)[0] ?? null : store.current,
		instances
	};
}
//#endregion
//#region src/serve.ts
/**
* `coffre serve --url <url> --service <name> --proof <proof> [--place <project>/<env>] [--listen <address>] [--tunnel <name>=<address>]…`;
* `url`, the session flag's, if given before the command; `fetching`, the
* fetch for the instance at an origin, timed under `--verbose`.
*/
async function serve(args, sessionUrl, fetching) {
	const { values } = parse(args, {
		url: { type: "string" },
		service: { type: "string" },
		proof: { type: "string" },
		place: { type: "string" },
		listen: { type: "string" },
		tunnel: {
			type: "string",
			multiple: true
		}
	}, []);
	const given = values.url ?? sessionUrl;
	if (given === void 0 || values.service === void 0) throw new UsageError(`coffre serve --url <url> --service <name> --proof <proof>: which instance, as which service, proved how (${PROOFS})`);
	const origin = instanceOrigin(given);
	const address = addressOf(values.listen ?? "127.0.0.1:7300", "--listen");
	const tunnels = (values.tunnel ?? []).map((spec) => {
		const [name, at] = spec.split(/=(.*)/s);
		if (!name || at === void 0) throw new UsageError(`--tunnel ${spec}: a tunnel is <name>=<host>:<port>, as db=127.0.0.1:7432`);
		const where = addressOf(at, "--tunnel");
		if ("path" in where) throw new UsageError(`--tunnel ${spec}: a tunnel listens on a host and port`);
		return {
			name,
			where
		};
	});
	const proof = await proofOf(values.proof, process.env);
	const say = (line) => process.stderr.write(`${line}\n`);
	const coffre = await workload({
		url: origin,
		service: values.service,
		proof,
		place: values.place,
		log: say,
		sigterm: false,
		fetch: fetching(origin)
	});
	const opened = [];
	const stop = async (code) => {
		for (const each of opened) each.close();
		await coffre.close().catch((error) => say(`coffre: ${error instanceof Error ? error.message : String(error)}`));
		process.exit(code);
	};
	for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => void stop(0));
	try {
		const local = await forwarder(coffre, origin, address);
		opened.push(local);
		const lines = [`coffre: ${values.service} in ${coffre.places.join(", ")}, key-bound: ${local.url}/use/<credential>/… forwards to ${origin}, signed`];
		for (const { name, where } of tunnels) {
			const listener = await listen({
				key: name,
				url: tunnelUrl(coffre, name)
			}, coffre, { address: where });
			opened.push(listener);
			lines.push(`coffre: ${name} on ${listener.url}`);
		}
		say(lines.join("\n"));
	} catch (error) {
		say(`coffre: ${error instanceof Error ? error.message : String(error)}`);
		await stop(1);
	}
}
//#endregion
//#region src/version.ts
/**
* This CLI's version: the schema it migrates to, the version of coffre a
* deployment it makes runs, and the one `coffre migrate` expects to find.
*/
function cliVersion() {
	return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
}
//#endregion
//#region src/watch.ts
/** The longest wait between two rounds that failed. */
const MAX_WAIT_MS = 9e5;
/**
* Put `text` in `file`, mode 0600, whole or not at all: written beside it,
* then renamed over it, so a reader never sees half of it. False when the
* file held exactly that already, readable by you alone, and was left as it was.
*/
function replaceFile(file, text) {
	try {
		if ((statSync(file).mode & 63) === 0 && readFileSync(file, "utf8") === text) return false;
	} catch (error) {
		if (error.code !== "ENOENT") throw error;
	}
	const temporary = join(dirname(file), `.${basename(file)}.${randomBytes(6).toString("hex")}`);
	try {
		writeFileSync(temporary, text, {
			mode: 384,
			flag: "wx"
		});
		renameSync(temporary, file);
	} catch (error) {
		rmSync(temporary, { force: true });
		throw error;
	}
	return true;
}
/** `60`, `60s`, `5m` or `1h`, in milliseconds: five seconds to a day. */
function interval(text) {
	const match = /^(\d+)([smh]?)$/.exec(text);
	const unit = {
		"": 1e3,
		s: 1e3,
		m: 6e4,
		h: 36e5
	}[match?.[2] ?? ""];
	const ms = match === null || unit === void 0 ? NaN : Number(match[1]) * unit;
	if (!(ms >= 5e3 && ms <= 864e5)) throw new Error(`--interval takes a duration from 5s to 24h, such as 60s or 5m, not "${text}"`);
	return ms;
}
function duration(ms) {
	return ms % 6e4 === 0 ? `${ms / 6e4}m` : `${Math.round(ms / 1e3)}s`;
}
/**
* Keep `file` current, until stopped. Each round asks the version, and on a
* new one reads, writes the file when what it holds changed, then runs the
* hook. The first round fails as an export does, with nothing to keep; a
* later one says why, keeps the file as it was, and waits twice as long
* each time, up to 15 minutes or the interval, whichever is longer, before
* it asks again.
*/
async function watch({ version, read, file, intervalMs, onChange, say, wait = setTimeout$1 }) {
	let seen = null;
	let pause = intervalMs;
	for (;;) {
		try {
			if (await version() !== seen) {
				const got = await read();
				const changed = replaceFile(file, got.text);
				seen = got.version;
				if (changed) {
					say(`wrote ${file}`);
					if (onChange !== null) await hook(onChange, say);
				}
			}
			pause = intervalMs;
		} catch (error) {
			if (seen === null) throw error;
			pause = Math.min(pause * 2, Math.max(MAX_WAIT_MS, intervalMs));
			say(`${error instanceof Error ? error.message : String(error)}; ${file} keeps what it had, and coffre asks again in ${duration(pause)}`);
		}
		await wait(pause);
	}
}
/** Run the command through the shell, and wait for it: it gets no value, only the file. */
async function hook(command, say) {
	const code = await new Promise((done) => {
		const child = spawn(command, {
			shell: true,
			stdio: "inherit"
		});
		child.on("error", (error) => done(error.message));
		child.on("exit", (exit, signal) => done(signal ?? exit ?? 0));
	});
	if (code !== 0) say(`--on-change ${typeof code === "number" ? `exited with ${code}` : `failed: ${code}`}`);
}
//#endregion
//#region src/backup-help.ts
const BACKUP_USAGE = `usage: coffre backup [<file>]

Dumps the database with pg_dump, as a backup login, a member of
coffre_backup (\`coffre migrate --backup-login <login>\` grants it), into
<file> (coffre-<UTC time>.dump by default), and writes what it holds
beside it, <file minus .dump>.manifest.json: each table's rows, counted and
hashed, the newest migration and the audit log's head, read in the snapshot
pg_dump dumps, and the dump's SHA-256. Neither file holds a key: values stay
encrypted, but plain ones are in the clear, so the files are yours alone.

Asks for the login's connection string at a hidden prompt, or reads it from
stdin, never an argument. Needs PostgreSQL's pg_dump, of the server's major
version or newer, on PATH. Refuses a login whose row-level security would
hide rows of any table it counts, the audit log's above all, from the dump.`;
const KEYS_HELP = `With --keys, it asks for the vault keys, then the app keys, separated by
spaces: first the one each signs with now, then any it replaced. The
vault signs with its own signing key if its config gives one, otherwise
with its current vault key; a vault with a signing key of its own gets
that first, then its vault keys. It
then also opens every version of every value, each under the vault key
its vault ID names, and authenticates each audit entry under the keys
given; entries under others are linked only, and counted, but each
author's newest entries must be under the first key given, and no other
may write once it has. On stdin, the connection string
is the first line, the vault keys the second and the app keys the third;
a blank line skips them. Only local vault keys: one in a key service
never leaves it.`;
const RESTORE_USAGE = `usage: coffre restore <dump> [--keys]

Restores a dump \`coffre backup\` made into an empty database, as its
owner, with pg_restore, then checks it against the manifest beside the
dump: every table's rows, counted and hashed, the migrations, the audit
log's head, and its chain from the first entry to the head. Says what is
left to do before the deployment runs on it.

Asks for the owner's connection string at a hidden prompt, or reads it
from stdin, never an argument. The server needs coffre's roles, which the
dump's grants name. Needs PostgreSQL's pg_restore on PATH.

${KEYS_HELP}

Exits 1 when a check fails.`;
const VERIFY_BACKUP_USAGE = `usage: coffre verify backup <dump> [--keys]

Restores a dump \`coffre backup\` made into an empty scratch database, then
checks it as \`coffre restore\` does. Leaves owners, grants and row policies
out, so it needs none of coffre's roles on that server; the copy stays,
for you to drop. Asks for that database's owner's connection string at a
hidden prompt, or reads it from stdin. Needs pg_restore on PATH.

${KEYS_HELP}

Exits 1 when a check fails.`;
//#endregion
//#region src/verify/checks.ts
/** A check that failed: what went wrong, and what was seen instead. */
var Failure = class extends Error {
	detail;
	constructor(message, detail) {
		super(message);
		this.detail = detail;
	}
};
/** A check that cannot run against this instance, and why. */
var Skip = class extends Error {};
function expect(condition, message, detail) {
	if (!condition) throw new Failure(message, detail);
}
/** The status coffre turned a call away with. A call that went through fails the check: `what` says what it should not have done. */
async function refused$1(what, call) {
	const outcome = await call.then((value) => ({ value }), (error) => ({ error }));
	if ("value" in outcome) throw new Failure(`${what}, and was let`, outcome.value);
	if (!(outcome.error instanceof CoffreError)) throw outcome.error;
	expect(outcome.error.status >= 400 && outcome.error.status < 500, `${what}, and failed with ${outcome.error.status}`, outcome.error.message);
	return outcome.error;
}
/** End the command at once, for a mistake in how it was called: `message` on stderr, or on stdout for an exit 0 (help). */
function stop(code, message) {
	(code === 0 ? process.stdout : process.stderr).write(`${message}\n`);
	process.exit(code);
}
/** The API as a service or the CLI calls it, with a bearer token: every refusal thrown, as a check wants it. */
function bearer(origin, token) {
	return createClient({
		url: origin,
		headers: () => ({ authorization: `Bearer ${token}` })
	});
}
/** The checks of one run, each printed as it ends: a mark, its name, and a line. */
var Checks = class {
	#out;
	#results = [];
	constructor(out) {
		this.#out = out;
	}
	get results() {
		return this.#results;
	}
	get failed() {
		return this.#results.filter(({ status }) => status === "fail").map(({ name }) => name);
	}
	/**
	* Run one check. `needs` holds what earlier checks made: if one is
	* missing, this one is skipped rather than run against an instance that
	* is not in the state it expects.
	*/
	async check(name, needs, run) {
		const missing = Object.keys(needs).filter((key) => needs[key] === void 0 || needs[key] === null);
		if (missing.length > 0) {
			this.#print(name, "skip", `no ${missing.join(" or ")}: an earlier check failed`);
			return;
		}
		try {
			const passed = await run(needs);
			this.#print(name, "ok", typeof passed === "string" ? passed : passed.detail);
			return typeof passed === "string" ? void 0 : passed.value;
		} catch (error) {
			if (error instanceof Skip) {
				this.#print(name, "skip", error.message);
				return;
			}
			const detail = error instanceof Failure ? error.detail : error instanceof Unreachable ? void 0 : error instanceof Error ? error.stack : error;
			this.#print(name, "fail", error instanceof Error ? error.message : String(error), detail);
			return;
		}
	}
	#print(name, status, line, detail) {
		this.#results.push({
			name,
			status,
			line
		});
		const s = style(this.#out);
		const mark = {
			ok: s.green("✓"),
			fail: s.red("✗"),
			skip: s.dim("–")
		}[status];
		const text = status === "skip" ? s.dim(line) : status === "fail" ? s.red(line) : line;
		this.#out.write(`  ${mark} ${status === "skip" ? s.dim(name.padEnd(19)) : name.padEnd(19)} ${text}\n`);
		if (status === "fail" && detail !== void 0) {
			const shown = typeof detail === "string" ? detail : inspect(detail, {
				depth: 6,
				breakLength: 100,
				colors: false
			});
			this.#out.write(`${s.dim(shown.replace(/^/gm, " ".repeat(24)))}\n`);
		}
	}
};
//#endregion
//#region ../client/dist/routes.js
function getCalls({ places, secrets, members, services }) {
	const first = places[0];
	return {
		"GET /me": [{ params: {} }],
		"GET /projects": [{ params: {} }],
		"GET /secrets/:project/:environment": places.map((params) => ({ params })),
		"GET /projects/:project/:environment/missing": places.map((params) => ({ params })),
		"GET /personal/:project": [...new Set(places.map((params) => params.project))].map((project) => ({ params: { project } })),
		"GET /projects/:project/:environment/version": places.map((params) => ({ params })),
		"GET /secrets/:project/:environment/:key/versions": secrets.map((params) => ({ params })),
		"GET /members": [{ params: {} }, ...first === void 0 ? [] : [{
			params: {},
			input: { path: `${first.project}/${first.environment}` }
		}]],
		"GET /references": [...first === void 0 ? [] : [{
			params: {},
			input: { path: first.project }
		}, {
			params: {},
			input: { path: `${first.project}/${first.environment}` }
		}]],
		"GET /members/:member": members.map((member) => ({ params: { member } })),
		"GET /members/:member/access": members.map((member) => ({ params: { member } })),
		"GET /members/:member/tokens": services.map((member) => ({ params: { member } })),
		"GET /members/:member/bindings": services.map((member) => ({ params: { member } })),
		"GET /members/:member/bindings/:id/enrollments": services.map((member) => ({ params: {
			member,
			id: "00000000-0000-4000-8000-000000000000"
		} })),
		"GET /workloads/lookup": [{
			params: {},
			input: { github: "acme/api" }
		}],
		"GET /workloads/repositories": [{ params: {} }],
		"GET /freezes": [{ params: {} }],
		"GET /roles": [{ params: {} }],
		"GET /settings": [{ params: {} }],
		"GET /sessions": [{ params: {} }],
		"GET /identities": [{ params: {} }],
		"GET /device-logins/:code": [{ params: { code: "BCDF-GHJK" } }],
		"GET /oauth/authorizations": [{
			params: {},
			input: {
				client_id: "00000000-0000-4000-8000-000000000000",
				redirect_uri: "https://conformance.invalid/callback"
			}
		}],
		"GET /approvals/:id": [{ params: { id: "00000000-0000-4000-8000-000000000000" } }],
		"GET /apps": [{ params: {} }],
		"GET /audit": [{
			params: {},
			input: { limit: 500 }
		}, {
			params: {},
			input: {
				limit: 500,
				detail: "1"
			}
		}],
		"GET /audit/verification": [{ params: {} }],
		"GET /audit/trees": [{ params: {} }],
		"GET /audit/keys": [{ params: {} }]
	};
}
/** Each GET call as a URL, with its parameters and query filled in. */
function getUrls(origin, calls) {
	const urls = [];
	for (const [key, asks] of Object.entries(calls)) for (const { params, input } of asks) urls.push({
		key,
		url: address(origin, key, params, input)
	});
	return urls;
}
/** Every route, whatever its method. */
const EVERY_ROUTE = {
	"GET /me": true,
	"GET /projects": true,
	"PUT /projects/:project": true,
	"PATCH /projects/:project": true,
	"DELETE /projects/:project": true,
	"PUT /projects/:project/:environment": true,
	"PATCH /projects/:project/:environment": true,
	"DELETE /projects/:project/:environment": true,
	"GET /projects/:project/:environment/missing": true,
	"GET /personal/:project": true,
	"GET /projects/:project/:environment/version": true,
	"PATCH /projects/:project/:environment/dismissals": true,
	"GET /secrets/:project/:environment": true,
	"PATCH /secrets/:project/:environment": true,
	"PATCH /secrets/:project/:environment/:key": true,
	"GET /secrets/:project/:environment/:key/versions": true,
	"POST /secrets/:project/:environment/:key/restore": true,
	"DELETE /secrets/:project/:environment/:key/reference": true,
	"PATCH /folders/:folder": true,
	"DELETE /folders/:folder": true,
	"PATCH /folders/:project/:environment/:folder": true,
	"DELETE /folders/:project/:environment/:folder": true,
	"GET /references": true,
	"POST /reveals": true,
	"GET /members": true,
	"GET /members/:member": true,
	"GET /members/:member/access": true,
	"PUT /members/:member": true,
	"DELETE /members/:member": true,
	"GET /members/:member/tokens": true,
	"POST /members/:member/tokens": true,
	"DELETE /members/:member/tokens/:id": true,
	"POST /handles": true,
	"DELETE /handles/:id": true,
	"GET /members/:member/bindings": true,
	"POST /members/:member/bindings": true,
	"POST /members/:member/bindings/keys": true,
	"DELETE /members/:member/bindings/:id": true,
	"GET /members/:member/bindings/:id/enrollments": true,
	"POST /members/:member/bindings/:id/enrollments": true,
	"POST /members/:member/bindings/:id/enrollments/:enrollment/promote": true,
	"POST /members/:member/tokens/:id/approve": true,
	"GET /freezes": true,
	"POST /freezes": true,
	"DELETE /freezes/:target": true,
	"GET /workloads/lookup": true,
	"GET /workloads/repositories": true,
	"GET /roles": true,
	"PUT /roles/:role": true,
	"DELETE /roles/:role": true,
	"PUT /instance-roles/:role": true,
	"DELETE /instance-roles/:role": true,
	"GET /settings": true,
	"PUT /settings": true,
	"PATCH /access/:member": true,
	"GET /sessions": true,
	"DELETE /sessions/:id": true,
	"GET /identities": true,
	"DELETE /identities/:id": true,
	"GET /device-logins/:code": true,
	"POST /device-logins/:code": true,
	"GET /oauth/authorizations": true,
	"POST /oauth/authorizations": true,
	"GET /approvals/:id": true,
	"POST /approvals/:id": true,
	"GET /apps": true,
	"DELETE /apps/:id": true,
	"GET /audit": true,
	"GET /audit/verification": true,
	"GET /audit/trees": true,
	"GET /audit/keys": true,
	"POST /audit/loss": true
};
/**
* Every route as a method and a URL, each parameter a made-up value: what
* a caller with no right to any of them would send.
*/
function everyRoute(origin) {
	return Object.keys(EVERY_ROUTE).map((key) => {
		const [method, pattern] = key.split(" ");
		return {
			key,
			method,
			url: `${origin}/api${pattern.replace(/:(\w+)/g, (_, name) => encodeURIComponent(name === "member" ? "token:conformance-nobody" : "conformance-nobody"))}`
		};
	});
}
function address(origin, key, params, input) {
	const path = key.slice(4).replace(/:(\w+)/g, (_, name) => encodeURIComponent(params[name]));
	const url = new URL(`${origin}/api${path}`);
	for (const [name, value] of Object.entries(input ?? {})) url.searchParams.set(name, String(value));
	return url.href;
}
//#endregion
//#region src/verify/anonymous.ts
/** The page anyone may open. Every other page sends no one to /login. */
const OPEN_PAGES = ["/login"];
/** The pages behind sign-in, whatever the instance holds. */
const CLOSED_PAGES = [
	"/",
	"/account",
	"/audit",
	"/auth/device",
	"/settings",
	"/projects",
	"/users",
	"/service-accounts",
	"/unregistered"
];
/** A made-up place and member, which no instance has. */
const NOWHERE = {
	project: "conformance-nowhere",
	environment: "none"
};
const NOBODY = "token:conformance-nobody";
/** The checks anyone can run: no sign-in, nothing written. */
async function anonymousChecks(report, origin) {
	let instance = origin;
	await report.check("health", {}, () => reachable(origin).catch((error) => {
		if (error instanceof Unreachable) instance = void 0;
		throw error;
	}));
	await report.check("headers", { instance }, () => headers(origin));
	await report.check("anonymous api", { instance }, () => anonymousApi(origin));
	await report.check("forged cross-site", { instance }, () => forgedCrossSite(origin));
	await report.check("sign-in info", { instance }, () => signinInfo(origin));
	await report.check("anonymous answers", { instance }, () => anonymousAnswers(origin));
}
/** An instance someone else runs: up, and its scheduled job beating. */
async function reachable(origin) {
	const live = await fetch(`${origin}/livez`).catch((error) => {
		throw new Unreachable(origin, error);
	});
	expect(live.ok, `/livez answered ${live.status}`);
	const ready = await fetch(`${origin}/readyz`);
	expect(ready.ok, `/readyz answered ${ready.status}: is the scheduled job running?`, await ready.text());
	return "/livez and /readyz";
}
async function headers(origin) {
	const anonymous = await fetch(`${origin}/api/me`);
	expect(anonymous.status === 401, `/api/me answered ${anonymous.status} to no one`);
	securityHeaders(anonymous, "a refusal");
	const login = await fetch(`${origin}/login`);
	expect(login.status === 200, `/login answered ${login.status}`);
	const csp = securityHeaders(login, "/login");
	const html = await login.text();
	const nonce = /'nonce-([^']+)'/.exec(csp)[1];
	expect(html.includes(`nonce="${nonce}"`), "/login's scripts do not carry the policy's nonce");
	expect(!securityHeaders(await fetch(`${origin}/login`), "/login").includes(`'nonce-${nonce}'`), "two pages were served with the same nonce");
	const asset = /\/_coffre\/assets\/[\w.-]+\.js/.exec(html)?.[0];
	expect(asset !== void 0, "/login loads no script from /_coffre/assets/", html.slice(0, 2e3));
	const script = await fetch(`${origin}${asset}`);
	expect(script.ok && /javascript/.test(script.headers.get("content-type") ?? ""), `${asset} answered ${script.status} ${script.headers.get("content-type")}`);
	const allowed = (await fetch(`${origin}/api/me`, { headers: { origin: "https://attacker.example" } })).headers.get("access-control-allow-origin");
	expect(allowed === null, `the API allows another origin to read it: ${allowed}`);
	return `a fresh CSP nonce per page, frames refused, nosniff; no CORS; ${asset} served`;
}
function securityHeaders(response, what) {
	const csp = response.headers.get("content-security-policy") ?? "";
	expect(/script-src 'self' 'nonce-[^']+'/.test(csp), `${what}: no nonce-based script-src`, csp);
	expect(csp.includes("frame-ancestors 'none'"), `${what}: frames not refused`, csp);
	expect(response.headers.get("x-content-type-options") === "nosniff", `${what}: no nosniff`);
	expect(response.headers.get("x-frame-options") === "DENY", `${what}: no x-frame-options DENY`);
	expect(response.headers.get("cross-origin-resource-policy") === "same-origin", `${what}: other sites may embed it`);
	expect(/no-store/.test(response.headers.get("cache-control") ?? ""), `${what}: may be cached`);
	if (response.url.startsWith("https:")) {
		const hsts = response.headers.get("strict-transport-security") ?? "";
		expect(/max-age=\d{7,}/.test(hsts), `${what}: no strict-transport-security for months or more`, hsts);
	}
	return csp;
}
/** Every route, whatever its method, turns away a caller with no credential, and says nothing else. */
async function anonymousApi(origin) {
	const routes = everyRoute(origin);
	for (const { key, method, url } of routes) {
		const response = await fetch(url, {
			method,
			headers: { "content-type": "application/json" },
			body: method === "GET" ? void 0 : "{}"
		});
		const text = await response.text();
		expect(response.status === 401, `${key} answered ${response.status} to no one`, text);
		expect(onlyRefusal(text), `${key} refused no one with more than a refusal`, text);
	}
	return `${routes.length} routes, every method: 401, and nothing but the refusal`;
}
/**
* A change sent with a session cookie from another site's page is refused
* before the cookie is even looked at, so a made-up one shows it: a real
* cookie would get the same answer. Behind Cloudflare Access the same holds
* for its cookie and assertion.
*/
async function forgedCrossSite(origin) {
	const changes = everyRoute(origin).filter((route) => route.method !== "GET");
	const forged = {
		cookie: "coffre_session=conformance-forged; __Host-coffre_session=conformance-forged; CF_Authorization=conformance-forged",
		"cf-access-jwt-assertion": "conformance-forged",
		origin: "https://attacker.example",
		"sec-fetch-site": "cross-site",
		"content-type": "application/json"
	};
	for (const { key, method, url } of [...changes, {
		key: "POST /auth/signout",
		method: "POST",
		url: `${origin}/auth/signout`
	}]) {
		const response = await fetch(url, {
			method,
			headers: forged,
			body: "{}",
			redirect: "manual"
		});
		const text = await response.text();
		expect(response.status === 403, `${key} from another site answered ${response.status}`, text);
	}
	return `${changes.length + 1} changes, sign-out included, from another site with a session cookie: 403`;
}
/** `GET /api/auth` names how to sign in, and nothing more. */
async function signinInfo(origin) {
	const response = await fetch(`${origin}/api/auth`);
	expect(response.ok, `/api/auth answered ${response.status}`);
	const info = await response.json();
	expect(sameKeys(info, ["access", "signin"]), "/api/auth says more than how to sign in", info);
	expect(info.signin === null !== (info.access === null), "/api/auth names neither or both ways in", info);
	if (info.access !== null) {
		expect(sameKeys(info.access, ["assertion"]) && info.access.assertion === false, "/api/auth says more of Access than whether it vouched", info);
		return "Cloudflare Access, and nothing more";
	}
	const signin = info.signin;
	expect(sameKeys(signin, [
		"note",
		"providers",
		"title"
	]), "/api/auth says more of its sign-in than a page needs", signin);
	for (const provider of signin.providers) expect(sameKeys(provider, [
		"brand",
		"id",
		"label"
	]), `/api/auth says more of ${provider.id} than its button`, provider);
	return `coffre's sign-in through ${signin.providers.map((provider) => provider.id).join(", ")}, and nothing more`;
}
/**
* Nothing that could be a stored value in what no one is shown. Without a
* canary this is a best effort: the API's refusals are checked to be only
* refusals above, every closed page must send no one to /login with an
* empty body, and the open pages must carry no credential coffre issues.
*/
async function anonymousAnswers(origin) {
	const pages = [
		...CLOSED_PAGES,
		`/projects/${NOWHERE.project}`,
		`/projects/${NOWHERE.project}/${NOWHERE.environment}`
	];
	for (const path of pages) {
		let at = path;
		for (let hop = 0; at !== "/login"; hop++) {
			const response = await fetch(`${origin}${at}`, { redirect: "manual" });
			const text = await response.text();
			const to = new URL(response.headers.get("location") ?? at, origin);
			expect(hop < 3 && response.status >= 300 && response.status < 400 && to.origin === origin, `${at} answered no one ${response.status}${response.headers.has("location") ? ` to ${to.href}` : ""}, not a redirect on to /login`, text.slice(0, 2e3));
			expect(text.trim().length < 512, `${at} sent no one a body with its redirect`, text.slice(0, 2e3));
			at = to.pathname;
		}
	}
	for (const path of OPEN_PAGES) {
		const response = await fetch(`${origin}${path}`, { redirect: "manual" });
		const text = await response.text();
		expect(response.status === 200, `${path} answered ${response.status}`);
		const issued = /coffre_(svc|cli|web)_[A-Za-z0-9_-]{20,}/.exec(text);
		expect(issued === null, `${path} carries a credential coffre issues`, issued?.[0]);
	}
	return `best effort, without a canary: ${pages.length} closed pages send no one to /login with nothing else; /login carries no credential`;
}
/** `{ error, message }` and nothing else. */
function onlyRefusal(text) {
	try {
		return sameKeys(JSON.parse(text), ["error", "message"]);
	} catch {
		return false;
	}
}
function sameKeys(value, keys) {
	return typeof value === "object" && value !== null && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}
//#endregion
//#region src/verify/token.ts
/** Parse `<project>/<environment>/<KEY>=<value>`, or the path alone with the value given apart. */
function parseCanary(text, value) {
	const at = text.indexOf("=");
	const path = at === -1 ? text : text.slice(0, at);
	const given = at === -1 ? value : text.slice(at + 1);
	const parts = path.split("/");
	if (parts.length !== 3 || parts.some((part) => part === "")) throw new Error(`the canary is <project>/<environment>/<KEY>, not "${path}"`);
	if (given === void 0 || given === "") throw new Error("the canary has no value: paste it when asked, or pipe it in");
	const [project, environment, key] = parts;
	return {
		project,
		environment,
		key,
		value: given
	};
}
/**
* The checks with a bearer token that reads the canary, and audits its
* project. `prefix` names them apart, run twice; `verification` false leaves
* out the last, which a token can only skip, for a caller that verifies the
* chain otherwise.
*/
async function tokenChecks(report, origin, setup, { prefix = "", verification = true } = {}) {
	const api = setup.token === void 0 ? void 0 : bearer(origin, setup.token);
	const token = await report.check(`${prefix}token`, {
		api,
		canary: setup.canary
	}, ({ api, canary }) => whoIsToken(origin, api, canary));
	const needs = {
		api,
		canary: setup.canary,
		token,
		secret: setup.token
	};
	await report.check(`${prefix}token reveal`, needs, ({ api, canary, token }) => tokenReveal(api, canary, token));
	await report.check(`${prefix}token scan`, needs, ({ canary, secret }) => tokenScan(origin, secret, canary));
	await report.check(`${prefix}token scope`, needs, ({ api, canary }) => tokenScope(api, canary));
	if (verification) await report.check(`${prefix}token verification`, { api }, ({ api }) => tokenVerification(api));
}
/** The token is a service's, and reads the canary's environment. */
async function whoIsToken(origin, api, canary) {
	if ((await (await fetch(`${origin}/api/auth`)).json()).signin === null) throw new Skip("behind Cloudflare Access, coffre issues no bearer tokens: the token's checks need coffre's own sign-in");
	const me = await api.me();
	expect(me.principal.type === "service", `the token is ${me.principal.type}:${me.principal.id}'s, not a service's`);
	const member = `token:${me.principal.id}`;
	const place = `${canary.project}/${canary.environment}`;
	expect(me.environments.find((env) => `${env.project}/${env.environment}` === place)?.permissions.includes("secret.read"), `${shownMember$1(member)} cannot read ${place}`, me.environments);
	const { keys } = await api.secrets.list(place);
	expect(keys.some((key) => key.key === canary.key), `${place} holds no ${canary.key}`, keys.map((key) => key.key));
	return {
		detail: `${shownMember$1(member)}, reading ${place}`,
		value: { member }
	};
}
/** Reveal the canary once, and find its `secret.read` in the audit log, by the reveal's request. */
async function tokenReveal(api, canary, token) {
	const path = `${canary.project}/${canary.environment}`;
	const { operationId, values } = await api.secrets.reveal(`${path}/${canary.key}`);
	expect(values[canary.key] === canary.value, `${path}/${canary.key} is not the value given as the canary`);
	let entries;
	try {
		({entries} = await api.audit.list({
			path,
			actor: token.member,
			limit: 50
		}));
	} catch (error) {
		if (error instanceof CoffreError && error.status === 403) throw new Skip(`the token holds no audit.read on ${canary.project}, so the reveal's entry cannot be looked for`);
		throw error;
	}
	const read = entries.filter((entry) => entry.operationId === operationId);
	expect(read.length === 1, `the reveal is logged ${read.length} times, not once`, entries.slice(0, 5));
	const [entry] = read;
	expect(entry.action === "secret.read" && entry.decision === "allow" && entry.key === canary.key && entry.requestId !== null, "the reveal's entry is not an allowed read of the canary, under a request", entry);
	return `one secret.read of ${canary.key}, entry ${entry.seq}, under request ${entry.requestId}`;
}
/**
* The canary's value, in any answer to a GET route as the token or as no
* one, or in any page. The reveal is the only answer allowed to carry it.
*/
async function tokenScan(origin, token, canary) {
	const me = await bearer(origin, token).me();
	const member = `token:${me.principal.id}`;
	const listed = me.environments.map(({ project, environment }) => ({
		project,
		environment
	}));
	const calls = getCalls({
		places: [...listed, NOWHERE],
		secrets: [{
			project: canary.project,
			environment: canary.environment,
			key: canary.key
		}, {
			...NOWHERE,
			key: "NONE"
		}],
		members: [
			member,
			NOBODY,
			"user:nobody@conformance.example"
		],
		services: [member, NOBODY]
	});
	const forms = [
		canary.value,
		Buffer.from(canary.value).toString("base64"),
		Buffer.from(canary.value).toString("hex")
	];
	const leaks = [];
	const callers = [["the token", { authorization: `Bearer ${token}` }], ["no one", {}]];
	let answers = 0;
	const look = async (what, url, headers) => {
		const text = await (await fetch(url, {
			headers,
			redirect: "manual"
		})).text();
		answers++;
		if (forms.some((form) => text.includes(form))) leaks.push(what);
	};
	for (const { key, url } of getUrls(origin, calls)) for (const [name, headers] of callers) await look(`${key} as ${name}`, url, headers);
	const pages = [
		...OPEN_PAGES,
		...CLOSED_PAGES,
		...listed.flatMap(({ project, environment }) => [`/projects/${project}`, `/projects/${project}/${environment}`])
	];
	for (const path of new Set(pages)) for (const [name, headers] of callers) await look(`the page ${path} as ${name}`, `${origin}${path}`, headers);
	expect(leaks.length === 0, "the canary's value was found outside its reveal", leaks);
	return `${answers} answers from ${Object.keys(calls).length} GET routes and ${new Set(pages).size} pages, as the token and as no one: no value`;
}
/** The token reaches the canary's project and nothing else: not another environment, project or member. */
async function tokenScope(api, canary) {
	const { projects } = await api.projects.list();
	const seen = projects.map((project) => project.slug);
	expect(seen.length === 1 && seen[0] === canary.project, `the token sees ${seen.join(", ") || "no project"}, not only ${canary.project}`);
	const me = await api.me();
	const own = `${canary.project}/${canary.environment}`;
	const reads = me.environments.filter((env) => env.permissions.includes("secret.read")).map((env) => `${env.project}/${env.environment}`);
	expect(reads.length === 1 && reads[0] === own, `the token reads ${reads.join(", ")}, not only ${own}`);
	const more = [...new Set(me.environments.flatMap((env) => env.permissions))].filter((permission) => permission !== "secret.read" && permission !== "secret.use" && permission !== "audit.read");
	expect(more.length === 0, `the token holds more than reading: ${more.join(", ")}`);
	const others = projects[0].environments.map((env) => `${canary.project}/${env.slug}`).filter((path) => path !== own);
	const nowhere = `${NOWHERE.project}/${NOWHERE.environment}`;
	let refusals = 0;
	for (const path of [...others, nowhere]) {
		await refused$1(`the token listed ${path}`, api.secrets.list(path));
		await refused$1(`the token revealed ${path}`, api.secrets.reveal(path));
		refusals += 2;
	}
	await refused$1(`the token read ${nowhere}'s audit`, api.audit.list({
		path: nowhere,
		limit: 1
	}));
	await refused$1("the token listed the members", api.members.list());
	await refused$1(`the token read ${shownMember$1(NOBODY)}`, api.members.get(NOBODY));
	refusals += 3;
	try {
		const { entries } = await api.audit.list({ limit: 500 });
		const outside = entries.filter((entry) => entry.project !== null && entry.project !== canary.project);
		expect(outside.length === 0, `the token reads audit entries about ${[...new Set(outside.map((entry) => entry.project))].join(", ")}`);
	} catch (error) {
		if (!(error instanceof CoffreError && error.status === 403)) throw error;
	}
	const elsewhere = others.length === 0 ? "no other environment" : `${others.length} other environment${others.length === 1 ? "" : "s"}`;
	return `only ${own}; ${refusals} reads elsewhere refused: ${elsewhere} of ${canary.project}, a made-up place, the members`;
}
async function tokenVerification(api) {
	let verified;
	try {
		verified = await api.audit.verify();
	} catch (error) {
		if (error instanceof CoffreError && error.status === 403) throw new Skip("verification is for auditors, admins and owners of the whole instance, which this token is not: not checked");
		throw error;
	}
	expect(verified.ok, "the audit log does not verify", verified);
	return `${verified.entries} entries verify, through entry ${verified.through}`;
}
//#endregion
//#region src/verify/instance.ts
/** The run's own place on an instance, made the first time, and found after. Nothing else is touched. */
const PROBE = {
	project: "conformance",
	environment: "live",
	service: "token:conformance-probe",
	key: "SIGN_IN_CANARY"
};
const INSTANCE_USAGE = `usage:
  coffre verify instance [<url>]
  coffre verify instance [<url>] --canary <project>/<environment>/<KEY>, signed in with a bearer token

Checks an instance from outside, the current one unless <url> names another:

  as no one        health, headers, every route refusing no one, changes from
                   another site refused, /api/auth, nothing like a value shown
  as an owner      with your \`coffre login\` session, as an owner or a root
                   admin: finds or makes conformance/live and
                   service:conformance-probe, issues it a credential, writes a
                   fresh canary, runs the token's checks below, then verifies
                   the whole audit log as you. The credential is revoked
                   however the run ends, and your session stays signed in
  with a token     signed in with a bearer token, \`coffre login <url> --token\`,
                   as CI is: one that reads the canary's environment and
                   holds auditor on its project. Its value nowhere but its
                   reveal, the reveal audited, nothing else in reach
  --canary         the canary the token reads; its value is asked for, or
                   piped in, so that it stays out of the shell's history

Each run adds a few entries to the instance's audit log, which is
append-only, so they stay: the canary's read, and the reads it was refused.
A run as an owner leaves its project, environment and service for the next,
and writes its canary and its grants. Exits 1 when a check fails.`;
async function verifyInstance(args, store, session, local, out = process.stdout) {
	const { values, positionals } = parseArgs({
		args,
		allowPositionals: true,
		options: {
			canary: { type: "string" },
			help: {
				type: "boolean",
				short: "h"
			}
		}
	});
	if (values.help) stop(0, INSTANCE_USAGE);
	if (positionals.length > 1) stop(2, INSTANCE_USAGE);
	if (positionals[0] !== void 0 && session.url !== void 0) stop(2, "coffre: name the instance once: coffre verify instance <url>, or coffre --url <url> verify instance");
	if (session.service !== void 0) stop(2, "coffre: verify instance checks as no one, then with a bearer token `coffre login --token` saved, or as you with the session `coffre login` saved: --service is for other commands");
	const requested = positionals[0] ?? session.url ?? local?.origin ?? store.current;
	if (!requested) stop(1, `coffre: ${signInError("not signed in anywhere yet: run `coffre login <url>` first", askedMode(session.authMode))}`);
	let origin;
	try {
		origin = instanceOrigin(requested);
	} catch (error) {
		stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
	}
	const s = style(out);
	const report = new Checks(out);
	const saved = store.instances[origin];
	if (saved?.kind === "access" || saved?.kind === "run") stop(2, `coffre: verify instance checks as no one, then with a bearer token, or as you: the session saved for ${origin} is ${saved.kind === "access" ? "an Access service token" : "a run's ID token"}`);
	if (saved?.kind === "token" && saved.token !== void 0) {
		const token = saved.token;
		if (values.canary === void 0) stop(2, "coffre: with a token, name its canary: --canary <project>/<environment>/<KEY>");
		if (values.canary.includes("=")) stop(2, "coffre: the canary's value is asked for, never an argument: paste it, or pipe it in");
		let canary;
		try {
			parseCanary(values.canary, "-");
			canary = parseCanary(values.canary, await readSecret({
				label: "Canary value",
				hint: `The value of ${values.canary}, which the token reads. Hidden as you type.`
			}));
		} catch (error) {
			stop(2, `coffre: ${error instanceof Error ? error.message : String(error)}`);
		}
		out.write(`${s.bold(`Checking ${origin}`)}, as no one and with the bearer token \`coffre login --token\` saved\n`);
		out.write(s.dim("  The token's reads add a few entries to the instance's audit log, for good.\n\n"));
		await anonymousChecks(report, origin);
		await tokenChecks(report, origin, {
			token,
			canary
		});
		return finish(out, report);
	}
	if (values.canary !== void 0) stop(2, "coffre: --canary goes with a bearer token, `coffre login <url> --token`; as an owner, the run writes a canary of its own");
	if (store.instances[origin] === void 0) stop(1, `coffre: ${signInError(`not signed in: run \`coffre login ${origin}\` first`, askedMode(session.authMode))}`);
	let api;
	try {
		const to = resolveTarget({
			...session,
			url: origin
		}, store);
		if (to.mode === "cloudflare") stop(1, `coffre: ${origin} is behind Cloudflare Access, which turns everyone away before coffre answers, so it cannot be checked from outside. \`coffre verify log\` verifies its audit log, as you.`);
		api = createClient({
			url: origin,
			headers: () => credentialHeaders(to.mode, to.credential)
		});
	} catch (error) {
		stop(1, `coffre: ${error instanceof Error ? error.message : String(error)}`);
	}
	out.write(`${s.bold(`Checking ${origin}`)}, as no one, then as you\n`);
	out.write(s.dim(`  It keeps ${PROBE.project}/${PROBE.environment} and ${shownMember$1(PROBE.service)} for the next run, and its reads stay in the audit log, for good.\n\n`));
	await anonymousChecks(report, origin);
	await ownerChecks(report, origin, api);
	finish(out, report);
}
/**
* As the signed-in owner: who they are, set up, the token's checks,
* verification; and, however it ends, a Ctrl-C included, the credential
* revoked. The session stays as it was.
*/
async function ownerChecks(report, origin, api) {
	if (await report.check("owner", {}, () => signedIn(api, origin)) === void 0) return;
	const issued = [];
	let ended = null;
	const end = () => ended ??= cleanUp(api, issued);
	const interrupted = (code) => () => void end().finally(() => process.exit(code));
	const onInt = interrupted(130);
	const onTerm = interrupted(143);
	process.once("SIGINT", onInt);
	process.once("SIGTERM", onTerm);
	try {
		await tokenChecks(report, origin, await report.check("setup", {}, () => setUp(api, issued)) ?? {}, { verification: false });
		await report.check("owner verification", {}, () => verification(api));
	} finally {
		process.off("SIGINT", onInt);
		process.off("SIGTERM", onTerm);
		await report.check("clean-up", {}, end);
	}
}
/** The session's admin or owner of the whole instance: anyone else is stopped before anything is made. */
async function signedIn(api, origin) {
	let me;
	try {
		me = await api.me();
	} catch (error) {
		if (error instanceof CoffreError && error.status === 401) throw new Failure(`your session on ${origin} is missing, expired or revoked: run \`coffre login ${origin}\`, then again`, SIGN_IN_HINT);
		throw error;
	}
	const who = me.principal.id;
	if (!me.runsInstance) throw new Failure(`${who} is not an admin or owner of all of ${origin}: nothing was made. Sign in as one, or with a bearer token, \`coffre login ${origin} --token\`, and name its --canary`);
	return {
		detail: `${who}, ${/^[aeiou]/.test(me.instanceRole) ? "an" : "a"} ${me.instanceRole}, with this CLI's session`,
		value: who
	};
}
/** Make what is missing of the run's place, and the service's two grants; then a fresh canary, and a fresh credential. */
async function setUp(api, issued) {
	const place = `${PROBE.project}/${PROBE.environment}`;
	const made = [];
	const { projects } = await api.projects.list();
	const project = projects.find(({ slug }) => slug === PROBE.project);
	expect(project?.archivedAt == null, `${PROBE.project} is archived: unarchive it, or the run has nowhere to go`);
	if (project === void 0) {
		await api.projects.create(PROBE.project, { name: "Conformance" });
		made.push(`the project ${PROBE.project}`);
	}
	const environment = project?.environments.find(({ slug }) => slug === PROBE.environment);
	expect(environment?.details?.archivedAt == null, `${place} is archived: unarchive it, or the run has nowhere to go`);
	if (environment === void 0) {
		await api.environments.create(place, { name: "Live" });
		made.push(`the environment ${place}`);
	}
	if ((await api.members.add(PROBE.service)).created) made.push(`the service account ${shownMember$1(PROBE.service)}`);
	const { changes } = await api.access.set(PROBE.service, {
		[place]: "viewer",
		[PROBE.project]: "auditor"
	});
	const granted = Object.entries(changes).filter(([, change]) => change !== "unchanged");
	if (granted.length > 0) made.push(`its grants on ${granted.map(([where]) => where).join(" and ")}`);
	const value = `coffre-canary-${randomBytes(12).toString("hex")}`;
	await api.secrets.set(place, { [PROBE.key]: value });
	const credential = await api.tokens.issue(PROBE.service, {
		label: "coffre verify instance, one run",
		expiresInDays: 1
	});
	issued.push({
		member: PROBE.service,
		id: credential.id
	});
	return {
		detail: `${made.length === 0 ? "all found" : `made ${made.join(", ")}`}; a fresh ${place}/${PROBE.key} and a fresh credential for ${shownMember$1(PROBE.service)}`,
		value: {
			token: credential.token,
			canary: {
				project: PROBE.project,
				environment: PROBE.environment,
				key: PROBE.key,
				value
			}
		}
	};
}
/** What the whole audit chain says, walked from its first entry by the owner, which a token cannot be. */
async function verification(api) {
	const verified = await api.audit.verifyWhole();
	expect(verified.ok, "the audit log does not verify", verified);
	expect((verified.remaining ?? 0) === 0, "the audit log is not verified to its end: the checkpoints are catching up", verified);
	const trees = await api.audit.verifyTrees();
	expect(!trees.kept || trees.problems.length === 0, "0.15's log does not verify from its newest checkpoint", trees);
	expect(!trees.kept || !trees.capped, "0.15's log is not checked to its head: more entries wait above its newest checkpoint than a check reads, the checkpointer behind", trees);
	const sealed = !trees.kept ? "" : trees.checkpoint === null ? "; 0.15's log too, nothing sealed yet" : `; 0.15's log too, from its newest checkpoint, up to entry ${trees.checkpoint.upto}`;
	return `the whole chain verifies, as you: ${verified.entries} entries, through entry ${verified.through}${sealed}`;
}
/** Revoke what the run issued, and say what stays: the session among it. */
async function cleanUp(api, issued) {
	for (const { member, id } of issued) await api.tokens.revoke(member, id);
	const { tokens } = await api.tokens.list(PROBE.service).catch(() => ({ tokens: [] }));
	const others = tokens.length === 0 ? "no working credential" : `${tokens.length} credential${tokens.length === 1 ? "" : "s"} this run did not issue, left as they are`;
	return `${issued.length === 0 ? "nothing issued" : "the credential revoked"}; your session stays. Staying: ${PROBE.project}/${PROBE.environment} and its ${PROBE.key}, ${shownMember$1(PROBE.service)} with ${others}, and this run's entries in the audit log`;
}
/** The verdict, under the checks, and the exit code: 0 when every one passed, or was skipped for a reason given. */
function finish(out, report) {
	const s = style(out);
	const { failed } = report;
	out.write(failed.length === 0 ? `\n${s.green("✓")} ${s.bold("Conformant")}\n` : `\n${s.red("✗")} ${s.bold("Not conformant:")} ${failed.join(", ")}\n`);
	process.exitCode = failed.length === 0 ? 0 : 1;
}
Buffer.from("coffre.audit.mac.v2", "utf8");
Buffer.from("coffre.audit.chain.v2", "utf8");
Buffer.alloc(32, 0);
/**
* An author's log key, derived from one of its secrets: `auditChainKey` for
* the app. The id is a fingerprint of the key, so a rotation shows in every
* entry, and an old key can be kept for verification by its id.
*/
function deriveLogKey(author, secret) {
	if (secret.length < 32) throw new Error("a log key needs at least 32 bytes of secret");
	const key = Buffer.from(hkdfSync("sha256", secret, /* @__PURE__ */ new Uint8Array(0), `coffre.audit.${author}.v2`, 32));
	return {
		author,
		keyId: `${author}:${createHash("sha256").update(key).digest("hex").slice(0, 16)}`,
		key
	};
}
//#endregion
//#region ../core/dist/types-Cp3lB_-W.js
/**
* Version prefix for the AAD encoding. If the encoding ever changes, this
* changes with it, and old ciphertexts keep decrypting under the old rule.
*/
const AAD_VERSION = "coffre.aad.v1";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function assertUuid(value, field) {
	if (typeof value !== "string" || !UUID_RE.test(value)) throw new Error(`context.${field} must be a lowercase UUID, got: ${String(value)}`);
}
/** Throw unless every field is a lowercase UUID, an owner a lowercase SHA-256, and `sensitive` true if there. */
function checkContext(ctx) {
	assertUuid(ctx.projectId, "projectId");
	assertUuid(ctx.environmentId, "environmentId");
	assertUuid(ctx.secretId, "secretId");
	if (ctx.owner !== void 0 && (typeof ctx.owner !== "string" || !OWNER_RE.test(ctx.owner))) throw new Error(`context.owner must be a lowercase SHA-256, got: ${String(ctx.owner)}`);
	if (ctx.sensitive !== void 0 && ctx.sensitive !== true) throw new Error(`context.sensitive is true or absent, got: ${String(ctx.sensitive)}`);
}
const OWNER_RE = /^[0-9a-f]{64}$/;
/**
* Encode a context into AAD bytes.
*
* Every field is validated as a UUID first, which is what makes joining with
* `|` unambiguous: a UUID cannot contain the separator, so no two distinct
* contexts can encode to the same bytes.
*/
function encodeAad(ctx) {
	checkContext(ctx);
	return Buffer.from(`${AAD_VERSION}|${ctx.projectId}|${ctx.environmentId}|${ctx.secretId}${ctx.owner === void 0 ? "" : `|owner:${ctx.owner}`}${ctx.sensitive === true ? "|sensitive" : ""}`, "utf8");
}
/**
* The key service could not answer: it is down, throttling past the
* retries, or refusing coffre's own credentials. Nothing is known about the
* wrapped key, so the vault fails the call instead of refusing it.
*/
var KekUnavailableError = class extends Error {
	name = "KekUnavailableError";
	uncertain;
	constructor(message, uncertain = false) {
		super(message);
		this.uncertain = uncertain;
	}
};
/** No more work may start. A request already sent may have been accepted by KMS. */
var KekCancelledError = class extends KekUnavailableError {
	name = "KekCancelledError";
	constructor(uncertain = false) {
		super("key operation was cancelled", uncertain);
	}
};
/** The ciphertext does not open under the claimed key and context. */
var KekBadClaimError = class extends Error {
	name = "KekBadClaimError";
};
//#endregion
//#region ../core/dist/kek.js
function checkOperation(operation, uncertain = false) {
	if (operation !== void 0 && (operation.signal.aborted || Date.now() >= operation.deadline)) throw new KekCancelledError(uncertain);
}
const IV_BYTES = 12;
const KEK_BYTES = 32;
/**
* A KEK held in local process memory, loaded from configuration.
*
* This is the local-development implementation of `KekProvider`. It is a
* different implementation of the same interface, not a branch that skips
* wrapping: the envelope format, the context binding and the failure modes are
* identical to what a remote KMS-backed provider will produce.
*/
var LocalKekProvider = class LocalKekProvider {
	provider = "local";
	keyId;
	keyVersion;
	/** Imported once: a raw key would be imported again for every key it wraps or opens. */
	#kek;
	constructor(kek, keyId, keyVersion = "1") {
		if (kek.length !== KEK_BYTES) throw new Error(`a local vault key must be ${KEK_BYTES} bytes, got ${kek.length}`);
		this.#kek = createSecretKey(kek);
		this.keyId = keyId;
		this.keyVersion = keyVersion;
	}
	/** Build a provider from a base64-encoded 32-byte key, e.g. from an env var. */
	static fromBase64(encoded, keyId, keyVersion = "1") {
		return new LocalKekProvider(Buffer.from(encoded, "base64"), keyId, keyVersion);
	}
	/** Generate a fresh random KEK. Used by tests and by the dev seed script. */
	static generate(keyId, keyVersion = "1") {
		return new LocalKekProvider(randomBytes(KEK_BYTES), keyId, keyVersion);
	}
	/**
	* AAD for the wrap operation.
	*
	* Binds the wrapped DEK both to the secret it belongs to and to the KEK
	* identity that produced it, so a wrapped DEK cannot be replayed against a
	* row claiming a different KEK.
	*/
	#wrapAad(ctx) {
		return Buffer.concat([encodeAad(ctx), Buffer.from(`|${this.provider}|${this.keyId}|${this.keyVersion}`, "utf8")]);
	}
	async wrap(dek, ctx, operation) {
		checkOperation(operation);
		if (dek.length !== 32) throw new Error(`DEK must be 32 bytes, got ${dek.length}`);
		const iv = randomBytes(IV_BYTES);
		const cipher = createCipheriv("aes-256-gcm", this.#kek, iv);
		cipher.setAAD(this.#wrapAad(ctx));
		const body = Buffer.concat([cipher.update(dek), cipher.final()]);
		return {
			kekProvider: this.provider,
			kekId: this.keyId,
			kekVersion: this.keyVersion,
			bytes: Buffer.concat([
				iv,
				cipher.getAuthTag(),
				body
			])
		};
	}
	async unwrap(wrapped, ctx, operation) {
		checkOperation(operation);
		if (wrapped.kekProvider !== this.provider || wrapped.kekId !== this.keyId || wrapped.kekVersion !== this.keyVersion) throw new KekBadClaimError(`wrapped DEK is for ${wrapped.kekProvider}:${wrapped.kekId} version ${wrapped.kekVersion}, not ${this.provider}:${this.keyId} version ${this.keyVersion}`);
		if (wrapped.bytes.length !== 60) throw new KekBadClaimError("wrapped DEK has the wrong length");
		const iv = wrapped.bytes.subarray(0, IV_BYTES);
		const tag = wrapped.bytes.subarray(IV_BYTES, 28);
		const body = wrapped.bytes.subarray(28);
		const decipher = createDecipheriv("aes-256-gcm", this.#kek, iv);
		decipher.setAAD(this.#wrapAad(ctx));
		decipher.setAuthTag(tag);
		let dek;
		const partial = decipher.update(body);
		try {
			dek = Buffer.concat([partial, decipher.final()]);
		} catch {
			throw new KekBadClaimError("wrapped DEK does not open under this context");
		} finally {
			partial.fill(0);
		}
		if (dek.length !== 32) {
			dek.fill(0);
			throw new KekBadClaimError("unwrapped DEK has the wrong length");
		}
		return dek;
	}
};
/** Constant-time buffer comparison, for tests and callers that need it. */
function equalBytes(a, b) {
	return a.length === b.length && timingSafeEqual(a, b);
}
/** The known value a check wraps: the size of a data key. */
const KEY_CHECK_VALUE = createHash("sha256").update("coffre.kek.check.v1").digest();
const NIL = "00000000-0000-0000-0000-000000000000";
/** The context a check is wrapped in, which no secret has: the nil UUID throughout. */
const KEY_CHECK_CONTEXT = {
	projectId: NIL,
	environmentId: NIL,
	secretId: NIL
};
/**
* Whether `key`, a local vault key, is the one that wrapped `check`: it
* opens it, under the vault ID the check names, to the known value. The ID
* is bound into the wrap, so a match also says the ID is the escrowed one's.
*/
async function opensKeyCheck(key, check) {
	if (check.kekProvider !== "local" || key.length !== 32) return false;
	try {
		const value = await new LocalKekProvider(key, check.kekId, check.kekVersion).unwrap(check, KEY_CHECK_CONTEXT);
		const right = equalBytes(value, KEY_CHECK_VALUE);
		value.fill(0);
		return right;
	} catch (error) {
		if (error instanceof KekBadClaimError) return false;
		throw error;
	}
}
/** The id the log records for entries the app signs with `key`, its APP_KEY. */
function appLogKeyId(key) {
	return deriveLogKey("app", key).keyId;
}
//#endregion
//#region src/verify/keys.ts
const KEYS_USAGE = `usage:
  coffre verify keys [--vault-id <id>]

Asks for the vault key, then the app key, without showing them, and checks
each against the current instance, on this machine: neither is sent. Enter
alone skips one. As an admin or owner of the whole instance.

  --vault-id   the vault ID kept with the vault key, to check as well. It
               is shown either way

In a script, the keys come on stdin, the vault key on the first line and
the app key on the second, a blank line skipping one; never as arguments.
Exits 1 when a key is not the instance's.`;
/**
* A key's text, as an operator pastes it: 32 bytes in base64, and nothing
* more. Node's decoder, which the deployment uses, stops where it can, so a
* key pasted twice would decode to the key: the text must be the key's own.
*/
function decoded(text) {
	const key = Buffer.from(text, "base64");
	const unpadded = text.replace(/=+$/, "");
	return key.length === 32 && (unpadded === key.toString("base64").replace(/=+$/, "") || unpadded === key.toString("base64url")) ? key : null;
}
function malformed(what, text) {
	return new Failure(`not ${what}: one is 32 bytes in base64, 44 characters, and these ${text.length} characters are not`);
}
/**
* The vault key: the one the vault wraps under now if it opens that key's
* check; a key the vault replaced if it opens an older one's, which is said;
* otherwise none of this instance's. The vault ID is bound into every
* check, so the one opened names the key's.
*/
async function vaultKeyVerdict(text, material, vaultId) {
	if (text === "") throw new Skip("not given: not checked");
	const key = decoded(text);
	if (key === null) throw malformed("a vault key", text);
	try {
		const { current, checks } = material;
		let opened;
		for (const check of checks) if (await opensKeyCheck(key, {
			kekProvider: check.provider,
			kekId: check.vaultId,
			kekVersion: check.version,
			bytes: Buffer.from(check.wrapped, "base64")
		})) {
			opened = check;
			break;
		}
		const now = current.provider === "local" ? `vault ID ${current.vaultId}` : `${current.vaultId}, in ${current.provider}`;
		if (opened === void 0) {
			if (checks.length === 0) throw new Failure(`the vault holds no check to hold a key to yet. It wraps under ${now}`);
			throw new Failure(`not this instance's vault key: ${checks.length === 1 ? "it does not open the vault key's check" : `it opens none of the checks of its ${checks.length} vault keys, current or replaced`}. The vault wraps under ${now}`);
		}
		if (opened.vaultId !== current.vaultId || opened.provider !== current.provider) throw new Failure(`this is a previous vault key (vault ID ${opened.vaultId}), not the current one: the vault wraps under ${now}`);
		if (vaultId !== void 0 && vaultId !== opened.vaultId) throw new Failure(`the key is right, but its vault ID is ${opened.vaultId}, not ${vaultId}: keep the right one with it`);
		return `the current one, vault ID ${opened.vaultId}${vaultId === void 0 ? "" : ", as given"}`;
	} finally {
		key.fill(0);
	}
}
/**
* The app key: right if the log's entries the app signs now would carry the
* fingerprint it makes; one the app replaced if it makes one of theirs,
* which is said; otherwise none of this instance's.
*/
function appKeyVerdict(text, material) {
	if (text === "") throw new Skip("not given: not checked");
	const key = decoded(text);
	if (key === null) throw malformed("an app key", text);
	try {
		const id = appLogKeyId(key);
		if ((material.previous ?? []).includes(id)) throw new Failure(`this is a previous app key (${id}), not the current one: the app signs with ${material.keyId}`);
		if (id !== material.keyId) throw new Failure("not this instance's app key: the app signs with another");
		return "the one the app signs with now";
	} finally {
		key.fill(0);
	}
}
/**
* The two keys: stdin's lines in order when it is piped, or hidden prompts
* on a terminal.
*/
async function readKeys() {
	const missing = ["vault", "app"];
	const asked = {};
	if (!process.stdin.isTTY) {
		let text = "";
		for await (const chunk of process.stdin) text += String(chunk);
		const lines = text.split(/\r?\n/);
		missing.forEach((which, i) => asked[which] = {
			text: lines[i]?.trim() ?? "",
			from: "stdin"
		});
	} else {
		const s = style(process.stderr);
		for (const which of missing) {
			const name = which === "vault" ? "Vault key" : "App key";
			asked[which] = {
				text: await hiddenLine(process.stdin, process.stderr, s, `${name}?`, "Paste it: it stays hidden, and on this machine. Enter alone skips it."),
				from: "the prompt"
			};
		}
	}
	return {
		vault: asked.vault,
		app: asked.app
	};
}
async function verifyKeys(args, api, origin, out = process.stdout) {
	const { values } = parseArgs({
		args,
		allowPositionals: false,
		options: {
			"vault-id": { type: "string" },
			help: {
				type: "boolean",
				short: "h"
			}
		}
	});
	if (values.help) stop(0, KEYS_USAGE);
	const vaultId = values["vault-id"]?.trim() || void 0;
	const material = await api.audit.keys();
	const s = style(out);
	out.write(`${s.bold(`Checking your keys against ${origin}`)}\n`);
	out.write(s.dim("  On this machine: what they're checked against was read from the instance, and the keys go nowhere.\n\n"));
	const keys = await readKeys();
	const report = new Checks(out);
	await report.check("vault key", {}, () => said(keys.vault, () => vaultKeyVerdict(keys.vault.text, material.vault, vaultId)));
	await report.check("app key", {}, () => said(keys.app, () => appKeyVerdict(keys.app.text, material.app)));
	const { failed, results } = report;
	const right = results.filter(({ status }) => status === "ok").map(({ name }) => name);
	out.write(failed.length > 0 ? `\n${s.red("✗")} ${s.bold(failed.length === 2 ? `Neither key is ${origin}'s.` : `The ${failed[0]} is not ${origin}'s.`)}\n` : right.length === 0 ? `\n${s.red("✗")} ${s.bold("No key given: nothing checked.")}\n` : `\n${s.green("✓")} ${s.bold(right.length === 2 ? `Both keys are ${origin}'s.` : `The ${right[0]} is ${origin}'s.`)}\n`);
	process.exitCode = failed.length > 0 || right.length === 0 ? 1 : 0;
}
/** A key's verdict, and where the key came from when not a prompt: so that a script's run says it read stdin. */
async function said(source, verdict) {
	const where = source.from === "the prompt" ? "" : ` (from ${source.from})`;
	try {
		return `${await verdict()}${where}`;
	} catch (error) {
		if (error instanceof Failure) throw new Failure(`${error.message}${where}`, error.detail);
		throw error;
	}
}
//#endregion
//#region src/verify/index.ts
/** The checks, in the order they are offered: each one's name, and what it checks. */
const CHECKS = [
	["instance", "the instance from outside: as no one, then as you, an owner"],
	["keys", "the vault key and app key you keep, against the instance"],
	["log", "the whole audit log, as you, an owner"]
];
const VERIFY_USAGE = `usage: coffre verify instance | keys | log | backup <dump>

${CHECKS.map(([name, what]) => `  ${name.padEnd(10)}${what}`).join("\n")}
  backup    a dump coffre backup made, restored into an empty database

On a terminal, \`coffre verify\` alone asks which. \`coffre verify <check> --help\`
says more about each.`;
/** The check named, or, with none, the one chosen on the terminal; without a terminal, the list, and exit 2. */
async function pickCheck() {
	const terminal = openTerminal();
	if (terminal === null) stop(2, VERIFY_USAGE);
	const s = style(terminal.out);
	try {
		const at = await select(terminal.keys, terminal.out, s, "Which check?", CHECKS.map(([name, what]) => `${name.padEnd(10)}${s.dim(what)}`));
		terminal.out.write("\n");
		return CHECKS[at][0];
	} catch (error) {
		if (error instanceof Cancelled) process.exit(130);
		throw error;
	} finally {
		release(terminal.keys);
	}
}
//#endregion
//#region src/main.ts
/**
* coffre CLI.
*
* Deliberately dependency-free: node:util's parseArgs and node:child_process
* are enough. A tool that handles every credential we own is a poor place to
* add a transitive dependency tree for argument parsing.
*/
const CREDENTIALS_PATH = join(homedir(), ".coffre", "credentials.json");
const PINS_PATH = join(homedir(), ".coffre", "directories.json");
process.stdout.on("error", (error) => {
	if (error.code === "EPIPE") process.exit(0);
	throw error;
});
function readStore() {
	return existsSync(CREDENTIALS_PATH) ? parseStore(readFileSync(CREDENTIALS_PATH, "utf8")) : emptyStore();
}
function writeStore(store) {
	writePrivate(CREDENTIALS_PATH, "credentials", store);
}
/**
* Read the pins: none only if there is no file. One this CLI cannot read,
* or reached through a symbolic link, which `writePrivate` refuses too, is
* an error: a link, dangling or not, would let another file say where
* credentials go.
*/
function readPins() {
	try {
		for (const path of [dirname(PINS_PATH), PINS_PATH]) {
			const found = lstatSync(path, { throwIfNoEntry: false });
			if (found === void 0) return emptyPins();
			if (found.isSymbolicLink()) throw new Error("it is reached through a symbolic link");
		}
		return parsePins(readFileSync(PINS_PATH, "utf8"));
	} catch (error) {
		fail(`cannot read the pinned directories in ${PINS_PATH}: ${error.message}. Name the instance with --url, or move the file away`);
	}
}
function writePins(pins) {
	writePrivate(PINS_PATH, "pinned directories", pins);
}
/** Write one of the CLI's files, readable by you alone, in a directory only you can enter. */
function writePrivate(path, what, value) {
	const directory = dirname(path);
	try {
		mkdirSync(directory, {
			recursive: true,
			mode: 448
		});
		if (lstatSync(directory).isSymbolicLink() || existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error(`a symbolic link is not a ${what} path`);
		chmodSync(directory, 448);
		if ((statSync(directory).mode & 511) !== 448) throw new Error("directory permissions must be 0700");
		const temporary = join(directory, `.write-${crypto.randomUUID()}`);
		try {
			writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
				mode: 384,
				flag: "wx"
			});
			chmodSync(temporary, 384);
			if ((statSync(temporary).mode & 511) !== 384) throw new Error("file permissions must be 0600");
			renameSync(temporary, path);
		} finally {
			rmSync(temporary, { force: true });
		}
	} catch (error) {
		fail(`cannot secure ${what} at ${path}: ${error instanceof Error ? error.message : String(error)}`);
	}
}
/**
* Where the command runs, as pins name it: its real path. A directory gone
* since is an error, not one without a pin: that would be the default
* instance's, whatever its pin said.
*/
function here(then) {
	try {
		return realpathSync(process.cwd());
	} catch (error) {
		fail(`cannot tell which directory this is: ${error.message}. ${then}`);
	}
}
/** Your home, as pins name it. */
function realHome() {
	return attempt(() => realpathSync(homedir()));
}
/**
* The pin or `coffre.json` that applies where the command runs, unless
* --url names the instance, and so without reading either.
*/
function localHere() {
	if (sessionFlags.url !== void 0) return null;
	return attempt(() => localFor(readPins(), here("Name the instance with --url"), realHome(), readRepoFile));
}
/** A `coffre.json`'s text, or null if there is none: one that is a link or no file is refused, not passed over. */
function readRepoFile(path) {
	try {
		const entry = lstatSync(path);
		if (!entry.isFile()) throw new Error(`it is ${entry.isSymbolicLink() ? "a symbolic link" : "not a file"}, and a ${REPO_FILE} is a file of the repository's own`);
		return readFileSync(path, "utf8");
	} catch (error) {
		const code = error.code;
		if (code === "ENOENT" || code === "ENOTDIR") return null;
		throw new Error(`cannot use ${path}: ${error.message}`);
	}
}
/** Why a command uses the instance it does, as `whoami` and `use` say: `pinned at ~/Code/acme`. */
function because(local) {
	return local.by === "pin" ? `pinned at ${shown(local.directory)}` : `named by ${shown(join(local.directory, REPO_FILE))}`;
}
/** A directory as you would type it: `~/Code/acme`. */
function shown(directory) {
	const home = realHome();
	return home !== "/" && within(directory, home) ? `~${directory.slice(home.length)}` : directory;
}
function fail(message) {
	process.stderr.write(`coffre: ${message}\n`);
	process.exit(1);
}
function attempt(step) {
	try {
		return step();
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error));
	}
}
function target() {
	return attempt(() => resolveTarget(sessionFlags, readStore(), localHere()));
}
/** cloudflared keeps and refreshes the Access token; ask it each time. */
async function cloudflaredToken(origin) {
	try {
		const { stdout } = await promisify(execFile)("cloudflared", [
			"access",
			"token",
			`-app=${origin}`
		]);
		const token = stdout.trim();
		if (token === "" || token.includes(" ")) throw new Error(stdout);
		return token;
	} catch {
		throw new Error(`could not get a Cloudflare Access token for ${origin}: run \`coffre login ${origin}\``);
	}
}
/**
* `fetch`, under `--verbose` each request said on stderr with its answer
* and its time (`timings.ts`): by its path when it is `instance`'s, by its
* host when it is a platform's or GitHub's. Without `instance`, for the
* requests only the instance is sent.
*/
function fetching(instance) {
	return sessionFlags.verbose ? timed(fetch, stderr, instance) : fetch;
}
/** A request to the instance. */
function http(input, init) {
	return fetching()(input, init);
}
/**
* A CI run's credential, and the ID tokens asked for to buy it: asked for once
* in this process, before its first request, and kept in memory only.
*/
let exchanged = null;
function workloadCredential(origin, workload) {
	exchanged ??= signIn(origin, workload.service).then(({ issued, idTokens }) => ({
		credential: issued.token,
		idTokens
	})).catch((error) => fail(error instanceof Error ? error.message : String(error)));
	return exchanged;
}
/**
* How long a request waits before each time it asks again, while the
* instance cannot answer it yet (`momentary`): twice, each wait between
* half and one and a half of these, so that the jobs of one run that
* failed together do not all ask again together, or at least as long as
* the instance's `Retry-After` says (5 s on a 503 `unavailable`), spread
* past it as far, and never more than `MAX_RETRY_AFTER_MS`. Then its
* answer stands.
*/
const UNAVAILABLE_RETRY_MS = [2e3, 5e3];
/** The longest a run waits before it asks again, each time, whatever the instance's `Retry-After`: a CI step, not a daemon. */
const MAX_RETRY_AFTER_MS = 15e3;
/** The wait before asking again the `attempt`th time, or none left: at least what the instance's `Retry-After` (seconds) says, up to `MAX_RETRY_AFTER_MS`. */
function unavailableWait(attempt, retryAfter) {
	const wait = UNAVAILABLE_RETRY_MS[attempt];
	if (wait === void 0) return void 0;
	const said = Number(retryAfter);
	if (Number.isFinite(said) && said * 1e3 > MAX_RETRY_AFTER_MS) return void 0;
	const asked = retryAfter !== null && Number.isFinite(said) && said > 0 ? Math.min(said * 1e3, MAX_RETRY_AFTER_MS / 1.5) : 0;
	const jittered = wait * (.5 + Math.random());
	return Math.round(asked === 0 ? jittered : Math.min(MAX_RETRY_AFTER_MS, Math.max(jittered, asked * (1 + Math.random() / 2))));
}
/**
* Whether the instance answered 503 for a while it says passes: it could
* not reach its database or its vault (`unavailable`, no reason), count
* exchanges (`busy`), or reach the issuer's keys (`issuer_unavailable`),
* or it is moving to its new app key (`rotating`). Not one that waits on
* an operator or a deploy (`wrong_kek`, `vault_outdated`, `app_key`,
* `migrating`), nor the proxy's own answers, nor Cloudflare's page.
*/
function momentary(status, body) {
	if (status !== 503) return false;
	if (body?.error === "rotating") return true;
	return body?.error === "unavailable" && (body.reason === void 0 || body.reason === "busy" || body.reason === "issuer_unavailable");
}
/**
* A CI run signed in as `service`: its ID token, the one given or a fresh
* one from GitHub's runner, traded for a credential. Asked again while the
* instance cannot answer it yet (`momentary`), each time with a fresh
* ID token from GitHub: an exchange that committed and lost its answer has
* spent the one before (docs/design/oidc.md, section 3).
*/
async function signIn(origin, service, given) {
	const idTokens = [];
	for (let attempt = 0;; attempt++) {
		const token = await idToken(given, process.env, origin, fetching(origin));
		idTokens.push(token);
		try {
			return {
				issued: await exchange(origin, service, token, http),
				idTokens
			};
		} catch (error) {
			if (!(error instanceof ExchangeFailed && momentary(error.status, error.body))) throw error;
			const wait = unavailableWait(attempt, error.retryAfter);
			if (wait === void 0) throw error;
			if (sessionFlags.verbose) stderr(`the instance could not answer POST /api/auth/oidc: asking again in ${took(wait)}`);
			await setTimeout$1(wait);
		}
	}
}
/** What GitHub must hide from the job's log, beside the values: the run's ID tokens and credential, if it used them. */
async function workloadSecrets() {
	if (exchanged === null) return [];
	const { credential, idTokens } = await exchanged;
	return [...[...new Set(idTokens)].map((token) => ["", token]), ["", credential]];
}
async function headersFor(to) {
	if (to.credential.kind === "workload") return credentialHeaders(to.mode, to.credential, (await workloadCredential(to.origin, to.credential)).credential);
	const access = to.credential.kind === "cloudflared" ? await cloudflaredToken(to.origin) : void 0;
	return credentialHeaders(to.mode, to.credential, access);
}
/**
* The API, for one instance. A refusal of a status in `handled` comes back
* to the command, as a CoffreError, for it to say what to do; any other
* ends the CLI, said in `send`'s words. `ask` sends each request.
*/
function client(to = target(), hint, handled = [], ask = once) {
	return createClient({
		url: to.origin,
		headers: () => headersFor(to).catch((error) => fail(error instanceof Error ? error.message : String(error))),
		transport: (request) => send(request, to, hint, handled, ask)
	});
}
/**
* A request, sent once. Cloudflare Access redirects rejected non-browser
* clients to its login page. Following that redirect would turn an auth
* failure into HTML that later explodes in JSON parsing.
*/
function once(request) {
	return http(request, { redirect: "manual" });
}
/** How long a read waits before it asks again, once the access policy changed under it. */
const POLICY_RETRY_MS = 300;
/**
* A read of values (`get`, `run`, `export`), or the handle `run` makes,
* asked again once, a moment later, when the instance answered 409
* `policy_changed` (which rolled any write back): the access policy
* changed while it was answered, and asked again, it is weighed as
* the policy is now. A second change is answered as any refusal is.
*/
async function retryingPolicyChange(request) {
	const again = request.clone();
	const response = await once(request);
	if (response.status !== 409) return response;
	if ((await response.clone().json().catch(() => null))?.reason !== "policy_changed") return response;
	if (sessionFlags.verbose) stderr(`the access policy changed while ${requestLine(request.method, new URL(request.url))} was answered: asking again in ${took(POLICY_RETRY_MS)}`);
	await setTimeout$1(POLICY_RETRY_MS);
	return once(again);
}
/**
* A read of values, `retryingPolicyChange`, asked again too while the
* instance cannot answer it yet (`momentary`). Each read the vault
* answered is in the audit log, the one whose answer was lost included.
*/
async function reading(request) {
	for (let attempt = 0;; attempt++) {
		const again = request.clone();
		const response = await retryingPolicyChange(request);
		const wait = unavailableWait(attempt, response.headers.get("retry-after"));
		if (wait === void 0 || response.status !== 503 || !momentary(response.status, await response.clone().json().catch(() => null))) return response;
		if (sessionFlags.verbose) stderr(`the instance could not answer ${requestLine(request.method, new URL(request.url))}: asking again in ${took(wait)}`);
		await setTimeout$1(wait);
		request = again;
	}
}
/** `client`, for the values `get`, `run` and `export` read: each request is `reading`. */
function reader(handled = []) {
	return client(target(), void 0, handled, reading);
}
/**
* The API, for one instance, where every refusal and failure comes back to
* the command as an error, said in the server's words, and none ends the
* CLI: for `export --watch`, which outlives a failed round.
*/
function enduringClient(to) {
	return createClient({
		url: to.origin,
		headers: () => headersFor(to),
		transport: (request) => retryingPolicyChange(request).catch((error) => {
			throw new Error(unreachable(to.origin, error));
		})
	});
}
/** One request; every way it can fail is explained in terms of what to do next. */
async function send(request, to, hint, handled = [], ask = once) {
	let response;
	try {
		response = await ask(request);
	} catch (error) {
		fail(unreachable(to.origin, error));
	}
	const relogin = `run \`coffre login ${to.origin}\``;
	if (response.status >= 300 && response.status < 400) {
		if (to.mode === "cloudflare") fail(`Cloudflare Access did not accept your token: ${relogin}`);
		fail(`${to.origin} redirected to ${response.headers.get("location") ?? "elsewhere"}; is that the right address?`);
	}
	if (response.status === 401) fail(refused(to));
	if (handled.includes(response.status)) return response;
	const json = isJsonContentType(response.headers.get("content-type"));
	if (!response.ok) {
		const body = json ? await response.json().catch(() => ({})) : {};
		const detail = typeof body.message === "string" && body.message.length > 0 ? body.message : null;
		const next = detail === null ? null : hint?.(response.status, typeof body.reason === "string" ? body.reason : null) ?? null;
		if (next !== null) fail(`${detail}: ${next}`);
		if (response.status === 403) fail(`forbidden: ${detail ?? "you do not have a grant for that environment"}`);
		if (response.status === 404) fail(detail === null ? "not found" : `not found: ${detail}`);
		const status = `request failed with status ${response.status}`;
		if (detail !== null) fail(`${status}: ${detail}`);
		if (typeof body.error === "string" && body.error.length > 0) fail(`${status}: ${body.error}`);
		fail(status);
	}
	if (!json) fail("request returned a non-JSON response");
	return response;
}
/**
* Why the instance turned the credential away, by whose it is. The server
* says no more than unknown, expired or revoked, on purpose; but a person's
* saved session that has not reached its end, which the CLI checks first,
* is one the instance no longer knows: signed out, or the instance reset.
*/
function refused(to) {
	const relogin = `\`coffre login ${to.origin}\``;
	switch (to.by) {
		case "service": return `${to.origin} refused the credential this run's ID token bought: is its binding still there?`;
		case "run": return `${to.origin} does not know the credential this run's ID token bought: it lasts five minutes. Sign in again, \`coffre login ${to.origin} --service <name>\``;
		case "token": return `${to.origin} does not know this bearer token: it is unknown, expired or revoked`;
		case "access": return `${to.origin} refused the Access service token's sign-in: is its service still a member?`;
		case "person": return to.mode === "cloudflare" ? `${to.origin} refused your Cloudflare Access sign-in: run ${relogin}` : signInError(`${to.origin} does not know the session saved here: it was signed out, or the instance was reset since. Sign in again: ${relogin}`, "signin");
	}
}
/** The instance a command names, as its argument or as --url: one of the two, or neither. */
function oneUrl(given, command) {
	if (given !== void 0 && sessionFlags.url !== void 0) throw new Error(`name the instance once: coffre ${command} <url>, or coffre --url <url> ${command}`);
	return given ?? sessionFlags.url;
}
/** A member as `coffre access` and `whoami` show one: `service:deploy (service account)`, `ada@acme.example (user)`. */
function named(type, id) {
	return type === "service" ? `service:${id} (service account)` : `${id} (user)`;
}
/** Parse `project/environment/KEY` or `project/environment`. */
function parsePath(raw) {
	const parts = raw.split("/");
	if (parts.length < 2 || parts.length > 3 || parts.some((part) => part.length === 0)) fail(`expected project/environment[/KEY], got: ${raw}`);
	return {
		project: parts[0],
		environment: parts[1],
		key: parts[2]
	};
}
function printMe(me) {
	if (me.environments.length === 0) process.stdout.write("  no environments granted yet\n");
	for (const entry of me.environments) process.stdout.write(`  ${`${entry.project}/${entry.environment}`.padEnd(24)} ${entry.permissions.join(", ")}\n`);
}
/**
* Sign in to an instance, make it the default, and pin the directory the
* login ran in to it. How depends on who vouches for people there, which
* the CLI finds out by asking (`loginMode`):
*
* - coffre's own sign-in: the CLI shows a code, you approve it in a browser
*   where you are signed in, and the CLI receives a session token of its own.
*   A session saved here that the instance still knows is kept: the login
*   only pins.
* - Cloudflare Access: the CLI hands over to `cloudflared`, which keeps the
*   Access token from then on.
*/
async function login(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			"no-browser": {
				type: "boolean",
				default: false
			},
			token: {
				type: "boolean",
				default: false
			},
			"access-client-id": { type: "string" },
			service: { type: "string" },
			"id-token": {
				type: "boolean",
				default: false
			}
		},
		allowPositionals: true
	});
	if (positionals.length > 1) fail(`too many arguments: ${positionals.slice(1).join(" ")}`);
	const machine = [
		"token",
		"access-client-id",
		"service"
	].filter((name) => values[name] !== void 0 && values[name] !== false);
	if (machine.length > 1) fail(`${machine.map((name) => `--${name}`).join(" and ")} are two ways to sign in: give one`);
	if (values["id-token"] && values.service === void 0) fail("--id-token goes with --service <name>: the ID token signs a CI run in as that service");
	if (machine.length > 0 && values["no-browser"]) fail("--no-browser is for a person's sign-in, in a browser");
	if (machine.length > 0 && sessionFlags.authMode !== void 0) fail(`--auth-mode is for a person's sign-in: --${machine[0]} says which`);
	for (const name of ["access-client-id", "service"]) if (values[name]?.trim() === "") fail(`--${name} is empty: an unset variable, perhaps`);
	const mode = attempt(() => parseMode(sessionFlags.authMode));
	const directory = here("A login pins the directory it runs in: run it from one that exists");
	const given = attempt(() => oneUrl(positionals[0], "login"));
	const local = given === void 0 ? localHere() : null;
	const requested = given ?? local?.origin ?? readStore().current;
	if (!requested) fail("usage: coffre login <url>, for example `coffre login https://coffre.example.com`");
	const origin = attempt(() => instanceOrigin(requested));
	if (local?.by === "file") {
		const file = shown(join(local.directory, REPO_FILE));
		const handed = values.token ? "--token" : values["access-client-id"] !== void 0 ? "--access-client-id <id>" : values["id-token"] ? `--service ${values.service} --id-token` : null;
		if (handed !== null) fail(`${file} names ${origin}, and a secret goes only where you name it: \`coffre login ${origin} ${handed}\``);
		process.stderr.write(`Signing in to ${origin}, which ${file} names\n`);
	}
	const kept = readStore().instances[origin];
	if (machine.length > 0 && kept !== void 0 && kept.kind === void 0) fail(`signed in to ${origin} as ${kept.principal?.id ?? "a person"}: \`coffre logout ${origin}\` first, or sign the run in from a home of its own`);
	if (values.token) await tokenLogin(origin);
	else if (values["access-client-id"] !== void 0) await accessServiceLogin(origin, values["access-client-id"].trim());
	else if (values.service !== void 0) await runLogin(origin, serviceMember(values.service.trim()), values["id-token"]);
	else if (!await keepSession(origin, kept, mode)) await ((mode ?? await askMode(origin)) === "cloudflare" ? accessLogin(origin) : deviceLogin(origin, values["no-browser"]));
	pinTo(directory, origin);
}
/**
* A person's session on coffre's own sign-in, saved here, that the instance
* still knows: made the default again, rather than a new one asked for.
* Only the instance saying it does not know it, 401, replaces it: any other
* failure leaves it as it is, and says so.
*/
async function keepSession(origin, kept, mode) {
	if (kept === void 0 || kept.kind !== void 0 || kept.mode !== "signin" || !kept.token || mode === "cloudflare") return false;
	if (kept.expiresAt && Date.parse(kept.expiresAt) <= Date.now()) return false;
	const token = kept.token;
	let me;
	try {
		me = await createClient({
			url: origin,
			headers: () => ({ authorization: `Bearer ${token}` }),
			transport: (request) => http(request, { redirect: "manual" }).catch((error) => {
				throw new Unreachable(origin, error);
			})
		}).me();
		if (typeof me?.principal?.id !== "string") throw new Error("GET /api/me did not answer as coffre does");
	} catch (error) {
		if (error instanceof CoffreError && error.status === 401) return false;
		const why = error.message;
		fail(`could not check the session saved for ${origin}, which is kept: ${why}. Retry, or \`coffre logout ${origin}\` first for a new one`);
	}
	writeStore(withSession(readStore(), origin, kept));
	const ends = kept.expiresAt ? `, until ${kept.expiresAt.slice(0, 10)}` : "";
	process.stdout.write(`Signed in to ${origin} as ${me.principal.id} already${ends}: \`coffre logout\` first for a new session\n`);
	printMe(me);
	return true;
}
/**
* Pin the directory a login ran in to its instance, for it and every
* directory below: unless it is your home or above it, where the default
* the login set is enough, or a pin or `coffre.json` there names it already.
*/
function pinTo(directory, origin) {
	if (within(realHome(), directory)) return;
	const pins = readPins();
	const local = (() => {
		try {
			return localFor(pins, directory, realHome(), readRepoFile);
		} catch {
			return null;
		}
	})();
	if (local?.origin === origin) {
		process.stdout.write(local.by === "pin" ? `${shown(local.directory)} is pinned to it already\n` : `${shown(join(local.directory, REPO_FILE))} names it already\n`);
		return;
	}
	writePins(withPin(pins, directory, origin));
	process.stdout.write(`Pinned ${shown(directory)} to it: coffre uses ${origin} there and in every directory below\n`);
}
/** How long a code lasts, as it is said: `10 minutes`, `1 minute`, `45 seconds`. */
function expiresIn(seconds) {
	if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
	const minutes = Math.round(seconds / 60);
	return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}
/** A device login: a code shown here, approved in a browser signed in to coffre. */
async function deviceLogin(origin, noBrowser) {
	let started;
	try {
		started = await http(`${origin}/api/auth/device`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ client_label: `coffre CLI on ${hostname()}` })
		});
	} catch (error) {
		fail(unreachable(origin, error));
	}
	if (started.status === 429) fail("too many sign-in attempts from this address; wait a minute and retry");
	if (!started.ok || !isJsonContentType(started.headers.get("content-type"))) fail(`${origin} did not start a sign-in (status ${started.status})`);
	const device = await started.json();
	process.stderr.write(`\nTo sign in, open\n\n    ${device.verification_uri_complete}\n\nand check that it shows the code  ${device.user_code}\n\n`);
	if (!noBrowser && process.stderr.isTTY) openBrowser(device.verification_uri_complete);
	process.stderr.write(`Waiting for you to approve it; the code expires in ${expiresIn(device.expires_in)}…\n`);
	const session = await pollDevice(origin, device.device_code, device.interval, device.expires_in);
	const me = await client({
		origin,
		mode: "signin",
		by: "person",
		credential: {
			kind: "token",
			token: session.access_token
		}
	}).me();
	writeStore(withSession(readStore(), origin, {
		mode: "signin",
		token: session.access_token,
		principal: me.principal,
		expiresAt: session.expires_at,
		obtainedAt: (/* @__PURE__ */ new Date()).toISOString()
	}));
	process.stdout.write(`Signed in to ${origin} as ${me.principal.id}\n`);
	printMe(me);
}
/** Ask the instance how it signs people in. */
async function askMode(origin) {
	let response;
	try {
		response = await http(`${origin}/api/auth`, {
			redirect: "manual",
			headers: { accept: "application/json" }
		});
	} catch (error) {
		fail(unreachable(origin, error));
	}
	const body = isJsonContentType(response.headers.get("content-type")) ? await response.json().catch(() => void 0) : void 0;
	return attempt(() => loginMode(origin, response.status, body));
}
async function pollDevice(origin, deviceCode, interval, expiresIn) {
	const deadline = Date.now() + expiresIn * 1e3;
	let wait = Math.max(interval, 1) * 1e3;
	while (Date.now() < deadline) {
		await new Promise((resolve) => setTimeout(resolve, wait));
		let response;
		try {
			response = await http(`${origin}/api/auth/device/token`, {
				method: "POST",
				redirect: "manual",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ device_code: deviceCode })
			});
		} catch {
			continue;
		}
		if (response.ok) return await response.json();
		const { error } = await response.json().catch(() => ({}));
		if (response.status === 429 || error === "slow_down") {
			wait += 5e3;
			continue;
		}
		if (error === "authorization_pending") continue;
		if (error === "access_denied") fail("the sign-in was declined in the browser");
		if (error === "expired_token") fail(signInError("the code expired before it was approved; run `coffre login` again", "signin"));
		fail(`sign-in failed: ${error ?? `status ${response.status}`}`);
	}
	fail(signInError("the code expired before it was approved; run `coffre login` again", "signin"));
}
/** Best effort: on a machine without a desktop the printed link is enough. */
function openBrowser(url) {
	const [command, ...args] = process.platform === "darwin" ? ["open", url] : process.platform === "win32" ? [
		"cmd",
		"/c",
		"start",
		"\"\"",
		url
	] : ["xdg-open", url];
	const child = spawn(command, args, {
		stdio: "ignore",
		detached: true
	});
	child.on("error", () => {});
	child.unref();
}
/**
* A CI run's sign-in, saved as the instance's session for the commands
* after it: whoever `to` is, as the instance says, kept as `session`. It
* replaces another run's session there, never a person's (`login`).
*/
async function saveRun(to, session) {
	const me = await client(to, void 0, [], reading).me();
	writeStore(withSession(readStore(), to.origin, {
		...session,
		principal: me.principal,
		obtainedAt: (/* @__PURE__ */ new Date()).toISOString()
	}));
	process.stdout.write(`Signed in to ${to.origin} as ${me.principal.id}\n`);
	printMe(me);
}
/** `coffre login <url> --token`: a bearer token, asked for, and kept as the session. */
async function tokenLogin(origin) {
	const token = await readSecret({
		label: "Bearer token",
		hint: "coffre_svc_… or coffre_pat_…, from `coffre tokens issue` or the service's page. Hidden as you type."
	}).catch((error) => fail(error.message));
	await saveRun({
		origin,
		mode: "signin",
		by: "token",
		credential: {
			kind: "token",
			token
		}
	}, {
		mode: "signin",
		kind: "token",
		token,
		expiresAt: null
	});
}
/** `coffre login <url> --access-client-id <id>`: an Access service token, its secret asked for. */
async function accessServiceLogin(origin, clientId) {
	const clientSecret = await readSecret({
		label: "Access client secret",
		hint: `The secret of the Access service token ${clientId}. Hidden as you type.`
	}).catch((error) => fail(error.message));
	await saveRun({
		origin,
		mode: "cloudflare",
		by: "access",
		credential: {
			kind: "access-service-token",
			clientId,
			clientSecret
		}
	}, {
		mode: "cloudflare",
		kind: "access",
		clientId,
		clientSecret
	});
}
/**
* `coffre login <url> --service <name>`: a CI run's ID token, traded for a
* credential of the service that lasts five minutes, kept as the session.
* GitHub's runner gives the ID token; elsewhere, `--id-token` asks for it.
*/
async function runLogin(origin, service, ask) {
	const { issued } = await signIn(origin, service, ask ? await readSecret({
		label: "ID token",
		hint: `The run's ID token, for the audience ${origin}. Hidden as you type.`
	}).catch((error) => fail(error.message)) : void 0).catch((error) => fail(error instanceof Error ? error.message : String(error)));
	await saveRun({
		origin,
		mode: "signin",
		by: "run",
		credential: {
			kind: "token",
			token: issued.token
		}
	}, {
		mode: "signin",
		kind: "run",
		token: issued.token,
		expiresAt: issued.expiresAt
	});
}
async function accessLogin(origin) {
	process.stderr.write(`${origin} is behind Cloudflare Access; signing in with cloudflared.\n`);
	const code = await new Promise((resolve) => {
		const child = spawn("cloudflared", [
			"access",
			"login",
			origin
		], { stdio: "inherit" });
		child.on("error", () => resolve(null));
		child.on("exit", (status) => resolve(status));
	});
	if (code === null) fail("this instance uses Cloudflare Access, which needs cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/\n  In CI, sign in with an Access service token instead: coffre login <url> --access-client-id <id>, its secret pasted or piped in.");
	if (code !== 0) fail("cloudflared could not sign you in");
	const me = await client({
		origin,
		mode: "cloudflare",
		by: "person",
		credential: { kind: "cloudflared" }
	}).me();
	writeStore(withSession(readStore(), origin, {
		mode: "cloudflare",
		principal: me.principal,
		obtainedAt: (/* @__PURE__ */ new Date()).toISOString()
	}));
	process.stdout.write(`Signed in to ${origin} as ${me.principal.id}\n`);
	printMe(me);
}
/**
* End a person's session on the server, then forget it here. A CI run's
* is only forgotten: its bearer token or Access service token is the
* service's, for other runs too, and its credential ends by itself.
*/
async function logout(args) {
	parse(args, {}, ["<url>"], 1);
	const store = readStore();
	const requested = attempt(() => oneUrl(args[0], "logout")) ?? localHere()?.origin ?? store.current;
	if (!requested) fail("not signed in anywhere");
	const origin = attempt(() => instanceOrigin(requested));
	const session = store.instances[origin];
	const { pins, unpinned } = withoutPins(readPins(), origin);
	const unpin = () => {
		if (unpinned.length === 0) return;
		writePins(pins);
		process.stdout.write(`  Unpinned ${unpinned.map(shown).join(", ")}\n`);
	};
	if (session === void 0 && unpinned.length > 0) {
		process.stdout.write(`Not signed in to ${origin}\n`);
		return unpin();
	}
	if (session === void 0) fail(`not signed in to ${origin}`);
	if (session.kind === void 0 && session.mode === "signin" && session.token) {
		let response;
		try {
			response = await http(`${origin}/api/auth/logout`, {
				method: "POST",
				redirect: "manual",
				headers: {
					authorization: `Bearer ${session.token}`,
					"content-type": "application/json"
				}
			});
		} catch (error) {
			fail(`${unreachable(`${origin} to end the session`, error)}; nothing was changed`);
		}
		if (!response.ok && response.status !== 401) fail(`${origin} refused to end the session (status ${response.status}); nothing was changed`);
	}
	writeStore(withoutSession(store, origin));
	process.stdout.write(`Signed out of ${origin}\n`);
	unpin();
	if (session.kind === "token" || session.kind === "access") process.stdout.write(`  The ${session.kind === "token" ? "bearer token" : "Access service token"} is forgotten here, and works elsewhere until it is revoked.\n`);
	else if (session.mode === "cloudflare" && session.kind === void 0) process.stdout.write("  cloudflared still holds its Access token until it expires.\n");
}
async function whoami(args) {
	const { values } = parse(args, { json: {
		type: "boolean",
		default: false
	} }, []);
	const to = target();
	const me = await client(to).me();
	if (values.json) {
		process.stdout.write(`${JSON.stringify({
			origin: to.origin,
			...me
		}, null, 2)}\n`);
		return;
	}
	const store = readStore();
	const session = store.instances[to.origin];
	const choice = attempt(() => choose(sessionFlags, store, localHere()));
	const why = choice.by === "default" ? " (the default)" : choice.by === "url" ? "" : ` (${because(choice)})`;
	const via = {
		person: {
			signin: "coffre sign-in",
			cloudflare: "Cloudflare Access"
		}[to.mode],
		token: "a bearer token, from coffre login --token",
		access: "an Access service token, from coffre login --access-client-id",
		run: "the run's ID token, from coffre login --service",
		service: "the run's ID token, as --service"
	}[to.by];
	process.stdout.write(`${named(me.principal.type, me.principal.id)} on ${to.origin}${why}, via ${via}\n`);
	if (me.personalToken) {
		const { label, expiresAt, scope } = me.personalToken;
		process.stdout.write(`  personal token "${label}", ends ${expiresAt.slice(0, 16).replace("T", " ")} UTC, reaching ${credentialScopeInWords(scope)}\n`);
	}
	if (to.by === "person" && session?.expiresAt) {
		const days = Math.round((Date.parse(session.expiresAt) - Date.now()) / 864e5);
		process.stdout.write(`  session ends ${session.expiresAt.slice(0, 10)} (in ${days} day${days === 1 ? "" : "s"})\n`);
	}
	if (me.registered) {
		const mcp = me.features.mcp === null ? "off" : `on, at ${me.features.mcp}`;
		process.stdout.write(`  MCP clients: ${mcp}\n  CI sign-in by ID token: ${me.features.workloads ? "on" : "off"}\n`);
	}
	printMe(me);
}
/**
* Switch the default instance, or list them: the one used here starred,
* each with the directories pinned to it, and the `coffre.json` here.
*/
function use(args) {
	parse(args, {}, ["<url>"], 1);
	const store = readStore();
	const local = localHere();
	const file = local?.by === "file" ? local : null;
	if (args[0] === void 0) {
		const pinned = Object.entries(readPins().directories);
		const origins = [.../* @__PURE__ */ new Set([
			...Object.keys(store.instances),
			...pinned.map(([, origin]) => origin),
			...file === null ? [] : [file.origin]
		])];
		if (origins.length === 0) fail(signInError("not signed in anywhere yet: run `coffre login <url>`"));
		const used = local?.origin ?? store.current;
		for (const origin of origins) {
			const session = store.instances[origin];
			const why = [
				...origin === store.current ? ["the default"] : [],
				...pinned.filter(([, to]) => to === origin).map(([directory]) => `pinned at ${shown(directory)}`),
				...file?.origin === origin ? [because(file)] : []
			];
			const who = session === void 0 ? "not signed in" : session.principal?.id ?? "";
			process.stdout.write(`${`${origin === used ? "*" : " "} ${origin.padEnd(36)} ${who.padEnd(24)} ${why.join(", ")}`.trimEnd()}\n`);
		}
		return;
	}
	const origin = attempt(() => instanceOrigin(args[0]));
	if (!(origin in store.instances)) fail(signInError(`not signed in: run \`coffre login ${origin}\``));
	writeStore({
		...store,
		current: origin
	});
	process.stdout.write(`Now using ${origin} by default\n`);
	if (local !== null && local.origin !== origin) {
		const named = local.by === "pin" ? `${shown(local.directory)} is pinned to ${local.origin}` : `${shown(join(local.directory, REPO_FILE))} names ${local.origin}`;
		process.stdout.write(`  but not here: ${named}, and \`coffre login ${origin}\` pins this directory to it\n`);
	}
}
async function get(args) {
	const [target] = parse(args, {}, ["<project>/<environment>/<KEY>"]).positionals;
	const { project, environment, key } = parsePath(target);
	if (!key) fail("usage: coffre get <project>/<environment>/<KEY>");
	const { values } = await reader().secrets.reveal(`${project}/${environment}/${key}`);
	process.stdout.write(process.stdout.isTTY ? `${values[key]}\n` : values[key]);
}
async function list(args) {
	const { values, positionals } = parse(args, {
		json: {
			type: "boolean",
			default: false
		},
		"older-than": { type: "string" },
		stale: {
			type: "boolean",
			default: false
		}
	}, ["<project>/<environment>"]);
	if (values.stale && values["older-than"] !== void 0) throw new UsageError("--stale or --older-than, not both");
	const olderThanDays = values["older-than"] === void 0 ? null : days(values["older-than"]);
	const { project, environment } = parsePath(positionals[0]);
	const result = await client().secrets.list(`${project}/${environment}`);
	if (result.personal?.fallback === true) process.stderr.write(`coffre: you have no personal config of ${project}/${result.personal.of}: these are its own keys; a write to ${project}/${environment} makes one\n`);
	const told = result.rotateAfterDays;
	if (values.stale && told === void 0) fail("this instance is older than rotation ages (coffre 0.6), and has no rotateAfterDays: upgrade it, or name an age, --older-than 90d");
	const rotateAfterDays = told ?? null;
	if (values.stale && rotateAfterDays === null) fail("this instance flags no value for rotation (its rotateAfterDays is null): name an age, --older-than 90d");
	const over = values.stale ? rotateAfterDays : olderThanDays;
	const now = Date.now();
	const keys = over === null ? result.keys : result.keys.filter((entry) => olderThan(entry, over, now));
	if (values.json) {
		process.stdout.write(`${JSON.stringify(keys, null, 2)}\n`);
		return;
	}
	for (const [folder, inFolder] of byFolder(keys)) {
		const indent = folder === null ? "" : "  ";
		if (folder !== null) process.stdout.write(`${folder}/\n`);
		for (const entry of inFolder) {
			const age = ageInDays(entry, now);
			const written = age === null ? "-" : age === 0 ? "today" : `${age} day${age === 1 ? "" : "s"} ago`;
			const recipe = entry.generated == null ? null : entry.generated.recipe;
			const rotate = recipe === null ? "rotate it" : `\`coffre regenerate ${project}/${environment}/${entry.key}\``;
			const due = rotateAfterDays !== null && olderThan(entry, rotateAfterDays, now) ? `  (unchanged over ${rotateAfterDays} days: ${rotate})` : "";
			const made = recipe === null ? "" : `  (generated, ${recipe})`;
			const archived = entry.archived ? "  (archived)" : "";
			const plain = entry.value != null ? `  plain: ${entry.value}` : entry.sensitivity === "sensitive" ? "  sensitive" : "";
			const parent = entry.parent ?? null;
			const standing = parent === null ? "" : parent.state === "inherited" ? `  (from ${parent.from}${parent.reset ? "; its own reset, and kept" : ""})` : parent.state === "removed" ? `  (removed here: ${parent.held === false ? `${parent.from} dropped it too` : `not inherited from ${parent.from}`})` : `  (overrides ${parent.from}${parent.changed ? `; ${parent.from} changed since` : ""})`;
			const { reference } = entry;
			if (reference !== null) {
				const state = reference.state === "live" ? `v${reference.version}` : reference.state.replace("_", " ");
				process.stdout.write(`${indent}${entry.key}\t→ ${reference.source}\t${state}\t${shownMember$1(reference.createdBy).replace(/^user:/, "")}\t${written}${plain}${due}${archived}${standing}\n`);
				continue;
			}
			process.stdout.write(`${indent}${entry.key}\tv${entry.version ?? "-"}\t${entry.updatedBy ?? "-"}\t${written}${made}${plain}${due}${archived}${standing}\n`);
		}
	}
}
/** `90d`: an age in whole days, as `--older-than` takes it. */
function days(text) {
	const match = /^(\d+)d$/.exec(text);
	if (match === null) throw new UsageError(`--older-than takes days, as 90d, not "${text}"`);
	return Number(match[1]);
}
async function set(args) {
	const { values, positionals } = parse(args, {
		ref: { type: "string" },
		generate: { type: "string" },
		"public-key": { type: "string" },
		plain: { type: "boolean" },
		secret: { type: "boolean" },
		sensitive: { type: "boolean" }
	}, ["<project>/<environment>/<KEY>", "[value]"], 1);
	const [target, given] = positionals;
	if (given !== void 0 && values.plain !== true) fail("coffre set asks for the value: paste it, or pipe it in, never as an argument; a value that is no secret may be one, with --plain");
	const { project, environment, key } = parsePath(target);
	if (!key) fail("usage: coffre set <project>/<environment>/<KEY>");
	const levels = [
		"plain",
		"secret",
		"sensitive"
	].filter((level) => values[level] === true);
	if (levels.length > 1) fail(`--plain, --secret or --sensitive: one says who sees the value, not ${levels.map((level) => `--${level}`).join(" and ")}`);
	const sensitivity = levels[0];
	if (values.ref !== void 0 && values.generate !== void 0) fail("--ref or --generate: a key reads another secret, or holds a value made here, not both");
	if (values.ref !== void 0 && sensitivity !== void 0) fail(`--${sensitivity} says who sees a value: a reference has its source's`);
	if (values.plain === true && values.generate !== void 0) fail("--plain writes a value given here, as it is: not with --generate");
	if (values["public-key"] !== void 0 && values.generate === void 0) fail("--public-key goes with --generate and a key pair's recipe, as ecdsa:p-256");
	if (values.generate !== void 0) {
		const made = await generatedPatch(key, recipeFlag(values.generate), values["public-key"]);
		const patch = sensitivity === void 0 ? made : Object.fromEntries(Object.entries(made).map(([name, write]) => [name, {
			...write,
			sensitivity
		}]));
		const result = await client().secrets.set(`${project}/${environment}`, patch);
		process.stdout.write(`${generatedLines(patch, versionsOf(result.keys), "generated").join("\n")}\n`);
		return;
	}
	if (values.ref !== void 0) {
		if (!parsePath(values.ref).key) fail(`--ref names a secret, <project>/<environment>/<KEY>, not "${values.ref}"`);
		const outcome = (await client().secrets.set(`${project}/${environment}`, { [key]: { ref: values.ref } })).keys[key];
		process.stdout.write(`${key} is a reference to ${"reference" in outcome ? outcome.reference : values.ref}: whoever reads ${project}/${environment} reads it\n`);
		return;
	}
	const value = given ?? await readValue(key);
	const written = sensitivity === void 0 ? value : sensitivity === "plain" ? {
		value,
		plain: true
	} : {
		value,
		sensitivity
	};
	const outcome = (await client().secrets.set(`${project}/${environment}`, { [key]: written })).keys[key];
	const level = "sensitivity" in outcome ? outcome.sensitivity : sensitivity;
	const personal = environment.endsWith("@me");
	const said = level === "plain" ? `, plain: shown to ${personal ? "you alone" : `whoever lists ${project}/${environment}`}` : level === "sensitive" ? `, sensitive: shown to nobody, Owners included; apps use it through the credential proxy, and services read it${sensitivity === void 0 ? `, as ${personal ? "the key it overrides" : "it was"}; --secret makes it a secret ${personal ? "your app is given" : "its readers see"}` : ""}` : "";
	process.stdout.write(`${key} written as version ${"version" in outcome ? outcome.version : "?"}${said}\n`);
}
/**
* Make keys stricter, their values kept (`Sensitivity`): one key, or every
* key of an environment that is looser now. A key is made looser only by
* writing its value again (`coffre set … --plain`), never by flipping one
* nobody could read, so only stricter levels are asked for here; but an
* Owner of the project makes a sensitive value secret in place
* (`loosenable`), `mark market/prod secret` then every sensitive one of
* its own too. A key of the environment's that is a reference, or that a
* fork inherits, reads the level of the value where it is held: left as it
* is, and named, with where to mark it, when it is not at the level asked.
*/
async function mark(args) {
	const { positionals } = parse(args, {}, ["<project>/<environment>[/<KEY>]", "<plain|secret|sensitive>"]);
	const [target, level] = positionals;
	if (level !== "plain" && level !== "secret" && level !== "sensitive") fail(`coffre mark makes keys plain, secret or sensitive, not "${level}"`);
	const { project, environment, key } = parsePath(target);
	const path = `${project}/${environment}`;
	const coffre = client();
	const { keys: listed, loosenable } = await coffre.secrets.list(path);
	const order = [
		"plain",
		"secret",
		"sensitive"
	];
	const marks = (sensitivity) => order.indexOf(sensitivity) < order.indexOf(level) || loosenable === true && level === "secret" && sensitivity === "sensitive";
	const own = listed.filter((entry) => !entry.archived && entry.reference === null && entry.version !== null && entry.parent?.state !== "inherited" && entry.parent?.state !== "removed");
	if (listed.some((entry) => entry.version !== null && entry.sensitivity === void 0)) fail(`${path}'s instance is older than sensitivity (coffre 0.10): upgrade it first`);
	const marking = key === void 0 ? own.filter((entry) => marks(entry.sensitivity ?? "secret")).map((entry) => entry.key) : [key];
	const left = key !== void 0 ? [] : listed.flatMap((entry) => {
		if (entry.archived || !marks(entry.sensitivity ?? "secret")) return [];
		if (entry.reference !== null) return entry.reference.state === "live" ? [`${entry.key}, a reference to ${entry.reference.source}: mark it there`] : [];
		if (entry.parent?.state !== "inherited") return [];
		return [`${entry.key}, inherited from ${project}/${entry.parent.from}: mark it there, or write ${environment}'s own`];
	});
	if (marking.length === 0) process.stdout.write(`nothing to mark in ${path}: every value of its own is ${level}${loosenable === true && level === "secret" ? "" : " or stricter"}\n`);
	else {
		const before = new Map(listed.map((entry) => [entry.key, entry.sensitivity]));
		const result = await coffre.secrets.set(path, Object.fromEntries(marking.map((name) => [name, { sensitivity: level }])));
		for (const name of marking) {
			const outcome = result.keys[name];
			const was = before.get(name);
			const version = outcome !== void 0 && "version" in outcome ? outcome.version : "?";
			process.stdout.write(was === level ? `${name}: already ${level}\n` : `${name}: ${was ?? "secret"} → ${level}, as version ${version}, its value kept\n`);
		}
	}
	if (left.length > 0) process.stderr.write(`coffre: left as they are: ${left.join("; ")}\n`);
}
/**
* Regenerate a key by the recipe its current value was made by: a new value
* made here and written as a new version, never shown, and for a key pair's
* either half, both halves at once. Listing the environment reads no value.
*/
async function regenerate(args) {
	const [target] = parse(args, {}, ["<project>/<environment>/<KEY>"]).positionals;
	const { project, environment, key } = parsePath(target);
	if (!key) fail("usage: coffre regenerate <project>/<environment>/<KEY>");
	const path = `${project}/${environment}`;
	const coffre = client();
	const listed = (await coffre.secrets.list(path)).keys;
	const patch = await regeneratedPatch(path, key, listed).catch((error) => fail(error.message));
	const result = await coffre.secrets.set(path, patch);
	process.stdout.write(`${generatedLines(patch, versionsOf(result.keys), "regenerated").join("\n")}\n`);
}
/** The version each key of a write got. */
function versionsOf(keys) {
	return Object.fromEntries(Object.entries(keys).map(([key, outcome]) => [key, "version" in outcome ? outcome.version : null]));
}
/**
* A secret's value, as it is: typed at a hidden prompt on a terminal, or
* stdin, a value of several lines included, less exactly one final line
* break. Never empty: an unset variable piped in would blank the secret.
*/
async function readValue(key) {
	const value = process.stdin.isTTY ? await hiddenLine(process.stdin, process.stderr, style(process.stderr), `${key}:`, "Hidden as you type; for a value of several lines, pipe it in.", true) : readFileSync(0, "utf8").replace(/\r?\n$/, "");
	if (value === "") fail(process.stdin.isTTY ? "no value given" : "no value: none came on stdin, and there is no terminal to ask on");
	return value;
}
/**
* The keys each environment named gives a read of them, by path: listed,
* which opens no value, those `patterns` names (`export --keys`), or all of
* them. One the caller may not list, a reference among them that cannot be
* read, a pattern that names none of them, or a key two of them define
* stops here, before anything is read, thrown for the command to end on.
*/
async function listKeys(paths, list, patterns) {
	const keys = /* @__PURE__ */ new Map();
	for (const path of paths) {
		const live = (await list.secrets.list(path).catch((error) => {
			throw new Error(`${path}: ${error instanceof CoffreError ? error.message : String(error)}. Nothing was read`);
		})).keys.filter(({ key, archived }) => !archived && (patterns === null || patterns.some((pattern) => keyNamed(pattern, key))));
		const hidden = live.filter(({ version, reference, parent }) => version === null && reference === null && parent?.state === "inherited");
		if (hidden.length > 0) {
			const which = [...new Set(hidden.map(({ parent }) => parent.from))].map((from) => `${hidden.filter(({ parent }) => parent.from === from).map(({ key }) => key).join(", ")} from ${path.split("/")[0]}/${from}`);
			throw new Error(`${path} inherits ${which.join("; ")}, which you cannot read. Nothing was read`);
		}
		const stuck = live.find(({ version, reference }) => version === null && reference !== null && reference.state !== "live");
		if (stuck !== void 0) throw new Error(`${path}/${stuck.key} is a reference that cannot be read (${stuck.reference.state.replaceAll("_", " ")}): \`coffre references ${path}\` says more. Nothing was read`);
		keys.set(path, live.filter(({ version, reference }) => version !== null || reference !== null).map(({ key }) => key));
	}
	const unmatched = (patterns ?? []).filter((pattern) => ![...keys.values()].some((held) => held.some((key) => keyNamed(pattern, key))));
	if (unmatched.length > 0) throw new Error(`${listOf(paths)} hold${paths.length === 1 ? "s" : ""} no key that --keys names as ${listOf(unmatched)}. Nothing was read`);
	const shared = clash([...keys]);
	if (shared !== null) throw new Error(`${shared}: a key comes from one environment only. Nothing was read`);
	return keys;
}
/**
* Every value in the environments named, as one environment: all are read,
* or none is. One is read as it always was. Of several, each is listed
* first (`listKeys`), unless `only` says already which keys of each to read,
* those `export --keys` names, and an environment it names none of is not
* read at all. Then each is read, one audited read apiece, and what came
* back is checked again, for an environment changed in between. What stops
* it is thrown, for the command to end on or, watching, to outlive.
*/
async function readEnvironments(paths, api, only = null) {
	if (only === null && paths.length > 1) await listKeys(paths, api.list, null);
	const useOnly = [];
	const read = [];
	for (const path of paths) {
		const keys = only?.get(path);
		if (keys === void 0) {
			read.push([path, await api.read.secrets.reveal(path)]);
			continue;
		}
		if (keys.length === 0) continue;
		const answer = await api.read.secrets.reveal(path, keys);
		const wanted = new Set(keys);
		if (Object.keys(answer.values).some((key) => !wanted.has(key))) process.stderr.write(`coffre: ${path} was read whole, as an instance before 0.12 reads it: only the keys --keys names are exported, and the audit log has every one\n`);
		const values = Object.fromEntries(Object.entries(answer.values).filter(([key]) => wanted.has(key)));
		const gone = keys.filter((key) => !Object.hasOwn(values, key) && !(answer.sensitive ?? []).includes(key) && !(answer.useOnly ?? []).includes(key));
		if (gone.length > 0) throw new Error(`${path} no longer holds ${listOf(gone)}, as read just now. No value was used, and the read is in the audit log`);
		useOnly.push(...keys.filter((key) => (answer.useOnly ?? []).includes(key)));
		read.push([path, {
			...answer,
			values
		}]);
	}
	const shared = clash(read.map(([path, { values }]) => [path, Object.keys(values)]));
	if (shared !== null) throw new Error(`${shared}, as read just now. No value was used, and the reads are in the audit log`);
	const sensitive = read.flatMap(([, answer]) => answer.sensitive ?? []).sort();
	return {
		entries: read.flatMap(([, { values }]) => Object.entries(values)),
		version: read.map(([, answer]) => answer.version).join(" "),
		sensitive,
		useOnly: useOnly.sort()
	};
}
/** What a read left out, on stderr: a person's sensitive keys, which nobody is handed, and the keys --keys named that a workload only uses. */
function sayLeftOut(sensitive, useOnly = []) {
	if (sensitive.length > 0) process.stderr.write(`coffre: left out, sensitive, which nobody is handed: ${sensitive.join(", ")} (the credential proxy uses them, and a service account reads them)\n`);
	if (useOnly.length > 0) process.stderr.write(`coffre: left out, which this workload only uses through coffre: ${useOnly.join(", ")} (its binding's reads do not list them)\n`);
}
/** `readEnvironments` for a command that ends on what stops it, said in `send`'s words for a failed request. */
function readOrEnd(paths, only = null) {
	return readEnvironments(paths, {
		read: reader(),
		list: reader([403, 404])
	}, only).then((read) => {
		sayLeftOut(read.sensitive, read.useOnly);
		return read.entries;
	}, (error) => fail(error instanceof Error ? error.message : String(error)));
}
/**
* Placeholders for the environments named, where the instance has the
* credential proxy (docs/design/credential-proxy.md) and the session is a
* person's: one handle for the run, which the proxy takes in place of each
* credential's keys, and the values the person may read, as they are. Null where the instance has no
* proxy, or for a service account, which reads values (R13).
*/
async function placeholders(paths, to = target()) {
	if (!await proxied(to)) return null;
	const at = (path, headers) => retryingPolicyChange(new Request(`${to.origin}/use${path}`, { headers })).catch((error) => fail(unreachable(to.origin, error)));
	const label = `coffre run on ${hostname()}: ${paths.join(" ")}`;
	const handle = await client(to, void 0, [], retryingPolicyChange).handles.create({
		label: label.length <= 120 ? label : `${label.slice(0, 119)}…`,
		paths: [...paths]
	});
	const planOf = async (path) => {
		const response = await at(`/${path}`, { authorization: `Bearer ${handle.token}` });
		const body = await response.json().catch(() => ({}));
		if (!response.ok) fail(`${path}: ${body.message ?? `the credential proxy answered ${response.status}`}`);
		return body;
	};
	const plans = [];
	const made = [];
	for (const path of paths) {
		let plan = await planOf(path);
		for (let attempt = 1; Object.keys(plan.generate ?? {}).length > 0; attempt++) {
			if (attempt > 3) fail(`${path}: its keys kept changing while coffre made your own; run again`);
			const mine = `${path.replace(/@me$/, "")}@me`;
			const writes = await Promise.all(Object.entries(plan.generate).map(async ([key, { recipe, replaces, sensitivity }]) => {
				const write = await regenerateWrite(key, { recipe }, () => replaces);
				if (sensitivity !== void 0) for (const entry of Object.values(write)) entry.sensitivity = sensitivity;
				return write;
			}));
			const patch = Object.assign(Object.create(null), ...writes);
			if (await client(to, void 0, [409]).secrets.set(mine, { ...patch }).then(() => true, (error) => {
				if (error instanceof CoffreError && error.status === 409 && error.reason === "stale") return false;
				if (error instanceof CoffreError) fail(`${mine}: ${error.message}`);
				throw error;
			})) made.push([mine, Object.keys(patch).sort()]);
			plan = await planOf(path);
		}
		plans.push([path, plan]);
	}
	const tunnelsOf = (plan) => Object.values(plan.tunnels ?? {});
	const shared = clash(plans.map(([path, plan]) => [path, [
		...Object.keys(plan.env),
		...tunnelsOf(plan).map((tunnel) => tunnel.key),
		...plan.left
	]]));
	if (shared !== null) fail(`${shared}: a key comes from one environment only`);
	const credentials = Object.fromEntries(plans.flatMap(([, plan]) => Object.entries(plan.credentials)));
	const env = Object.fromEntries(plans.flatMap(([, plan]) => Object.entries(plan.env)));
	return {
		env: {
			...env,
			COFFRE_CREDENTIALS: JSON.stringify(credentials),
			COFFRE_HANDLE: handle.token
		},
		left: plans.flatMap(([, plan]) => plan.left).sort(),
		credentials: Object.keys(credentials).sort(),
		given: Object.keys(env).filter((key) => !env[key].includes(handle.token)).sort(),
		expiresAt: handle.expiresAt,
		tunnels: plans.flatMap(([, plan]) => tunnelsOf(plan)),
		handle: handle.token,
		made,
		revoke: async () => void await createClient({
			url: to.origin,
			headers: () => headersFor(to),
			transport: once
		}).handles.revoke(handle.id)
	};
}
/** Whether `to` is a person's session, a personal token's included, on an instance with the credential proxy: what gets placeholders. */
async function proxied(to) {
	if (!(to.by === "person" || to.credential.kind === "token" && to.credential.token.startsWith("coffre_pat_"))) return false;
	const proxy = await http(`${to.origin}/use`, {
		headers: await headersFor(to),
		redirect: "manual"
	}).catch((error) => fail(unreachable(to.origin, error)));
	if (proxy.status === 404 || !isJsonContentType(proxy.headers.get("content-type"))) return false;
	if (!proxy.ok) fail(`${to.origin}'s credential proxy answered ${proxy.status}`);
	return true;
}
/** What `run` and `export` say of a person's placeholders, on stderr: what the app holds, and what it does without. */
function sayPlaceholders(placed, paths, to) {
	const lines = [
		`coffre: placeholders for ${listOf(paths)}: ${placed.credentials.length === 0 ? "no credential the proxy covers" : `${placed.credentials.join(", ")} through ${to.origin}/use`}; the handle lasts until ${new Date(placed.expiresAt).toLocaleString()} (\`coffre tokens\` lists it)`,
		...placed.made.map(([mine, keys]) => `coffre: made your own ${keys.join(", ")} in ${mine}, each by its recipe: your next runs use them`),
		...placed.given.length === 0 ? [] : [`coffre: values as they are, which you may read: ${placed.given.join(", ")}`],
		...placed.tunnels.length === 0 ? [] : [`coffre: ${placed.tunnels.map((tunnel) => tunnel.key).join(", ")} through a tunnel to its database, on 127.0.0.1`],
		...placed.left.length === 0 ? [] : [`coffre: left out, neither proxied nor yours to read: ${placed.left.join(", ")}`]
	];
	process.stderr.write(`${lines.join("\n")}\n`);
}
/**
* Fetch every secret of the environments named and exec a command with them
* in its environment: one audited read per environment, and one audit row
* per secret injected. A variable the shell already sets is overwritten,
* unless --keep-existing keeps it. (`export` prints values for a tool to
* apply, so it has no shell environment to defer to.)
*/
async function run(args) {
	const separator = args.indexOf("--");
	if (separator === -1 || separator === args.length - 1) fail("usage: coffre run [--keep-existing] <project>/<environment> [<project>/<environment> ...] -- <command> [args...]");
	const { values: flags, positionals } = parseArgs({
		args: args.slice(0, separator),
		options: {
			"keep-existing": {
				type: "boolean",
				default: false
			},
			proof: { type: "string" }
		},
		allowPositionals: true,
		strict: true
	});
	const command = args.slice(separator + 1);
	const to = target();
	if (flags.proof !== void 0 && to.credential.kind !== "workload") fail("--proof is how a service proves itself: coffre --service <name> run --proof …");
	const bound = to.credential.kind === "workload" ? await keyBound(to.origin, to.credential.service, await proofOf(flags.proof, process.env), positionals, (line) => process.stderr.write(`${line}\n`), fetching(to.origin)).catch((error) => fail(error instanceof Error ? error.message : String(error))) : null;
	const paths = bound?.places ?? environmentPaths(positionals);
	const placed = bound === null ? await placeholders(paths) : null;
	if (placed !== null) sayPlaceholders(placed, paths, to);
	const values = bound?.env ?? placed?.env ?? Object.fromEntries(await readOrEnd(paths));
	for (const tunnel of placed?.tunnels ?? []) {
		const { url } = await listen(tunnel, placed.handle).catch((error) => fail(error.message));
		Object.defineProperty(values, tunnel.key, {
			value: url,
			enumerable: true,
			writable: true,
			configurable: true
		});
	}
	const kept = flags["keep-existing"] ? Object.keys(values).filter((key) => Object.hasOwn(process.env, key)) : [];
	for (const key of kept) delete values[key];
	if (kept.length > 0) process.stderr.write(`coffre: kept the value already set in your environment for ${kept.sort().join(", ")}, not coffre's\n`);
	const child = spawn(command[0], command.slice(1), {
		env: {
			...process.env,
			...values
		},
		stdio: "inherit"
	});
	const passOn = (signal) => () => void child.kill(signal);
	const handlers = {
		SIGINT: () => void 0,
		SIGTERM: passOn("SIGTERM"),
		SIGHUP: passOn("SIGHUP")
	};
	for (const [signal, handler] of Object.entries(handlers)) process.on(signal, handler);
	/** Its handle revoked, or its key-bound session logged out, a few seconds at most, and then `then`: offline, either ends by itself, at its expiry. */
	const ended = (then) => {
		for (const [name, handler] of Object.entries(handlers)) process.off(name, handler);
		const ending = placed?.revoke() ?? bound?.close();
		(ending === void 0 ? Promise.resolve() : Promise.race([ending.catch(() => void 0), new Promise((resolve) => setTimeout(resolve, 3e3).unref())])).then(then);
	};
	child.on("error", (error) => ended(() => fail(`failed to run ${command[0]}: ${error.message}`)));
	child.on("exit", (code, signal) => ended(() => {
		if (signal) process.kill(process.pid, signal);
		process.exit(code ?? 0);
	}));
}
/**
* Print every secret of the environments named, for tools that want a file
* or a shell rather than a child process. Each value read is one audit row
* in your name, exactly as with `run`.
*/
async function exportEnv(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			format: {
				type: "string",
				default: "dotenv"
			},
			"output-file": { type: "string" },
			watch: {
				type: "boolean",
				default: false
			},
			interval: { type: "string" },
			"on-change": { type: "string" },
			keys: {
				type: "string",
				multiple: true
			}
		},
		allowPositionals: true
	});
	const usage = "usage: coffre export <project>/<environment> [<project>/<environment> ...] [--keys <KEY | PREFIX_*>...] [--format dotenv|json|shell|github] [--output-file <file> [--watch [--interval 60s] [--on-change <command>]]]";
	const format = values.format;
	if (format !== "dotenv" && format !== "json" && format !== "shell" && format !== "github") fail(usage);
	const paths = environmentPaths(positionals);
	const patterns = values.keys === void 0 ? null : keyPatterns(values.keys.join(" "));
	const file = values["output-file"];
	const githubEnv = process.env.GITHUB_ENV;
	if (format === "github" && !githubEnv) fail("--format github requires GITHUB_ENV (run it in a GitHub Actions step)");
	if (format === "github" && file !== void 0) fail("--format github appends to GITHUB_ENV, and writes no other file");
	if (format === "github" && patterns === null) fail(`--format github exports to every later step of the job only the keys the workflow names: --keys "DATABASE_URL STRIPE_*". To hand every key to one process, \`coffre run ${paths.join(" ")} -- <command>\``);
	const hijacks = (keys) => {
		const key = format === "github" ? keys.find(runsCode) : void 0;
		if (key !== void 0) fail(`${key} cannot be set through GITHUB_ENV: a later step's shell, loader or runtime would take code to run from it. Nothing was read`);
	};
	hijacks(patterns?.filter((pattern) => !pattern.endsWith("*")) ?? []);
	if (values.watch && file === void 0) fail("--watch keeps a file current: name it, --output-file <file>");
	if (values.watch && patterns !== null) fail("--watch keeps every key of its environments current: leave --keys out");
	if (!values.watch && (values.interval !== void 0 || values["on-change"] !== void 0)) fail("--interval and --on-change are for --watch");
	const text = (entries) => format === "json" ? `${JSON.stringify(Object.fromEntries(entries), null, 2)}\n` : format === "shell" ? formatShellExports(entries) : formatDotenv(entries);
	const byKey = (entries) => entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
	if (values.watch) {
		const intervalMs = attempt(() => interval(values.interval ?? "60s"));
		const to = target();
		if (to.by === "run" || to.credential.kind === "workload") fail("--watch outlives a CI run's credential, which lasts five minutes: watch with a session or a bearer token");
		if (await proxied(to)) fail("--watch keeps a file of values current, and a person's gets placeholders, which change only with the deployment: export again then");
		const api = enduringClient(to);
		process.stderr.write(`coffre: keeping ${file} current with ${listOf(paths)}; each read is in the audit log under your name, and asking whether to read is not\n`);
		let said = "";
		await watch({
			version: async () => (await Promise.all(paths.map((path) => api.environments.version(path)))).map((answer) => answer.version).join(" "),
			read: async () => {
				const { entries, version, sensitive } = await readEnvironments(paths, {
					read: api,
					list: api
				});
				if (sensitive.join(" ") !== said) sayLeftOut(sensitive);
				said = sensitive.join(" ");
				return {
					text: text(byKey(entries)),
					version
				};
			},
			file,
			intervalMs,
			onChange: values["on-change"] ?? null,
			say: (line) => process.stderr.write(`coffre: ${line}\n`)
		}).catch((error) => fail(error instanceof Error ? error.message : String(error)));
	}
	if (patterns !== null && format !== "github" && await proxied(target())) fail("--keys picks values, and a person's export here gets placeholders, which the credential proxy plans for whole environments: leave --keys out");
	const only = patterns === null ? null : await listKeys(paths, reader([403, 404]), patterns).catch((error) => fail(error instanceof Error ? error.message : String(error)));
	hijacks(only === null ? [] : [...only.values()].flat());
	const placed = format === "github" ? null : await placeholders(paths);
	if (placed !== null) sayPlaceholders(placed, paths, target());
	if (placed !== null && placed.tunnels.length > 0) process.stderr.write(`coffre: left out of the export: ${placed.tunnels.map((tunnel) => tunnel.key).join(", ")}, whose tunnel lives only as long as \`coffre run\`\n`);
	const entries = byKey(placed === null ? await readOrEnd(paths, only) : Object.entries(placed.env));
	if (format === "github") {
		process.stdout.write(githubMasks([...await workloadSecrets(), ...entries]));
		attempt(() => appendFileSync(githubEnv, githubEnvironment(entries), {
			encoding: "utf8",
			mode: 384
		}));
	} else if (file !== void 0) attempt(() => replaceFile(file, text(entries)));
	else process.stdout.write(attempt(() => text(entries)));
	if (process.stderr.isTTY && placed === null) {
		const count = entries.length;
		process.stderr.write(`coffre: read ${count} secret${count === 1 ? "" : "s"} from ${listOf(paths)}${file === void 0 ? "" : ` into ${file}`}; each read is in the audit log under your name\n`);
	}
}
async function history(args) {
	const { values, positionals } = parse(args, { json: {
		type: "boolean",
		default: false
	} }, ["<project>/<environment>/<KEY>"]);
	const { project, environment, key } = parsePath(positionals[0]);
	if (!key) throw new UsageError("name a secret: <project>/<environment>/<KEY>");
	const result = await client().secrets.history(`${project}/${environment}/${key}`);
	if (values.json) {
		process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		return;
	}
	for (const version of result.versions) process.stdout.write(`v${String(version.version).padEnd(4)} ${version.createdAt.slice(0, 19).replace("T", " ")}  ${version.createdBy.padEnd(24)}${version.current ? " (current)" : ""}${version.recipe == null ? "" : `  (generated, ${version.recipe})`}\n`);
}
async function rollback(args) {
	const [target, version] = parse(args, {}, ["<project>/<environment>/<KEY>", "<version>"]).positionals;
	const { project, environment, key } = parsePath(target);
	if (!key) fail("usage: coffre rollback <project>/<environment>/<KEY> <version>");
	const wanted = Number(version);
	if (!Number.isInteger(wanted) || wanted < 1) fail(`"${version}" is not a version number`);
	await client().secrets.restore(`${project}/${environment}/${key}`, wanted);
	process.stdout.write(`${key} rolled back to version ${version}\n`);
}
/**
* Import a .env file. Previews by default; --apply writes.
*
* The preview is a dry run of the write: the server compares against the
* current values, logs each one it opens as a read, and sends none back.
* --apply then writes the keys that differ in one transaction, a new version
* each.
*/
async function importEnv(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			file: { type: "string" },
			apply: {
				type: "boolean",
				default: false
			}
		},
		allowPositionals: true
	});
	const target = positionals[0];
	if (!target) fail("usage: coffre import <project>/<environment> [--file .env] [--apply]");
	const { project, environment } = parsePath(target);
	const parsed = parseDotenv(values.file ? readFileSync(values.file, "utf8") : readFileSync(0, "utf8"));
	for (const problem of parsed.problems) process.stderr.write(`  line ${problem.line}: ${problem.reason}${problem.key === void 0 ? "" : ` (${problem.key})`}\n`);
	if (parsed.entries.length === 0) return;
	const coffre = client();
	const path = `${project}/${environment}`;
	const { plan, changes } = await planImport(coffre, path, parsed.entries);
	if (values.apply && Object.keys(changes).length > 0) await coffre.secrets.set(path, changes);
	for (const entry of plan) process.stdout.write(`${entry.action.padEnd(10)} ${entry.key}\n`);
	if (!values.apply) {
		const pending = Object.keys(changes).length;
		process.stdout.write(`\n${pending} change${pending === 1 ? "" : "s"} pending. Re-run with --apply to write.\n`);
	}
}
async function whoHasAccess(args) {
	const { values, positionals } = parse(args, {
		json: {
			type: "boolean",
			default: false
		},
		service: {
			type: "boolean",
			default: false
		}
	}, ["<project>[/<environment>] | <member>"], 1);
	const asked = positionals[0];
	if (asked !== void 0 && (values.service || /[@:]/.test(asked))) return memberAccess(memberOf(asked, values.service), values.json);
	const result = await client().members.list(positionals[0]);
	if (values.json) {
		process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
		return;
	}
	for (const member of result.members) {
		const role = member.instanceRole === "member" ? "" : `  ${roleInWords(member)}`;
		const tampered = member.tampered ? "  [record failed its integrity check: remove to start over]" : "";
		process.stdout.write(`${named(member.principalType, member.principalId)}${role}${tampered}\n`);
		for (const g of member.grants) {
			const place = g.environment === null ? g.project : `${g.project}/${g.environment}`;
			const until = g.expiresAt === null ? "" : ` until ${g.expiresAt.slice(0, 10)}`;
			process.stdout.write(`  ${place.padEnd(24)} ${g.role}${until}\n`);
		}
	}
	if (positionals[0] === void 0) return;
	const into = (await client().references.list(positionals[0])).references.filter((reference) => reference.source.startsWith(`${positionals[0]}/`) && reference.readers !== null);
	if (into.length === 0) return;
	process.stdout.write(`\nAlso readable through references\n`);
	for (const reference of into) {
		process.stdout.write(`  ${reference.source} through ${reference.holder}, made by ${shownMember$1(reference.createdBy).replace(/^user:/, "")}\n`);
		for (const reader of reference.readers) process.stdout.write(`    ${shownMember$1(reader).replace(/^user:/, "")}\n`);
	}
}
/** `coffre access ada@acme.example`: their instance role and the grants you manage, in one read. */
async function memberAccess(member, json) {
	const access = await client().members.access(member);
	if (json) return void process.stdout.write(`${JSON.stringify(access, null, 2)}\n`);
	const tampered = access.status === "tampered" ? "  [record failed its integrity check: remove to start over]" : access.status === "removed" ? "  [removed]" : "";
	process.stdout.write(`${named(access.principalType, access.principalId)}  ${roleInWords(access)}${tampered}\n`);
	for (const g of access.grants) {
		const place = g.environment === null ? g.project : `${g.project}/${g.environment}`;
		process.stdout.write(`  ${place.padEnd(24)} ${g.role}${g.expiresAt === null ? "" : ` until ${g.expiresAt.slice(0, 10)}`}\n`);
	}
}
async function grantAccess(args) {
	const { values, positionals } = parse(args, {
		role: { type: "string" },
		env: { type: "string" },
		service: {
			type: "boolean",
			default: false
		},
		expires: { type: "string" }
	}, ["<project>", "<principal>"]);
	const [project, principalId] = positionals;
	if (!values.role) throw new UsageError("name the role: --role <role>");
	onAProject(project);
	const role = values.role;
	if (!ROLE_ID.test(role)) fail(`no role "${role}": \`coffre roles\` lists them`);
	const scope = values.env ? `${project}/${values.env}` : project;
	const who = memberOf(principalId, values.service);
	const admit = `coffre admit ${shownMember$1(who).replace(/^user:/, "")}`;
	const hint = (status, reason) => status === 409 && reason === "principal_not_registered" ? `admit them first, \`${admit}\`` : null;
	await client(target(), hint).access.set(who, { [scope]: values.expires ? {
		role,
		until: values.expires
	} : role });
	process.stdout.write(`granted ${values.role} on ${scope} to ${shownMember$1(who).replace(/^user:/, "")}\n`);
}
function plural(count, word) {
	return `${count} ${word}${count === 1 ? "" : "s"}`;
}
/** "2 grants, 1 session, 0 linked accounts, 1 connected app": what a removal ends. */
function waysIn(principalType, counts) {
	return principalType === "user" ? [
		plural(counts.grants, "grant"),
		plural(counts.sessions, "session"),
		...counts.tokens > 0 ? [plural(counts.tokens, "personal token")] : [],
		plural(counts.identities, "linked account"),
		plural(counts.apps, "connected app")
	].join(", ") : [plural(counts.grants, "grant"), plural(counts.tokens, "token")].join(", ");
}
/**
* Offboard someone. Previews by default, like import: what removing them
* would revoke, and what they leave behind. --apply removes them.
*
* Removal takes every way in away at once. What it cannot take back is what
* they saw, so the report after it is the list of values to rotate.
*/
async function trust(args) {
	const { values, positionals } = parseArgs({
		args,
		options: TRUST_OPTIONS,
		allowPositionals: true
	});
	const [service] = positionals;
	if (positionals.length === 0 && Object.values(values).every((value) => value === void 0 || value === false)) {
		process.stdout.write(`${TRUST_USAGE}\n`);
		return;
	}
	if (!service) throw new UsageError("name the service: coffre trust <service> …");
	if (positionals.length > 1) throw new UsageError(`too many arguments: ${positionals.slice(1).join(" ")}`);
	const member = serviceMember(service);
	const coffre = client();
	const { scope: scopeFlags, label, replace, apply, "jwks-file": jwksFile, "replace-keys": replaceKeys, ...flags } = values;
	if (Object.keys(flags).length === 0 && jwksFile === void 0 && replaceKeys === void 0) {
		process.stdout.write(describeBindings(member, (await coffre.bindings.list(member)).bindings));
		return;
	}
	const jwks = (() => {
		if (jwksFile === void 0) return void 0;
		try {
			return keySetFrom(readFileSync(jwksFile, "utf8"), jwksFile);
		} catch (error) {
			return fail(error.code === void 0 ? error.message : `could not read ${jwksFile}: ${error.message}`);
		}
	})();
	if (replaceKeys === true) {
		const { issuer, ...others } = flags;
		if (issuer === void 0 || jwks === void 0) throw new UsageError("--replace-keys takes --issuer <iss> and --jwks-file <path>: whose bindings get which keys");
		const extra = [
			...Object.keys(others),
			...scopeFlags === void 0 ? [] : ["scope"],
			...label === void 0 ? [] : ["label"],
			...replace === void 0 ? [] : ["replace"]
		];
		if (extra.length > 0) throw new UsageError(`--replace-keys changes only the keys of the bindings on --issuer, not --${extra.join(", --")}`);
		const plan = await coffre.bindings.previewKeys(member, {
			issuer,
			jwks
		});
		if (!apply) {
			process.stdout.write(`${describeKeys(member, plan, null)}Run it again with --apply to save it.\n`);
			return;
		}
		const saved = await coffre.bindings.replaceKeys(member, {
			issuer,
			jwks
		});
		process.stdout.write(describeKeys(member, plan, saved));
		return;
	}
	const lookup = client(target(), void 0, [400, 404]);
	const binding = await bindingFrom(flags, (input) => lookup.bindings.lookup(input), { service: member }).catch((error) => fail(error instanceof Error ? error.message : String(error)));
	const scope = (() => {
		try {
			return scopeFrom(scopeFlags);
		} catch (error) {
			throw new UsageError(error.message);
		}
	})();
	const input = {
		...binding,
		...scope === void 0 ? {} : { scope },
		...jwks === void 0 ? {} : { jwks },
		label: label ?? null,
		replaces: replace ?? []
	};
	const plan = await coffre.bindings.preview(member, input);
	const events = describeEvents(plan);
	if (!apply) {
		process.stdout.write(describePlan(member, plan, null));
		if (events !== null) process.stdout.write(`${events}\n`);
		process.stdout.write("Run it again with --apply to save it.\n");
		return;
	}
	const saved = await coffre.bindings.create(member, input);
	process.stdout.write(describePlan(member, plan, saved.binding));
	if (events !== null) process.stdout.write(`${events}\n`);
}
/** `coffre offboard` of a service account by its manager: what it holds, and with --apply, removed. */
async function offboardManaged(coffre, member, apply) {
	const access = await coffre.members.access(member);
	const shown = shownMember$1(member);
	if (!access.managed) fail(`you do not manage ${shown}: it holds something you do not, or the instance keeps it to admins`);
	if (!apply) {
		process.stdout.write(`${shown} is active; removing it would revoke ${access.grants.length} grant${access.grants.length === 1 ? "" : "s"}, and every token and trust binding\nNothing changed. Re-run with --apply to remove it.\n`);
		return;
	}
	const removed = await coffre.members.remove(member);
	process.stdout.write(`removed ${shown}: revoked ${waysIn("service", removed.revoked)}\n`);
}
async function offboard(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			service: {
				type: "boolean",
				default: false
			},
			apply: {
				type: "boolean",
				default: false
			}
		},
		allowPositionals: true
	});
	const principalId = positionals[0];
	if (!principalId) fail("usage: coffre offboard <principal> [--service] [--apply]");
	const member = memberOf(principalId, values.service);
	const shown = shownMember$1(member).replace(/^user:/, "");
	const coffre = client();
	const found = await coffre.members.get(member).catch((error) => {
		if (error instanceof CoffreError && error.status === 403 && member.startsWith("token:")) return null;
		throw error;
	});
	if (found === null) return offboardManaged(coffre, member, values.apply);
	let report = found;
	const they = report.principalType === "user" ? "they" : "it";
	if (report.status === "active" && values.apply) {
		const removed = await coffre.members.remove(member);
		process.stdout.write(`removed ${shown}: revoked ${waysIn(report.principalType, removed.revoked)}\n`);
		report = removed.report ?? report;
	} else if (report.status === "active") process.stdout.write(`${shown} is active; removing would revoke ${waysIn(report.principalType, report.live)}\n`);
	else {
		const by = report.removedBy === null ? "" : ` by ${report.removedBy}`;
		const at = report.removedAt === null ? "" : ` on ${report.removedAt.slice(0, 16).replace("T", " ")}`;
		process.stdout.write(`${shown} was removed${by}${at}\n`);
	}
	const rotated = report.rotated > 0 ? `, ${report.rotated} already rotated` : "";
	const when = report.status === "active" ? ` once ${they} ${they === "they" ? "leave" : "is retired"}` : "";
	process.stdout.write(`\nValues ${they} saw that nobody has changed since, to rotate${when} (${report.exposed.length}${rotated})\n`);
	if (report.exposed.length === 0) process.stdout.write("  none\n");
	const names = report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`);
	const width = Math.max(0, ...names.map((name) => name.length));
	report.exposed.forEach((entry, index) => {
		process.stdout.write(`  ${names[index].padEnd(width)}  v${String(entry.version).padEnd(4)} ${entry.how} ${entry.at.slice(0, 10)}\n`);
	});
	if (report.apps.length > 0) {
		process.stdout.write(`\nConnected apps, which removing them disconnects (${report.apps.length})\n`);
		const width = Math.max(...report.apps.map((app) => app.name.length));
		for (const app of report.apps) {
			const used = app.lastUsedAt === null ? "never used" : `last used ${app.lastUsedAt.slice(0, 10)}`;
			process.stdout.write(`  ${app.name.padEnd(width)}  ${app.host ?? "no website"}, may ${app.scopes.join(", ")}, ${used}\n`);
		}
	}
	const personalTokens = report.personalTokens ?? [];
	if (personalTokens.length > 0) {
		process.stdout.write(`\nPersonal tokens, which act as them and removing them revokes (${personalTokens.length})\n`);
		for (const token of personalTokens) {
			const used = token.lastUsedAt === null ? "never used" : `last used ${token.lastUsedAt.slice(0, 10)}`;
			process.stdout.write(`  "${token.label ?? ""}" ${token.hint}, reaching ${reaches(token.scope)}, ${used}, expires ${token.expiresAt.slice(0, 16).replace("T", " ")} UTC\n`);
		}
	}
	if (report.issuedTokens.length > 0) {
		process.stdout.write(`\nBearer tokens ${they} issued to service accounts, which still work\n`);
		for (const token of report.issuedTokens) {
			const label = token.label === null ? "" : ` "${token.label}"`;
			process.stdout.write(`  service:${serviceName(token.service)}${label} ${token.hint}, reaching ${reaches(token.scope)}, expires ${token.expiresAt.slice(0, 10)}\n`);
		}
	}
	if (report.references.length > 0) {
		process.stdout.write(`\nReferences ${they} made: each belongs to the environment that holds it, so removing ${they === "they" ? "them" : "it"} ends none. Review them; \`coffre references break\` ends one\n`);
		for (const reference of report.references) {
			const state = reference.state === "live" ? "" : `  (${reference.state.replace("_", " ")})`;
			process.stdout.write(`  ${reference.holder} → ${reference.source}, ${reference.createdAt.slice(0, 10)}${state}\n`);
		}
	}
	if (report.status === "active" && !values.apply) process.stdout.write(`\nNothing changed. Re-run with --apply to remove ${shown}.\n`);
}
async function audit(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			limit: {
				type: "string",
				default: "20"
			},
			actor: { type: "string" },
			denied: {
				type: "boolean",
				default: false
			},
			detail: {
				type: "boolean",
				default: false
			},
			json: {
				type: "boolean",
				default: false
			}
		},
		allowPositionals: true
	});
	const limit = Number(values.limit);
	if (!Number.isInteger(limit) || limit < 1) fail(`--limit takes a positive number, not "${values.limit}"`);
	if (positionals.length > 1) fail("usage: coffre audit [<project>[/<environment>[/<KEY>]]] [--limit N] [--actor <id>] [--denied] [--detail] [--json]");
	const result = await client().audit.list({
		path: positionals[0],
		limit,
		actor: values.actor === void 0 ? void 0 : apiMember(values.actor),
		decision: values.denied ? "deny" : void 0,
		detail: values.detail ? "1" : void 0,
		sealed: "1"
	});
	if (values.json) {
		process.stdout.write(`${JSON.stringify(result.entries, null, 2)}\n`);
		return;
	}
	for (const entry of result.entries.reverse()) {
		const read = entry.secrets == null ? "" : ` (${entry.secrets.length} secrets)`;
		const place = ([
			entry.project,
			entry.environment,
			entry.key
		].filter((part) => part !== null).join("/") || "-") + read;
		const run = entry.run == null ? "" : ` (${runLabel(entry.run)})`;
		const actor = `${entry.actorType === "service" ? `service:${entry.actorId}` : entry.actorId}${entry.token == null ? "" : ` via "${entry.token.label}"`}${run}`;
		process.stdout.write(`${entry.occurredAt}  ${entry.decision.padEnd(5)}  ${actor.padEnd(28)}  ${entry.action.padEnd(16)}  ${place}\n`);
	}
}
/**
* An Owner's acceptance that audit entries `<from>` to `<to>` are lost for
* good: the audit watch's anchor goes on past them, and its finding, with
* the acceptance, stays in the log.
*/
async function acceptLoss(args) {
	const [from, to, ...rest] = args;
	const entry = (value) => value !== void 0 && /^[0-9]{1,15}$/.test(value) ? Number(value) : null;
	if (entry(from) === null || entry(to) === null || rest.length > 0) fail("usage: coffre audit accept-loss <from> <to>");
	const { resumes } = await client().audit.acceptLoss({
		from: entry(from),
		to: entry(to)
	});
	process.stdout.write(`entries ${from} to ${to} accepted as lost: the audit watch goes on from entry ${resumes ?? 0}\n`);
}
/** One check of the instance, named, or chosen on the terminal (`verify/index.ts`). */
async function verify(args) {
	const [named, ...more] = args;
	if (named === "--help" || named === "-h") {
		process.stdout.write(`${VERIFY_USAGE}\n`);
		return;
	}
	const check = named ?? await pickCheck();
	switch (check) {
		case "instance": return verifyInstance(more, readStore(), sessionFlags, localHere());
		case "keys": {
			const to = target();
			return verifyKeys(more, client(to), to.origin);
		}
		case "log":
			if (more.length > 0) fail("usage: coffre verify log");
			return verifyLog();
		case "backup": return (await import("./restore.ts")).verifyBackup(more);
		default:
			process.stderr.write(`coffre: no check named ${check}\n${VERIFY_USAGE}\n`);
			process.exit(2);
	}
}
/**
* The whole audit log, verified by the app and the vault from its first
* entry, a stretch a request, for whoever reads it whole: what the audit
* page's check, which goes on from the newest checkpoint, takes on trust.
*/
async function verifyLog() {
	const shown = process.stderr.isTTY;
	const result = await client().audit.verifyWhole((stretch) => {
		if (shown && stretch.ok && typeof stretch.next === "string") process.stderr.write(`\rverified through entry ${stretch.through}…`);
	});
	if (shown) process.stderr.write("\r\x1B[K");
	if (result.ok) {
		const through = result.through === null ? "empty" : `verified from the first entry through entry ${result.through}`;
		const signed = result.checkpoint === null ? "no checkpoint signed yet" : `last checkpoint: entry ${result.checkpoint.seq}, signed ${result.checkpoint.signedAt}`;
		const pending = result.pending === void 0 ? "" : `${result.pending} key operations still under way\n`;
		if (result.remaining > 0) {
			process.stderr.write(`audit log not verified to its end: ${through}, and ${result.remaining} newer entries wait for the checkpoints to catch up, a walk every five minutes; run this again after the next beats
`);
			process.exit(3);
		}
		process.stdout.write(`audit log OK: ${through}, ${result.entries} entries; members and grants replayed\n${signed}\n${pending}`);
		return;
	}
	const at = result.failedAtSeq === null ? "" : ` at entry ${result.failedAtSeq}`;
	const through = result.through === null ? "nothing verified" : `verified through entry ${result.through}`;
	process.stderr.write(`audit log BROKEN${at}, found by the ${result.author}'s check (${through}): ${result.reason}\n`);
	process.exit(2);
}
/** `coffre init --workers|--node [<dir>]`: a new deployment of coffre. */
function initProject(args) {
	const { values, positionals } = parseArgs({
		args,
		options: {
			workers: { type: "boolean" },
			node: { type: "boolean" }
		},
		allowPositionals: true
	});
	const kinds = KINDS$1.filter((kind) => values[kind]);
	if (kinds.length !== 1 || positionals.length > 1) fail("usage: coffre init --workers|--node [<dir>]");
	const kind = kinds[0];
	const dir = resolve(positionals[0] ?? ".");
	const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
	const files = attempt(() => init(kind, dir, version));
	for (const file of files) process.stdout.write(`  ${file}\n`);
	const at = dir === process.cwd() ? null : positionals[0] ?? null;
	process.stdout.write(`\nA ${kind === "workers" ? "Cloudflare Workers" : "Node"} deployment of coffre ${version}${at === null ? " here" : ` in ${at}`}. Next:\n\n${at === null ? "" : `  cd ${/\s/.test(at) ? `'${at}'` : at}\n`}  pnpm install\n\nThen README.md takes it from there.
`);
}
const line = attempt(() => commandLine(process.argv.slice(2)));
const { command, rest } = line;
/** What the session flags say, their files read before any command runs: a file that is not there stops it first. */
const sessionFlags = attempt(() => readSession(line.session));
/** The API of the instance the session names, asked for once a command has read its arguments. */
const connect = () => client();
/** Each command, by the words that name it: those `coffre help` lists, each one (`commands.ts`). */
const COMMANDS = {
	init: initProject,
	keys,
	setup: async (args) => (await import("./setup.ts")).setup(args),
	update: async (args) => (await import("./update.ts")).update(args),
	migrate: async (args) => (await import("./migrate.ts")).migrate(args),
	backup: async (args) => (await import("./backup.ts")).backup(args),
	restore: async (args) => (await import("./restore.ts")).restore(args),
	login,
	logout,
	whoami,
	use,
	sessions: (args) => sessions(connect, args),
	"sessions revoke": (args) => sessionsRevoke(connect, args),
	apps: (args) => apps(connect, args),
	"apps revoke": (args) => appsRevoke(connect, args),
	identities: (args) => identities(connect, args),
	"identities unlink": (args) => identitiesUnlink(connect, args),
	list,
	get,
	set,
	mark,
	regenerate,
	run,
	export: exportEnv,
	version: (args) => version(connect, args),
	history,
	rollback,
	import: importEnv,
	rename: (args) => renameSecret(connect, args),
	archive: (args) => archiveSecret(connect, args, true),
	unarchive: (args) => archiveSecret(connect, args, false),
	reset: (args) => resetSecret(connect, args),
	remove: (args) => removeSecret(connect, args),
	move: (args) => move(connect, args),
	folders: (args) => folders(connect, args),
	"folders rename": (args) => foldersRename(connect, args),
	"folders remove": (args) => foldersRemove(connect, args),
	missing: (args) => missing(() => client(target(), void 0, [], reading), args),
	"missing dismiss": (args) => missingDismiss(connect, args, true),
	"missing restore": (args) => missingDismiss(connect, args, false),
	projects: (args) => projects(connect, args),
	"projects create": (args) => projectsCreate(connect, args),
	"projects rename": (args) => projectsRename(connect, args),
	"projects archive": (args) => projectsArchive(connect, args, true),
	"projects unarchive": (args) => projectsArchive(connect, args, false),
	"projects delete": (args) => placeDelete(connect, args, false),
	"environments create": (args) => environmentsCreate(connect, args),
	references: (args) => references(connect, args),
	"references break": (args) => referencesBreak(connect, args),
	fork: (args) => fork(connect, args),
	personal: (args) => personal(connect, args),
	"environments rename": (args) => environmentsRename(connect, args),
	"environments archive": (args) => environmentsArchive(connect, args, true),
	"environments unarchive": (args) => environmentsArchive(connect, args, false),
	"environments delete": (args) => placeDelete(connect, args, true),
	"environments protect": (args) => environmentsProtect(connect, args, true),
	"environments unprotect": (args) => environmentsProtect(connect, args, false),
	roles: (args) => roles(connect, args),
	"roles set": (args) => rolesSet(connect, args),
	"roles reset": (args) => rolesReset(connect, args),
	"roles remove": (args) => rolesRemove(connect, args),
	access: whoHasAccess,
	admit: (args) => admit(connect, args),
	grant: grantAccess,
	revoke: (args) => revoke(connect, args),
	offboard,
	settings: (args) => settings(connect, args),
	tokens: (args) => tokens(connect, args),
	"tokens issue": (args) => tokensIssue(connect, args),
	"tokens revoke": (args) => tokensRevoke(connect, args),
	trust,
	untrust: (args) => untrust(connect, args),
	enroll,
	approve,
	freeze,
	unfreeze,
	serve: (args) => serve(args, sessionFlags.url, fetching),
	audit,
	"audit accept-loss": acceptLoss,
	verify,
	"verify instance": (args) => verify(["instance", ...args]),
	"verify keys": (args) => verify(["keys", ...args]),
	"verify log": (args) => verify(["log", ...args]),
	"verify backup": (args) => verify(["backup", ...args])
};
/** The commands whose --help says more than their line in `coffre help`. */
const HELP = {
	trust: TRUST_USAGE,
	verify: VERIFY_USAGE,
	"verify instance": INSTANCE_USAGE,
	"verify keys": KEYS_USAGE,
	"verify backup": VERIFY_BACKUP_USAGE,
	backup: BACKUP_USAGE,
	restore: RESTORE_USAGE
};
/** A command's help, or a group's. */
function helpText(words) {
	const own = HELP[words];
	return own === void 0 ? help(words) : `${own}\n`;
}
/** A parse error's first sentence, without Node's advice: `unknown option '--bogus'`. */
function parseError(error) {
	const code = error?.code;
	if (error instanceof UsageError) return error.message;
	if (typeof code !== "string" || !code.startsWith("ERR_PARSE_ARGS")) return null;
	const message = error.message.split(/\.(\s|$)/)[0];
	return message.charAt(0).toLowerCase() + message.slice(1);
}
if (command === "--version" || command === "-v") {
	process.stdout.write(`${cliVersion()}\n`);
	process.exit(0);
}
if (command === void 0 || command === "--help" || command === "-h" || command === "help") {
	const about = command === "help" && rest.length > 0 ? lookup(rest) : null;
	if (command === "help" && rest.length > 0 && about === null) {
		process.stderr.write(`coffre: no command ${rest.join(" ")}\n${usage()}`);
		process.exit(2);
	}
	process.stdout.write(about === null ? usage() : helpText("group" in about ? about.group : about.command));
	process.exit(0);
}
const found = lookup([command, ...rest]);
if (found === null) {
	process.stderr.write(`coffre: no command ${command}\n\n${usage()}`);
	process.exit(1);
}
const words = "group" in found ? found.group : found.command;
const args = "group" in found ? rest : found.args;
const end = args.indexOf("--");
if ((end === -1 ? args : args.slice(0, end)).some((arg) => arg === "--help" || arg === "-h")) {
	process.stdout.write(helpText(words));
	process.exit(0);
}
if ("group" in found) {
	process.stderr.write(`coffre: ${command} needs a command after it\n${helpText(words)}`);
	process.exit(2);
}
try {
	await COMMANDS[found.command](found.args);
} catch (error) {
	if (error instanceof CheckFailed) {
		process.stderr.write(`coffre: ${error.message}\n`);
		process.exitCode = 1;
	} else {
		const misuse = parseError(error);
		if (misuse === null) fail(error instanceof Error ? error.message : String(error));
		process.stderr.write(`coffre: ${misuse}\n${helpText(words)}`);
		process.exit(2);
	}
}
//#endregion
export {};
