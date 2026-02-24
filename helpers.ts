import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const VALID_PROFILES = ["open", "intro-sec", "engineering"] as const;
export type ProfileName = (typeof VALID_PROFILES)[number];

export interface ProfilePolicy {
	network?: {
		allowedDomains?: string[];
		deniedDomains?: string[];
	};
	filesystem?: {
		denyRead?: string[];
		allowWrite?: string[];
		denyWrite?: string[];
	};
}

export const PROFILES_DIR = join(homedir(), ".pi", "agent", "sandbox-profiles");
export const TELEMETRY_DIR = join(PROFILES_DIR, "telemetry");
export const TELEMETRY_RETENTION_DAYS = 30;

export const DEFAULT_PROTECTED_PATHS: readonly string[] = [
	"~/.bashrc",
	"~/.zshrc",
	"~/.profile",
	"~/.bash_profile",
	"~/.ssh",
	".git/hooks",
];

export function loadProtectedPaths(profilesDir: string = PROFILES_DIR): string[] {
	try {
		const filePath = join(profilesDir, "protected-paths.json");
		if (!existsSync(filePath)) return [...DEFAULT_PROTECTED_PATHS];
		const raw = JSON.parse(readFileSync(filePath, "utf-8"));
		if (Array.isArray(raw?.denyWrite) && raw.denyWrite.every((v: unknown) => typeof v === "string")) {
			if (raw.denyWrite.some((pattern: string) => pattern.includes("*"))) {
				return [...DEFAULT_PROTECTED_PATHS];
			}
			return raw.denyWrite;
		}
		return [...DEFAULT_PROTECTED_PATHS];
	} catch {
		return [...DEFAULT_PROTECTED_PATHS];
	}
}

export function expandTilde(p: string): string {
	if (p.startsWith("~/") || p === "~") return join(homedir(), p.slice(1));
	return p;
}

export function resolvePath(toolPath: string, cwd: string): string {
	const expanded = expandTilde(toolPath);
	const abs = expanded.startsWith("/") ? expanded : join(cwd, expanded);

	let probe = abs;
	while (true) {
		try {
			const realProbe = realpathSync(probe);
			if (probe === abs) return realProbe;
			const suffix = abs.slice(probe.length).replace(/^\/+/u, "");
			return suffix ? join(realProbe, suffix) : realProbe;
		} catch {
			const parent = dirname(probe);
			if (parent === probe) return abs;
			probe = parent;
		}
	}
}

export function matchesAnyPath(absPath: string, patterns: string[], cwd: string): boolean {
	return patterns.some((pattern) => {
		const resolved = resolvePath(pattern, cwd);
		if (absPath === resolved) return true;
		const prefix = resolved.endsWith("/") ? resolved : resolved + "/";
		return absPath.startsWith(prefix);
	});
}

export function extractDomain(command: string): string {
	const urlMatch = command.match(/https?:\/\/([^\/\s:?#]+)/);
	if (urlMatch) return urlMatch[1];
	const hostMatch = command.match(/(?:--host|--connect-to|@)\s*(\S+)/);
	if (hostMatch) return hostMatch[1];
	return "(unknown)";
}

export function redactCommand(command: string): string {
	let preview = command.slice(0, 120);
	preview = preview.replace(
		/((?:token|key|secret|password|authorization|bearer)[=:\s]+)\S+/gi,
		"$1[REDACTED]",
	);
	return preview;
}

export function formatStatusline(name: string, policy: ProfilePolicy | null): { text: string; style: "warning" | "accent" } {
	if (name === "open") {
		return { text: `⚠️ sandbox:open (no sandbox)`, style: "warning" };
	}
	const writePaths = policy?.filesystem?.allowWrite?.length ?? 0;
	return { text: `🔒 sandbox:${name} (allowlist, ${writePaths} write paths)`, style: "accent" };
}

export function loadProfilePolicy(
	name: string,
	profilesDir: string = PROFILES_DIR,
): ProfilePolicy | null {
	if (name === "open") return null;

	if (!VALID_PROFILES.includes(name as ProfileName)) {
		throw new Error(`Unknown profile "${name}". Valid profiles: ${VALID_PROFILES.join(", ")}`);
	}

	const filePath = join(profilesDir, `${name}.json`);
	if (!existsSync(filePath)) {
		throw new Error(`Profile policy file not found: ${filePath}`);
	}

	let raw: unknown;
	try {
		raw = JSON.parse(readFileSync(filePath, "utf-8"));
	} catch (e) {
		throw new Error(`Failed to parse ${filePath}: ${e instanceof Error ? e.message : e}`);
	}

	const policy = raw as ProfilePolicy;

	// Validate shape: all array fields must be string[]
	const validateStringArray = (arr: unknown, label: string) => {
		if (arr === undefined) return;
		if (!Array.isArray(arr) || !arr.every((v) => typeof v === "string")) {
			throw new Error(`${label} must be a string[] in ${filePath}`);
		}
	};

	const validateDomainPatterns = (arr: string[] | undefined, label: string) => {
		if (!arr) return;
		for (const domain of arr) {
			if (domain === "*") {
				throw new Error(`${label} entry "*" is not allowed in ${filePath}; use explicit domains or *.example.com`);
			}
			if (domain.includes("*") && !domain.startsWith("*.")) {
				throw new Error(`${label} entry "${domain}" has invalid wildcard syntax in ${filePath}; only *.example.com style is supported`);
			}
		}
	};

	const validateNoFilesystemWildcards = (arr: string[] | undefined, label: string) => {
		if (!arr) return;
		for (const pattern of arr) {
			if (pattern.includes("*")) {
				throw new Error(`${label} entry "${pattern}" uses wildcard syntax in ${filePath}; glob matching is not supported`);
			}
		}
	};

	if (policy.network !== undefined) {
		if (typeof policy.network !== "object" || policy.network === null) {
			throw new Error(`network must be an object in ${filePath}`);
		}
		validateStringArray(policy.network.allowedDomains, "network.allowedDomains");
		validateStringArray(policy.network.deniedDomains, "network.deniedDomains");
		validateDomainPatterns(policy.network.allowedDomains, "network.allowedDomains");
		validateDomainPatterns(policy.network.deniedDomains, "network.deniedDomains");
	}

	if (policy.filesystem !== undefined) {
		if (typeof policy.filesystem !== "object" || policy.filesystem === null) {
			throw new Error(`filesystem must be an object in ${filePath}`);
		}
		validateStringArray(policy.filesystem.denyRead, "filesystem.denyRead");
		validateStringArray(policy.filesystem.allowWrite, "filesystem.allowWrite");
		validateStringArray(policy.filesystem.denyWrite, "filesystem.denyWrite");
		validateNoFilesystemWildcards(policy.filesystem.denyRead, "filesystem.denyRead");
		validateNoFilesystemWildcards(policy.filesystem.allowWrite, "filesystem.allowWrite");
		validateNoFilesystemWildcards(policy.filesystem.denyWrite, "filesystem.denyWrite");
	}

	// Critical guardrail: if network is undefined, set empty defaults
	// to prevent httpProxyPort crash in sandbox-runtime
	if (policy.network === undefined) {
		policy.network = { allowedDomains: [], deniedDomains: [] };
	}

	return policy;
}

export function logNetworkDeny(
	event: {
		type: "blocked" | "self-restrained";
		profile: string;
		domain: string;
		commandPreview?: string;
	},
	telemetryDir: string = TELEMETRY_DIR,
): void {
	try {
		mkdirSync(telemetryDir, { recursive: true });
		const today = new Date().toISOString().slice(0, 10);
		const filePath = join(telemetryDir, `network-deny-${today}.jsonl`);
		const record = {
			ts: new Date().toISOString(),
			type: event.type,
			profile: event.profile,
			domain: event.domain,
			command_preview: event.commandPreview || undefined,
		};
		appendFileSync(filePath, JSON.stringify(record) + "\n");
	} catch {
		// Telemetry must not break execution
	}
}

export function pruneOldTelemetry(telemetryDir: string = TELEMETRY_DIR): void {
	try {
		if (!existsSync(telemetryDir)) return;
		const cutoff = Date.now() - TELEMETRY_RETENTION_DAYS * 86400_000;
		for (const f of readdirSync(telemetryDir)) {
			const match = f.match(/^network-deny-(\d{4}-\d{2}-\d{2})\.jsonl$/);
			if (match) {
				const fileDate = new Date(match[1]).getTime();
				if (fileDate < cutoff) {
					try { unlinkSync(join(telemetryDir, f)); } catch { /* ignore */ }
				}
			}
		}
	} catch {
		// Telemetry cleanup must not break startup
	}
}
