/**
 * Sandbox Profile extension
 *
 * Enforces sandbox profiles for bash and file tools (`read`, `write`, `edit`).
 * Profile policies are loaded from `~/.pi/agent/sandbox-profiles/`.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { type BashOperations, createBashTool } from "@mariozechner/pi-coding-agent";
import {
	type ProfilePolicy,
	VALID_PROFILES,
	type ProfileName,
	loadProfilePolicy,
	formatStatusline,
	resolvePath,
	matchesAnyPath,
	loadProtectedPaths,
	extractDomain,
	redactCommand,
	logNetworkDeny,
	pruneOldTelemetry,
} from "./helpers.js";

function createSandboxedBashOps(currentProfile: () => string): BashOperations {
	return {
		async exec(command, cwd, { onData, signal, timeout }) {
			if (!existsSync(cwd)) {
				throw new Error(`Working directory does not exist: ${cwd}`);
			}

			const wrappedCommand = await SandboxManager.wrapWithSandbox(command);

			return new Promise((resolve, reject) => {
				const child = spawn("bash", ["-c", wrappedCommand], {
					cwd,
					detached: true,
					stdio: ["ignore", "pipe", "pipe"],
				});

				let timedOut = false;
				let timeoutHandle: NodeJS.Timeout | undefined;

				if (timeout !== undefined && timeout > 0) {
					timeoutHandle = setTimeout(() => {
						timedOut = true;
						if (child.pid) {
							try {
								process.kill(-child.pid, "SIGKILL");
							} catch {
								child.kill("SIGKILL");
							}
						}
					}, timeout * 1000);
				}

				child.stdout?.on("data", onData);
				child.stderr?.on("data", (chunk) => {
					onData(chunk);
					const text = chunk.toString();
					if (text.includes("deny") || text.includes("sandbox") || text.includes("not allowed")) {
						logNetworkDeny({
							type: "blocked",
							profile: currentProfile(),
							domain: extractDomain(command),
							commandPreview: redactCommand(command),
						});
					}
				});

				child.on("error", (err) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					reject(err);
				});

				const onAbort = () => {
					if (child.pid) {
						try {
							process.kill(-child.pid, "SIGKILL");
						} catch {
							child.kill("SIGKILL");
						}
					}
				};

				signal?.addEventListener("abort", onAbort, { once: true });

				child.on("close", (code) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					signal?.removeEventListener("abort", onAbort);

					if (signal?.aborted) {
						reject(new Error("aborted"));
					} else if (timedOut) {
						reject(new Error(`timeout:${timeout}`));
					} else {
						resolve({ exitCode: code });
					}
				});
			});
		},
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	pi.registerFlag("sandbox-profile", {
		description: "Set initial sandbox profile (default: open)",
		type: "string",
		default: "open",
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	let sandboxEnabled = false;
	let sandboxInitialized = false;
	let sandboxRequired = false;
	const failClosed = true;
	let activeProfile: string = "open";
	let protectedPaths: string[] = [];

	pi.registerTool({
		...localBash,
		label: "bash (sandboxed)",
		async execute(id, params, signal, onUpdate) {
			if (failClosed && sandboxRequired && !sandboxInitialized) {
				return {
					content: [{ type: "text", text: "Sandbox is required but not initialized. Refusing unsandboxed bash execution." }],
					isError: true,
					details: { error: "sandbox_not_initialized" },
				};
			}

			if (!sandboxEnabled || !sandboxInitialized) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const sandboxedBash = createBashTool(localCwd, {
				operations: createSandboxedBashOps(() => activeProfile),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", () => {
		if (failClosed && sandboxRequired && !sandboxInitialized) {
			return {
				result: {
					output: "Sandbox is required but not initialized. Refusing unsandboxed user bash execution.",
					exitCode: 1,
					cancelled: false,
					truncated: false,
				},
			};
		}
		if (!sandboxEnabled || !sandboxInitialized) return;
		return { operations: createSandboxedBashOps(() => activeProfile) };
	});

	pi.on("tool_call", async (event, ctx) => {
		if (activeProfile === "open") return undefined;

		let loadedPolicy: ProfilePolicy | null;
		try {
			loadedPolicy = loadProfilePolicy(activeProfile);
		} catch (err) {
			if (event.toolName === "read" || event.toolName === "write" || event.toolName === "edit") {
				const reason = err instanceof Error ? err.message : String(err);
				return { block: true, reason: `Profile "${activeProfile}" policy unavailable: ${reason}` };
			}
			return undefined;
		}
		if (!loadedPolicy) {
			if (event.toolName === "read" || event.toolName === "write" || event.toolName === "edit") {
				return { block: true, reason: `Profile "${activeProfile}" policy unavailable: no policy loaded` };
			}
			return undefined;
		}
		const policy = loadedPolicy;

		const toolPath = (event.input as { path?: string }).path;
		if (!toolPath) return undefined;
		const absPath = resolvePath(toolPath, ctx.cwd);

		// Enforce denyRead on read tool
		if (event.toolName === "read") {
			const denyRead = policy.filesystem?.denyRead ?? [];
			if (denyRead.length > 0 && matchesAnyPath(absPath, denyRead, ctx.cwd)) {
				return { block: true, reason: `Profile "${activeProfile}": read denied for ${toolPath}` };
			}
			return undefined;
		}

		// Enforce allowWrite / denyWrite on write and edit tools
		if (event.toolName === "write" || event.toolName === "edit") {
			// Protected paths — secondary defense, user-editable (ADR 0009)
			if (protectedPaths.length > 0 && matchesAnyPath(absPath, protectedPaths, ctx.cwd)) {
				return { block: true, reason: `Protected path: write blocked for ${toolPath} (see ~/.pi/agent/sandbox-profiles/protected-paths.json)` };
			}

			const allowWrite = policy.filesystem?.allowWrite ?? [];
			const denyWrite = policy.filesystem?.denyWrite ?? [];

			// If allowWrite is empty → block all writes
			if (allowWrite.length === 0) {
				return { block: true, reason: `Profile "${activeProfile}": writes not allowed` };
			}

			// Check denyWrite first (takes precedence)
			if (denyWrite.length > 0 && matchesAnyPath(absPath, denyWrite, ctx.cwd)) {
				return { block: true, reason: `Profile "${activeProfile}": write denied for ${toolPath}` };
			}

			// Check allowWrite
			if (!matchesAnyPath(absPath, allowWrite, ctx.cwd)) {
				return { block: true, reason: `Profile "${activeProfile}": write not in allowed paths for ${toolPath}` };
			}

			return undefined;
		}

		return undefined;
	});

	async function applyProfile(name: string, ctx: Parameters<Parameters<typeof pi.on>[1]>[1]): Promise<{ ok: boolean; reason?: string }> {
		try {
			if (name === "open") {
				if (sandboxInitialized) {
					await SandboxManager.reset();
				}
				sandboxEnabled = false;
				sandboxInitialized = false;
				sandboxRequired = false;
				activeProfile = "open";
				const status = formatStatusline("open", null);
				ctx.ui.setStatus("sandbox", ctx.ui.theme.fg(status.style, status.text));
				return { ok: true };
			}

			const policy = loadProfilePolicy(name);
			if (!policy) {
				throw new Error(`Profile "${name}" has no policy`);
			}

			if (!sandboxInitialized) {
				await SandboxManager.initialize({
					network: policy.network,
					filesystem: policy.filesystem,
				});
			} else {
				await SandboxManager.updateConfig({
					network: policy.network,
					filesystem: policy.filesystem,
				});
			}

			sandboxEnabled = true;
			sandboxInitialized = true;
			sandboxRequired = true;
			activeProfile = name;
			const status = formatStatusline(name, policy);
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg(status.style, status.text));
			return { ok: true };
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			return { ok: false, reason };
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		pruneOldTelemetry();
		protectedPaths = loadProtectedPaths();
		sandboxEnabled = false;
		sandboxInitialized = false;
		sandboxRequired = false;
		activeProfile = "open";

		const noSandbox = pi.getFlag("no-sandbox") as boolean;

		if (noSandbox) {
			ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
			const status = formatStatusline("open", null);
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg(status.style, status.text));
			return;
		}

		const platform = process.platform;
		if (platform !== "darwin" && platform !== "linux") {
			ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
			const status = formatStatusline("open", null);
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg(status.style, status.text));
			return;
		}

		const profileName = (pi.getFlag("sandbox-profile") as string) || "open";

		const result = await applyProfile(profileName, ctx);
		if (result.ok) {
			if (profileName !== "open") {
				ctx.ui.notify(`Sandbox profile "${profileName}" activated`, "info");
			}
		} else {
			ctx.ui.notify(`Sandbox profile "${profileName}" failed: ${result.reason}`, "error");
			if (failClosed) {
				ctx.ui.notify("Fail-closed active: unsandboxed bash execution is blocked.", "warning");
			}
			const status = formatStatusline("open", null);
			ctx.ui.setStatus("sandbox", ctx.ui.theme.fg(status.style, status.text));
		}
	});

	pi.on("session_shutdown", async () => {
		if (sandboxInitialized) {
			try {
				await SandboxManager.reset();
			} catch {
				// Ignore cleanup errors
			}
		}
	});

	pi.registerCommand("sandbox", {
		description: "Show sandbox configuration",
		handler: async (_args, ctx) => {
			const lines = [
				"Sandbox Configuration:",
				`  Active: ${sandboxEnabled && sandboxInitialized ? "yes" : "no"}`,
				`  Active profile: ${activeProfile}`,
				`  Required: ${sandboxRequired ? "yes" : "no"}`,
				`  Fail closed: ${failClosed ? "yes" : "no"}`,
				"",
				"Protected paths (secondary defense):",
				`  ${protectedPaths.join(", ") || "(none)"}`,
			];

			if (activeProfile === "open") {
				lines.push("", "Profile policy:", "  (none; open disables sandbox)");
				ctx.ui.notify(lines.join("\n"), "info");
				return;
			}

			try {
				const policy = loadProfilePolicy(activeProfile);
				lines.push(
					"",
					"Network:",
					`  Allowed: ${policy?.network?.allowedDomains?.join(", ") || "(none)"}`,
					`  Denied: ${policy?.network?.deniedDomains?.join(", ") || "(none)"}`,
					"",
					"Filesystem:",
					`  Deny Read: ${policy?.filesystem?.denyRead?.join(", ") || "(none)"}`,
					`  Allow Write: ${policy?.filesystem?.allowWrite?.join(", ") || "(none)"}`,
					`  Deny Write: ${policy?.filesystem?.denyWrite?.join(", ") || "(none)"}`,
				);
			} catch (err) {
				const reason = err instanceof Error ? err.message : String(err);
				lines.push("", "Profile policy:", `  ERROR: ${reason}`);
			}

			ctx.ui.notify(lines.join("\n"), "info");
		},
	});

	pi.registerCommand("sandbox-profile", {
		description: "Show or switch sandbox profile",
		handler: async (args, ctx) => {
			const name = args.trim();

			// No argument: show current profile info
			if (!name) {
				let policyInfo = "";
				if (activeProfile !== "open") {
					try {
						const policy = loadProfilePolicy(activeProfile);
						const status = formatStatusline(activeProfile, policy);
						policyInfo = `\n  Status: ${status.text}`;
					} catch {
						policyInfo = "\n  Status: (policy file unavailable)";
					}
				}
				ctx.ui.notify(`Current sandbox profile: ${activeProfile}${policyInfo}\nValid profiles: ${VALID_PROFILES.join(", ")}`, "info");
				return;
			}

			// Validate profile name
			if (!VALID_PROFILES.includes(name as ProfileName)) {
				ctx.ui.notify(`Unknown profile "${name}". Valid profiles: ${VALID_PROFILES.join(", ")}`, "error");
				return;
			}

			// Already active: info message
			if (name === activeProfile) {
				ctx.ui.notify(`Profile "${name}" is already active.`, "info");
				return;
			}

			// Apply the profile
			const result = await applyProfile(name, ctx);
			if (result.ok) {
				ctx.ui.notify(`Switched to sandbox profile: ${name}`, "info");
			} else {
				ctx.ui.notify(`Failed to switch to profile "${name}": ${result.reason}`, "error");
			}
		},
	});
}
