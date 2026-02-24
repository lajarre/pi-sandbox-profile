# pi-extension-sandbox-profile

Sandbox profiles for Pi with:
- profile switching (`/sandbox-profile`, `--sandbox-profile`)
- bash sandboxing via `@anthropic-ai/sandbox-runtime`
- file-tool enforcement for `read` / `write` / `edit`
- denied-network telemetry and protected-path blocking

## Install

```bash
pi install /Users/alex/workspace/aidev/pi-sandbox-profile
```

Or from Git once published:

```bash
pi install git:github.com/lajarre/pi-sandbox-profile
```

## Quick start

Create profile files:

- `~/.pi/agent/sandbox-profiles/intro-sec.json`
- `~/.pi/agent/sandbox-profiles/engineering.json`

Optional protected paths override:

- `~/.pi/agent/sandbox-profiles/protected-paths.json`

Then start Pi with the extension loaded and pick a profile:

```bash
/sandbox-profile intro-sec
```

## Configuration

### Profiles directory

`~/.pi/agent/sandbox-profiles/`

- `intro-sec.json`
- `engineering.json`
- `telemetry/network-deny-YYYY-MM-DD.jsonl`
- `protected-paths.json`

### Commands

- `/sandbox` — show active sandbox/profile info
- `/sandbox-profile` — show current profile
- `/sandbox-profile <name>` — switch profile

### CLI flags

- `--sandbox-profile <name>`
- `--no-sandbox`

## Prerequisites

- Pi runtime
- `@anthropic-ai/sandbox-runtime` supported platform (macOS/Linux)
- For best security posture, run under a dedicated Unix user and rely primarily on Unix permissions
