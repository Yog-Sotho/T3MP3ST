# T3MP3ST — Usage Guide

T3MP3ST has three interfaces: the **interactive terminal CLI** (primary), the **HTTP API server**, and the **MCP server**. There is no web UI. Everything runs in your terminal.

---

## Quick reference

| Command | What it does |
|---|---|
| `npm run setup` | Configure API keys, providers, detect local agents |
| `npm start` | Launch the interactive terminal CLI |
| `npm run server:prod` | Start the HTTP API server on port 3333 |
| `npm run mcp:prod` | Start the MCP server |
| `npm run doctor` | System health check |
| `npm run arsenal:doctor` | Check which external security tools are installed |
| `npm run verify-claims` | Re-derive all benchmark numbers from committed data |

> All `:prod` commands require `npm run build` first. Dev variants (`npm run server`, `npm run mcp`) use `tsx` and work without a build step.

---

## Interactive terminal CLI

This is the main way to use T3MP3ST.

```bash
npm run build   # once, or after pulling new code
npm start
```

You'll see the T3MP3ST banner followed by a menu.

### Main menu

```
? What would you like to do?
❯ 🚀 Start New Operation
  ⚙️  Settings
  🚪 Exit
```

Once an operation is running, additional options appear:

```
❯ 🚀 Start New Operation
  📊 View Status
  👤 Spawn Operator
  🎯 Add Target
  📋 Create Mission
  💬 Chat with AI
  📝 Generate Report
  ⏹️  Stop Operation
  ⚙️  Settings
  🚪 Exit
```

---

### Start New Operation

Select **Start New Operation** and choose a name and type:

| Type | Description |
|---|---|
| **Auto** | Uses your configured defaults (recommended) |
| **Stealth** | Minimizes detection — slower, lower footprint |
| **Aggressive** | Maximum speed — noisier |
| **Test** | Uses a mock LLM — no API calls, for exploring the UI |

The operation starts immediately after selection.

---

### Spawn Operator

Operators are the agents that do the actual work. Each maps to a kill-chain phase:

| Archetype | Phase | What it does |
|---|---|---|
| **recon** | Reconnaissance | OSINT, DNS, network discovery, asset enumeration |
| **scanner** | Discovery | Vulnerability scanning, service fingerprinting |
| **exploiter** | Initial Access | Exploitation, payload delivery |
| **infiltrator** | Lateral Movement | Post-exploitation, privilege escalation |
| **exfiltrator** | Collection / Exfil | Data extraction, credential harvesting |
| **ghost** | Persistence | Persistence, stealth, cleanup |
| **coordinator** | Command & Control | Mission orchestration |
| **analyst** | Analysis | Pattern analysis, reporting |

Spawn as many operators as needed. You can give each a custom callsign.

---

### Add Target

```
? Target address (URL or IP): https://example.com
? Target type: web_application
? Target zone: external
```

Target types: `web_application`, `api`, `network`, `host`, `database`, `cloud`

Target zones: `external`, `dmz`, `internal`, `restricted`

Egress scope containment is on by default — networked tools will refuse requests to hosts outside your declared target and its subdomains.

---

### Create Mission

A mission defines objectives for the operation.

```
? Mission name: Primary Mission
? Objectives (comma-separated): Enumerate attack surface, Identify vulnerabilities, Document findings
```

A mission must be active for report generation to work.

---

### Chat with AI

Direct chat session with the configured LLM backbone. Useful for ad-hoc analysis, prompt crafting, or asking the model about findings.

```
You: Summarize the attack surface for a typical e-commerce web app
AI:  ...
```

Type `exit` to return to the menu.

---

### Generate Report

Produces a structured findings report from the active mission's evidence vault. Includes findings by severity (Critical / High / Medium / Low / Info) and OPSEC status.

---

### Settings (from CLI)

The in-CLI Settings menu lets you:

- View current configuration (provider, model, configured keys)
- Change the default provider
- Change the default model
- Add or update an API key

For full setup including Nvidia and local agents, use `npm run setup` instead.

---

## Using Nvidia Build API

After running `npm run setup` and adding your Nvidia key:

1. The setup wizard sets Nvidia as your default provider automatically (if you choose it)
2. Default model: `nvidia/llama-3.1-nemotron-ultra-253b-v1` (Nemotron Ultra 253B)

Available Nvidia NIM models (selectable in setup):

| Model ID | Name |
|---|---|
| `nvidia/llama-3.1-nemotron-ultra-253b-v1` | Llama 3.1 Nemotron Ultra 253B |
| `nvidia/llama-3.3-nemotron-super-49b-v1` | Llama 3.3 Nemotron Super 49B |
| `meta/llama-3.3-70b-instruct` | Llama 3.3 70B Instruct |
| `qwen/qwen3-235b-a22b` | Qwen3 235B |

To switch models: **Settings → Change default model**.

---

## Using Pi Coding Agent

Pi runs as a local CLI — no API key, no login. T3MP3ST drives it the same way it drives other LLM providers.

**Requirements:**
- `pi` binary on your `PATH`
- A Pi session running (e.g. in a tmux window) — Pi handles its own context

**Selecting Pi as backbone:**

```bash
npm run setup
# → "Change default provider" → "Pi Coding Agent (local CLI)"
```

Or set it from inside the CLI: **Settings → Change default provider → Pi Coding Agent (local CLI)**.

**Detection check:**

```bash
npm run setup
# → "Check local agents"
#   ✓ Pi Coding Agent   ready
```

If Pi shows `not installed`, make sure the `pi` binary is on your PATH and executable.

---

## HTTP API server

The API server exposes all T3MP3ST capabilities over HTTP. Useful for scripting, integrations, or driving T3MP3ST from another tool.

```bash
npm run build
npm run server:prod
# Listening on http://127.0.0.1:3333
```

Dev mode (no build needed):

```bash
npm run server
```

### Key endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/mission/start` | Start a mission |
| `GET` | `/api/mission/status` | Current mission status |
| `POST` | `/api/recon` | Run reconnaissance |
| `GET` | `/api/local-agents` | List detected local agents |
| `POST` | `/api/local-agents/:id/ping` | Ping a local agent (liveness check) |
| `POST` | `/api/local-agents/:id/dispatch` | Send a prompt to a local agent |
| `GET` | `/api/arsenal` | List available tools |
| `POST` | `/api/arsenal/run` | Run an arsenal tool |
| `GET` | `/ui/` | Serves docs markdown files |

Change host/port with environment variables:

```bash
T3MP3ST_HOST=0.0.0.0 T3MP3ST_PORT=8080 npm run server:prod
```

---

## MCP server

Exposes T3MP3ST's `security_recon` tool to any MCP-compatible AI agent (Claude, Cursor, etc.).

```bash
npm run build
npm run mcp:prod
```

Dev mode:

```bash
npm run mcp
```

---

## Useful diagnostic commands

```bash
# Check system health
npm run doctor

# Check which Arsenal tools are installed
npm run arsenal:doctor

# Run all unit tests
npm test

# Re-derive all benchmark numbers from committed data
npm run verify-claims

# Run a quick smoke test
npm run smoke
```

---

## Useful scripts for advanced use

| Script | Description |
|---|---|
| `npm run keys` | Manage API keys from the shell |
| `npm run keys:list` | List configured keys (masked) |
| `npm run field:drill` | Run a field exercise |
| `npm run cve:bench` | CVE hunting benchmark (offline) |
| `npm run cve:bench:live` | CVE hunting benchmark (live models) |
| `npm run cybench` | Cybench CTF benchmark |
| `npm run decompose` | White-box repo decomposition |
| `npm run swarm` | Multi-agent swarm runner |

---

## Timeouts

Local agents and long operations can take time. Increase timeouts as needed:

```bash
# Per CLI call to a local agent (default 10 min)
T3MP3ST_LOCAL_AGENT_TIMEOUT_MS=1200000

# Per mission task (default 10 min)
T3MP3ST_TASK_TIMEOUT_MS=1200000

# General LLM requests (default 2 min)
T3MP3ST_GENERAL_TIMEOUT_MS=300000
```

---

## Full Arsenal (optional)

By default T3MP3ST loads 35 built-in tools. To enable all 83 (including more powerful post-exploitation drivers with human-approval gates):

```bash
T3MP3ST_FULL_ARSENAL=1 npm start
```

External binaries used by the full Arsenal need to be installed separately. See [docs/ARSENAL_ACTIVATION_PLAN.md](docs/ARSENAL_ACTIVATION_PLAN.md) and [docs/INSTALL_MATRIX.md](docs/INSTALL_MATRIX.md).

---

## Authorized use only

T3MP3ST is an offensive security tool. Only point it at systems you own or have explicit written permission to test. See [SECURITY.md](SECURITY.md) and [docs/SCOPE_AND_AUTHORIZATION.md](docs/SCOPE_AND_AUTHORIZATION.md).
