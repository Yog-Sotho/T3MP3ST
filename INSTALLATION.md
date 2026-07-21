# T3MP3ST — Installation Guide

## Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Node.js | 18.0.0 | LTS recommended. `node --version` to check |
| npm | 8+ | Bundled with Node.js |
| git | any | For cloning |
| OS | Linux / macOS | Headless Linux fully supported |

No browser or display server is required. T3MP3ST runs entirely in the terminal.

---

## 1. Clone

```bash
gh repo clone Yog-Sotho/T3MP3ST
cd T3MP3ST
```

Or with plain git:

```bash
git clone https://github.com/Yog-Sotho/T3MP3ST.git
cd T3MP3ST
```

---

## 2. Install dependencies

```bash
npm install
```

---

## 3. Build

```bash
npm run build
```

This compiles TypeScript to `dist/`. Required before running `npm start`.

---

## 4. Run the setup wizard

```bash
npm run setup
```

The wizard walks you through:

- Adding API keys (Nvidia, OpenRouter, Venice, Anthropic, OpenAI, xAI)
- Setting your default provider and model
- Detecting local agent CLIs (Pi, Claude Code, Codex, Hermes)

Run it again any time to change configuration.

---

## 5. Provider setup

### Nvidia Build API (recommended)

Get a free key at <https://build.nvidia.com/>. Keys start with `nvapi-`.

```
Enter your Nvidia Build API key (nvapi-...):
```

The wizard validates the key against Nvidia's endpoint and saves it. Default model: `nvidia/llama-3.1-nemotron-ultra-253b-v1`.

### OpenRouter

Get a key at <https://openrouter.ai/keys>. Gives access to Claude, GPT-4, Llama, and 200+ models from a single key.

### Venice AI

Get a key at <https://venice.ai/settings/api>. Privacy-focused, uncensored models.

### Anthropic

Get a key at <https://console.anthropic.com/>. Direct Claude access.

### OpenAI

Get a key at <https://platform.openai.com/api-keys>.

### xAI (Grok)

Set via environment variable: `XAI_API_KEY=your-key`.

---

## 6. Local agent setup (keyless)

T3MP3ST can use locally installed AI coding agent CLIs as its LLM backbone — no API key needed.

### Pi Coding Agent

Pi needs no login step. Once the `pi` binary is on your `PATH`, T3MP3ST detects it automatically.

```bash
# Verify Pi is detected
npm run setup
# Choose: Check local agents (Pi / Claude Code / Codex / Hermes)
# ✓ Pi Coding Agent   ready
```

### Claude Code

```bash
npm install -g @anthropic-ai/claude-code
claude login   # authenticate once
```

### OpenAI Codex CLI

```bash
npm install -g @openai/codex
codex login
```

### Hermes Agent

Install per Hermes docs, then authenticate.

---

## 7. Environment variables (alternative to setup wizard)

You can skip the wizard and set keys directly as environment variables. Put them in a `.env` file in the project root or export them in your shell.

```bash
# API keys
OPENROUTER_API_KEY=sk-or-...
VENICE_API_KEY=...
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
XAI_API_KEY=...
NVIDIA_API_KEY=nvapi-...

# Local model (Ollama / LM Studio / vLLM / llama.cpp)
TEMPEST_LOCAL_BASE_URL=http://localhost:11434/api
TEMPEST_LOCAL_MODEL=llama3

# Server
T3MP3ST_PORT=3333          # default
T3MP3ST_HOST=127.0.0.1    # default

# Timeouts (milliseconds)
T3MP3ST_LOCAL_AGENT_TIMEOUT_MS=600000
T3MP3ST_TASK_TIMEOUT_MS=600000
T3MP3ST_GENERAL_TIMEOUT_MS=120000
```

Keys set via environment variables take precedence over keys saved by the setup wizard.

---

## 8. Optional: external security tools (Arsenal)

The Arsenal uses external binaries for recon, scanning, and exploitation. None are required to start — missing tools are skipped gracefully. Install what you need:

### Quick set (recommended first install)

```bash
# Debian / Ubuntu
sudo apt-get install -y nmap curl dig whois openssl

# Recon / scanning (ProjectDiscovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Web fuzzing
go install github.com/ffuf/ffuf/v2@latest

# Secret scanning
pip install semgrep
brew install gitleaks   # or: go install github.com/gitleaks/gitleaks/v8@latest
```

Full tool matrix: [docs/INSTALL_MATRIX.md](docs/INSTALL_MATRIX.md)

Check which tools are detected:

```bash
npm run arsenal:doctor
```

---

## 9. Updating

After merging a PR or pulling upstream changes:

```bash
git pull origin main
npm install      # if package.json changed
npm run build    # always rebuild after pulling
```

---

## Verify everything works

```bash
npm test         # 417 unit tests — all should pass
npm run doctor   # system health check
```

---

## Where configuration is stored

The setup wizard saves keys and preferences using the OS config directory (via the `conf` library):

- **Linux**: `~/.config/t3mp3st/`
- **macOS**: `~/Library/Preferences/t3mp3st/`

Delete this directory to reset all configuration.
