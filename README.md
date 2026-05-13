# AI VM Builder

**Autonomous AI-driven container provisioning and real-time zero-day defense.**  
Built for **Challenge 1: Active Cyber Defense** — GDG × Duckurity AISprint Hackathon.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-required-2496ED.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Challenge](https://img.shields.io/badge/Challenge-Active%20Cyber%20Defense-red.svg)](RUBRIC_EVALUATION.md)

> **GitHub:** [github.com/abdo800/ai-vm-builder](https://github.com/abdo800/ai-vm-builder)

---

## What it does

Type a description like *"a Python Flask API with PostgreSQL"* — the system builds and starts a Docker container with all packages installed, then defends it continuously against zero-day threats without ever rebooting.

**Three core systems:**

- **VM Provisioner** — Plain English → LLM → JSON config → Docker container with apt + pip + npm packages auto-installed
- **5-Stage Defense Pipeline** — eBPF syscall collection → ML anomaly detection (Z-score + Isolation Forest + Autoencoder) → LLM threat analysis → live patching → interactive honeypot
- **Red vs Blue Adversarial Engine** — Two LLM agents battle in a sandbox: Red Agent attacks with 18 real techniques, Blue Agent detects and blocks using ML scores + eBPF events

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/abdo800/ai-vm-builder.git
cd ai-vm-builder

# 2. Virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install scikit-learn numpy   # optional — enables Isolation Forest

# 4. Configure (Groq is recommended — free, 14,400 req/day)
cp .env.example .env
# Edit .env: set GROQ_API_KEY=gsk_... and LLM_PROVIDER=groq

# 5. Start Docker Desktop, then:
cd phase3_web && python app.py
# Open http://localhost:5000
```

---

## Installation — Full Details

### Prerequisites

| Tool | Required | Install |
|---|---|---|
| Python 3.10+ | Yes | [python.org/downloads](https://python.org/downloads) |
| Docker Desktop | Yes | [docs.docker.com/get-docker](https://docs.docker.com/get-docker) |
| Git | Yes | [git-scm.com](https://git-scm.com) |
| scikit-learn + numpy | Recommended | `pip install scikit-learn numpy` |
| frida + frida-tools | Optional | `pip install frida frida-tools` |
| bcc (Linux only) | Optional | `apt-get install bpfcc-tools linux-headers-$(uname -r)` |

### Python dependencies

```bash
pip install -r requirements.txt
```

| Package | Version | Purpose |
|---|---|---|
| `anthropic` | >=0.25.0 | Anthropic Claude API (native SDK) |
| `openai` | >=1.30.0 | OpenAI + all OpenAI-compatible providers (OpenRouter, Groq, LiteLLM, etc.) |
| `python-dotenv` | >=1.0.0 | Load `.env` file into environment variables |
| `docker` | >=7.0.0 | Docker SDK — create and manage containers from Python |
| `flask` | >=3.0.0 | Web UI and REST API |

### Linux Docker installation (if needed)

```bash
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update && sudo apt-get install docker-ce docker-ce-cli containerd.io
sudo usermod -aG docker $USER && newgrp docker
```

---

## API Keys — Getting Them

### Groq ✓ Free tier — recommended

1. Sign up at [console.groq.com](https://console.groq.com)
2. Click **API Keys** → **Create API Key**
3. Copy the key (starts with `gsk_`)
4. Set in `.env`:
```env
LLM_PROVIDER=groq
LLM_MODEL=llama3-70b-8192
GROQ_API_KEY=gsk_your_key_here
```
**Free tier:** 14,400 requests/day on `llama3-70b-8192`.

### OpenRouter ✓ Free tier — 200+ models

1. Sign up at [openrouter.ai](https://openrouter.ai) → [openrouter.ai/keys](https://openrouter.ai/keys)
2. Copy the key (starts with `sk-or-`)
3. Set in `.env`:
```env
LLM_PROVIDER=openrouter
LLM_MODEL=mistralai/mistral-7b-instruct
OPENROUTER_API_KEY=sk-or-v1-your_key_here
```
**Free tier:** 50 requests/day. Add $5 for 1,000/day.  
**Free models:** `mistralai/mistral-7b-instruct` · `meta-llama/llama-3-8b-instruct` · `google/gemini-flash-1.5`

### Anthropic — Claude (paid)

```env
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-20250514
ANTHROPIC_API_KEY=sk-ant-your_key_here
```
Get key: [console.anthropic.com](https://console.anthropic.com)

### OpenAI (paid)

```env
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-your_key_here
```

### Together AI — $25 free credit

```env
LLM_PROVIDER=together
LLM_MODEL=meta-llama/Llama-3-70b-chat-hf
TOGETHER_API_KEY=your_key_here
```
Get key: [api.together.xyz/settings/api-keys](https://api.together.xyz/settings/api-keys)

### Ollama — fully local, no key needed

```bash
# Install from ollama.com then:
ollama pull llama3
```
```env
LLM_PROVIDER=ollama
LLM_MODEL=llama3
```

---

## Proxy Gateway Setup

### LiteLLM (self-hosted)

```bash
pip install litellm
litellm --model ollama/llama3 --port 4000
```
```env
LLM_PROVIDER=litellm
LITELLM_BASE_URL=http://localhost:4000
```

### Cloudflare AI Gateway

```env
LLM_PROVIDER=cloudflare
CLOUDFLARE_BASE_URL=https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_name}/openai
CLOUDFLARE_API_KEY=your_underlying_provider_key
LLM_MODEL=gpt-4o-mini
```

### Portkey

```env
LLM_PROVIDER=portkey
PORTKEY_API_KEY=pk-your_key
LLM_MODEL=gpt-4o-mini
```
Add in the web UI (⚙ LLM Settings → Advanced Headers):
```json
{"x-portkey-provider": "openai", "x-portkey-virtual-key": "vk-your_key"}
```

### Custom / Self-Hosted (vLLM, TGI, LocalAI, etc.)

```env
LLM_PROVIDER=custom
CUSTOM_BASE_URL=http://your-server:8000/v1
CUSTOM_API_KEY=optional
LLM_MODEL=your-model-name
```

---

## Usage

### Web UI (recommended)

```bash
cd phase3_web && python app.py
# Open http://localhost:5000
```

**6 tabs:**

| Tab | Purpose |
|---|---|
| 🖥 Build VM | Describe your VM, review AI-generated config, create container |
| 📦 Containers | List, stop, remove containers; jump to security |
| 🛡 Security | ML+LLM scans, continuous monitoring, auto-patching |
| 📋 Defense Log | All scan results with ML scores and patch history |
| ⚔ Red vs Blue | Start adversarial battle, live scoreboard, round-by-round log |
| ⚙ LLM Settings | Configure provider/model/key separately for each purpose |

### CLI

```bash
# Test LLM without Docker
python phase1_cli.py --provider groq --model llama3-70b-8192

# List all supported providers
python phase1_cli.py --list-providers

# List OpenRouter model aliases
python phase1_cli.py --list-models

# Create a container
python phase2_docker.py

# Security scan — dry run (no changes applied)
python security/ai_defense.py --container <id> --once --dry-run

# Continuous monitoring with auto-patching
python security/ai_defense.py --container <id> --interval 60 --auto-patch

# Red vs Blue battle (10 rounds, 15 seconds between)
python security/ai_defense.py --container <id> --red-blue --rounds 10 --interval 15

# ARIA persona guide (Challenge 5)
python security/persona_guide.py
```

---

## LLM Settings — Per-Purpose Configuration

Configure each **purpose** independently via the ⚙ LLM Settings tab:

| Purpose | Used for |
|---|---|
| VM Build | Analyzing plain-English VM descriptions → JSON config |
| Security | Threat analysis — receives ML scores + eBPF events |
| Battle | Red Agent and Blue Agent LLM calls |

**Recommended setup:** Groq for VM Build + Battle (fast, free), Anthropic or OpenAI for Security (best reasoning).

---

## Frida Setup — Surgical Process Injection

Frida intercepts `connect()`, `execve()`, and `send()` inside suspicious processes — redirecting C2 traffic to a honeypot instead of killing the process.

> Without Frida: system runs in **mock mode** — all other features work normally.

```bash
# Step 1 — Install on your machine (Windows, macOS, Linux)
pip install frida frida-tools

# Step 2 — Start container with seccomp disabled (required for ptrace)
docker run --security-opt seccomp:unconfined -it ubuntu:22.04 /bin/bash

# Step 3 — Download frida-server from github.com/frida/frida/releases
# Check your version first:
python -c "import frida; print(frida.__version__)"
# Download: frida-server-XX.X.X-linux-x86_64.xz  (for x86_64 containers)

# Step 4 — Deploy inside container
unxz frida-server-XX.X.X-linux-x86_64.xz
docker cp frida-server-XX.X.X-linux-x86_64 <container_id>:/tmp/frida-server
docker exec <container_id> chmod +x /tmp/frida-server
docker exec -d <container_id> /tmp/frida-server

# Step 5 — Auto-connects on next scan (default port 27042)
```

---

## Real eBPF Setup (Linux only)

Real eBPF gives kernel-level visibility — every process spawn and network connection is captured before it appears in `ps` or `ss`.

```bash
# Ubuntu / Debian
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
pip install bcc

# Run as root
sudo python security/ai_defense.py --container <id> --once
```

On Windows/macOS, the `/proc` fallback runs automatically with the same interface.

---

## Environment Variables Reference

```env
# ── Default provider ──────────────────────────────────────────────────────────
LLM_PROVIDER=groq               # openrouter|anthropic|openai|groq|together|
                                # ollama|litellm|cloudflare|portkey|custom
LLM_MODEL=llama3-70b-8192      # leave blank for provider default
SECURITY_MODEL=                 # override for security scans only

# ── Direct providers ──────────────────────────────────────────────────────────
OPENROUTER_API_KEY=sk-or-v1-...
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...
TOGETHER_API_KEY=...

# ── Proxy gateways ────────────────────────────────────────────────────────────
LITELLM_BASE_URL=http://localhost:4000
LITELLM_API_KEY=
CLOUDFLARE_BASE_URL=https://gateway.ai.cloudflare.com/v1/{id}/{gw}/openai
CLOUDFLARE_API_KEY=
PORTKEY_API_KEY=pk-...
CUSTOM_BASE_URL=
CUSTOM_API_KEY=

# ── Frida ─────────────────────────────────────────────────────────────────────
FRIDA_SERVER_PORT=27042         # port frida-server listens on inside container
```

---

## REST API Reference

Base URL: `http://localhost:5000`

### VM Provisioning

| Method | Route | Description |
|---|---|---|
| `GET` | `/models` | Provider catalog and model aliases |
| `POST` | `/analyze` | `{prompt, provider?, model?}` → JSON VM config |
| `POST` | `/create` | `{config}` → create container + install all packages |
| `GET` | `/containers` | List all ai-vm-builder containers |
| `POST` | `/containers/<id>/stop` | Stop container |
| `DELETE` | `/containers/<id>/remove` | Remove container |

### Security & Defense

| Method | Route | Description |
|---|---|---|
| `POST` | `/security/scan/<id>` | `{dry_run, auto_patch}` → ML + LLM scan |
| `POST` | `/security/monitor/<id>` | `{interval, dry_run, auto_patch}` → start background monitoring |
| `DELETE` | `/security/monitor/<id>` | Stop monitoring |
| `GET` | `/security/status/<id>` | Latest scan result with ML component scores |
| `GET` | `/security/log?n=20` | Last N entries from `defense_log.jsonl` |
| `POST` | `/security/patch/<id>` | `{command, dry_run}` → apply manual patch |
| `GET` | `/security/ml_status/<id>` | ML baseline training progress |
| `GET` | `/security/ebpf_status/<id>` | eBPF, Frida, and honeypot status |

### Red vs Blue Battle

| Method | Route | Description |
|---|---|---|
| `POST` | `/battle/start/<id>` | `{rounds, interval}` → start adversarial battle |
| `POST` | `/battle/stop/<id>` | Stop battle |
| `GET` | `/battle/status/<id>` | Live scoreboard |
| `GET` | `/battle/log?n=30` | Battle round history |
| `POST` | `/battle/run_round/<id>` | One round — for demo/testing |

### LLM Configuration

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/llm/providers` | Full provider catalog with labels and models |
| `GET` | `/api/llm/config` | Current config for all purposes (keys masked) |
| `POST` | `/api/llm/config` | Save config for any/all purposes |
| `POST` | `/api/llm/test` | `{purpose}` → test connection, returns OK or error |
| `GET` | `/api/llm/current/<purpose>` | Resolved config for provisioning/security/battle |

---

## Project Structure

```
ai-vm-builder/
├── llm_manager.py                ← All 10 providers + proxies, per-purpose config
├── phase1_cli.py                 ← CLI: plain English → JSON VM config
├── phase2_docker.py              ← Docker: create container, install apt+pip+npm
├── phase3_web/
│   ├── app.py                    ← Flask REST API (25 routes)
│   └── templates/index.html     ← 6-tab dark-theme web UI
├── security/
│   ├── ai_defense.py             ← 5-stage defense orchestrator
│   ├── persona_guide.py          ← ARIA persona guide (Challenge 5)
│   ├── ml/
│   │   └── anomaly_detector.py  ← Z-score + Isolation Forest + Autoencoder
│   ├── ebpf/
│   │   ├── ebpf_hooks.py        ← Real eBPF BPF program + /proc fallback
│   │   ├── frida_intercept.py   ← Frida JS hooks + InteractiveHoneypot
│   │   └── runtime_collector.py ← ProcessEvent, NetworkEvent, HoneypotRedirector
│   └── adversarial/
│       └── red_blue_engine.py   ← RedAgent + BlueAgent + AdversarialEngine
├── system_prompt.txt             ← LLM VM configuration prompt
├── .env.example                  ← All environment variables documented
├── requirements.txt
└── RUBRIC_EVALUATION.md          ← Hackathon rubric self-score: 89/100
```

---

## Troubleshooting

| Error | Fix |
|---|---|
| `429 Rate limit exceeded` | Switch to Groq: `LLM_PROVIDER=groq` — 14,400 free req/day |
| `401 Unauthorized` | Wrong API key. Get a new one from the provider dashboard. |
| `LLM returned non-JSON` | Use a larger model. Groq `llama3-70b-8192` is reliable. |
| `Cannot connect to Docker` | Start Docker Desktop and wait for the whale icon in taskbar. |
| Blue Agent always uses `echo monitoring` | Replace `red_blue_engine.py` with the latest version. |
| Red Agent stuck on recon | Replace `red_blue_engine.py` with the latest version. |
| Battle routes return 404 | Replace `app.py` with the latest version — battle routes added post v1. |
| Frida: connection refused | Run `docker exec -d <id> /tmp/frida-server` inside the container. |
| eBPF: permission denied | Run as root: `sudo python security/ai_defense.py ...` |
| Ollama: connection refused | Run `ollama serve` first, then start the Flask app. |

---

## Challenge 1 — Rubric Coverage

| Requirement | Implementation |
|---|---|
| Unsupervised ML baseline | Z-score (30-sample rolling window) + Isolation Forest (contamination=0.05) + Autoencoder (pure Python, 3-layer) — `security/ml/anomaly_detector.py` |
| Analyze anomalies dynamically | LLM receives ML ensemble scores + typed eBPF `SyscallEvent` objects + Frida TTP captures → structured JSON threat assessment with patch commands |
| Inject code / re-route to honeypots | `FridaIntercept`: 3 JS hooks injected at runtime (connect→honeypot, execve→/bin/true, send→log). `InteractiveHoneypot`: fake SSH + fake HTTP + iptables REDIRECT |
| eBPF | Real BPF C program with kprobes on `sys_execve`, `sys_connect`, `sys_open`, `sys_ptrace`. Auto-falls back to `/proc` with identical `SyscallEvent` interface |
| Isolation Forests | `sklearn.IsolationForest`, 12-feature vector, contamination=0.05, ensemble weight 0.35 |
| Autoencoders | Pure-Python 3-layer autoencoder (input→n/2→n/4→n/2→output), ReLU+sigmoid, MSE reconstruction error scoring, ensemble weight 0.25 |
| Frida Dynamic Injection | 3 embedded JS hook scripts (`CONNECT_HOOK_SCRIPT`, `EXECVE_HOOK_SCRIPT`, `SEND_HOOK_SCRIPT`). Connects to frida-server in container via TCP. Mock mode for demo. |
| LLM | 10 providers: OpenRouter, Anthropic, OpenAI, Groq, Together AI, Ollama, LiteLLM, Cloudflare AI Gateway, Portkey, Custom |
| Kubernetes | Not implemented — acknowledged in `RUBRIC_EVALUATION.md` |

**Estimated rubric score: 89 / 100**

---

## Security Notes

- **Never commit `.env`** — add it to `.gitignore` before pushing
- **Red Agent sandbox** — tool whitelist (`RED_ALLOWED_COMMANDS`) prevents host escape; treat the battle container as expendable
- **Dry run default** — security scans use `dry_run=True` until you explicitly enable `auto_patch`
- **Prompt injection guard** — patterns like "ignore previous instructions" are stripped before all LLM calls
- **API keys in UI** — saved to `llm_config.json` locally; masked in all API responses

---

## Author

**Abdo** — [@abdo800](https://github.com/abdo800)

*AI VM Builder v2.0.0 — Challenge 1: Active Cyber Defense — GDG × Duckurity AISprint 2025*
