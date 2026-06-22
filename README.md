# GCA AppSec AI Agent/Skills Risk Assessment Platform

A FastAPI-based platform for assessing the deployment risk of open-source **AI agents** and **skills/tools** from GitHub repositories.

It combines static repository inspection, dependency and ecosystem checks, LLM-assisted capability analysis, and SkillSpector-based skill scanning to answer a practical question:

> **How risky is it to deploy this agent or skill inside an enterprise environment?**

## What it does

The platform analyzes a target GitHub repository across multiple security dimensions and produces:

- a **weighted overall score** (`0-100`, higher is safer)
- a **risk level** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- per-module findings and explanations
- optional **AppSec security control recommendations** for deployment teams

The web UI supports **module-level selection**, so users can choose which analyses to run for a given scan.

## Current analysis modules

1. **Agent Capability Analysis**  
   Identifies what the LLM can actually trigger, estimates blast radius, and distinguishes LLM-invocable capabilities from deterministic code.

2. **Skill Security Quality**  
   Uses **SkillSpector** to scan skills/tools, then post-filters the results to keep only **subjectively malicious High/Critical findings**. Routine coding sloppiness, generic CVEs, and non-malicious validation gaps are excluded.

3. **AI Safety Guardrails**  
   Evaluates whether the repository contains controls that constrain the **LLM decision loop**, such as human approval, step limits, tool gating, and prompt-injection defenses.

4. **Reputation & Activity**  
   Uses GitHub repository metadata such as stars, contributors, last update time, and security documentation.

5. **deps.dev Package Health**  
   Adds package-level ecosystem health signals from deps.dev.

6. **Dependency Vulnerability Scan**  
   Scans dependency manifests and queries OSV.dev for known vulnerabilities.

7. **Data Privacy**  
   Looks for risky handling of logs, telemetry, and sensitive user or conversation data.

8. **Supply Chain Integrity**  
   Checks for lock files, version pinning, integrity signals, and risky dependency/distribution patterns.

9. **Runtime Isolation**  
   Assesses containerization, sandboxing, privilege level, and host exposure.

## Core design principles

### 1. Risk comes from what the LLM can actually do

For agent capability analysis, the platform does **not** treat all code equally. It focuses on:

- tools/skills the LLM can invoke directly
- operations reachable from those tools
- how much of the dangerous action the model can control

This keeps the blast-radius score aligned with the real AI threat model, instead of overcounting deterministic code paths.

### 2. Guardrails apply to the LLM loop, not all code hygiene

The AI Safety module only scores controls that constrain model behavior, such as:

- human-in-the-loop approval
- step/turn limits
- tool allowlists
- output validation on model-driven actions
- prompt injection defenses

Ordinary validation or software hygiene that is not tied to the LLM control loop is not treated as an AI guardrail.

### 3. Skill risk is narrower than generic skill quality

The Skill module is intentionally opinionated:

- it uses SkillSpector as the scanning engine
- but it only keeps **malicious High/Critical** findings
- it excludes low-signal or merely sloppy-but-not-malicious findings

In other words, this module is closer to **"malicious skill risk"** than generic linting or code-quality review.

## Architecture

### Backend

- **FastAPI** application in `main.py`
- analysis results streamed to the UI via **Server-Sent Events (SSE)**
- each analyzer returns a normalized result shape:
  - `score`
  - `risk_level`
  - `summary`
  - `findings`
  - `metrics`

### Frontend

- single-page UI in `static/index.html`
- supports:
  - repository input
  - per-module selection
  - bilingual UI (`zh` / `en`)
  - collapsible per-module findings
  - generated AppSec controls

### Skill scanning engine

`Skill Security Quality` is implemented by adapting **NVIDIA SkillSpector**:

- SkillSpector performs static/AST/YARA/semantic skill scanning
- this project post-filters those findings
- only **malicious High/Critical** results are retained for scoring and display

## Scoring model

Each module returns a **0-100** score where:

- **higher = safer**
- **lower = riskier**

The overall score is a weighted average across enabled modules, excluding modules with `risk_level = "UNKNOWN"`.

Current weights:

| Module | Weight |
|---|---:|
| Agent Capability Analysis | 0.23 |
| AI Safety Guardrails | 0.18 |
| Dependency Vulnerability Scan | 0.13 |
| Reputation & Activity | 0.12 |
| Skill Security Quality | 0.12 |
| Data Privacy | 0.08 |
| deps.dev Package Health | 0.05 |
| Supply Chain Integrity | 0.05 |
| Runtime Isolation | 0.04 |

Overall risk bands:

| Score | Risk |
|---|---|
| `>= 75` | LOW |
| `55 - 74.9` | MEDIUM |
| `35 - 54.9` | HIGH |
| `< 35` | CRITICAL |

For detailed module internals, see [`MODULES.md`](./MODULES.md).

## Requirements

- **Python 3.12+** recommended  
  SkillSpector currently drives the minimum practical Python version.
- GitHub network access
- Optional:
  - **`GITHUB_DEFAULT_TOKEN`** for higher GitHub API limits
  - **`QWEN_API_KEY`** for LLM-based analysis

## Installation

```bash
git clone https://github.com/ZhongdaoChen/AI-Agent-Risk-Evaluation.git
cd AI-Agent-Risk-Evaluation

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Configuration

Create a local `.env` file or export environment variables in your shell:

```bash
export GITHUB_DEFAULT_TOKEN=ghp_xxx
export QWEN_API_KEY=your_dashscope_key
```

Notes:

- `GITHUB_DEFAULT_TOKEN` is optional but helps avoid GitHub rate limits.
- `QWEN_API_KEY` is required for LLM-backed modules such as:
  - Agent Capability Analysis
  - AI Safety Guardrails
  - AppSec Security Controls generation
- The Skill module can fall back to static scanning when no Qwen key is available.

## Running locally

### Option 1: start script

```bash
bash run.sh
```

### Option 2: run uvicorn directly

```bash
python3 -m uvicorn main:app --host 127.0.0.1 --port 9999 --reload
```

Then open:

```text
http://127.0.0.1:9999
```

## How to use the UI

1. Enter a GitHub repository URL
2. Optionally provide a GitHub token
3. Choose which modules to run
4. Click **Analyze**
5. Review:
   - overall score
   - per-module findings
   - optional AppSec controls

### AppSec controls generation

The **AppSec Security Controls** panel is only generated when at least one of these modules is selected:

- `code`
- `ai_safety`
- `runtime`

That is because the controls prompt is currently grounded in:

- agent capability findings
- guardrail findings
- runtime isolation findings

## API

### `GET /api/health`

Health check.

Example response:

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

### `GET /api/config`

Returns whether a default GitHub token is configured.

### `GET /api/analyze`

Streams analysis results over SSE.

Query parameters:

- `url` — GitHub repository URL
- `token` — optional GitHub PAT
- `lang` — `zh` or `en`
- `modules` — comma-separated analyzer keys

Example:

```bash
curl -N "http://127.0.0.1:9999/api/analyze?url=https://github.com/openai/openai-agents-python&lang=en&modules=code,skill,ai_safety"
```

### `POST /api/security-controls`

Generates deployment-oriented AppSec recommendations from existing scan results.

## Known limitations

This project is intentionally **static-analysis-first**. It does not observe the real runtime behavior of an agent.

Examples of what it cannot fully prove:

- prompts dynamically fetched from remote URLs
- runtime-only tool chains and planner behavior
- permissions actually granted after MCP/server connection
- real side effects during execution
- complete coverage for extremely large repositories

Also note:

- Qwen/DashScope may return **429 Too Many Requests** under heavy multi-module scanning
- GitHub API may return **403 rate limit exceeded** without a token
- SkillSpector-based scanning may be slower than the legacy skill analyzer because it performs deeper per-skill inspection

## Repository structure

```text
.
├── analyzers/           # Per-dimension analyzers
├── static/index.html    # Frontend UI
├── main.py              # FastAPI app + SSE orchestration
├── MODULES.md           # Detailed module scoring and logic
├── requirements.txt     # Python dependencies
├── run.sh               # Local dev startup script
└── deploy.sh            # Simple deployment helper
```

## Development notes

- The backend orchestrates analyzers sequentially for stable SSE progress updates.
- The frontend controls which modules run by passing `modules=...` to `/api/analyze`.
- Skill findings are rendered per file and grouped by severity in the UI.
- `UNKNOWN` modules are excluded from the weighted overall score.

## Roadmap ideas

- stronger rate-limit handling and backoff for DashScope/Qwen
- cache layer for repeated scans
- better GitHub archive/fork handling
- richer API docs
- optional JSON/SARIF export for skill-only workflows

## License

This repository currently does not declare a standalone root license file in the scanned context. Add one if you plan to distribute the project externally.
