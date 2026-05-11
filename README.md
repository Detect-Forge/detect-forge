# Detect-Forge

AI-Native Detection engineering toolkit. One install, one config, one CI step.

## Overview

Detect-Forge is a composable CLI for detection engineers. Each capability is a subcommand; they share configuration, output formatting, caching, and a single CI gate. No platform, no sign-up.

The first shipping capability is `stale` — it scores your Sigma (YAML) and Elastic Detection Rules (TOML — covering EQL, KQL, and ESQL) for ATT&CK technique staleness along three dimensions:

1. **Timestamp drift** — compares ATT&CK STIX `modified` timestamps to rule modification dates (deterministic).
2. **Semantic alignment** ✅ — embeddings-based cosine similarity between rule text (title + description) and current ATT&CK technique description. Flags rules whose alignment falls below a configurable threshold (`--semantic-threshold`, default 0.65). True historical drift (comparing against past MITRE definitions) is Phase 3.b.
3. **LLM diff proposals** ✅ — opt-in, BYOLLM via OpenAI structured output; proposes rewritten rules for `semantic_drift` findings. Never auto-applied — every proposal is reviewed manually. Anthropic Claude support deferred to v0.2.

Designed to run in GitHub Actions as a CI gate. No data leaves your environment.

## Status

🚀 May 23, 2026 launch — `stale` ships with all three scoring dimensions: timestamp drift, semantic drift (Phase 3.a), and LLM diff proposals (Phase 4). True historical drift (Phase 3.b) deferred to v0.2. Other subcommands (`backtest`, `coverage`, `cti ingest`, `audit`) are registered as stubs and will ship in subsequent releases.

## Requirements

- Python **3.12** or newer

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
detect-forge --help
detect-forge --version
detect-forge stale path/to/rules
```

### Subcommands

| Command | Status | Description |
|---|---|---|
| `stale` | ✅ Available | Score detection rules for ATT&CK technique staleness. |
| `backtest` | 📅 Jun 28, 2026 | Adversarial replay (Types 3 + 4). |
| `coverage` | 📝 Q3 2026 | Coverage gap mapping (Type 6a expansion). |
| `cti ingest` | 📝 Q3–Q4 2026 | CTI-to-detection generation. |
| `audit` | 📝 Reserved | Runs every check once 2+ subcommands ship. |

### `stale` options

| Option | Default | Description |
|---|---|---|
| `RULE_DIR` (positional) | — | Directory of detection rules to scan. Recursively picks up `.yml`/`.yaml` (Sigma) and `.toml` (Elastic Detection Rules: EQL/KQL/ESQL). Must exist. |
| `--format {terminal,json,html}` | `terminal` | Output format. |
| `-o, --output PATH` | _stdout_ | Write output to a file instead of stdout. |
| `--min-severity {low,medium,high,critical}` | `low` | Only show rules at or above this severity. |
| `--no-cache` | off | Bypass the disk cache and fetch a fresh ATT&CK bundle. |
| `--domain {enterprise-attack,ics-attack,mobile-attack}` | `enterprise-attack` | ATT&CK domain to fetch. |
| `--semantic-threshold FLOAT` | `0.65` | Cosine similarity threshold; pairs below this value emit a `semantic_drift` finding. |

Supported rule formats are auto-detected by extension. `.yml`/`.yaml` files are parsed as Sigma rules; `.toml` files are parsed as Elastic Detection Rules. The Elastic schema covers EQL, KQL (kuery), and ESQL — they share the same TOML structure and only differ in the `language` field.

### How alignment is scored

Each rule is embedded as `title + description` (the natural-language portion — the detection-query body is NOT embedded, since query languages don't align well with general-purpose text embeddings). Each ATT&CK technique is embedded as `name + description` from the STIX bundle. For every technique a rule tags, we compute the cosine similarity between the two vectors; pairs whose score falls strictly below `--semantic-threshold` (default `0.65`) emit a `semantic_drift` finding at `medium` severity, with the score visible in the `Similarity` column of the report.

Embeddings are computed once with [`fastembed`](https://github.com/qdrant/fastembed) (model `BAAI/bge-small-en-v1.5`, ~30MB, auto-downloaded on first run) and cached under `$CACHE_DIR/embeddings/`. Subsequent runs read from cache. There is no `--no-semantic` flag: warm-cache cost is near-zero, and cold-cache work has to happen at least once anyway.

#### Similarity score reference

| Similarity | What it means |
|---|---|
| < 0.50 | Major concept divergence — rule and technique are describing different things |
| 0.50–0.70 | Significant drift — technique has evolved substantially |
| 0.70–0.85 | Moderate drift — wording changes, some behavioral shifts |
| > 0.85 | Minor or no drift |

The default trigger (`semantic_threshold = 0.65`) catches rules with significant or major drift — meaningful divergence that warrants attention, not just a flag.

Progress spinners go to **stderr**; the report goes to **stdout** so JSON output can be piped safely:

```bash
detect-forge stale path/to/rules --format json | jq '.scores'
detect-forge stale path/to/rules --format json -o report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no gating findings (CI passes). |
| `1` | Tool error, stub command, or unimplemented capability. |
| `2` | CI-gating condition met (e.g. `stale` found a critical finding). |

Use exit-code `2` to fail your CI pipeline:

```bash
detect-forge stale path/to/rules
code=$?
if [ "$code" -eq 2 ]; then exit 2; fi
```

### Environment variables

All settings can be overridden via `DETECT_FORGE_`-prefixed env vars (or a `.env` file in the working directory). Copy `.env.sample` at the repo root to `.env` to get started.

| Variable | Default | Purpose |
|---|---|---|
| `DETECT_FORGE_CACHE_DIR` | `$XDG_CACHE_HOME/detect-forge` (or `~/.cache/detect-forge`) | Where the ATT&CK bundle is cached. |
| `DETECT_FORGE_CACHE_TTL_HOURS` | `24` | Cache lifetime in hours. |
| `DETECT_FORGE_ATTACK_DOMAIN` | `enterprise-attack` | Default `--domain` value. |
| `DETECT_FORGE_NO_CACHE` | `false` | If truthy, always bypass the cache. |
| `DETECT_FORGE_SEMANTIC_THRESHOLD` | unset | Overrides `semantic_threshold` from `.detect-forge.toml` and the CLI flag (highest precedence). |
| `OPENAI_API_KEY` | unset | Required to enable LLM diff proposals. When unset, scans complete normally and print a skip banner. |

### LLM Diff Proposals (Phase 4)

When a rule emits a `semantic_drift` finding, `stale` can optionally call OpenAI's structured-output API to propose a rewritten rule aligned with the current ATT&CK technique. Proposals are **BYOLLM** and **never auto-applied** — the practitioner reviews every suggestion and manually decides what to keep.

#### Enabling

Set `OPENAI_API_KEY` in your environment. Without it, the scan completes normally and prints `💡 LLM diff proposals skipped` at the end of the report.

```bash
export OPENAI_API_KEY=sk-...
detect-forge stale ./rules
```

#### Configuration via `.detect-forge.toml`

LLM proposal settings live in `.detect-forge.toml` (discovered upward from your CWD, halting at the git root). There are no CLI flags for these. A starter `.detect-forge.toml` with the defaults ships at the repo root — edit in place or copy to your own project.

```toml
[stale]
semantic_threshold = 0.65   # Cosine similarity floor; pairs below trigger a proposal
llm_model = "gpt-4o-mini"   # Any OpenAI chat-completion model that supports structured outputs
max_proposals = 5           # Hard ceiling on LLM calls per scan run (cost guard)
```

`max_proposals` is your primary cost lever — every proposal attempt (success, refusal, or validation rejection) counts against this quota.

#### Cost

At default settings (`gpt-4o-mini`, 5 proposals): well under $0.01 per scan. Roughly $0.0005 per proposal. The `max_proposals` setting is your hard cost ceiling.

#### What proposals look like

For each candidate rule, you get a terminal panel with the rule filename, the model's confidence (0–1), the list of fields it changed, a brief explanation, and the rewritten rule body in syntax-highlighted YAML (Sigma) or TOML (Elastic). The HTML report adds a "LLM Proposals" section at the bottom with color-coded confidence badges.

#### What proposals don't do

- They never modify your rules on disk. Apply changes manually after review.
- They don't run if `OPENAI_API_KEY` is unset.
- They use only the rule's natural-language fields and your current ATT&CK technique description — no telemetry leaves your environment beyond the OpenAI API call.
- They're not a substitute for human review. The model's `confidence` field is self-reported and unreliable — treat every proposal as a draft.

## Python API

Each subcommand exposes a programmatic API for power users:

```python
from pathlib import Path
from detect_forge.stale import scan

report = scan(Path("./rules"), domain="enterprise-attack")
for score in report.scores:
    if score.worst_severity == "critical":
        print(f"{score.title}: {score.worst_days_stale} days stale")
```

## Development

```bash
pytest -q                     # run the test suite
ruff check src/ tests/        # lint
mypy src/                     # type-check (strict)
```

The package layout:

```
src/detect_forge/
├── cli.py              # click root group; registers all subcommands
├── settings.py         # DETECT_FORGE_* pydantic-settings config
├── console.py          # rich stdout + stderr consoles
├── cache.py            # XDG-aware cache (default_cache_dir() factory)
├── common.py           # @common_output_options decorator
├── exit_codes.py       # CLEAN=0, RESERVED=1, GATED=2
├── _stubs.py           # stub_command() helper
├── stale/              # the staleness pipeline (real subcommand)
├── backtest/           # stub
├── coverage/           # stub
├── cti/                # group + ingest stub
└── audit/              # stub
```

## License

MIT
