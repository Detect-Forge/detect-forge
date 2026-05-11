# Detect-Forge

AI-Native Detection engineering toolkit. One install, one config, one CI step.

## Overview

Detect-Forge is a composable CLI for detection engineers. Each capability is a subcommand; they share configuration, output formatting, caching, and a single CI gate. No platform, no sign-up.

The first shipping capability is `stale` — it scores your Sigma (YAML) and Elastic Detection Rules (TOML — covering EQL, KQL, and ESQL) for ATT&CK technique staleness along three dimensions:

1. **Timestamp drift** — compares ATT&CK STIX `modified` timestamps to rule modification dates (deterministic).
2. **Semantic alignment** ✅ — embeddings-based cosine similarity between rule text (title + description) and current ATT&CK technique description. Flags rules whose alignment falls below a configurable threshold (`--semantic-threshold`, default 0.65). True historical drift (comparing against past MITRE definitions) is Phase 3.b.
3. **LLM diff proposals** *(planned)* — opt-in, BYOLLM (OpenAI primary, Claude secondary); proposes updated rules for flagged stale entries.

Designed to run in GitHub Actions as a CI gate. No data leaves your environment.

## Status

🔨 Building toward May 23, 2026 launch — `stale` semantic alignment now shipped (Phase 3.a); true historical drift (Phase 3.b) and LLM diff proposals (Phase 4) planned. Other subcommands (`backtest`, `coverage`, `cti ingest`, `audit`) are registered as stubs and will ship in subsequent releases.

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
| `--semantic-threshold FLOAT` | `0.65` | Cosine similarity threshold; pairs below this value emit a `low_alignment` finding. |

Supported rule formats are auto-detected by extension. `.yml`/`.yaml` files are parsed as Sigma rules; `.toml` files are parsed as Elastic Detection Rules. The Elastic schema covers EQL, KQL (kuery), and ESQL — they share the same TOML structure and only differ in the `language` field.

### How alignment is scored

Each rule is embedded as `title + description` (the natural-language portion — the detection-query body is NOT embedded, since query languages don't align well with general-purpose text embeddings). Each ATT&CK technique is embedded as `name + description` from the STIX bundle. For every technique a rule tags, we compute the cosine similarity between the two vectors; pairs whose score falls strictly below `--semantic-threshold` (default `0.65`) emit a `low_alignment` finding at `medium` severity, with the score visible in the `Similarity` column of the report.

Embeddings are computed once with [`fastembed`](https://github.com/qdrant/fastembed) (model `BAAI/bge-small-en-v1.5`, ~30MB, auto-downloaded on first run) and cached under `$CACHE_DIR/embeddings/`. Subsequent runs read from cache. There is no `--no-semantic` flag: warm-cache cost is near-zero, and cold-cache work has to happen at least once anyway.

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

All settings can be overridden via `DETECT_FORGE_`-prefixed env vars (or a `.env` file in the working directory):

| Variable | Default | Purpose |
|---|---|---|
| `DETECT_FORGE_CACHE_DIR` | `$XDG_CACHE_HOME/detect-forge` (or `~/.cache/detect-forge`) | Where the ATT&CK bundle is cached. |
| `DETECT_FORGE_CACHE_TTL_HOURS` | `24` | Cache lifetime in hours. |
| `DETECT_FORGE_ATTACK_DOMAIN` | `enterprise-attack` | Default `--domain` value. |
| `DETECT_FORGE_NO_CACHE` | `false` | If truthy, always bypass the cache. |

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
