# SBOM Accuracy Analyzer Agent

Agentic pipeline for comparing SBOM accuracy between SBOMs produced by SBOMit and other SBOM generation tools. Builds software in isolated containers, generates SBOMs using syft and sbomit, diffs them on hash/PURL/name+version, and classifies discrepancies using an LLM agent with human override support.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Temporal Workflow                         │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Discover │─>│ Execute  │─>│ Analyze  │─>│ Classify │        │
│  │(LangGr.) │  │ (Dagger) │  │(Python)  │  │ (Agent)  │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│   1 LLM call   0 LLM calls  0 LLM calls   N LLM calls         │
│   ~2K tokens   containers    spdx-tools    ~2K per diff         │
│                                hash-first                       │
│                                                                 │
│  Human Override ─── Temporal signal ─── Resume from step        │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- [Temporal CLI](https://docs.temporal.io/cli) (`temporal server start-dev`)
- OpenRouter API key
- Base Docker image built (contains syft, witness, sbomit binaries)

### Setup

```bash
# Clone and install
git clone <repo-url>
cd sbomit-accuracy-analyzer-agent
cp .env.example .env
# Edit .env with your API keys

# Configure binary paths for base image
# Edit .env and set:
#   SBOMIT_BINARY_DIR=/path/to/witness-data
#   SBOMIT_SBOMIT_DIR=/path/to/sbomit

# Build base Docker image (contains all binaries)
./scripts/build-base-image.sh

# Install dependencies
pip install -e ".[dev]"
# or
uv pip install -e ".[dev]"
```

### Prerequisites for Building Base Image

Before running `./scripts/build-base-image.sh`, ensure:

1. **Configure paths** in your `.env` file:
   - `SBOMIT_BINARY_DIR` - Path to directory containing syft, witness binaries and witness config
   - `SBOMIT_SBOMIT_DIR` - Path to directory containing sbomit binary

2. **Required files in BINARY_DIR:**
   - `syft` (binary, must be executable)
   - `witness` (binary, must be executable)
   - `.witness.yaml` (witness configuration)
   - `testkey.pem` (signing key)
   - `testpub.pem` (verification key)
   - `witness_nettrace_proxy/` (directory with proxy and certs)

3. **Required files in SBOMIT_DIR:**
   - `sbomit` (binary, must be executable)

4. **File permissions** - The following files must be readable:
   ```bash
   chmod 644 /path/to/witness-data/witness_nettrace_proxy/ca_key.pem
   chmod +x /path/to/witness-data/syft
   chmod +x /path/to/witness-data/witness
   chmod +x /path/to/sbomit/sbomit
   ```

### Run the Pipeline

```bash
# Start Temporal dev server
temporal server start-dev

# Start the worker (in a separate terminal)
sbomit-analyzer worker

# Run analysis (with commit SHA)
sbomit-analyzer run \
  --repo-url https://github.com/example/project \
  --commit-sha abc123def456

# Run analysis (without commit SHA - uses latest)
sbomit-analyzer run \
  --repo-url https://github.com/example/project
```

### Override Classifications

```bash
# View run details
sbomit-analyzer detail --run-id <uuid>

# Override a wrong classification
sbomit-analyzer override \
  --run-id <uuid> \
  --package libssl3 \
  --classification sbomit_correct \
  --reason "syft lists v1 but go.mod shows v1.1.1" \
  --human-id vyom

# Re-run from specific step
sbomit-analyzer rerun --run-id <uuid> --from-step classify
```

### Query Results

```bash
# List runs
sbomit-analyzer history --repo-url https://github.com/example/project

# Export results
sbomit-analyzer export --run-id <uuid> --output result.json

# Export audit trail
sbomit-analyzer audit --run-id <uuid> --output audit.json
```

## Project Structure

```
src/
├── cli.py              # CLI entry point (typer)
├── config.py           # Pydantic Settings (env vars)
├── discovery/          # LangGraph build discovery agent
│   ├── graph.py        # State machine
│   ├── tools.py        # list_dir, read_file, grep, build_signal_manifest
│   ├── models.py       # DiscoveryResult, ReconciledPlan Pydantic models
│   └── prompts.py      # System prompts (discovery + dependency reconcile)
├── executor/           # Dagger build execution
│   ├── runner.py       # Container build orchestration
│   ├── reconcile.py    # Probe container + LLM dependency reconciliation
│   ├── installer.py    # Toolchain install + version checks
│   ├── witness.py      # Witness binary wrapper
│   └── sbom_gen.py     # SBOM generation commands
├── analyzer/           # SBOM diff (deterministic)
│   ├── parser.py       # SPDX v2.3 JSON parser
│   ├── differ.py       # Hash-first diff engine
│   └── reporter.py     # Human-readable + JSON reports
├── classifier/         # Agent-based diff classification
│   ├── graph.py        # LLM classification logic
│   ├── models.py       # DiffClassification Pydantic model
│   └── prompts.py      # Classification prompts
├── storage/            # SQLite persistence
│   ├── models.py       # SQLAlchemy ORM models
│   ├── db.py           # Connection management
│   └── __init__.py     # CRUD helpers
└── orchestrator/       # Temporal workflows
    ├── workflows.py    # State machine workflow
    ├── activities.py   # Activity implementations
    ├── models.py       # PipelineStep, PipelineState
    └── client.py       # Worker + client helpers
```

## Diff Matching Strategy

| Priority | Method | Detects |
|----------|--------|---------|
| 1st | SHA-256 hash | Same content, different version = discrepancy |
| 2nd | PURL | Same package identity, different hash = content mismatch |
| 3rd | Name + version | Same label, different hash/PURL |
| 4th | Name only | Low confidence match |

## Classification Categories

| Category | Meaning |
|----------|---------|
| `sbomit_correct` | sbomit's value is more accurate |
| `syft_correct` | syft's value is more accurate |
| `inconclusive` | Insufficient evidence to decide which tool is correct |

## Storage Schema

SQLite database with tables:
- `runs` — Pipeline runs with state checkpoints
- `build_artifacts` — Binary, attestation, SBOM files
- `sbom_diffs` — Individual diff entries
- `classifications` — Agent classifications per diff
- `agent_metrics` — Aggregate accuracy metrics
- `override_history` — Human override audit trail

## Development

```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Test
pytest tests/
```

## Token Budget

| Phase | Tokens per repo |
|-------|----------------|
| Discovery | ~2,000 |
| Classification | ~2,000 per diff entry |
| Total (10 diffs) | ~22,000 |
| Total (20 diffs) | ~42,000 |

## License

Apache-2.0
