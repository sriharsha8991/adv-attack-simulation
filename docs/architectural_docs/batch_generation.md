# Batch Generation Service

> **Module:** `src/services/batch_generator.py`  
> **CLI:** `scripts/generate_all.py`  
> **Config:** `src/config.py` → Batch Generation section  
> **Output:** `output/abilities/<category>.json`

---

## 1. Problem Statement

The existing `ReasoningEngine` (Layer 3) generates abilities one at a time through a conversational, multi-turn flow: the user specifies a category + platform, the LLM runs a **Phase A** tool-calling loop (up to 10 iterations of CTI tool calls), then **Phase B** composes the final ability. This is ideal for interactive use but infeasible for full MITRE ATT&CK coverage:

| Metric | Interactive (ReasoningEngine) | Batch Generator |
|--------|-------------------------------|-----------------|
| LLM calls per technique | ~11 (10 Phase A + 1 Phase B) | **1** (Phase B only) |
| Estimated calls for full sweep (~600 targets) | ~6,600 | **~600** |
| Concurrency | 1 (sequential) | **100** (ThreadPoolExecutor) |
| User input required | Yes (category + platform) | **None** |

The Batch Generator is a **standalone service** — it does not modify, import, or share state with `ReasoningEngine` or the FastAPI API. Zero changes to existing code.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   scripts/generate_all.py                   │
│                     (Click CLI entry point)                  │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     BatchGenerator                          │
│                src/services/batch_generator.py               │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Phase 1  │→ │ Phase 2  │→ │ Phase 3  │→ │  Phase 4   │  │
│  │Discovery │  │Enrichment│  │Composition│  │ Persistence│  │
│  │(Graph)   │  │(Graph+   │  │(LLM call)│  │ (JSON)     │  │
│  │          │  │ MISP)    │  │          │  │            │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
│                                                             │
│  Resources (created once, shared across all targets):       │
│  • Neo4jConnection       • GalaxyManager                   │
│  • CTITools              • MISPTools                       │
│  • SafetyValidator       • GeminiClient                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Four-Phase Pipeline

### Phase 1 — Discovery

**Method:** `discover_targets(categories)`

Queries the knowledge graph to build a complete manifest of **technique × platform** targets:

1. Iterate each category in `GENERATION_MATRIX`
2. Resolve tactics via `CATEGORY_TO_TACTICS` mapping
3. Call `get_techniques_by_tactic(tactic)` for parent techniques
4. Call `get_subtechniques(parent_id)` for each parent
5. Cross-product with meaningful platforms from the matrix
6. **Global deduplication** on `(technique_id, platform)` tuples — a technique that appears under multiple tactics is only generated once

**Output:** List of `TechniqueTarget` dataclass objects.

```python
@dataclass
class TechniqueTarget:
    technique_id: str        # e.g. "T1059" or "T1059.001"
    technique_name: str      # e.g. "Command and Scripting Interpreter"
    category: str            # e.g. "credential_access"
    platform: str            # e.g. "windows"
    tactic: str              # e.g. "execution"
    is_subtechnique: bool    # True for T1059.001 etc.
    parent_id: str | None    # parent technique ID if sub-technique
```

### Phase 2 — Enrichment (No LLM)

**Method:** `_enrich_technique(technique_id)`

Unlike the interactive `ReasoningEngine` which uses LLM Phase A (up to 10 tool-call iterations), the batch generator **queries the graph directly**:

- `CTITools.get_technique_intel(tid)` → returns groups, tools, campaigns, mitigations, detection info
- `MISPTools.enrich_technique_context(tid)` → returns MISP Galaxy associations

The raw data is formatted via `_format_enrichment()` into a structured markdown string ready for the LLM.

**Why skip Phase A?** Phase A exists to let the LLM decide which tools to call based on conversational context. In batch mode, every technique needs the same enrichment — a direct query is deterministic, faster, and saves ~10 LLM calls per technique.

### Phase 3 — Composition (Single LLM Call)

**Method:** `_compose_ability(target)`

1. Build the `BATCH_COMPOSITION_PROMPT` with enrichment context, technique ID, platform, category
2. Call LLM with `schema=Ability` (Pydantic structured output enforcement)
3. **Post-generation enforcement:**
   - `approval_status` → `PENDING`
   - `created_by` → `"AI"`
   - `simulation_only` → `True`
   - `schema_version`, `generated_at`, `agent_version` stamped
4. **Safety validation** (if `enable_safety_layer` is `True` in config):
   - Run `SafetyValidator.validate(ability)`
   - Hard failures → `approval_status` = `BLOCKED`
5. Attach `GenerationTrace` metadata (model, tokens, tools called, warnings)

### Phase 4 — Parallel Execution & Persistence

**Methods:** `run()`, `_generate_category()`, `_save_category()`

- Targets are grouped by category
- Each category batch is processed via `ThreadPoolExecutor(max_workers=concurrency)`
- Up to **100 concurrent LLM calls** (configurable)
- Results are saved as one JSON file per category

---

## 4. Smart Generation Matrix

The matrix maps each attack category to only the platforms where that category is operationally meaningful:

```python
GENERATION_MATRIX = {
    "credential_access":          ["windows", "linux", "macos"],
    "privilege_escalation":       ["windows", "linux", "macos"],
    "persistence":                ["windows", "linux", "macos"],
    "lateral_movement":           ["windows", "linux"],
    "defense_evasion":            ["windows", "linux", "macos"],
    "command_and_control":        ["windows", "linux", "macos"],
    "discovery":                  ["windows", "linux", "macos",
                                   "cloud_aws", "cloud_azure", "cloud_gcp"],
    "collection":                 ["windows", "linux", "macos"],
    "exfiltration":               ["windows", "linux"],
    "cloud_iam_abuse":            ["cloud_aws", "cloud_azure", "cloud_gcp"],
    "active_directory_abuse":     ["windows"],
    "web_application_simulation": ["linux", "windows"],
    "network_signaling":          ["windows", "linux"],
}
```

**13 categories × 36 total platform slots** — but actual target count depends on which techniques in the graph support each platform (typically 400–700 unique targets after deduplication).

### Platform Mapping

Our platform names map to MITRE's platform taxonomy:

| Our Platform | MITRE Matches |
|---|---|
| `windows` | Windows |
| `linux` | Linux |
| `macos` | macOS |
| `cloud_aws` | IaaS, SaaS, AWS |
| `cloud_azure` | Azure AD, IaaS, SaaS, Office 365, Azure |
| `cloud_gcp` | IaaS, SaaS, Google Workspace, GCP |

---

## 5. Output Format

Each category gets its own folder under `output/abilities/`, with **one JSON file per ability** and a lightweight `_manifest.json` index:

```
output/abilities/
├── credential_access/
│   ├── _manifest.json
│   ├── T1003_windows.json
│   ├── T1003_linux.json
│   ├── T1003.001_windows.json
│   ├── T1003.002_linux.json
│   └── ...
├── privilege_escalation/
│   ├── _manifest.json
│   ├── T1548_windows.json
│   └── ...
└── cloud_iam_abuse/
    ├── _manifest.json
    ├── T1078_cloud_aws.json
    └── ...
```

### Individual Ability File (`<technique_id>_<platform>.json`)

Each file contains a single `Ability` JSON object (see [ability_schema.md](ability_schema.md)):

```json
{
  "name": "OS Credential Dumping via LSASS",
  "attack_category": "credential_access",
  "mitre_mapping": { "technique": "T1003", "sub_technique": "T1003.001" },
  "executors": [ ... ],
  "simulation_only": true,
  "approval_status": "PENDING",
  ...
}
```

### Manifest File (`_manifest.json`)

A lightweight index listing all generated files in the category:

```json
{
  "category": "credential_access",
  "generated_at": "2025-07-12T10:30:45.123456+00:00",
  "model": "gemini-2.0-flash",
  "total_abilities": 87,
  "techniques_covered": ["T1003", "T1003.001", "T1003.002", "..."],
  "files": [
    { "file": "T1003_windows.json", "technique_id": "T1003", "platform": "windows", "name": "OS Credential Dumping" },
    { "file": "T1003.001_windows.json", "technique_id": "T1003.001", "platform": "windows", "name": "LSASS Memory Dump" }
  ]
}
```

---

## 6. CLI Usage

```bash
# Preview the full manifest (no LLM calls)
python scripts/generate_all.py --dry-run

# Full sweep — all 13 categories, 100 concurrent calls
python scripts/generate_all.py

# Single category only
python scripts/generate_all.py --category credential_access

# Resume after interruption (skips categories that already have output files)
python scripts/generate_all.py --resume

# Limit concurrency (e.g. for lower-tier API keys)
python scripts/generate_all.py --concurrency 50

# Verbose logging
python scripts/generate_all.py --log-level DEBUG
```

### CLI Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--category` | String | None (all) | Generate for a single category only |
| `--resume` | Flag | False | Skip categories with existing output files |
| `--dry-run` | Flag | False | Discover and print manifest, no generation |
| `--concurrency` | Integer | 100 | Max parallel LLM calls |
| `--log-level` | Choice | INFO | DEBUG, INFO, WARNING, ERROR |

---

## 7. Concurrency Model

```
ThreadPoolExecutor(max_workers=100)
    │
    ├── Thread 1:  _compose_ability(T1003/windows)
    ├── Thread 2:  _compose_ability(T1003.001/windows)
    ├── Thread 3:  _compose_ability(T1003.002/linux)
    ├── ...
    └── Thread 100: _compose_ability(T1548/macos)
```

- Each thread runs the full pipeline: enrich → format → LLM call → safety → trace
- The `GeminiClient.generate()` is synchronous — wrapping in `ThreadPoolExecutor` achieves true parallelism for I/O-bound LLM HTTP calls
- Neo4j connection and tool instances are thread-safe and shared
- Default `BATCH_CONCURRENCY = 100` is tuned for Gemini tier-3 rate limits
- Adjustable via `--concurrency` CLI flag

---

## 8. Resume Support

The `--resume` flag enables idempotent re-runs:

1. Before generating a category, check if `output/abilities/<category>/_manifest.json` exists
2. If it exists → skip entire category, log `SKIP <category> — manifest already exists`
3. If not → generate normally

This protects against:
- Network interruptions mid-sweep
- API rate limit errors
- Manual re-runs to fill in failed categories

---

## 9. Dry Run Mode

`--dry-run` executes only Phase 1 (Discovery) and prints a formatted manifest:

```
========================================================================
  BATCH GENERATION MANIFEST (dry run)
========================================================================

  credential_access (87 targets)
    windows           45 techniques  [T1003..T1558]
    linux             28 techniques  [T1003..T1552]
    macos             14 techniques  [T1003..T1555]

  cloud_iam_abuse (42 targets)
    cloud_aws         18 techniques  [T1078..T1550]
    cloud_azure       15 techniques  [T1078..T1550]
    cloud_gcp          9 techniques  [T1078..T1550]

  ...

────────────────────────────────────────────────────────────────────────
  TOTAL: 623 technique×platform targets
  Estimated LLM calls: 623
========================================================================
```

---

## 10. Statistics & Monitoring

`BatchStats` tracks the following across the entire run:

| Metric | Description |
|--------|-------------|
| `total_targets` | Total unique technique × platform targets discovered |
| `generated` | Successfully composed abilities |
| `failed` | Composition failures (LLM errors, missing enrichment) |
| `blocked` | Safety-blocked abilities (still saved, status = BLOCKED) |
| `skipped_categories` | Categories skipped due to `--resume` |
| `elapsed_seconds` | Wall-clock time for the full sweep |
| `errors` | List of error detail strings (first 20 logged) |

Final summary is logged at the end of every run.

---

## 11. Key Design Decisions

### Why a Separate Service?

- **No coupling** — `BatchGenerator` creates its own `Neo4jConnection`, `GeminiClient`, tools, and validator. The `ReasoningEngine` and FastAPI API are untouched
- **Different optimization profile** — interactive needs conversational context (Phase A); batch needs throughput (skip Phase A, maximize concurrency)
- **Independent lifecycle** — batch runs can be triggered via cron, CI/CD, or manual CLI without starting the API server

### Why Skip LLM Phase A?

In the interactive flow, Phase A lets the LLM choose which CTI tools to call based on user context. In batch mode:
- Every technique needs the same enrichment (intel + MISP)
- The LLM's tool-selection adds no value — a direct call is deterministic
- Eliminating Phase A saves ~10 LLM API calls per technique
- For a 600-target sweep, that's **~6,000 LLM calls saved**

### Why Technique-Driven (Not Count-Based)?

Early designs considered generating N abilities per category × platform. The final approach generates **exactly one ability per technique × platform combination** because:
- Complete MITRE coverage — every technique gets at least one ability
- No duplicates — deduplication ensures `(technique_id, platform)` uniqueness
- Deterministic output — re-running produces the same manifest

---

## 12. Configuration Reference

All batch generation constants are centralized in `src/config.py`:

```python
# Smart matrix: category → meaningful platforms
GENERATION_MATRIX: dict[str, list[str]] = { ... }  # 13 categories

# Concurrency ceiling (tuned for Gemini tier-3)
BATCH_CONCURRENCY: int = 100

# Output directory for generated JSON files
BATCH_OUTPUT_DIR: Path = Path("output/abilities/")
```

The safety layer toggle (`enable_safety_layer` in Settings) applies to batch generation as well — when disabled, abilities skip `SafetyValidator.validate()` and no warnings are attached.

---

## 13. Comparison with Interactive Flow

| Aspect | Interactive (`ReasoningEngine`) | Batch (`BatchGenerator`) |
|--------|--------------------------------|--------------------------|
| Entry point | FastAPI `/generate` endpoint | `scripts/generate_all.py` CLI |
| User input | Category + platform required | None (automatic from matrix) |
| Phase A (tool calling) | 10-iteration LLM loop | Skipped — direct graph query |
| Phase B (composition) | 1 LLM call | 1 LLM call |
| Concurrency | Sequential | 100 parallel (configurable) |
| Output | Single Ability JSON response | One JSON file per ability in category folders |
| Safety | Gated by `enable_safety_layer` | Same gate |
| Scope | One ability at a time | Full ATT&CK sweep |
| State sharing | Uses shared ReasoningEngine | Own instances of all resources |
