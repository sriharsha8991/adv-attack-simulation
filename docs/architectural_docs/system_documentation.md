# Blackhat AI Agent — System Documentation

> **Controlled Adversary Scenario Compiler** | Version 0.1.0 | February 2026

---

## Table of Contents

- [1. What This System Does](#1-what-this-system-does)
- [2. Architecture Overview](#2-architecture-overview)
- [3. Data Sources & Ingestion](#3-data-sources--ingestion)
- [4. Knowledge Graph (Neo4j)](#4-knowledge-graph-neo4j)
- [5. MISP Galaxy Enrichment](#5-misp-galaxy-enrichment)
- [6. LLM Integration — How We Use the Model](#6-llm-integration--how-we-use-the-model)
- [7. Tool System — How the LLM Queries the Knowledge Graph](#7-tool-system--how-the-llm-queries-the-knowledge-graph)
- [8. Two-Phase Generation Pipeline](#8-two-phase-generation-pipeline)
- [9. Structured Output — Pydantic Schema Enforcement](#9-structured-output--pydantic-schema-enforcement)
- [10. Safety Validation Pipeline (18 Rules)](#10-safety-validation-pipeline-18-rules)
- [11. API Layer](#11-api-layer)
- [12. Output Format — The Ability Object](#12-output-format--the-ability-object)
- [13. End-to-End Flow Diagram](#13-end-to-end-flow-diagram)
- [14. Module Map](#14-module-map)
- [15. Configuration & Environment](#15-configuration--environment)
- [16. Development Phases Completed](#16-development-phases-completed)

---

## 1. What This System Does

The Blackhat AI Agent is a **tool-augmented LLM pipeline** that generates simulation-safe adversary scenarios (called "Abilities") for defensive security testing. Each Ability is a structured JSON payload describing:

- **What** attack technique to simulate (mapped to MITRE ATT&CK)
- **How** to execute it (copy-paste executable platform commands)
- **Who** uses this technique in the real world (APT groups, tools, campaigns)
- **How to detect** it (telemetry sources, SIEM rules)
- **How to clean up** after simulation

The system **never executes** any commands. All output is advisory — requiring human approval before any execution is possible.

### Core Principles

| Principle | Enforcement |
|---|---|
| **Human-in-the-Loop** | All abilities output as `PENDING` — human must approve |
| **Simulation-Only** | `simulation_only: true` hardcoded, cannot be overridden |
| **Fail Closed** | Any safety check failure → ability `BLOCKED` automatically |
| **Full Lineage** | Every ability records: model used, tools called, tokens consumed, blocklist version |
| **Copy-Paste Executable** | Commands are syntactically valid, directly runnable — no placeholders, no comments |

---

## 2. Architecture Overview

The system follows a **7-layer model** where each layer has a single responsibility:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Layer 7: API / FastAPI                       │
│               POST /generate  →  JSON response                  │
├─────────────────────────────────────────────────────────────────┤
│                Layer 6: Safety & Governance                      │
│         18-rule validation pipeline  →  PASS / BLOCK            │
├─────────────────────────────────────────────────────────────────┤
│           Layer 5: Executor & Payload Builder                   │
│      (Covered by Phase B structured output + Pydantic schema)   │
├─────────────────────────────────────────────────────────────────┤
│           Layer 4 + 3: Attack Reasoning Engine                  │
│      Phase A (tool reasoning) + Phase B (structured output)     │
├───────────────────────┬─────────────────────────────────────────┤
│  Layer 2: MISP Galaxy │      Layer 1: Knowledge Ingestion       │
│  (in-memory enrichment│  STIX 2.1 → Neo4j knowledge graph      │
│   4 JSON files)       │  enterprise-attack.json → 9 node types  │
├───────────────────────┴─────────────────────────────────────────┤
│                     Infrastructure                               │
│   Neo4j Aura  ·  Gemini 3 Flash  ·  Pydantic v2  ·  FastAPI   │
└─────────────────────────────────────────────────────────────────┘
```

### How the Layers Map to Code

| Layer | Files | Purpose |
|---|---|---|
| **1 — Ingestion** | `src/layers/layer1_ingestion.py`, `src/graph/loader.py`, `src/graph/schema.py` | Download MITRE ATT&CK STIX bundle → parse → load into Neo4j |
| **2 — Enrichment** | `src/layers/layer2_enrichment.py`, `src/tools/misp_tools.py` | MISP Galaxy download → in-memory indexes → technique-keyed lookups |
| **3 — Reasoning** | `src/layers/layer3_reasoning.py`, `src/tools/graph_tools.py`, `src/tools/cti_tools.py` | Two-phase LLM pipeline with tool calling |
| **4/5 — Composition** | (Merged into Layer 3 Phase B) | LLM generates structured `Ability` JSON constrained by Pydantic schema |
| **6 — Safety** | `src/layers/layer6_safety.py` | 18-rule deterministic validation: blocklist, platform coherence, content checks |
| **7 — API** | `src/api/main.py` | FastAPI endpoint, lifespan management, response formatting |

---

## 3. Data Sources & Ingestion

### MITRE ATT&CK Enterprise (STIX 2.1)

The primary knowledge source. ~50 MB JSON bundle containing every technique, group, tool, campaign, and their relationships.

```
Download URL: https://raw.githubusercontent.com/mitre/cti/.../enterprise-attack.json
Cache path:   src/data/mitre/enterprise-attack.json
Parser:       stix2.MemoryStore
```

**Ingestion pipeline** (`layer1_ingestion.py`):

1. `download_stix_bundle()` — streams to local cache (skips if cached)
2. `load_stix_store()` — loads into `stix2.MemoryStore`
3. Nine specialized parsers extract typed dicts:

| Parser | Output Type | Neo4j Label | Count |
|---|---|---|---|
| `parse_tactics` | Tactic dicts | `:Tactic` | ~14 |
| `parse_techniques` | Technique dicts (parent only) | `:Technique` | ~200 |
| `parse_subtechniques` | SubTechnique dicts | `:SubTechnique` | ~400 |
| `parse_intrusion_sets` | APT group dicts | `:IntrusionSet` | ~140 |
| `parse_tools` | Tool dicts | `:Tool` | ~70 |
| `parse_malware` | Malware dicts | `:Malware` | ~500 |
| `parse_data_sources` | Data source dicts | `:DataSource` | ~40 |
| `parse_mitigations` | Mitigation dicts | `:Mitigation` | ~40 |
| `parse_campaigns` | Campaign dicts with temporal data | `:Campaign` | ~25 |

4. `parse_relationships()` — groups STIX relationship objects by type: `uses`, `mitigates`, `detects`, `subtechnique-of`, `attributed-to`
5. `parse_tactic_technique_links()` — special case: extracts from `kill_chain_phases` on attack-patterns (not STIX relationships)

All parsers filter out revoked and deprecated objects via `_remove_revoked_deprecated()`.

### Neo4j Graph Loading (`graph/loader.py`)

Batch loads via `UNWIND + MERGE` pattern (idempotent):

- **9 node types** loaded in sequence
- **7 relationship types**: `USES_TECHNIQUE`, `HAS_SUBTECHNIQUE`, `MITIGATES`, `DETECTED_BY`, `CAMPAIGN_USES`, `ATTRIBUTED_TO`, `BELONGS_TO_TACTIC`
- Batch size: 500 items per transaction (Aura transaction limits)

### MISP Galaxy Data (Layer 2)

Four community JSON files from the MISP project, downloaded from GitHub:

| File | Content | In-Memory Index |
|---|---|---|
| `mitre-attack-pattern.json` | Attack pattern UUIDs + metadata | `{technique_id → uuid}` |
| `mitre-intrusion-set.json` | APT groups + technique cross-refs | `{technique_uuid → [groups]}` |
| `mitre-tool.json` | Offensive tools + technique cross-refs | `{technique_uuid → [tools]}` |
| `mitre-malware.json` | Malware families + technique cross-refs | `{technique_uuid → [malware]}` |

**Key design**: Cross-references work via `related[].dest-uuid` fields. Attack patterns must be parsed first to build the UUID-to-technique_id mapping.

---

## 4. Knowledge Graph (Neo4j)

### Schema

```
(:Tactic)─[:BELONGS_TO_TACTIC]─(:Technique)─[:HAS_SUBTECHNIQUE]─(:SubTechnique)
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                 │
             [:USES_TECHNIQUE]  [:MITIGATES]    [:DETECTED_BY]
                    │                │                 │
             (:IntrusionSet)   (:Mitigation)    (:DataSource)
             (:Tool)
             (:Malware)
             (:Campaign)─[:ATTRIBUTED_TO]─(:IntrusionSet)
                       └─[:CAMPAIGN_USES]─(:Technique)
```

### Indexes & Constraints

- **6 uniqueness constraints**: `stix_id` on Technique, SubTechnique, Tactic, IntrusionSet, Campaign + `id` on Ability
- **19 indexes**: Primary lookups (shortname, attack_id), STIX ID indexes, name indexes, Ability indexes

### Query Library (`graph/queries.py`)

12 parameterized Cypher queries covering:
- Technique discovery by tactic / platform
- Sub-technique navigation
- Group, tool, malware associations
- Detection guidance and mitigations
- Campaign temporal data with group attribution
- Full combined context in single query (`FULL_TECHNIQUE_CONTEXT`)

---

## 5. MISP Galaxy Enrichment

`GalaxyManager` loads all 4 galaxy files into in-memory dictionaries, then provides fast lookups:

```python
galaxy.get_technique_context("T1003.001")
→ {
    "attack_pattern": {...},          # From attack-pattern galaxy
    "groups": [{"name": "APT29", "country": "russia", ...}],
    "tools":  [{"name": "Mimikatz", ...}],
    "malware": [{"name": "NotPetya", ...}],
  }
```

This data is merged with Neo4j query results during tool calls to produce comprehensive `ThreatIntelContext` objects with deduplicated groups, tools, and campaign lists.

---

## 6. LLM Integration — How We Use the Model

### Provider Architecture

A single abstract contract (`LLMClient`) with one method — `generate()` — that handles three modes based on arguments:

```python
class LLMClient(ABC):
    @abstractmethod
    def generate(
        self,
        messages: list[dict],
        *,
        tools: list[Callable] | None = None,      # → function calling mode
        schema: type[BaseModel] | None = None,     # → structured output mode
        max_iterations: int = 10,
    ) -> GenerateResult: ...
```

| Argument | Mode | Behavior |
|---|---|---|
| Neither `tools` nor `schema` | Plain text | Standard chat completion |
| `tools=[...]` | Function calling | LLM can call tools, results fed back (multi-turn) |
| `schema=Ability` | Structured output | LLM must return JSON matching the Pydantic schema |
| Both (OpenAI only) | Combined | Tool loop first, then structured parse |

### Provider Implementations

| Provider | Client | SDK | Notes |
|---|---|---|---|
| **Gemini 3 Flash** (primary) | `GeminiClient` | `google-genai` | Automatic function calling, native `responseSchema`, `_strip_schema_examples()` |
| **Groq** (fallback) | `OpenAICompatClient` | `openai` | Manual tool dispatch loop, JSON schema injected into system prompt |
| **Ollama** (local) | `OpenAICompatClient` | `openai` | Same as Groq, `base_url=localhost` |

### Factory

```python
from src.llm import create_llm_client
llm = create_llm_client(settings)  # settings.llm_provider = "gemini" | "groq" | "ollama"
```

### Gemini-Specific Behavior

**Tool calling**: Uses `automaticFunctionCalling` — the SDK handles the entire call→execute→re-prompt cycle internally. We pass Python closures directly and Gemini auto-generates tool schemas from type hints + docstrings.

**Structured output**: `responseSchema` uses the Pydantic model's JSON schema (cleaned of `examples` keys via `_strip_schema_examples()`). Even with native schema enforcement, we always do manual `model_validate_json()` as a safety net with up to 3 validation retries.

**Schema examples fix**: Gemini's `types.Schema` validator rejects the `examples` keyword that Pydantic v2 includes in JSON schemas. Our `_strip_schema_examples()` recursively removes all `examples` keys before sending to the API.

### Retry & Error Handling

All providers use exponential backoff with jitter:
- Max retries: 3
- Retryable: 429 (rate limit), 5xx (server error), timeouts, connection errors
- Non-retryable: 401/403 (auth errors)

---

## 7. Tool System — How the LLM Queries the Knowledge Graph

### The 4 LLM-Facing Tools

Created as closures that capture shared `Neo4jConnection` + `GalaxyManager`:

| Tool | Signature | What It Does |
|---|---|---|
| `get_techniques_by_tactic` | `(tactic: str) → list[dict]` | Discover all techniques in a tactic (e.g., "credential-access") |
| `get_techniques_for_platform` | `(tactic: str, platform: str) → list[dict]` | Techniques filtered by OS/cloud platform |
| `get_subtechniques` | `(technique_id: str) → list[dict]` | Navigate parent → sub-techniques (T1003 → T1003.001, .002, …) |
| `get_technique_intel` | `(technique_id: str) → dict` | **Omnibus enrichment** — 5 Neo4j queries + MISP Galaxy in one call |

### Why Only 4 Tools?

Originally 9+ tools existed. Reduced to 4 to:
- Prevent "choice paralysis" (LLM wastes iterations deciding which overlapping tool to call)
- Save ~450 tokens per prompt (tool schemas included in every API call)
- `get_technique_intel` combines groups + tools + detection + mitigations + campaigns in one call

### Tool Registration Flow

```
graph_tools.py
  └─ create_reasoning_tools(conn, galaxy)
       ├─ get_techniques_by_tactic()     ← closure capturing conn, galaxy
       ├─ get_techniques_for_platform()  ← closure capturing conn, galaxy
       ├─ get_subtechniques()            ← closure capturing conn, galaxy
       └─ get_technique_intel()          ← closure capturing conn, galaxy
            │
            ├─ CTITools.get_technique_intel(tid)   → 5 Neo4j queries merged
            └─ MISPTools.search_misp_galaxy(tid)   → MISP galaxy lookups
```

### Tool Invocation by Provider

**Gemini**: Closures passed directly → SDK auto-generates schemas from type hints + docstrings → `automaticFunctionCalling` manages the call loop internally.

**Groq/Ollama**: `_build_openai_tool_schemas()` converts to OpenAI format → manual dispatch loop in `_tool_loop()` → `dispatch_map[func_name](**args)` → results appended as `{"role": "tool"}` messages → loop until done.

---

## 8. Two-Phase Generation Pipeline

The core of the system. For each `/generate` request:

### Phase A — Reasoning with Tools

**Goal**: Explore the knowledge graph, select techniques, gather comprehensive threat intelligence.

```python
result = llm.generate(
    messages=[system_prompt, user_prompt],
    tools=[4_closures],             # Enable function calling
    max_iterations=10,              # Max tool call rounds
)
```

**Typical tool call sequence** (for `credential_access` on `windows`):

```
1. get_techniques_by_tactic("credential-access")
   → Returns ~15 techniques with IDs, names, descriptions

2. get_subtechniques("T1003")
   → Returns T1003.001 (LSASS), T1003.002 (SAM), T1003.003 (NTDS), ...

3. get_technique_intel("T1003.001")
   → Returns: {groups: [APT29, APT28, ...], tools: [Mimikatz, ProcDump, ...],
      detection: "Sysmon Event ID 10...", mitigations: [...],
      campaigns: [{SolarWinds, 2019-2021, APT29}], misp_galaxy: {...}}

4. get_technique_intel("T1558.003")
   → Returns: Kerberoasting enrichment data

5. get_technique_intel("T1552.001")
   → Returns: Credentials in Files enrichment data
```

**Output**: `GenerateResult` with:
- `text` = full reasoning context (~3000+ chars)
- `tool_calls` = log of every tool invocation
- `total_tokens` = cumulative token consumption

### Phase B — Structured Composition (×N)

**Goal**: For each ability, produce a validated `Ability` JSON using the Phase A context.

```python
result = llm.generate(
    messages=[system_prompt, composition_prompt],
    schema=Ability,                 # Enable structured output
)
```

The `composition_prompt` includes:
- Full Phase A reasoning context
- Task: "Generate ability N of M for {category} targeting {platform}"
- 8 requirements (real technique, real intel, executable commands, no placeholders, cleanup, etc.)

**Output**: `GenerateResult` with:
- `parsed` = validated `Ability` Pydantic instance

### Post-Processing

After each Phase B produces an `Ability`:

1. **`_enforce_safety_fields()`** — Override safety-critical fields regardless of LLM output:
   - `approval_status = PENDING`
   - `created_by = "AI"`
   - `simulation_only = True`
   - `schema_version = "1.0"`
   - `generated_at = <current UTC timestamp>`
   - `agent_version = "0.1.0"`

2. **`SafetyValidator.validate()`** — Run 18 deterministic rules (see Section 10)
   - If any hard rule fails → `approval_status = BLOCKED`
   - Soft warnings stored in `generation_trace.validation_warnings`

3. **Attach `GenerationTrace`** — Audit metadata:
   - `model`: which LLM produced this
   - `tools_called`: list of tool names from Phase A
   - `reasoning_steps`: number of tool calls
   - `total_tokens`: cumulative across both phases
   - `blocklist_version`: which blocklist was active
   - `validation_warnings`: any soft rule warnings

---

## 9. Structured Output — Pydantic Schema Enforcement

### The Ability Schema (Simplified)

```
Ability
├── id: UUID (auto-generated)
├── name: str (≥ 5 chars)
├── description: str (≥ 50 chars)
├── attack_category: AttackCategory (13 enum values)
├── mitre_mapping: MitreMapping
│   ├── tactic: str
│   ├── technique: str (e.g., "T1003")
│   └── sub_technique: Optional[str] (e.g., "T1003.001")
├── threat_intel_context: ThreatIntelContext
│   ├── associated_groups: List[str]
│   ├── associated_tools: List[str]
│   ├── recent_campaigns: List[CampaignUsage]
│   └── detection_guidance: Optional[str]
├── executors: List[Executor] (≥ 1)
│   ├── name: ExecutorType (10 enum values)
│   ├── platform: Platform (6 enum values)
│   ├── privilege_required: PrivilegeLevel (4 enum values)
│   ├── command: str (copy-paste executable)
│   ├── payload_description: str (explanatory text)
│   └── cleanup_procedure: str (copy-paste executable)
├── approval_status: ApprovalStatus (always PENDING from AI)
├── created_by: str (always "AI")
├── simulation_only: bool (always True)
├── schema_version: str
├── generated_at: ISO 8601 timestamp
├── agent_version: str
└── generation_trace: GenerationTrace (audit trail)
```

### How Schema Enforcement Works Per Provider

| Provider | Mechanism | Fallback |
|---|---|---|
| **Gemini** | `responseSchema = cleaned JSON schema` (native) | `model_validate_json()` + 3 retry rounds with error context fed back to model |
| **Groq/Ollama** | `response_format={"type":"json_object"}` + schema in system prompt | `model_validate_json()` + 3 retry rounds |

### Command Field Design

The `command` field description explicitly instructs the LLM:

> "Complete, copy-paste executable command for the target interpreter. Must be syntactically valid and runnable as-is in the declared shell. Use real OS binary names, correct flags, proper escaping, and real filesystem paths. No placeholder values. No inline comments explaining what the command does."

All explanatory text goes in `payload_description` instead.

---

## 10. Safety Validation Pipeline (18 Rules)

Implemented in `layer6_safety.py`. Runs after every ability is generated.

### Hard Rules (12) — Auto-BLOCK on failure

| # | Rule | Check |
|---|---|---|
| 1 | **Schema Valid** | Pydantic validation passed (always true for instances) |
| 2 | **Approval Status** | `approval_status == PENDING` |
| 3 | **Simulation Flag** | `simulation_only == True` |
| 4 | **Creator Tag** | `created_by == "AI"` |
| 5 | **MITRE Mapping** | Technique exists in Neo4j graph |
| 6 | **Executor Present** | At least 1 executor defined |
| 7 | **Command Blocklist** | No command/cleanup matches 22 dangerous regex patterns |
| 8 | **Platform Coherence** | Executor type matches platform; no cross-shell syntax |
| 9 | **Executor Name Enum** | Valid `ExecutorType` value |
| 10 | **Cleanup Present** | Every executor has non-empty `cleanup_procedure` |
| 11 | **Content Check** | Name ≥ 5 chars, description ≥ 50 chars |
| 12 | **Identity Check** | Valid UUID + valid ISO 8601 timestamp |

### Soft Rules (2) — WARN for human review

| # | Rule | Check |
|---|---|---|
| 13 | **Command Syntax** | Unmatched quotes, parentheses, trailing pipes |
| 14 | **Known Binaries** | First token exists in OS-default binary allowlist |

### Command Blocklist (22 Patterns)

Blocks dangerous operations across categories:

| Category | Examples |
|---|---|
| Destructive disk | `rm -rf /`, `format C:`, `dd if=... of=/dev/sd*` |
| Ransomware | `openssl enc -aes...`, `gpg --encrypt`, `cipher /w:` |
| External exfiltration | `curl.*pastebin.com`, `wget.*transfer.sh`, `Invoke-WebRequest.*ngrok` |
| Bootloader/firmware | `dd.*of=/dev/sda`, `bcdedit /set...boot`, `flashrom` |
| Network attacks | `nmap` (non-RFC1918), `masscan`, `hping3` |
| Kernel manipulation | `insmod`, `modprobe`, `sc create...binpath` |
| Cred theft to external | `mimikatz...>...\\\\`, `reg save...sam...\\\\` |

### Platform Coherence Rules

Validates executor type → platform → command syntax alignment:

| Executor | Must Be Platform | Must NOT Contain | Should Contain |
|---|---|---|---|
| `powershell` | windows | `#!/bin/bash`, `#!/bin/sh` | `$env:`, `Get-`, `Set-`, `Invoke-` |
| `cmd` | windows | `$env:`, `Get-Process` | `echo`, `set`, `%var%` |
| `bash` | linux, macos | `$env:`, `Write-Host`, `REM` | `echo`, `grep`, `export` |
| `aws_cli` | cloud_aws + any OS | — | `aws ...` |
| `az_cli` | cloud_azure + any OS | — | `az ...` |

### Audit Trail

Every rule result is appended to `output/safety_audit.jsonl`:

```json
{"timestamp": "2026-02-24T10:30:01Z", "ability_id": "abc-123", "rule": "command_blocklist", "result": "PASS"}
{"timestamp": "2026-02-24T10:30:01Z", "ability_id": "abc-123", "rule": "platform_coherence", "result": "PASS"}
```

---

## 11. API Layer

### FastAPI Service (`src/api/main.py`)

| Route | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check: `{"status": "ok", "engine_ready": true}` |
| `/generate` | POST | Generate abilities via the two-phase pipeline |

### Request

```json
POST /generate
{
  "category": "credential_access",
  "platform": "windows",
  "count": 3
}
```

- `category`: One of 13 `AttackCategory` enum values
- `platform`: One of 6 `Platform` enum values
- `count`: 1–10 (default 1)

### Response

```json
{
  "abilities": [ { /* full Ability JSON */ }, ... ],
  "count": 3,
  "elapsed_seconds": 45.2,
  "model": "gemini-3-flash-preview",
  "validation_summary": {
    "total": 3,
    "passed": 2,
    "blocked": 1,
    "warned": 1
  }
}
```

### Lifespan Management

Resources are initialized once at startup and shared across all requests:

```
Startup:
  1. Settings loaded from .env
  2. LLM client created (Gemini/Groq/Ollama)
  3. Neo4j connection established
  4. MISP Galaxy data loaded (4 files → in-memory indexes)
  5. ReasoningEngine initialized with llm + conn + galaxy + SafetyValidator

Shutdown:
  1. ReasoningEngine.close() → closes owned Neo4j connection
```

---

## 12. Output Format — The Ability Object

### Example (Actual Generated Output)

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "LSASS Memory Credential Dumping via comsvcs.dll",
  "description": "Dumps LSASS process memory using the comsvcs.dll MiniDump export to harvest cached credentials. This sub-technique (T1003.001) is used by APT29, APT28, and Wizard Spider in enterprise Windows environments to extract NTLM hashes and Kerberos tickets from memory.",
  "attack_category": "credential_access",
  "mitre_mapping": {
    "tactic": "credential-access",
    "technique": "T1003",
    "sub_technique": "T1003.001"
  },
  "threat_intel_context": {
    "associated_groups": ["APT29", "APT28", "Wizard Spider"],
    "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
    "recent_campaigns": [
      {
        "campaign_name": "SolarWinds Compromise",
        "first_seen": "2019-08-01T05:00:00+00:00",
        "last_seen": "2021-01-01T06:00:00+00:00",
        "attributed_groups": ["APT29"],
        "description_snippet": null
      }
    ],
    "detection_guidance": "Monitor for access to LSASS process via Sysmon Event ID 10. Enable Credential Guard. Alert on rundll32.exe loading comsvcs.dll with MiniDump export."
  },
  "executors": [
    {
      "name": "powershell",
      "platform": "windows",
      "privilege_required": "admin",
      "command": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\lsass_dump.dmp full",
      "payload_description": "Dumps LSASS process memory via comsvcs.dll MiniDump export. Triggers Sysmon Event ID 10 (ProcessAccess) and Windows Defender Credential Guard alerts. Used by APT29 and APT28.",
      "cleanup_procedure": "Remove-Item -Path $env:TEMP\\lsass_dump.dmp -Force -ErrorAction SilentlyContinue"
    }
  ],
  "approval_status": "PENDING",
  "created_by": "AI",
  "simulation_only": true,
  "schema_version": "1.0",
  "generated_at": "2026-02-24T14:30:00Z",
  "agent_version": "0.1.0",
  "generation_trace": {
    "model": "gemini-3-flash-preview",
    "tools_called": [
      "get_techniques_by_tactic",
      "get_subtechniques",
      "get_technique_intel",
      "get_technique_intel",
      "get_technique_intel"
    ],
    "reasoning_steps": 5,
    "total_tokens": 8200,
    "blocklist_version": "1.0.0",
    "validation_warnings": []
  }
}
```

---

## 13. End-to-End Flow Diagram

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                          API REQUEST                                         │
 │  POST /generate {"category": "credential_access", "platform": "windows"}    │
 └─────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                     REASONING ENGINE STARTUP                                 │
 │                                                                              │
 │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐   │
 │  │  LLM Client │  │ Neo4j Conn   │  │ Galaxy Mgr   │  │ Safety Validtr │   │
 │  │ (Gemini 3)  │  │ (Aura cloud) │  │ (4 JSON idx) │  │ (18 rules)     │   │
 │  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘   │
 │         │                │                  │                   │            │
 │         │    4 Tool Closures created capturing conn + galaxy    │            │
 │         │    ┌──────────────────────────────────────────┐       │            │
 │         │    │ get_techniques_by_tactic(tactic)         │       │            │
 │         │    │ get_techniques_for_platform(tactic, plat)│       │            │
 │         │    │ get_subtechniques(technique_id)          │       │            │
 │         │    │ get_technique_intel(technique_id)        │       │            │
 │         │    └──────────────────┬───────────────────────┘       │            │
 └─────────┼──────────────────────┼────────────────────────────────┼────────────┘
           │                      │                                │
           ▼                      ▼                                │
 ┌──────────────────────────────────────────────────────────┐      │
 │              PHASE A — REASONING WITH TOOLS               │      │
 │                                                           │      │
 │  LLM.generate(messages, tools=[4 closures], max_iter=10) │      │
 │                                                           │      │
 │  ┌─── LLM Reasoning Loop ──────────────────────────────┐ │      │
 │  │                                                      │ │      │
 │  │  1. LLM decides: "I need credential-access          │ │      │
 │  │     techniques for windows"                          │ │      │
 │  │     → calls get_techniques_for_platform(             │ │      │
 │  │       "credential-access", "windows")                │ │      │
 │  │     → Neo4j returns 12 techniques                    │ │      │
 │  │                                                      │ │      │
 │  │  2. LLM decides: "T1003 looks promising,            │ │      │
 │  │     let me explore sub-techniques"                   │ │      │
 │  │     → calls get_subtechniques("T1003")               │ │      │
 │  │     → Returns T1003.001, .002, .003, .004, ...       │ │      │
 │  │                                                      │ │      │
 │  │  3. LLM decides: "Get full intel for T1003.001"     │ │      │
 │  │     → calls get_technique_intel("T1003.001")         │ │      │
 │  │     → Neo4j: 5 queries (groups, tools, detection,   │ │      │
 │  │       mitigations, campaigns) MERGED                 │ │      │
 │  │     → MISP Galaxy: community enrichment data         │ │      │
 │  │     → Returns comprehensive intel dict               │ │      │
 │  │                                                      │ │      │
 │  │  4-5. More get_technique_intel calls...              │ │      │
 │  │                                                      │ │      │
 │  │  6. LLM produces reasoning summary:                 │ │      │
 │  │     "Selected T1003.001, T1558.003, T1552.001..."   │ │      │
 │  │                                                      │ │      │
 │  └──────────────────────────────────────────────────────┘ │      │
 │                                                           │      │
 │  Output: reasoning_context (text) + tool_call_log         │      │
 └───────────────────────────┬───────────────────────────────┘      │
                             │                                      │
                             ▼                                      │
 ┌──────────────────────────────────────────────────────────┐       │
 │         PHASE B — STRUCTURED COMPOSITION (×N)            │       │
 │                                                          │       │
 │  For each ability (1 to count):                          │       │
 │                                                          │       │
 │  LLM.generate(                                           │       │
 │    messages=[system_prompt, composition_prompt],          │       │
 │    schema=Ability     ← Pydantic model as schema         │       │
 │  )                                                       │       │
 │                                                          │       │
 │  ┌─── Composition Prompt ─────────────────────────────┐  │       │
 │  │  ## Research Context                               │  │       │
 │  │  <full Phase A reasoning text>                     │  │       │
 │  │                                                    │  │       │
 │  │  ## Task                                           │  │       │
 │  │  Generate ability 1 of 3 for credential_access     │  │       │
 │  │  targeting windows.                                │  │       │
 │  │                                                    │  │       │
 │  │  ## Requirements                                   │  │       │
 │  │  1. attack_category = credential_access            │  │       │
 │  │  2. Real technique from research                   │  │       │
 │  │  3. Real threat intel — no fabrication              │  │       │
 │  │  4. Executable commands, no comments/placeholders  │  │       │
 │  │  5. payload_description has explanatory text        │  │       │
 │  │  6. simulation_only = true                         │  │       │
 │  │  7. approval_status = PENDING                      │  │       │
 │  │  8. created_by = AI                                │  │       │
 │  └────────────────────────────────────────────────────┘  │       │
 │                                                          │       │
 │  Gemini: responseSchema = Ability JSON schema (cleaned)  │       │
 │  → model_validate_json() with up to 3 retries           │       │
 │                                                          │       │
 │  Output: validated Ability (Pydantic instance)           │       │
 └───────────────────────────┬──────────────────────────────┘       │
                             │                                      │
                             ▼                                      │
 ┌──────────────────────────────────────────────────────────┐       │
 │           POST-GENERATION ENFORCEMENT                    │       │
 │                                                          │       │
 │  _enforce_safety_fields(ability):                        │       │
 │    ability.approval_status = PENDING   (override LLM)    │       │
 │    ability.created_by = "AI"           (override LLM)    │       │
 │    ability.simulation_only = True      (override LLM)    │       │
 │    ability.schema_version = "1.0"                        │       │
 │    ability.generated_at = <now UTC>                      │       │
 │    ability.agent_version = "0.1.0"                       │       │
 └───────────────────────────┬──────────────────────────────┘       │
                             │                                      │
                             ▼                                      │
 ┌────────────────────────────────────────────────────────────┐     │
 │            SAFETY VALIDATION (18 Rules)                     │◄───┘
 │                                                             │
 │  SafetyValidator.validate(ability):                         │
 │                                                             │
 │  HARD RULES (auto-BLOCK):                                   │
 │  ✓ schema_valid         ✓ approval_status (== PENDING)      │
 │  ✓ simulation_flag      ✓ creator_tag (== "AI")             │
 │  ✓ mitre_mapping        ✓ executor_present (≥ 1)            │
 │  ✓ command_blocklist    ✓ platform_coherence                │
 │  ✓ executor_name_enum   ✓ cleanup_present                   │
 │  ✓ content_check        ✓ identity_check                    │
 │                                                             │
 │  SOFT RULES (WARN):                                         │
 │  ⚠ command_syntax       ⚠ known_binaries                    │
 │                                                             │
 │  → If hard failure: ability.approval_status = BLOCKED       │
 │  → Warnings stored in generation_trace.validation_warnings  │
 │  → Every rule result → output/safety_audit.jsonl            │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                GENERATION TRACE ATTACHMENT                    │
 │                                                              │
 │  ability.generation_trace = GenerationTrace(                 │
 │    model = "gemini-3-flash-preview",                         │
 │    tools_called = ["get_techniques_by_tactic", ...],         │
 │    reasoning_steps = 5,                                      │
 │    total_tokens = 8200,                                      │
 │    blocklist_version = "1.0.0",                              │
 │    validation_warnings = ["bash: 'xyzutil' not in..."],      │
 │  )                                                           │
 └────────────────────────────┬─────────────────────────────────┘
                              │
                              ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                        API RESPONSE                              │
 │                                                                  │
 │  {                                                               │
 │    "abilities": [ {Ability JSON}, {Ability JSON}, {Ability JSON}]│
 │    "count": 3,                                                   │
 │    "elapsed_seconds": 45.2,                                      │
 │    "model": "gemini-3-flash-preview",                            │
 │    "validation_summary": {                                       │
 │      "total": 3, "passed": 2, "blocked": 1, "warned": 1         │
 │    }                                                             │
 │  }                                                               │
 └──────────────────────────────────────────────────────────────────┘
```

---

## 14. Module Map

### Directory Structure with Responsibilities

```
src/
├── __init__.py
├── config.py                       # Settings from .env (Pydantic BaseSettings)
│
├── models/                         # Data models (source of truth)
│   ├── enums.py                    #   5 enums: ApprovalStatus, AttackCategory,
│   │                               #   Platform, ExecutorType, PrivilegeLevel
│   └── ability.py                  #   6 Pydantic models: Ability, Executor,
│                                   #   MitreMapping, ThreatIntelContext,
│                                   #   CampaignUsage, GenerationTrace
│
├── graph/                          # Neo4j knowledge graph
│   ├── connection.py               #   Neo4jConnection (driver wrapper)
│   ├── schema.py                   #   19 indexes + 6 constraints (idempotent)
│   ├── loader.py                   #   STIX → Neo4j batch loader (UNWIND+MERGE)
│   └── queries.py                  #   12 parameterized Cypher queries
│
├── layers/                         # Processing pipeline
│   ├── layer1_ingestion.py         #   STIX 2.1 download + parse (9 parsers)
│   ├── layer2_enrichment.py        #   MISP Galaxy download + in-memory indexes
│   ├── layer3_reasoning.py         #   ReasoningEngine: Phase A + Phase B + safety
│   └── layer6_safety.py            #   SafetyValidator: 18 rules + audit log
│
├── tools/                          # LLM tool interfaces
│   ├── cti_tools.py                #   CTITools: 10 Neo4j query methods + dispatch
│   ├── misp_tools.py               #   MISPTools: MISP Galaxy bridge + enrichment
│   └── graph_tools.py              #   4 LLM-facing closures (capturing conn+galaxy)
│
├── llm/                            # LLM provider abstraction
│   ├── base.py                     #   LLMClient ABC + GenerateResult dataclass
│   ├── gemini_client.py            #   GeminiClient (google-genai, auto-FC)
│   ├── openai_compat.py            #   OpenAICompatClient (Groq, Ollama)
│   └── __init__.py                 #   create_llm_client() factory
│
├── api/                            # HTTP API
│   └── main.py                     #   FastAPI: POST /generate, GET /health
│
└── data/                           # Cached data files
    ├── mitre/
    │   └── enterprise-attack.json  #   MITRE ATT&CK STIX 2.1 bundle (~50 MB)
    └── misp_galaxies/
        ├── mitre-attack-pattern.json
        ├── mitre-intrusion-set.json
        ├── mitre-tool.json
        └── mitre-malware.json
```

### Dependency Graph

```
config.py ◄──────────────── everything
    │
    ▼
models/enums.py ◄─────────── models/ability.py
models/ability.py ◄────────── layer3_reasoning.py, layer6_safety.py, api/main.py
    │
    ▼
graph/connection.py ◄──────── graph/schema.py, graph/loader.py
graph/queries.py ◄─────────── tools/cti_tools.py
    │
    ▼
tools/cti_tools.py ◄───────── tools/graph_tools.py, tools/misp_tools.py
tools/misp_tools.py ◄──────── tools/graph_tools.py
tools/graph_tools.py ◄─────── layer3_reasoning.py
    │
    ▼
layers/layer1_ingestion.py     (standalone — STIX parsing)
layers/layer2_enrichment.py ◄── tools/graph_tools.py, layer3_reasoning.py
layers/layer3_reasoning.py ◄── api/main.py
layers/layer6_safety.py ◄───── layer3_reasoning.py
    │
    ▼
llm/base.py ◄──────────────── llm/gemini_client.py, llm/openai_compat.py
llm/__init__.py ◄──────────── api/main.py
    │
    ▼
api/main.py                    (entry point — FastAPI)
```

---

## 15. Configuration & Environment

### Required Environment Variables (`.env`)

```bash
# LLM Provider (choose one)
LLM_PROVIDER=gemini                           # gemini | groq | ollama
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-3-flash-preview           # default

# Neo4j Aura
NEO4J_URI=neo4j+s://xxxxxxxx.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your-neo4j-password
NEO4J_DATABASE=neo4j

# Optional
LOG_LEVEL=INFO
MAX_ABILITIES_PER_BATCH=20
```

### Dependencies (`requirements.txt`)

| Category | Package | Purpose |
|---|---|---|
| LLM | `google-genai` | Gemini unified SDK (auto function calling, structured output) |
| LLM | `openai>=1.30.0` | Groq/Ollama via OpenAI-compatible API |
| Graph | `neo4j>=5.20.0` | Neo4j Python driver |
| STIX | `stix2>=3.0.0` | MITRE ATT&CK STIX 2.1 parsing |
| HTTP | `requests>=2.31.0`, `httpx>=0.27.0` | Downloads (STIX bundle, MISP galaxies) |
| Validation | `pydantic>=2.7.0`, `pydantic-settings>=2.0.0` | Schema validation, settings |
| API | `fastapi`, `uvicorn` | HTTP endpoint |
| CLI | `rich>=13.7.0`, `click>=8.1.0` | Rich console output |

---

## 16. Development Phases Completed

| Phase | Status | What Was Built |
|---|---|---|
| **1 — Architecture & Data Modeling** | ✅ Complete | 7-layer spec, Pydantic models, enums, docs |
| **2 — Knowledge Ingestion** | ✅ Complete | STIX download + parse → Neo4j (9 node types, 7 relationships, ~1757 nodes, ~21K rels) |
| **3 — CTI Enrichment** | ✅ Complete | MISP Galaxy manager + CTI query tools + graph tool closures |
| **4 — Attack Reasoning Engine** | ✅ Complete | LLM abstraction (Gemini/Groq/Ollama), single `generate()` method, tool calling, structured output |
| **5 — Ability Composition** | ✅ Complete | Two-phase pipeline (Phase A: reasoning → Phase B: structured), Executor generation via Pydantic schema |
| **6 — Safety & API** | ✅ Complete | 18-rule SafetyValidator, command blocklist, platform coherence, FastAPI endpoint, validation summary |
| **7 — Testing & Demo** | 🔄 Pending | Cross-category testing, edge cases, demo notebook |

### Key Design Decisions Made During Development

| Decision | Rationale |
|---|---|
| **Single `generate()` method** (not `chat()` / `chat_with_tools()` / `chat_structured()`) | Matches Google GenAI SDK's unified API; simpler dispatch logic |
| **4 tools, not 9+** | Prevents LLM "choice paralysis"; `get_technique_intel` is an omnibus call |
| **Commands are copy-paste executable** (no simulation markers in command body) | `simulation_only: true` + `created_by: "AI"` + `approval_status: PENDING` serve as programmatic safety signals; `payload_description` carries the explanatory text |
| **Post-generation safety override** | AI can never approve its own output; `_enforce_safety_fields()` hardcodes PENDING + AI + True |
| **`_strip_schema_examples()`** | Gemini's `types.Schema` validator rejects Pydantic's `examples` keyword; recursive removal before API call |
| **Soft vs hard rules** | Syntax and binary checks WARN (LLM patterns can be uncommon but valid); platform coherence and blocklist hard-BLOCK |
| **No CLI scripts** | Everything runs through the API — single `/generate` endpoint is the only interface |
