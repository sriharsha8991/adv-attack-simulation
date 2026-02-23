# Development Plan — Day-by-Day Roadmap

> MVP Target: ~1 week (flexible) · Start: February 20, 2026

---

## Table of Contents

- [Timeline Overview](#timeline-overview)
- [Phase 1 — Architecture & Data Modeling (Day 1–2)](#phase-1--architecture--data-modeling-day-12)
- [Phase 2 — Knowledge Ingestion (Day 2–3)](#phase-2--knowledge-ingestion-day-23)
- [Phase 3 — Threat Intelligence Enrichment (Day 3–4)](#phase-3--threat-intelligence-enrichment-day-34)
- [Phase 4 — Attack Reasoning Engine (Day 4–5)](#phase-4--attack-reasoning-engine-day-45)
- [Phase 5 — Ability Composition + Executor Builder (Day 5–6)](#phase-5--ability-composition--executor-builder-day-56)
- [Phase 6 — Safety & API Integration (Day 6–7)](#phase-6--safety--api-integration-day-67)
- [Phase 7 — Testing & Demo (Day 7+)](#phase-7--testing--demo-day-7)
- [Verification Matrix](#verification-matrix)
- [Risk Register](#risk-register)

---

## Timeline Overview

```
Day 1   Day 2   Day 3   Day 4   Day 5   Day 6   Day 7
 │       │       │       │       │       │       │
 ├───────┤       │       │       │       │       │
 │Phase 1│       │       │       │       │       │
 │Arch + │       │       │       │       │       │
 │Models │       │       │       │       │       │
 │       ├───────┤       │       │       │       │
 │       │Phase 2│       │       │       │       │
 │       │Ingest │       │       │       │       │
 │       │MITRE  │       │       │       │       │
 │       │       ├───────┤       │       │       │
 │       │       │Phase 3│       │       │       │
 │       │       │CTI    │       │       │       │
 │       │       │Enrich │       │       │       │
 │       │       │       ├───────┤       │       │
 │       │       │       │Phase 4│       │       │
 │       │       │       │Reason │       │       │
 │       │       │       │Engine │       │       │
 │       │       │       │       ├───────┤       │
 │       │       │       │       │Phase 5│       │
 │       │       │       │       │Compose│       │
 │       │       │       │       │+Exec  │       │
 │       │       │       │       │       ├───────┤
 │       │       │       │       │       │Phase 6│
 │       │       │       │       │       │Safety │
 │       │       │       │       │       │+ API  │
 │       │       │       │       │       │       ├──►
 │       │       │       │       │       │       │Phase 7
 │       │       │       │       │       │       │Test
 │       │       │       │       │       │       │Demo
```

---

## Phase 1 — Architecture & Data Modeling (Day 1–2)

### Objective

Establish the project foundation: structure, schemas, configuration, and Neo4j connection.

### Tasks

#### 1.1 Create project directory structure

Create the full directory tree as defined in README.md:

```
src/
├── __init__.py
├── config.py
├── models/
│   ├── __init__.py
│   ├── ability.py
│   └── enums.py
├── layers/ (empty __init__.py stubs)
├── graph/
│   ├── __init__.py
│   ├── connection.py
│   ├── schema.py
│   ├── loader.py
│   └── queries.py
├── llm/
│   ├── __init__.py
│   ├── base.py
│   ├── gemini_client.py
│   └── openai_compat.py
├── tools/
│   ├── __init__.py
│   ├── graph_tools.py
│   ├── cti_tools.py
│   ├── misp_tools.py
│   └── validation_tools.py
└── data/
    ├── mitre/
    └── misp_galaxies/
scripts/
output/abilities/
```

**Deliverable**: Empty project skeleton with all `__init__.py` files.

#### 1.2 Implement Pydantic models

File: `src/models/enums.py` + `src/models/ability.py`

- Define all enums: `ApprovalStatus`, `AttackCategory`, `Platform`, `PrivilegeLevel`
- Define all models: `MitreMapping`, `Executor`, `ThreatIntelContext`, `GenerationTrace`, `Ability`
- Add `Field(description=...)` on every field (Gemini uses these)
- Add `Config.json_schema_extra` with examples
- Test: `Ability.model_json_schema()` exports valid JSON Schema

**Deliverable**: Complete Pydantic models. Unit tests pass.

#### 1.3 Implement central config

File: `src/config.py`

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # LLM
    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3-flash-preview"
    groq_api_key: str = ""
    groq_model: str = "qwen/qwen3-32b"
    ollama_model: str = "qwen3:32b"
    ollama_base_url: str = "http://localhost:11434/v1"
    
    # Neo4j
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"
    
    # Safety
    max_abilities_per_batch: int = 20
    enable_api_submission: bool = False
    backend_api_url: str = ""
    
    class Config:
        env_file = ".env"
```

**Deliverable**: Config loads from `.env`. Test: settings object initializes correctly.

#### 1.4 Neo4j connection wrapper

File: `src/graph/connection.py`

- Connect to Neo4j Aura using `neo4j` Python driver
- Methods: `run_query(cypher, params)`, `run_write(cypher, params)`, `clear_all()`, `close()`
- Connection pooling via driver
- Test: `driver.verify_connectivity()` succeeds against Aura instance

**Deliverable**: Working Neo4j connection. Connectivity test passes.

#### 1.5 Requirements and environment

Files: `requirements.txt`, `.env.template`

```
google-genai
openai>=1.30.0
neo4j>=5.20.0
stix2>=3.0.0
pymisp>=2.5.0
pydantic>=2.7.0
pydantic-settings>=2.0.0
python-dotenv>=1.0.0
rich>=13.7.0
click>=8.1.0
requests>=2.31.0
```

**Deliverable**: `pip install -r requirements.txt` succeeds. `.env.template` created.

### Day 1–2 Verification Checkpoint

- [ ] Project structure created
- [ ] `Ability.model_validate(sample_data)` works
- [ ] `Ability.model_json_schema()` exports valid schema
- [ ] Neo4j connection test passes
- [ ] Config loads from `.env`
- [ ] All dependencies install successfully

---

## Phase 2 — Knowledge Ingestion (Day 2–3)

### Objective

Parse MITRE ATT&CK STIX 2.1 data and load it into the Neo4j knowledge graph.

### Tasks

#### 2.1 Implement STIX parser

File: `src/layers/layer1_ingestion.py`

Steps:
1. Download `enterprise-attack.json` from GitHub raw URL (or use local cache)
2. Load into `stix2.MemoryStore`
3. Filter objects by type using `stix2.Filter`
4. Remove revoked and deprecated objects
5. Transform each STIX object into a Neo4j-compatible dict
6. Extract relationships from STIX `relationship` objects

Key parsing functions:
- `parse_tactics(src)` → list of tactic dicts
- `parse_techniques(src)` → list of technique dicts (is_subtechnique=false)
- `parse_subtechniques(src)` → list of subtechnique dicts (is_subtechnique=true)
- `parse_intrusion_sets(src)` → list of group dicts
- `parse_tools(src)` → list of tool dicts
- `parse_malware(src)` → list of malware dicts
- `parse_relationships(src)` → list of relationship dicts (source_ref, target_ref, type)
- `parse_tactic_technique_links(techniques, tactics)` → list of technique→tactic links (from kill_chain_phases)

**Deliverable**: Parser extracts all objects and relationships from STIX bundle.

#### 2.2 Implement Neo4j graph schema

File: `src/graph/schema.py`

Functions:
- `create_indexes(driver)` — create all indexes from knowledge_graph_schema.md
- `create_constraints(driver)` — create uniqueness constraints
- `clear_graph(driver)` — `MATCH (n) DETACH DELETE n`

**Deliverable**: Schema script runs without errors on Aura instance.

#### 2.3 Implement Neo4j batch loader

File: `src/graph/loader.py`

Functions:
- `load_tactics(driver, tactics)` — UNWIND + MERGE
- `load_techniques(driver, techniques)` — UNWIND + MERGE
- `load_subtechniques(driver, subtechniques)` — UNWIND + MERGE
- `load_intrusion_sets(driver, groups)` — UNWIND + MERGE
- `load_tools(driver, tools)` — UNWIND + MERGE
- `load_malware(driver, malware)` — UNWIND + MERGE
- `load_relationships(driver, rels)` — match source + target by stix_id, MERGE edge
- `load_tactic_links(driver, links)` — Technique→Tactic PART_OF

**Deliverable**: Full MITRE dataset loaded into Neo4j.

#### 2.4 Build ingestion script

File: `scripts/ingest_mitre.py`

```bash
python scripts/ingest_mitre.py --source github --clear
python scripts/ingest_mitre.py --source local --file src/data/mitre/enterprise-attack.json
```

- Downloads STIX data (or reads from local file)
- Parses all objects
- Optionally clears existing graph
- Loads all nodes and relationships
- Prints summary statistics

**Deliverable**: One-command ingestion. Verified counts match expectations.

### Day 2–3 Verification Checkpoint

- [ ] `enterprise-attack.json` downloaded and cached locally
- [ ] STIX parser extracts: 14 tactics, ~216 techniques (non-revoked), ~475 sub-techniques, ~52 campaigns\n- [ ] All nodes loaded: `MATCH (n) RETURN labels(n), count(n)` shows ~1,757 nodes
- [ ] All nodes loaded: `MATCH (n) RETURN labels(n), count(n)` shows expected counts
- [ ] Relationships loaded: `MATCH ()-[r]->() RETURN type(r), count(r)` shows expected counts
- [ ] Sample query works: `MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: "credential-access"}) RETURN t.name`

---

## Phase 3 — Threat Intelligence Enrichment (Day 3–4)

### Objective

Add CTI enrichment capability using MISP galaxy data, STIX Campaign objects, and Neo4j graph context.

### Tasks

#### 3.1 Download and parse MISP galaxy files

File: `src/layers/layer2_enrichment.py`

Download from `github.com/MISP/misp-galaxy`:
- `clusters/mitre-attack-pattern.json`
- `clusters/mitre-intrusion-set.json`
- `clusters/mitre-tool.json`

Parse galaxy clusters into lookup dicts keyed by ATT&CK technique ID.

**Deliverable**: Galaxy data cached locally in `src/data/misp_galaxies/`.

#### 3.2 Build CTI tools

File: `src/tools/cti_tools.py`

Functions (registered as Gemini function tools):
- `get_intrusion_sets_for_technique(technique_id: str) -> list[dict]`
- `get_tools_for_technique(technique_id: str) -> list[dict]`
- `get_detection_guidance(technique_id: str) -> str`
- `get_mitigations(technique_id: str) -> list[dict]`
- `get_campaigns_for_technique(technique_id: str) -> list[dict]`
- `get_campaigns_for_group(group_name: str) -> list[dict]`

Each function executes a parameterized Cypher query from `src/graph/queries.py`.

**Deliverable**: CTI tools return structured data for any valid technique ID.

#### 3.3 Build MISP galaxy enrichment tool

File: `src/tools/misp_tools.py`

Functions:
- `search_misp_galaxy(technique_id: str) -> dict` — returns galaxy context (groups, tools, campaigns)
- `enrich_technique_context(technique_id: str) -> ThreatIntelContext` — combines Neo4j + MISP + STIX Campaign data

**Deliverable**: Enrichment tool returns `ThreatIntelContext` for any technique.

#### 3.4 Campaign enrichment upgrade (added post-MVP)

**Problem**: 52 STIX Campaign objects (1,019 technique links, 25 group attributions) were sitting unused
in the STIX bundle. The original `ThreatIntelContext.recent_campaigns` was `List[str]` populated by
keyword heuristics — no structured data.

**Solution implemented**:
- **Parser**: `parse_campaigns()` in `layer1_ingestion.py` extracts Campaign objects from STIX
- **Loader**: `load_campaigns()`, `load_campaign_uses_relationships()`, `load_attributed_to_relationships()` in `loader.py`
- **Schema**: 3 new indexes (`idx_campaign_stix`, `idx_campaign_name`, `idx_campaign_external_id`) + 1 constraint (`uniq_campaign_stix`)
- **Queries**: `CAMPAIGNS_FOR_TECHNIQUE` and `CAMPAIGNS_FOR_GROUP` in `queries.py`; `FULL_TECHNIQUE_CONTEXT` updated to include campaigns
- **Model**: New `CampaignUsage` Pydantic model; `ThreatIntelContext.recent_campaigns` changed to `List[CampaignUsage]`
- **Tools**: `get_campaigns_for_technique()` and `get_campaigns_for_group()` added to `cti_tools.py`
- **Enrichment**: `misp_tools.py` rewritten — `_build_campaign_objects()` converts Neo4j records into `CampaignUsage` models instead of keyword grep

**Impact**: T1003 alone now returns 19 real campaigns (SolarWinds, Operation Wocao, Cutting Edge, etc.) with structured first_seen/last_seen dates and attributed groups.

### Day 3–4 Verification Checkpoint

- [ ] MISP galaxy files downloaded and parsed
- [ ] `get_intrusion_sets_for_technique("T1003")` returns APT29, APT28, etc.
- [ ] `get_tools_for_technique("T1003.001")` returns Mimikatz, ProcDump, etc.
- [ ] `get_detection_guidance("T1003")` returns data sources
- [ ] `get_campaigns_for_technique("T1003")` returns ~19 campaigns with structured CampaignUsage data
- [ ] `get_campaigns_for_group("APT29")` returns campaigns attributed to APT29
- [ ] Enrichment works end-to-end: technique_id → ThreatIntelContext with campaigns

---

## Phase 4 — Attack Reasoning Engine (Day 4–5)

### Objective

Build the core agentic loop — Gemini 3 Flash with function calling against the knowledge graph.

### Tasks

#### 4.1 Build LLM abstraction layer

File: `src/llm/base.py`, `src/llm/gemini_client.py`, `src/llm/openai_compat.py`

Abstract interface:
```python
class LLMClient(ABC):
    def chat(self, messages: list) -> str: ...
    def chat_with_tools(self, messages: list, tools: list) -> ToolCallResult: ...
    def chat_structured(self, messages: list, schema: type[BaseModel]) -> BaseModel: ...
```

Gemini implementation using `google-genai`:
- Function calling with `FunctionDeclaration.from_callable()`
- Structured output with `response_schema=Ability`
- Automatic tool calling loop (SDK handles call → result → re-prompt)

OpenAI-compatible implementation for Groq/Ollama fallback.

**Deliverable**: LLM client instantiates based on `LLM_PROVIDER` env var. Test: basic chat completion works.

#### 4.2 Register function tools with Gemini

File: `src/tools/graph_tools.py`

Functions decorated for Gemini auto-schema generation:
- `query_techniques_by_tactic(tactic: str) -> list[dict]`
- `find_subtechniques(technique_id: str) -> list[dict]`
- `get_technique_details(technique_id: str) -> dict`
- `get_platforms_for_technique(technique_id: str) -> list[str]`

Each tool has:
- Clear docstring (Gemini uses this as tool description)
- Type-annotated parameters
- Returns JSON-serializable data

**Deliverable**: All tools registered. Gemini can discover and call them.

#### 4.3 Build reasoning engine

File: `src/layers/layer3_reasoning.py`

The agent loop:

```python
def generate_abilities(category: str, platform: str, count: int) -> list[Ability]:
    system_prompt = ADVERSARY_SIMULATION_SYSTEM_PROMPT
    user_prompt = f"Generate {count} {category} abilities for {platform}"
    
    messages = [system_prompt, user_prompt]
    tools = [graph_tools, cti_tools, misp_tools]
    
    # Gemini function calling loop
    while iterations < max_iterations:
        response = llm.chat_with_tools(messages, tools)
        
        if response.has_tool_calls:
            results = execute_tool_calls(response.tool_calls)
            messages.append(response)
            messages.append(tool_results)
        else:
            # Final answer — extract abilities
            abilities = parse_abilities(response.text)
            return abilities
```

**Deliverable**: Agent loop runs. Gemini calls graph tools, enrichment tools, and produces ability candidates.

### Day 4–5 Verification Checkpoint

- [ ] LLM client connects to Gemini/Groq successfully
- [ ] Function tools registered and callable by Gemini
- [ ] Agent loop executes: request → tool calls → ability candidate
- [ ] At least one credential_access ability generated end-to-end
- [ ] Tool call chain visible in logs

---

## Phase 5 — Ability Composition + Executor Builder (Day 5–6)

### Objective

Transform reasoning output into validated Ability objects with multi-platform executors.

### Tasks

#### 5.1 Build composition engine

File: `src/layers/layer4_composition.py`

- Take reasoning context (technique details, CTI enrichment) and produce structured `Ability`
- Use Gemini structured output: `response_schema=Ability`
- Auto-generate UUID ids (UUID5 for deterministic, UUID4 for random)
- Force safety defaults: `PENDING`, `AI`, `true`
- Add metadata: `generated_at`, `agent_version`, `schema_version`

**Deliverable**: Composition engine produces validated Ability Pydantic objects.

#### 5.2 Build executor builder

File: `src/layers/layer5_executor.py`

- Generate executors based on platform + technique context
- Ensure simulation markers in every command
- Ensure cleanup procedures for every executor
- Platform-specific command generation:
  - Windows: PowerShell + cmd variants
  - Linux: bash variant
  - macOS: zsh/bash variant
- Map technique privilege requirements to executor `privilege_required`

**Deliverable**: Abilities have 1+ executors per platform. Simulation markers present.

#### 5.3 Extend to all 13 attack categories

Test generation across:
1. credential_access
2. privilege_escalation
3. persistence
4. lateral_movement
5. defense_evasion
6. command_and_control
7. discovery
8. collection
9. exfiltration
10. cloud_iam_abuse
11. active_directory_abuse
12. web_application_simulation
13. network_signaling

**Deliverable**: At least 1 ability generated per category.

### Day 5–6 Verification Checkpoint

- [ ] Abilities have valid `MitreMapping` (tactic + technique)
- [ ] Each ability has >= 1 executor with simulation marker
- [ ] Cleanup procedures present on all executors
- [ ] `ThreatIntelContext` populated (groups, tools, campaigns)
- [ ] At least 1 ability for each of the 13 categories

---

## Phase 6 — Safety & API Integration (Day 6–7)

### Objective

Enforce all safety constraints and build the JSON output pipeline.

### Tasks

#### 6.1 Implement safety validation

File: `src/layers/layer6_safety.py`

Hard rules (see safety_governance.md):
- `approval_status == PENDING` check
- `simulation_only == true` check
- `created_by == "AI"` check
- Command blocklist regex matching
- Simulation marker presence check
- Cleanup procedure presence check
- MITRE technique validation against Neo4j
- Pydantic schema validation
- **Platform coherence check** — executor name/platform match, no cross-shell syntax
- **Executor name enum validation** — must be a valid `ExecutorType` value

Soft rules (WARNING — flag for human review, do not auto-block):
- **Command syntax validation** — parse command in target shell grammar (PowerShell parser, `bash -n`, `ast.parse()`)
- **Known binary check** — verify referenced binaries against per-platform allowlist

Run all checks. Any hard failure → ability BLOCKED with reason logged. Soft warnings → ability marked `needs_human_review=true`.

**Deliverable**: Safety validation catches all violations. Unit tests for each rule.

#### 6.2 Implement API integration layer

File: `src/layers/layer7_api.py`

Two output modes:
- **File mode** (default): Write `output/abilities/{category}_{timestamp}.json`
- **API mode**: POST to `BACKEND_API_URL` with retry logic

Features:
- JSON sanitization (strip non-JSON tokens)
- Batch submission support
- Idempotent ability IDs
- Error logging

**Deliverable**: Abilities written to JSON files. API submission works when configured.

#### 6.3 Build CLI entry point

File: `scripts/generate_abilities.py`

```bash
python scripts/generate_abilities.py --category credential_access --platform windows --count 5
python scripts/generate_abilities.py --category all --platform all --count 3
python scripts/generate_abilities.py --technique T1003 --platform windows
```

Rich CLI output with structured logging.

**Deliverable**: Working CLI. End-to-end generation via command line.

### Day 6–7 Verification Checkpoint

- [ ] Safety validation rejects: invalid status, missing markers, blocked commands
- [ ] Safety validation rejects: platform-mismatched executors (e.g., bash syntax in powershell executor)
- [ ] Safety validation rejects: invalid executor names not in `ExecutorType` enum
- [ ] Safety validation warns: commands with syntax parse failures
- [ ] Safety validation warns: commands referencing unknown binaries
- [ ] Valid abilities pass all safety checks
- [ ] JSON output files written to `output/abilities/`
- [ ] CLI works for all supported arguments
- [ ] Structured logging shows tool calls, decisions, outcomes
- [ ] Blocklist version recorded in `generation_trace` of every ability

---

## Phase 7 — Testing & Demo (Day 7+)

### Objective

Full system verification, cross-category generation, and demo preparation.

### Tasks

#### 7.1 Full generation run

Generate abilities across ALL 13 categories:

```bash
python scripts/generate_abilities.py --category all --platform all --count 3
```

Expected output: ~39 abilities (3 per category × 13 categories).

#### 7.2 Validation sweep

For every generated ability verify:
- MITRE mapping is valid (technique exists in graph)
- `approval_status == PENDING`
- `simulation_only == true`
- `created_by == "AI"`
- At least 1 executor
- Simulation markers present
- Cleanup procedures present
- JSON is valid and parseable
- `ThreatIntelContext` has at least groups OR tools populated
- Executor name is a valid `ExecutorType` enum value
- Platform coherence: executor commands match their declared platform/shell
- Command syntax warnings reviewed: any parse failures manually checked
- Unknown binary warnings reviewed: any flagged binaries manually verified
- `blocklist_version` recorded in `generation_trace`

#### 7.3 Demo preparation

1. Prepare demo script (~5 min walkthrough):
   - Show architecture diagram
   - Run `ingest_mitre.py` (or show pre-loaded graph)
   - Show Neo4j browser with knowledge graph
   - Run `generate_abilities.py --category credential_access --platform windows --count 3`
   - Walk through generated ability JSON
   - Show safety validation catching a bad ability
   - Show how to swap LLM provider (change 1 env var)

2. Create 2-3 "highlight" abilities per category for demo portfolio

#### 7.4 Gap analysis

Document:
- Which categories produce the strongest abilities?
- Which categories need more work?
- What limitations exist with current model (Gemini) for command generation?
- What would Phase 2 add? (live MISP, attack chains, detection coverage mapping)

### Day 7+ Verification Checkpoint (Final)

- [ ] 39+ abilities generated across all categories
- [ ] Zero safety violations in final output
- [ ] All MITRE mappings verified against graph
- [ ] Demo script rehearsed and timed (< 5 min)
- [ ] Gap analysis documented

---

## Verification Matrix

| Verification | Phase | Method | Pass Criteria |
|---|---|---|---|
| Pydantic models validate | 1 | `Ability.model_validate(sample)` | No `ValidationError` |
| Neo4j connects | 1 | `driver.verify_connectivity()` | Returns True |
| STIX parse counts | 2 | Compare parsed counts to ATT&CK v18.1 | 14 tactics, ~216 techniques, ~475 sub-techniques |
| Neo4j node counts | 2 | `MATCH (n) RETURN labels(n), count(n)` | Matches parse counts |
| Graph relationships | 2 | `MATCH ()-[r]->() RETURN type(r), count(r)` | ~10K relationships |
| CTI tools return data | 3 | `get_intrusion_sets_for_technique("T1003")` | Non-empty list |
| LLM chat works | 4 | Basic completion | Valid response |
| Agent tool calls work | 4 | Reasoning loop executes | Tool call appears in log |
| Ability composition | 5 | Generate 1 ability | Valid Pydantic model |
| Safety rejects bad input | 6 | Pass ability with `approval_status=APPROVED` | Rejected |
| Platform coherence rejects mismatch | 6 | Pass ability with bash syntax in powershell executor | Rejected |
| Executor name enum rejects invalid | 6 | Pass ability with `executor.name="ansible"` | Rejected |
| Syntax check warns on bad cmd | 6 | Pass ability with invalid PowerShell syntax | Warning logged |
| Binary check warns on unknown | 6 | Pass ability referencing `fake_tool.exe` | Warning logged |
| CLI end-to-end | 6 | `generate_abilities.py --category ... --count 1` | JSON file created |
| Full generation | 7 | All 13 categories × 3 abilities | 39+ valid abilities |

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Gemini rate limits hit | Slows generation | Medium | Batch API, retry logic, switch to Groq fallback |
| Neo4j Aura downtime | Blocks graph queries | Low | Local cache of STIX data as fallback |
| STIX data format changes | Parse failure | Low | Pin to specific ATT&CK version (v18.1) |
| LLM generates unsafe commands | Safety violation | Medium | Layer 6 blocklist + validation before any output |
| LLM generates syntactically invalid commands | Broken abilities at execution | High | Command syntax validation (rule 16) + human review flag |
| LLM hallucinates non-existent binaries/cmdlets | Non-functional abilities | Medium | Known binary allowlist (rule 17) + human review flag |
| LLM mixes platform syntax (bash in PowerShell) | Broken abilities | Medium | Platform coherence check (rule 15) — hard block |
| Gemini structured output doesn't match schema | Parse failure | Medium | Pydantic validation catches; retry with clearer prompt |
| MISP galaxy JSON unavailable | Reduced CTI enrichment | Low | Neo4j graph alone provides group/tool context |
| Neo4j Aura Free perf limits | Slow queries | Low | ATT&CK data is small; queries complete in <100ms |
| Backend API contract unknown | Integration failure on Day 6–7 | High | Get API spec from client early; mock API for testing |
