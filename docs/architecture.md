# Architecture Specification — Blackhat AI Agent (Ability Generator)

> Version 1.0 · February 2026

---

## Table of Contents

- [1. System Overview](#1-system-overview)
- [2. High-Level Architecture Diagram](#2-high-level-architecture-diagram)
- [3. The 7-Layer Model — Detailed Specification](#3-the-7-layer-model--detailed-specification)
  - [Layer 1: Knowledge Ingestion](#layer-1-knowledge-ingestion)
  - [Layer 2: Threat Intelligence Enrichment](#layer-2-threat-intelligence-enrichment)
  - [Layer 3: Attack Reasoning Engine](#layer-3-attack-reasoning-engine)
  - [Layer 4: Ability Composition Engine](#layer-4-ability-composition-engine)
  - [Layer 5: Executor & Payload Builder](#layer-5-executor--payload-builder)
  - [Layer 6: Safety & Governance](#layer-6-safety--governance)
  - [Layer 7: API Integration](#layer-7-api-integration)
- [4. Data Flow: End-to-End Ability Generation](#4-data-flow-end-to-end-ability-generation)
- [5. Infrastructure Components](#5-infrastructure-components)
- [6. LLM Integration Architecture](#6-llm-integration-architecture)
- [7. Knowledge Graph Design Rationale](#7-knowledge-graph-design-rationale)
- [8. Agent Loop Design](#8-agent-loop-design)
- [9. Key Design Decisions](#9-key-design-decisions)
- [10. Deployment Model](#10-deployment-model)
- [11. Future Architecture Considerations](#11-future-architecture-considerations)

---

## 1. System Overview

The Blackhat AI Agent is a **controlled adversary scenario compiler**. It generates simulation-safe attack abilities (JSON payloads) based on the MITRE ATT&CK framework, enriched with real-world threat intelligence, and validated against hard safety constraints.

### What it IS

- A **generator** — produces structured attack scenario descriptions
- A **graph-powered reasoner** — uses Neo4j knowledge graph for technique selection and context retrieval
- A **tool-augmented LLM agent** — Gemini 3 Flash uses function calling to query the knowledge graph and CTI sources
- A **schema-validated output pipeline** — every ability conforms to a versioned Pydantic schema

### What it is NOT

- NOT an autonomous attacker — never executes attacks
- NOT a chatbot — produces strict JSON, no conversational output
- NOT a vulnerability scanner — does not probe live targets
- NOT a penetration testing tool — generates scenarios for evaluation, not exploitation

---

## 2. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BLACKHAT AI AGENT SYSTEM                             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │                     CLI / Entry Point                           │        │
│  │  scripts/generate_abilities.py                                  │        │
│  │  Input: --category | --technique | --platform | --count         │        │
│  └──────────────────────────────┬──────────────────────────────────┘        │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │              LAYER 3: Attack Reasoning Engine                    │       │
│  │                                                                  │       │
│  │  ┌──────────────────────────────────────────────────────┐       │       │
│  │  │               Gemini 3 Flash (LLM)                    │       │       │
│  │  │                                                       │       │       │
│  │  │  System Prompt: Adversary Simulation Generator        │       │       │
│  │  │  Mode: Function Calling (AUTO)                        │       │       │
│  │  │                                                       │       │       │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │       │       │
│  │  │  │  Reason  │→│  Select  │→│  Enrich  │→ Compose    │       │       │
│  │  │  │  about   │ │technique │ │  with    │  ability    │       │       │
│  │  │  │  tactic  │ │+ sub-tech│ │  CTI     │  JSON       │       │       │
│  │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘             │       │       │
│  │  │       │             │             │                   │       │       │
│  │  └───────┼─────────────┼─────────────┼───────────────────┘       │       │
│  │          │             │             │                            │       │
│  │          ▼             ▼             ▼                            │       │
│  │  ┌─────────────────────────────────────────────────────┐        │       │
│  │  │              Function Tools (Agent Actions)          │        │       │
│  │  │                                                      │        │       │
│  │  │  graph_tools.py         cti_tools.py                 │        │       │
│  │  │  ├─ query_techniques     ├─ get_intrusion_sets       │        │       │
│  │  │  ├─ find_subtechniques   ├─ get_tools_for_technique  │        │       │
│  │  │  └─ get_platforms        └─ get_detection_guidance   │        │       │
│  │  │                                                      │        │       │
│  │  │  misp_tools.py          validation_tools.py          │        │       │
│  │  │  ├─ search_threat_intel  ├─ validate_ability         │        │       │
│  │  │  └─ get_misp_events      └─ check_safety             │        │       │
│  │  └───────┬──────────────────────┬───────────────────────┘        │       │
│  └──────────┼──────────────────────┼────────────────────────────────┘       │
│             │                      │                                        │
│             ▼                      ▼                                        │
│  ┌──────────────────┐   ┌──────────────────────────────┐                   │
│  │   Neo4j Aura     │   │  MISP Galaxy JSONs / httpx   │                   │
│  │  Knowledge Graph │   │  Threat Intelligence         │                   │
│  │                  │   │                              │                   │
│  │  LAYER 1:        │   │  LAYER 2:                    │                   │
│  │  14 Tactics      │   │  ATT&CK galaxy clusters      │                   │
│  │  216 Techniques  │   │  Intrusion set → technique   │                   │
│  │  475 Sub-techs   │   │  Tool → technique mappings   │                   │
│  │  ~150 Groups     │   │  Campaign context (STIX)     │                   │
│  │  ~52 Campaigns   │   │  IOC patterns                 │                   │
│  │  ~700 Tools      │   │                              │                   │
│  │  ~21K Relations  │   │                              │                   │
│  └──────────────────┘   └──────────────────────────────┘                   │
│                                                                             │
│             │ (Ability JSON from Layer 3)                                   │
│             ▼                                                               │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │           LAYER 4: Ability Composition Engine                    │       │
│  │  Gemini structured output → Pydantic Ability model              │       │
│  │  UUID generation · Default fields · Schema compliance           │       │
│  └──────────────────────────────┬───────────────────────────────────┘       │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │           LAYER 5: Executor & Payload Builder                    │       │
│  │  Platform-aware commands · Simulation markers · Cleanup procs   │       │
│  │  Windows (PowerShell, cmd) · Linux (bash) · macOS (zsh)         │       │
│  └──────────────────────────────┬───────────────────────────────────┘       │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │           LAYER 6: Safety & Governance                           │       │
│  │  approval_status = PENDING · simulation_only = true             │       │
│  │  Command blocklist · MITRE validation · Schema validation       │       │
│  │  Audit metadata: generated_at, agent_version, schema_version    │       │
│  └──────────────────────────────┬───────────────────────────────────┘       │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │           LAYER 7: API Integration                               │       │
│  │  Strict JSON output · Batch submission · Retry logic            │       │
│  │  File output: output/abilities/*.json                           │       │
│  │  API output: POST to BACKEND_API_URL (when ready)               │       │
│  └──────────────────────────────┬───────────────────────────────────┘       │
│                                 │                                           │
└─────────────────────────────────┼───────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │    Backend Platform API    │
                    │  (External — not ours)     │
                    │                           │
                    │  Human reviews ability     │
                    │  PENDING → APPROVED        │
                    │      or → REJECTED         │
                    └──────────────────────────┘
```

---

## 3. The 7-Layer Model — Detailed Specification

### Layer 1: Knowledge Ingestion

**File**: `src/layers/layer1_ingestion.py` + `src/graph/`  
**Purpose**: Parse MITRE ATT&CK STIX data and load it into Neo4j as a queryable knowledge graph.

#### Data Source

| Source | Format | URL |
|---|---|---|
| MITRE ATT&CK Enterprise | STIX 2.1 JSON bundle | `github.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` |

**File size**: ~50 MB single JSON bundle containing all ATT&CK objects.

#### STIX Object → Neo4j Node Mapping

| STIX Object Type | Neo4j Label | Key Properties | Count (v18.1) |
|---|---|---|---|
| `x-mitre-tactic` | `:Tactic` | name, shortname, stix_id, description, external_id | 14 |
| `attack-pattern` (is_subtechnique=false) | `:Technique` | name, attack_id, stix_id, description, platforms[], detection | 216 |
| `attack-pattern` (is_subtechnique=true) | `:SubTechnique` | name, attack_id, stix_id, description, platforms[], detection | 475 |
| `intrusion-set` | `:IntrusionSet` | name, stix_id, aliases[], description | ~150 |
| `tool` | `:Tool` | name, stix_id, description, platforms[] | ~100 |
| `malware` | `:Malware` | name, stix_id, description, platforms[] | ~600 |
| `x-mitre-data-source` | `:DataSource` | name, stix_id, description | ~40 |
| `course-of-action` | `:Mitigation` | name, stix_id, description | ~45 |
| `campaign` | `:Campaign` | name, stix_id, external_id, description, first_seen, last_seen | ~52 |

**Total**: ~1,757 nodes

#### STIX Relationship → Neo4j Edge Mapping

| STIX relationship_type | Neo4j Relationship | Source → Target |
|---|---|---|
| technique → tactic (via kill_chain_phases) | `[:PART_OF]` | Technique → Tactic |
| subtechnique-of | `[:PART_OF]` | SubTechnique → Technique |
| uses (group → technique) | `[:USES]` | IntrusionSet → Technique |
| uses (group → software) | `[:USES]` | IntrusionSet → Tool/Malware |
| uses (software → technique) | `[:USES]` | Tool/Malware → Technique |
| detects | `[:DETECTED_BY]` | Technique → DataSource |
| mitigates | `[:MITIGATES]` | Mitigation → Technique |
| uses (campaign → technique/software) | `[:CAMPAIGN_USES]` | Campaign → Technique/Tool/Malware |
| attributed-to | `[:ATTRIBUTED_TO]` | Campaign → IntrusionSet |

**Total**: ~21,814 relationships

#### Parsing Strategy

```python
from stix2 import MemoryStore, Filter

# Load the STIX bundle
src = MemoryStore()
src.load_from_file("enterprise-attack.json")

# Filter by object type
techniques = src.query([
    Filter('type', '=', 'attack-pattern'),
    Filter('x_mitre_is_subtechnique', '=', False),
    Filter('revoked', '=', False),          # Exclude revoked
    Filter('x_mitre_deprecated', '=', False) # Exclude deprecated
])
```

#### Neo4j Loading Pattern

```cypher
-- Batch load techniques using UNWIND
UNWIND $techniques AS t
MERGE (tech:Technique {stix_id: t.stix_id})
SET tech.name = t.name,
    tech.attack_id = t.attack_id,
    tech.description = t.description,
    tech.platforms = t.platforms,
    tech.detection = t.detection

-- Batch load relationships
UNWIND $rels AS rel
MATCH (src {stix_id: rel.source_ref})
MATCH (tgt {stix_id: rel.target_ref})
MERGE (src)-[r:USES]->(tgt)
SET r.description = rel.description
```

#### Indexes (Critical for Query Performance)

```cypher
CREATE INDEX idx_technique_stix FOR (t:Technique) ON (t.stix_id);
CREATE INDEX idx_technique_id FOR (t:Technique) ON (t.attack_id);
CREATE INDEX idx_subtechnique_stix FOR (s:SubTechnique) ON (s.stix_id);
CREATE INDEX idx_subtechnique_id FOR (s:SubTechnique) ON (s.attack_id);
CREATE INDEX idx_tactic_stix FOR (tac:Tactic) ON (tac.stix_id);
CREATE INDEX idx_tactic_shortname FOR (tac:Tactic) ON (tac.shortname);
CREATE INDEX idx_intrusion_stix FOR (g:IntrusionSet) ON (g.stix_id);
CREATE INDEX idx_tool_stix FOR (t:Tool) ON (t.stix_id);
CREATE INDEX idx_malware_stix FOR (m:Malware) ON (m.stix_id);
```

---

### Layer 2: Threat Intelligence Enrichment

**File**: `src/layers/layer2_enrichment.py` + `src/tools/misp_tools.py`  
**Purpose**: Enrich MITRE technique data with real-world threat intelligence — who uses this technique, how, and why.

#### CTI Strategy: Hybrid Approach

```
┌───────────────────────────────────────────────────────────────┐
│                 Threat Intelligence Sources                     │
│                                                                │
│  ┌────────────────────┐  ┌──────────────────────┐             │
│  │  MISP Galaxy JSONs │  │  Neo4j Graph Context │             │
│  │  (Primary / MVP)   │  │  (Always available)  │             │
│  │                    │  │                      │             │
│  │  Source: GitHub     │  │  IntrusionSet→USES→  │             │
│  │  misp-galaxy repo  │  │  Technique           │             │
│  │                    │  │  Tool/Malware→USES→  │             │
│  │  No server needed  │  │  Technique           │             │
│  │  Downloaded via    │  │  Campaign→CAMPAIGN_  │             │
│  │  httpx (async)     │  │  USES→Technique      │             │
│  │  Rich ATT&CK-      │  │  Campaign→ATTRIBUTED │             │
│  │  aligned metadata  │  │  _TO→IntrusionSet    │             │
│  │                    │  │                      │             │
│  │                    │  │  Already loaded in   │             │
│  │                    │  │  Layer 1 (STIX)      │             │
│  └────────────────────┘  └──────────────────────┘             │
│                                                                │
│  ┌────────────────────┐  ┌──────────────────────┐             │
│  │  STIX Campaigns    │  │  Live MISP API       │             │
│  │  (52 campaigns)    │  │  (Optional / Prod)   │             │
│  │                    │  │                      │             │
│  │  Source: STIX      │  │  Requires MISP       │             │
│  │  bundle (same      │  │  server instance     │             │
│  │  enterprise-       │  │  Real-time events    │             │
│  │  attack.json)      │  │  IOC correlation     │             │
│  │  1,019 technique   │  │  Via httpx client    │             │
│  │  links             │  │                      │             │
│  │  25 group          │  │                      │             │
│  │  attributions      │  │                      │             │
│  └────────────────────┘  └──────────────────────┘             │
└───────────────────────────────────────────────────────────────┘
```

#### MISP Galaxy Files (MVP)

Downloaded from `github.com/MISP/misp-galaxy`:
- `mitre-attack-pattern.json` — technique descriptions, synonyms, usage context
- `mitre-intrusion-set.json` — APT groups with technique mappings
- `mitre-tool.json` — tools with technique associations
- `mitre-malware.json` — malware with technique associations

These provide rich, structured metadata WITHOUT needing a running MISP server.

#### Enrichment Output per Technique

```python
ThreatIntelContext(
    associated_groups=["APT29", "APT28", "Lazarus Group"],
    associated_tools=["Mimikatz", "ProcDump", "comsvcs.dll"],
    recent_campaigns=[
        CampaignUsage(
            campaign_name="SolarWinds Compromise",
            first_seen="2019-08",
            last_seen="2021-01",
            attributed_groups=["APT29"],
            description_snippet="Supply chain attack leveraging trojanized SolarWinds Orion update..."
        ),
        CampaignUsage(
            campaign_name="Operation Wocao",
            first_seen="2017-12",
            last_seen="2019-12",
            attributed_groups=[],
            description_snippet="China-linked espionage campaign targeting government and managed service providers..."
        )
    ],
    detection_guidance="Monitor for access to LSASS process. Enable Credential Guard."
)
```

#### Enrichment is Non-Blocking

If MISP data is unavailable, the agent still generates abilities using:
1. Neo4j graph context (IntrusionSets, Tools from STIX data — always available)
2. Gemini's built-in knowledge (used as supplement, not source of truth)

---

### Layer 3: Attack Reasoning Engine

**File**: `src/layers/layer3_reasoning.py`  
**Purpose**: The core intelligence layer. Uses Gemini 3 Flash with function calling to select appropriate techniques and compose abilities.

#### System Prompt

```
You are an enterprise adversary simulation generator.

You generate simulation-safe attack Abilities based strictly on:
- MITRE ATT&CK Enterprise knowledge graph
- Real-world CTI enrichment
- Enterprise system targeting only

You DO NOT execute attacks.
You DO NOT bypass approval gates.
You DO NOT produce destructive payloads.

Every Ability must:
- Map to a valid MITRE ATT&CK technique (verified against the knowledge graph)
- Include threat intelligence context from the graph and CTI sources
- Include multiple executors when appropriate (PowerShell, bash, cmd)
- Default approval_status to "PENDING"
- Set created_by to "AI"
- Set simulation_only to true
- Contain realistic but simulation-safe commands
- Include cleanup procedures for every executor

Abilities must be atomic and composable.
Avoid full campaign chains. Focus on single techniques or small 2-3 step atomic scenarios.
Focus on realism and detection evaluation.

Output only valid JSON conforming to the Ability schema.
```

#### Agent Function Tools

| Tool | Purpose | Data Source |
|---|---|---|
| `query_techniques_by_tactic(tactic)` | Get all techniques for a tactic | Neo4j |
| `find_subtechniques(technique_id)` | Get sub-techniques for a technique | Neo4j |
| `get_technique_details(technique_id)` | Full technique info: description, platforms, detection | Neo4j |
| `get_intrusion_sets_for_technique(technique_id)` | APT groups using this technique | Neo4j |
| `get_tools_for_technique(technique_id)` | Tools/malware associated with technique | Neo4j |
| `get_detection_guidance(technique_id)` | Data sources and detection logic | Neo4j |
| `get_campaigns_for_technique(technique_id)` | Real-world campaigns using this technique | Neo4j (STIX campaigns) |
| `get_campaigns_for_group(group_name)` | Campaigns attributed to a threat group | Neo4j (STIX campaigns) |
| `search_misp_galaxy(technique_id)` | MISP galaxy enrichment data | MISP JSONs |
| `validate_technique_exists(technique_id)` | Verify technique ID is valid | Neo4j |

#### Reasoning Flow

```
Request: "Generate credential access abilities for Windows"
                │
                ▼
Step 1: REASON — Identify tactic = "credential-access" (TA0006)
                │
                ▼
Step 2: CALL TOOL — query_techniques_by_tactic("credential-access")
         Returns: T1003, T1558, T1552, T1555, T1056, T1539, T1528, ...
                │
                ▼
Step 3: REASON — Select T1003 (OS Credential Dumping) for Windows
                │
                ▼
Step 4: CALL TOOL — find_subtechniques("T1003")
         Returns: T1003.001 (LSASS), T1003.002 (SAM), T1003.003 (NTDS),
                  T1003.004 (LSA Secrets), T1003.006 (DCSync), ...
                │
                ▼
Step 5: REASON — Select T1003.001 (LSASS Memory) as first ability
                │
                ▼
Step 6: CALL TOOL — get_intrusion_sets_for_technique("T1003.001")
         Returns: APT29, APT28, Lazarus Group, FIN6, ...
                │
                ▼
Step 7: CALL TOOL — get_tools_for_technique("T1003.001")
         Returns: Mimikatz, ProcDump, comsvcs.dll, ...
                │
                ▼
Step 8: CALL TOOL — get_detection_guidance("T1003.001")
         Returns: "Monitor Process: OS Credential Dumping, LSASS Memory..."
                │
                ▼
Step 9: COMPOSE — Generate Ability JSON with all gathered context
                │
                ▼
           [Ability JSON] → Layer 4 → Layer 5 → Layer 6 → Layer 7
```

---

### Layer 4: Ability Composition Engine

**File**: `src/layers/layer4_composition.py`  
**Purpose**: Transform reasoning output into validated Ability Pydantic models.

#### Composition Strategy

Uses **Gemini Structured Output** — the Ability Pydantic model is passed directly as `response_schema`:

```python
from google.genai import types

response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents=composition_prompt,
    config=types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=Ability,   # Pydantic model as schema
    )
)
```

Gemini returns JSON that **exactly matches** the Pydantic model structure with type safety.

#### Composition Rules

- **Atomic**: One technique per ability (or small 2–3 step chain)
- **Composable**: Abilities can be chained by the platform, not by the agent
- **UUID generation**: UUID5 based on `technique_id + platform + command_hash` for idempotency
- **Mandatory defaults**: `approval_status=PENDING`, `created_by="AI"`, `simulation_only=true`
- **Schema version**: `schema_version="1.0"` on every ability

---

### Layer 5: Executor & Payload Builder

**File**: `src/layers/layer5_executor.py`  
**Purpose**: Generate realistic, platform-aware, simulation-safe executor commands.

#### Executor Structure

```python
Executor(
    name="powershell",            # Executor type
    platform="windows",           # Target OS
    privilege_required="admin",   # Required privilege level
    command="...",                 # Simulation command
    payload_description="...",    # What this simulates
    cleanup_procedure="..."       # How to reverse
)
```

#### Platform Matrix

| Executor | Platform | Use Cases |
|---|---|---|
| `powershell` | Windows | Credential access, defense evasion, discovery, execution |
| `cmd` | Windows | Legacy techniques, LOLBins, batch scripts |
| `bash` | Linux | Credential access, privilege escalation, persistence |
| `zsh` | macOS | macOS-specific techniques |
| `python` | Cross-platform | Cross-platform tooling, scripting |
| `aws_cli` | cloud_aws | IAM abuse, STS token theft, S3 exfiltration, metadata exploitation |
| `az_cli` | cloud_azure | Entra ID abuse, role escalation, token theft |
| `gcloud_cli` | cloud_gcp | Service account abuse, project-level escalation |
| `curl` | Cross-platform | Metadata endpoint exploitation (169.254.169.254), API abuse |

#### Simulation Safety Requirements

Every executor command MUST:
1. Include simulation marker: `# SIMULATION ONLY — {technique_id}`
2. Use dummy artifacts (temp files, dummy credentials, simulation markers)
3. Be reversible — cleanup procedure undoes any modifications
4. NOT contain real exploit code (validated by Layer 6)
5. Produce behaviors detectable by security controls (the point is to TEST detection)

#### Example: T1003.001 — LSASS Memory Credential Dumping

```json
{
  "executors": [
    {
      "name": "powershell",
      "platform": "windows",
      "privilege_required": "admin",
      "command": "# SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\sim_lsass.dmp full",
      "payload_description": "Uses comsvcs.dll MiniDump to create a minidump of the LSASS process. Simulation-safe: dump written to temp with simulation marker.",
      "cleanup_procedure": "Remove-Item $env:TEMP\\sim_lsass.dmp -Force -ErrorAction SilentlyContinue"
    },
    {
      "name": "cmd",
      "platform": "windows",
      "privilege_required": "admin",
      "command": "REM SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump %LSASS_PID% %TEMP%\\sim_lsass.dmp full",
      "payload_description": "CMD variant of LSASS memory dump simulation using rundll32 and comsvcs.dll.",
      "cleanup_procedure": "del /f %TEMP%\\sim_lsass.dmp"
    }
  ]
}
```

---

### Layer 6: Safety & Governance

**File**: `src/layers/layer6_safety.py`  
**Purpose**: Hard enforcement of safety constraints. Non-negotiable. No overrides.

#### Approval State Machine

```
                   ┌─────────┐
        Creation   │         │   Human Review
       ─────────►  │ PENDING │ ──────────────►  APPROVED ──► EXECUTABLE
                   │         │         │
                   └─────────┘         └──────►  REJECTED ──► BLOCKED
                        ▲
                        │
                   Agent can ONLY
                   produce this state
```

#### Validation Rules (18 Total)

| Rule | Enforcement | Failure Action |
|---|---|---|
| `approval_status == PENDING` | Check on every ability before output | **BLOCKED** — ability discarded |
| `simulation_only == true` | Check on every ability before output | **BLOCKED** — ability discarded |
| `created_by == "AI"` | Check on every ability before output | **BLOCKED** — ability discarded |
| `technique` exists in Neo4j | Cross-check against knowledge graph | **BLOCKED** — invalid MITRE mapping |
| Tactic matches technique kill chain | Tactic/technique alignment | **BLOCKED** — tactic mismatch |
| At least 1 executor present | `len(executors) >= 1` | **BLOCKED** — no execution instructions |
| Simulation marker present | Check every executor `command` field | **BLOCKED** — missing safety marker |
| Cleanup procedure present | Every executor has non-empty `cleanup_procedure` | **BLOCKED** — no cleanup defined |
| No blocked commands | Regex check against blocklist | **BLOCKED** — unsafe command detected |
| Valid JSON schema | Pydantic model validation | **BLOCKED** — schema violation |
| Name ≥ 5 chars, description ≥ 50 chars | Content length check | **BLOCKED** — insufficient content |
| UUID format valid, timestamp ISO 8601 | Format check | **BLOCKED** — invalid identifiers |
| Platform coherence | Executor name matches platform; no cross-shell syntax | **BLOCKED** — platform mismatch |
| Executor name valid | `executor.name` is a valid `ExecutorType` enum value | **BLOCKED** — invalid executor |
| Command syntax check | Command parses in target shell grammar | **WARN** — flag for human review |
| Known binary check | Referenced binaries exist in OS-default allowlist | **WARN** — flag for human review |

#### Command Blocklist (Representative Subset)

> **Canonical list**: See [`safety_governance.md` § COMMAND_BLOCKLIST](safety_governance.md) for the full, versioned blocklist (35+ patterns across 7 threat categories).

```python
# Subset shown here for quick reference — authoritative source is COMMAND_BLOCKLIST
BLOCKED_PATTERNS = [
    r'rm\s+-rf\s+/(?!\w)',          # Root wipe
    r'format\s+[a-zA-Z]:',          # Windows disk format
    r'dd\s+if=.*of=/dev/sd',        # Disk overwrite
    r'mkfs\.\w+\s+/dev/',           # Filesystem format
    r'openssl\s+enc.*-aes.*-in\s+/',# Bulk encryption of root FS
    r'cipher\s+/w:',                # Windows cipher wipe
    r'curl.*pastebin\.com',         # Exfil to pastebin
    r'nmap\s+(?!127\.|10\.|192\.168\.)', # Non-RFC1918 scanning
    r'insmod\s+',                   # Kernel module load
]
```

#### Audit Metadata

Every ability automatically receives:
```json
{
  "generated_at": "2026-02-20T14:30:22Z",
  "agent_version": "0.1.0",
  "schema_version": "1.0",
  "generation_trace": {
    "model": "gemini-3-flash-preview",
    "tools_called": ["query_techniques_by_tactic", "find_subtechniques", "get_intrusion_sets_for_technique"],
    "reasoning_steps": 9,
    "total_tokens": 4200,
    "blocklist_version": "1.0.0",
    "validation_warnings": []
  }
}
```

---

### Layer 7: API Integration

**File**: `src/layers/layer7_api.py`  
**Purpose**: Clean JSON output, batch submission, error handling.

#### Output Modes

| Mode | Trigger | Behavior |
|---|---|---|
| **File output** | `ENABLE_API_SUBMISSION=false` (default) | Write to `output/abilities/{category}_{timestamp}.json` |
| **API submission** | `ENABLE_API_SUBMISSION=true` + `BACKEND_API_URL` set | POST to backend with retry logic |

#### API Submission Spec

```
POST {BACKEND_API_URL}/abilities
Content-Type: application/json

Body: [
  { Ability JSON },
  { Ability JSON },
  ...
]

Response: 201 Created | 400 Validation Error | 500 Server Error
```

#### Reliability

- **Retry logic**: 3 retries with exponential backoff (1s, 2s, 4s)
- **Idempotent IDs**: UUID5 based on `technique_id + platform + command_hash` — re-submitting same ability returns same ID
- **Batch support**: Submit multiple abilities in a single request (configurable `MAX_ABILITIES_PER_BATCH`)
- **JSON sanitization**: Strip any non-JSON tokens (LLM occasionally adds markdown)
- **Error logging**: Failed submissions logged with full request/response details

---

## 4. Data Flow: End-to-End Ability Generation

```
                    ONE-TIME SETUP
                    ═══════════════

    ┌──────────────────┐      ┌───────────────────────┐
    │  STIX 2.1 JSON   │      │   MISP Galaxy JSONs   │
    │  (50 MB bundle)  │      │   (from GitHub)       │
    └────────┬─────────┘      └──────────┬────────────┘
             │                            │
             ▼                            ▼
    ┌──────────────────┐      ┌───────────────────────┐
    │  stix2 Parser    │      │   JSON Parser         │
    │  MemoryStore     │      │   Galaxy → Enrichment │
    └────────┬─────────┘      └──────────┬────────────┘
             │                            │
             └──────────┬─────────────────┘
                        ▼
              ┌──────────────────┐
              │     Neo4j Aura   │
              │  ~1,640 Nodes    │
              │  ~10,000 Edges   │
              └──────────────────┘


                    PER-REQUEST FLOW
                    ═════════════════

User: "Generate 5 credential_access abilities for windows"
                        │
                        ▼
              ┌──────────────────┐
              │   Layer 3:       │
              │   Reasoning      │◄────── Gemini 3 Flash
              │   Engine         │        Function Calling
              └────────┬─────────┘
                       │
          ┌────────────┼───────────────┐
          ▼            ▼               ▼
    ┌──────────┐ ┌──────────┐ ┌────────────┐
    │ Neo4j    │ │ Neo4j    │ │ MISP/CTI   │
    │ Technique│ │ Groups + │ │ Enrichment │
    │ Query    │ │ Tools    │ │ Lookup     │
    └──────────┘ └──────────┘ └────────────┘
          │            │               │
          └────────────┼───────────────┘
                       ▼
              ┌──────────────────┐
              │   Layer 4:       │
              │   Composition    │◄────── Gemini Structured Output
              │   (Pydantic)     │        response_schema=Ability
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │   Layer 5:       │
              │   Executors      │ PowerShell, bash, cmd
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │   Layer 6:       │
              │   Safety Check   │ Pass / BLOCKED
              └────────┬─────────┘
                       │ (only if PASS)
                       ▼
              ┌──────────────────┐
              │   Layer 7:       │
              │   JSON Output    │──► output/abilities/*.json
              │   or API POST    │──► Backend API
              └──────────────────┘
```

---

## 5. Infrastructure Components

### Neo4j Aura Free

| Property | Value |
|---|---|
| Instance ID | `89f9ecd3` |
| Instance Name | `Instance-pentest` |
| URI | `neo4j+s://89f9ecd3.databases.neo4j.io` |
| Node Limit | 200,000 (we use ~1,640) |
| Relationship Limit | 400,000 (we use ~10,000) |
| Always-on | Yes (Free tier) |

**Why Neo4j over flat JSON**: MITRE ATT&CK is inherently a graph — tactics → techniques → sub-techniques → tools → groups. Graph queries like *"Find all credential access techniques used by APT29 on Windows with their associated tools"* are a single Cypher traversal. In flat JSON, this requires nested loops, multiple lookups, and manual joins. The graph structure also enables future features: variant generation, risk scoring, detection coverage mapping.

### Gemini 3 Flash

| Property | Value |
|---|---|
| Model | `gemini-3-flash-preview` |
| Context Window | 1,048,576 tokens (1M) |
| Max Output | 65,536 tokens |
| Function Calling | Yes (AUTO mode) |
| Structured Output | Yes (Pydantic models) |
| SDK | `google-genai` |

---

## 6. LLM Integration Architecture

The LLM layer is provider-agnostic by design.

```
┌──────────────────────────────────────────┐
│            LLM Abstraction Layer          │
│                                          │
│  src/llm/base.py                         │
│  ┌────────────────────────────────────┐  │
│  │  class LLMClient (Abstract):       │  │
│  │    chat(messages) → str            │  │
│  │    chat_with_tools(messages,       │  │
│  │        tools) → ToolCallResult     │  │
│  │    chat_structured(messages,       │  │
│  │        schema) → Pydantic model    │  │
│  └────────────────────────────────────┘  │
│                    ▲                     │
│         ┌──────────┼────────────┐        │
│         │          │            │        │
│  ┌──────┴───┐ ┌────┴─────┐ ┌───┴──────┐ │
│  │ Gemini   │ │ OpenAI   │ │ Ollama   │ │
│  │ Client   │ │ Compat   │ │ Client   │ │
│  │          │ │ (Groq)   │ │ (local)  │ │
│  └──────────┘ └──────────┘ └──────────┘ │
└──────────────────────────────────────────┘
```

**Switching providers** requires changing ONE environment variable:

```dotenv
# Gemini (primary)
LLM_PROVIDER=gemini
GEMINI_API_KEY=xxx
GEMINI_MODEL=gemini-3-flash-preview

# Groq (fallback)
LLM_PROVIDER=groq
GROQ_API_KEY=xxx
GROQ_MODEL=qwen/qwen3-32b

# Ollama (local)
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen3:32b
```

Zero code change required between providers. All use OpenAI-compatible API format (Gemini also exposes OpenAI-compatible endpoint at `generativelanguage.googleapis.com/v1beta/openai/`).

---

## 7. Knowledge Graph Design Rationale

### Why a Graph?

MITRE ATT&CK data answers questions like:
- *"What techniques does APT29 use for credential access on Windows?"*
- *"What tools implement T1003 sub-techniques?"*
- *"Which techniques are detectable by Sysmon?"*

These are **graph traversal problems**:

```cypher
-- "Techniques APT29 uses for credential access on Windows"
MATCH (g:IntrusionSet {name: "APT29"})-[:USES]->(t:Technique)-[:PART_OF]->(tac:Tactic {shortname: "credential-access"})
WHERE "Windows" IN t.platforms
RETURN t.name, t.attack_id
```

In flat JSON, this requires:
1. Find APT29's technique references
2. For each reference, look up the technique object
3. Filter by tactic (`kill_chain_phases`)
4. Filter by platform
5. Manual join across 3 data structures

The graph collapses this to **one query, one traversal, one result**.

### Graph Schema Visualization

```
                        (:Tactic)
                       /    |    \
                      /     |     \
          [:PART_OF] /      |      \ [:PART_OF]
                    /       |       \
           (:Technique) (:Technique) (:Technique)
              /    \          |
  [:PART_OF] /      \        | [:USES]
            /        \       |
  (:SubTechnique)     \  (:IntrusionSet)
                       \     |
                [:USES] \    | [:USES]
                         \   |
                   (:Tool) (:Malware)

  (:Mitigation) ──[:MITIGATES]──► (:Technique)
  (:Technique) ──[:DETECTED_BY]──► (:DataSource)
  (:Ability) ──[:IMPLEMENTS]──► (:Technique)    ← Generated abilities
  (:Executor) ──[:EXECUTES]──► (:Ability)       ← Linked executors
```

---

## 8. Agent Loop Design

The agent follows a **tool-augmented reasoning loop** using Gemini's native function calling.

```
┌──────────────────────────────────────────────┐
│                AGENT LOOP                     │
│                                               │
│   ┌─────────┐                                │
│   │ REQUEST │  "Generate credential access   │
│   │         │   abilities for Windows"        │
│   └────┬────┘                                │
│        │                                      │
│        ▼                                      │
│   ┌─────────────────────────────┐            │
│   │   LLM REASONING STEP       │            │
│   │   (Gemini 3 Flash)         │            │
│   │                             │            │
│   │   Decision:                 │            │
│   │   A) Call a tool  ──────────┼──► Execute │
│   │   B) Return result ─────────┼──► Done    │
│   └──────────────┬──────────────┘            │
│                  │                            │
│          ┌───────┴───────┐                   │
│          │ TOOL CALL     │                   │
│          │ e.g. query_   │                   │
│          │ techniques_   │                   │
│          │ by_tactic()   │                   │
│          └───────┬───────┘                   │
│                  │                            │
│                  ▼                            │
│          ┌───────────────┐                   │
│          │ TOOL RESULT   │                   │
│          │ [T1003, T1558,│                   │
│          │  T1552, ...]  │                   │
│          └───────┬───────┘                   │
│                  │                            │
│                  ▼                            │
│          Append to conversation               │
│          history and loop back to             │
│          LLM REASONING STEP                   │
│                                               │
│   Stop conditions:                            │
│   - Max iterations reached (default: 20)     │
│   - Agent signals completion                  │
│   - Error threshold exceeded                  │
└──────────────────────────────────────────────┘
```

### Gemini Function Calling Integration

```python
# Tools registered with Gemini
tools = [
    types.Tool(function_declarations=[
        FunctionDeclaration.from_callable(query_techniques_by_tactic),
        FunctionDeclaration.from_callable(find_subtechniques),
        FunctionDeclaration.from_callable(get_intrusion_sets_for_technique),
        FunctionDeclaration.from_callable(get_tools_for_technique),
        FunctionDeclaration.from_callable(get_detection_guidance),
        FunctionDeclaration.from_callable(search_misp_galaxy),
    ])
]

# Gemini AUTO mode: model decides when to call tools
config = types.GenerateContentConfig(
    tools=tools,
    tool_config=types.ToolConfig(
        function_calling_config=types.FunctionCallingConfig(mode="AUTO")
    )
)
```

---

## 9. Key Design Decisions

| Decision | Rationale |
|---|---|
| **Neo4j over flat JSON** | ATT&CK is a graph. Traversal queries are natural in Cypher, painful in JSON. Aura Free instance already provisioned. Production-appropriate choice. |
| **Gemini `google-genai` SDK over OpenAI compat** | Native function calling auto-generates schemas from Python functions. Structured output natively accepts Pydantic models. More ergonomic. OpenAI compat layer retained for fallback. |
| **Pydantic as single source of truth** | Same model used for Gemini structured output, JSON validation, API contract, and Neo4j serialization. No schema drift. |
| **MISP galaxy JSON over live MISP server** | No infrastructure dependency for MVP. Galaxy JSONs from GitHub provide identical enrichment data. PyMISP integration planned for production. |
| **stix2 MemoryStore over attackcti** | Lower-level but more control. Direct access to STIX objects and relationships. `attackcti` abstracts too much for our loading pipeline. |
| **7-layer architecture** | Each layer independently testable. Can swap Neo4j, Gemini, MISP without touching other layers. Mirrors real enterprise system design. |
| **Function calling over prompt-only** | Grounded reasoning: LLM queries real data from Neo4j instead of hallucinating technique details. Verifiable, auditable tool usage. |
| **UUID5 for ability IDs** | Deterministic: same technique + platform + command → same ID. Enables idempotent re-generation and deduplication. |
| **Abilities stored back in Neo4j** | `(:Ability)-[:IMPLEMENTS]->(:Technique)` creates provenance trail. Enables: "Show all generated abilities for T1003" and gap analysis. |

---

## 10. Deployment Model

### Development / MVP

```
┌─────────────────────────────┐
│    Developer Workstation     │
│                              │
│  Python 3.12 + venv          │
│  scripts/generate_abilities  │
│         │                    │
│         ├──► Neo4j Aura Free │ (cloud, free tier)
│         ├──► Gemini API      │ (cloud, Tier 1)
│         └──► File output     │ (local JSON files)
└─────────────────────────────┘
```

### Production

```
┌─────────────────────────────────────────┐
│    Production Environment                │
│                                          │
│  ┌───────────────┐  ┌────────────────┐  │
│  │  Agent Service │  │  Neo4j         │  │
│  │  (Container)   │──│  (Docker or    │  │
│  │                │  │   Aura Pro)    │  │
│  └───────┬───────┘  └────────────────┘  │
│          │                               │
│          ├──► Gemini API / Ollama        │
│          ├──► MISP Server (Docker)       │
│          └──► Backend Platform API       │
└─────────────────────────────────────────┘
```

**MVP → Production migration**: Change `.env` values only. No code changes. Swap `neo4j+s://` URI, set `BACKEND_API_URL`, enable `ENABLE_API_SUBMISSION=true`.

---

## 11. Future Architecture Considerations

| Enhancement | Impact | Effort |
|---|---|---|
| **Live MISP server integration** | Real-time CTI events, IOC correlation | Medium |
| **Attack chain generation** | Compose multi-ability attack chains (not just atomic) | Medium |
| **Detection coverage mapping** | Map abilities to data sources → identify blind spots | Low |
| **Variant generation** | Auto-generate executor variants per technique | Low |
| **Risk scoring** | Score abilities by: CVSS, detection difficulty, prevalence | Medium |
| **Batch generation pipeline** | Generate full test suites across all categories automatically | Low |
| **Multi-domain campaigns** | Cross-domain attack scenarios (cloud + AD + endpoint) | High |
| **Feedback loop** | Backend sends execution results → agent improves future abilities | High |

---

## 12. Service Mode — Complete API-First Flow

> This section documents the system as a **running service**, not a CLI tool.
> The CLI (`generate_abilities.py`) is only for local development.
> In production, everything is driven by HTTP API calls.

---

### 12.1 Service Lifecycle — Two Phases

```
╔══════════════════════════════════════════════════════════════════╗
║                  PHASE 1: BOOTSTRAP (One-Time)                   ║
║               Runs ONCE when the service first starts            ║
╚══════════════════════════════════════════════════════════════════╝

   MITRE ATT&CK STIX Bundle          MISP Galaxy JSONs
   (github.com/mitre-attack)         (github.com/MISP/misp-galaxy)
            │                                   │
            ▼                                   ▼
   stix2 MemoryStore Parser              JSON file parser
   - Filter revoked/deprecated          - mitre-attack-pattern.json
   - Transform to Neo4j dicts           - mitre-intrusion-set.json
            │                           - mitre-tool.json
            └──────────────┬────────────────────┘
                           │
                           ▼
             ┌─────────────────────────┐
             │    Neo4j Aura Instance  │
             │  89f9ecd3.databases     │
             │       .neo4j.io         │
             │                         │
             │   14 Tactics            │
             │   216 Techniques        │
             │   475 Sub-Techniques    │
             │   ~150 APT Groups       │
             │   ~700 Tools/Malware    │
             │   ~10,000 Relationships │
             └─────────────────────────┘
                           │
                           ▼
             ✅ Knowledge graph READY
             ✅ Service starts accepting requests


╔══════════════════════════════════════════════════════════════════╗
║               PHASE 2: RUNTIME (Every API Request)               ║
║                Repeats for every generation request              ║
╚══════════════════════════════════════════════════════════════════╝

   See Section 12.2 for full request-to-delivery flow
```

---

### 12.2 Request-to-Delivery Flow

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                     CALLER (Client System)                      │
 │                                                                 │
 │   POST /generate                                                │
 │   {                                                             │
 │     "attack_category": "credential_access",                    │
 │     "platform": "windows",                                      │
 │     "count": 5                                                  │
 │   }                                                             │
 └────────────────────────────┬────────────────────────────────────┘
                              │  HTTP Request
                              ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                    AI AGENT SERVICE                             │
 │                                                                 │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 1 — INPUT PARSING & TACTIC RESOLUTION             │   │
 │  │                                                         │   │
 │  │  Validate: attack_category in AttackCategory enum?      │   │
 │  │  Validate: platform in Platform enum?                   │   │
 │  │  Validate: 1 ≤ count ≤ MAX_ABILITIES_PER_BATCH (20)?   │   │
 │  │  Reject immediately if invalid → 400 Bad Request        │   │
 │  │                                                         │   │
 │  │  Resolve tactic shortname(s) from attack_category:      │   │
 │  │    credential_access      → "credential-access"         │   │
 │  │    privilege_escalation   → "privilege-escalation"      │   │
 │  │    cloud_iam_abuse        → ["privilege-escalation",    │   │
 │  │                              "credential-access"]       │   │
 │  │    active_directory_abuse → ["credential-access",       │   │
 │  │                              "lateral-movement"]        │   │
 │  │    web_application_simulation → "initial-access"        │   │
 │  │    (see AttackCategory → tactic mapping table)          │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │ VALID                            │
 │                             ▼                                  │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 2 — LAYER 3: ATTACK REASONING ENGINE              │   │
 │  │                                                         │   │
 │  │  Gemini 3 Flash starts function-calling loop:           │   │
 │  │                                                         │   │
 │  │  Iteration 1: query_techniques_by_tactic(tactic)        │   │
 │  │    └─► Cypher → Neo4j → returns technique list          │   │
 │  │                                                         │   │
 │  │  Iteration 2: find_subtechniques(technique_id)          │   │
 │  │    └─► Cypher → Neo4j → returns sub-technique list      │   │
 │  │                                                         │   │
 │  │  Iteration 3: get_intrusion_sets_for_technique(id)      │   │
 │  │    └─► Cypher → Neo4j → returns APT groups              │   │
 │  │                                                         │   │
 │  │  Iteration 4: get_tools_for_technique(id)               │   │
 │  │    └─► Cypher → Neo4j → returns tools/malware           │   │
 │  │                                                         │   │
 │  │  Iteration 5: get_detection_guidance(id)                │   │
 │  │    └─► Cypher → Neo4j → returns data sources            │   │
 │  │                                                         │   │
 │  │  Iteration 6: search_misp_galaxy(id)                    │   │
 │  │    └─► MISP JSON cache → returns campaign context       │   │
 │  │                                                         │   │
 │  │  [Repeats for each of the N requested abilities]        │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │ Reasoning context                │
 │                             ▼                                  │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 3 — LAYER 4: ABILITY COMPOSITION                  │   │
 │  │                                                         │   │
 │  │  Gemini Structured Output (response_schema=Ability)     │   │
 │  │  Produces Ability Pydantic model per technique          │   │
 │  │                                                         │   │
 │  │  Forces hardcoded safety defaults:                      │   │
 │  │    approval_status = "PENDING"   ← always               │   │
 │  │    created_by      = "AI"        ← always               │   │
 │  │    simulation_only = true        ← always               │   │
 │  │                                                         │   │
 │  │  Generates UUID5 = hash(technique + platform + cmd)     │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │ Ability draft                    │
 │                             ▼                                  │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 4 — LAYER 5: EXECUTOR BUILDER                     │   │
 │  │                                                         │   │
 │  │  Generates platform-aware executors:                    │   │
 │  │    windows  → powershell + cmd variants                 │   │
 │  │    linux    → bash variant                              │   │
 │  │    macos    → zsh/bash variant                          │   │
 │  │    cloud_*  → aws_cli / az_cli / gcloud_cli / curl      │   │
 │  │                                                         │   │
 │  │  Every command gets:                                    │   │
 │  │    - Simulation marker  (# SIMULATION ONLY — TXXXX)     │   │
 │  │    - Cleanup procedure  (reverse all changes)           │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │ Ability with executors           │
 │                             ▼                                  │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 5 — LAYER 6: SAFETY & GOVERNANCE (18 Rules)       │   │
 │  │                                                         │   │
 │  │  HARD RULES (fail = BLOCKED, ability dropped):          │   │
 │  │  ✓ approval_status == PENDING                           │   │
 │  │  ✓ simulation_only == true                              │   │
 │  │  ✓ created_by == "AI"                                   │   │
 │  │  ✓ MITRE technique exists in Neo4j                      │   │
 │  │  ✓ Tactic matches technique's kill chain phase          │   │
 │  │  ✓ At least 1 executor present                          │   │
 │  │  ✓ Simulation marker in every command                   │   │
 │  │  ✓ Cleanup procedure non-empty on every executor        │   │
 │  │  ✓ No blocklist regex matches                           │   │
 │  │  ✓ Pydantic schema validates                            │   │
 │  │  ✓ Platform coherence (no bash syntax in powershell)    │   │
 │  │  ✓ ExecutorType is valid enum value                     │   │
 │  │  ✓ Name >= 5 chars, description >= 50 chars             │   │
 │  │  ✓ UUID format valid, timestamp ISO 8601                │   │
 │  │                                                         │   │
 │  │  SOFT RULES (fail = WARNING, flagged for review):       │   │
 │  │  ⚠ Command syntax parses in target shell grammar        │   │
 │  │  ⚠ Referenced binaries exist in OS allowlist            │   │
 │  │                                                         │   │
 │  │  AUDIT: Every check written to safety_audit.jsonl       │   │
 │  │  AUDIT: blocklist_version recorded in generation_trace  │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │ Validated abilities only        │
 │                             ▼                                  │
 │  ┌─────────────────────────────────────────────────────────┐   │
 │  │ STEP 6 — LAYER 7: API DISPATCH                         │   │
 │  │                                                         │   │
 │  │  JSON sanitize (strip any LLM markdown artifacts)       │   │
 │  │  Batch abilities (up to MAX_ABILITIES_PER_BATCH=20)     │   │
 │  │                                                         │   │
 │  │  POST {BACKEND_API_URL}/abilities                       │   │
 │  │  Content-Type: application/json                         │   │
 │  │  Body: [ {Ability}, {Ability}, ... ]                    │   │
 │  │                                                         │   │
 │  │  On 201 → success, log IDs                              │   │
 │  │  On 400 → log validation detail, no retry               │   │
 │  │  On 5xx → retry 3x (1s → 2s → 4s backoff)              │   │
 │  │  On retry exhausted → log failure + full payload        │   │
 │  └──────────────────────────┬──────────────────────────────┘   │
 │                             │                                  │
 └─────────────────────────────┼──────────────────────────────────┘
                               │  HTTP Response to caller
                               ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │                     CALLER (Client System)                      │
 │                                                                 │
 │   Response: 201 Created                                         │
 │   {                                                             │
 │     "submitted": 4,                                             │
 │     "blocked": 1,                                               │
 │     "ability_ids": ["uuid1", "uuid2", "uuid3", "uuid4"],       │
 │     "warnings": { "uuid2": ["unknown binary: custom_tool.exe"]} │
 │   }                                                             │
 └─────────────────────────────────────────────────────────────────┘
```

---

### 12.3 What Lives in the Backend Platform (After Dispatch)

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                BACKEND PLATFORM (not our code)                  │
 │                                                                 │
 │  Receives abilities → All arrive as PENDING                     │
 │                                                                 │
 │  ┌───────────────────────────────────────────────────────────┐  │
 │  │                HUMAN REVIEW DASHBOARD                    │  │
 │  │                                                           │  │
 │  │  ┌─────────────────────────────────────────────────────┐ │  │
 │  │  │ Ability: "LSASS Memory Credential Dumping"          │ │  │
 │  │  │ Attack Category: credential_access                  │ │  │
 │  │  │ Tactic: credential-access  Technique: T1003.001     │ │  │
 │  │  │ Platform: windows  Privilege: admin                 │ │  │
 │  │  │ Groups: APT29, APT28  Tools: Mimikatz, comsvcs.dll  │ │  │
 │  │  │ Status: ⏳ PENDING                                   │ │  │
 │  │  │ Warnings: ⚠ [syntax parse warning on executor 1]   │ │  │
 │  │  │                                                     │ │  │
 │  │  │ Command:                                            │ │  │
 │  │  │  # SIMULATION ONLY — T1003.001                      │ │  │
 │  │  │  rundll32.exe comsvcs.dll, MiniDump ...             │ │  │
 │  │  │                                                     │ │  │
 │  │  │  [APPROVE]              [REJECT]                   │ │  │
 │  │  └─────────────────────────────────────────────────────┘ │  │
 │  └───────────────────────────────────────────────────────────┘  │
 │                                                                 │
 │  Human APPROVES                      Human REJECTS             │
 │       │                                     │                  │
 │       ▼                                     ▼                  │
 │   APPROVED                             REJECTED                │
 │       │                               (dead end)               │
 │       ▼                                                        │
 │  EXECUTABLE ◄── Scheduler verifies                             │
 │       │         all conditions met                             │
 │       ▼                                                        │
 │  Execution                                                     │
 │  Engine runs                                                   │
 │  the ability                                                   │
 │  in controlled                                                 │
 │  environment                                                   │
 └─────────────────────────────────────────────────────────────────┘
```

---

### 12.4 State Machine (Ability Lifecycle)

```
  AI Agent                   Backend Platform
  ─────────                  ────────────────

  Generates
     │
     ▼
  [PENDING] ──────────────► Human Review Dashboard
     │                             │
     │ (safety fail)               ├── Reviewer APPROVES ──► [APPROVED]
     ▼                             │                              │
  [BLOCKED]                        └── Reviewer REJECTS ──► [REJECTED]
  (never sent)                                                    │
                                                         [APPROVED]
                                                              │
                                                    Scheduler confirms ──► [EXECUTABLE]
                                                    execution window           │
                                                                        Executes in
                                                                        controlled env
```

**Invariant**: The AI agent can only ever produce `PENDING` or `BLOCKED`. It has zero ability to move any ability to `APPROVED`, `EXECUTABLE`, or `REJECTED`. That authority belongs entirely to the backend.

---

### 12.5 Service Configuration Reference

All behaviour is controlled via environment variables — no code changes between environments:

```env
# ── LLM Provider ────────────────────────────────────────
LLM_PROVIDER=gemini                # gemini | groq | ollama
GEMINI_API_KEY=your-key
GEMINI_MODEL=gemini-3-flash-preview

GROQ_API_KEY=your-key              # fallback
GROQ_MODEL=qwen/qwen3-32b

# ── Knowledge Graph ──────────────────────────────────────
NEO4J_URI=neo4j+s://89f9ecd3.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<from secrets file>
NEO4J_DATABASE=neo4j

# ── Output / API Mode ────────────────────────────────────
ENABLE_API_SUBMISSION=true         # false = write files, true = POST to API
BACKEND_API_URL=https://platform.example.com/api
MAX_ABILITIES_PER_BATCH=20

# ── Service Limits ───────────────────────────────────────
MAX_ITERATIONS_PER_ABILITY=20      # LLM reasoning loop cap
```

---

### 12.6 Failure Modes & Behaviour

| Failure Point | What Happens | Recovery |
|---|---|---|
| Neo4j unreachable | Layer 3 tool calls return empty. LLM falls back to built-in knowledge. Quality degrades but service does not crash. | Reconnect on next request. Alert on repeated failures. |
| Gemini rate limit (429) | Switch to Groq fallback if configured. If no fallback, queue and retry with backoff. | Configure `GROQ_API_KEY` as standby. |
| Gemini auth failure (401) | Service returns 503 to caller. Logs auth error. | Rotate API key. |
| Pydantic schema parse failure | Ability discarded. Retry generation with error context appended to prompt (up to 3 times). | Usually self-corrects. |
| Safety rule violation | Ability marked `BLOCKED`, dropped from batch. Remaining valid abilities still submitted. | Audit log records which rule failed. |
| Backend API 5xx | Retry 3× with backoff. If exhausted, log payload to `output/failed_submissions/` for manual resubmit. | Manual resubmit via file or re-trigger generation. |
| Backend API 400 | Log validation error detail. Do not retry (bad data). | Investigate schema mismatch with backend team. |
