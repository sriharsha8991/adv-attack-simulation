# Blackhat AI Agent — Threat Profile & Attack Scenario Generator

> **Part 1 — Ability Generation Engine (MVP)**

A controlled, AI-driven adversary simulation agent that generates realistic cyberattack scenarios (Abilities) mapped to the MITRE ATT&CK framework. The agent leverages a Neo4j knowledge graph for structured reasoning, MISP-sourced threat intelligence for real-world enrichment, and Gemini 3 Flash (configurable LLM) for intelligent attack composition.

**The agent never executes attacks.** It generates simulation-safe Abilities as strict JSON payloads with mandatory human-in-the-loop approval gating.

---

## Table of Contents

- [Overview](#overview)
- [Key Principles](#key-principles)
- [Architecture Summary](#architecture-summary)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Attack Categories (Week 1 Scope)](#attack-categories-week-1-scope)
- [Ability JSON Output](#ability-json-output)
- [Safety Model](#safety-model)
- [Documentation](#documentation)
- [Development Roadmap](#development-roadmap)
- [License](#license)

---

## Overview

This system acts as a **controlled adversary scenario compiler** — not a chatbot, not an autonomous attacker. It:

1. **Ingests** the full MITRE ATT&CK Enterprise dataset (STIX 2.1) into a Neo4j knowledge graph
2. **Enriches** techniques with real-world threat intelligence from MISP galaxies and CTI feeds
3. **Reasons** using Gemini 3 Flash (function calling) to select appropriate techniques, sub-techniques, tools, and intrusion set context
4. **Composes** simulation-safe Abilities with multiple executors, realistic commands, and cleanup procedures
5. **Validates** every Ability against hard safety constraints — approval gating, simulation markers, command blocklists
6. **Outputs** strict JSON payloads submitted to the backend API for human review and approval

```
User Request                    Knowledge Graph               Output
─────────────                   ──────────────────            ──────
"Generate 5 credential   ──►   Neo4j: 14 Tactics       ──►  [Ability JSON]
 access abilities for          216 Techniques                 approval_status: PENDING
 Windows enterprise"           475 Sub-techniques             created_by: AI
                               ~150 Intrusion Sets            simulation_only: true
         │                     ~700 Tools/Malware
         │                            │
         ▼                            ▼
   Gemini 3 Flash            Graph Traversal + CTI
   (Reasoning Engine)        (Technique Selection)
```

---

## Key Principles

| Principle | Enforcement |
|---|---|
| **Human-in-the-loop** | Every Ability defaults to `approval_status: PENDING`. No execution without `APPROVED` state. |
| **Simulation-only** | `simulation_only: true` on every Ability. Commands use dummy artifacts, simulation markers, and reversible operations. |
| **No destructive payloads** | Hard blocklist: no ransomware, no data destruction, no real credential theft. Validated at generation time. |
| **MITRE-grounded** | Every Ability maps to a valid ATT&CK technique. Validated against the knowledge graph. |
| **Enterprise-scoped** | Only enterprise attack scenarios. No consumer/mobile targets. |
| **Strict JSON** | Output is pure JSON. No markdown, no commentary, no explanation text in API payloads. |
| **Auditable** | Every Ability carries metadata: `generated_at`, `agent_version`, `schema_version`, generation trace. |

---

## Architecture Summary

The system follows a **7-layer modular architecture**. Each layer is independently testable and replaceable.

```
┌───────────────────────────────────────────────────────────────┐
│                    Layer 7: API Integration                    │
│         JSON validation · Batch submission · Retry logic       │
├───────────────────────────────────────────────────────────────┤
│                Layer 6: Safety & Governance                    │
│    Approval gating · Command blocklist · Schema validation     │
├───────────────────────────────────────────────────────────────┤
│               Layer 5: Executor & Payload Builder              │
│     Platform-aware commands · Cleanup procedures · Markers     │
├───────────────────────────────────────────────────────────────┤
│               Layer 4: Ability Composition Engine               │
│       Structured output · UUID generation · Default fields     │
├───────────────────────────────────────────────────────────────┤
│                Layer 3: Attack Reasoning Engine                 │
│      Gemini function calling · Technique selection · CTI       │
├───────────────────────────────────────────────────────────────┤
│           Layer 2: Threat Intelligence Enrichment              │
│        MISP galaxies · Intrusion sets · Tool associations      │
├───────────────────────────────────────────────────────────────┤
│               Layer 1: Knowledge Ingestion                     │
│       STIX 2.1 parser · Neo4j loader · Graph schema            │
└───────────────────────────────────────────────────────────────┘
              │                                │
              ▼                                ▼
    ┌──────────────────┐            ┌────────────────────┐
    │   Neo4j Aura     │            │   Gemini 3 Flash   │
    │ Knowledge Graph  │            │   (configurable)   │
    └──────────────────┘            └────────────────────┘
```

> Full architecture details: [docs/architecture.md](docs/architecture.md)

---

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **LLM** | Gemini 3 Flash (primary) / Groq / Ollama | Attack reasoning + ability composition |
| **Knowledge Graph** | Neo4j Aura Free | MITRE ATT&CK data storage + graph traversal |
| **MITRE Data** | STIX 2.1 (`attack-stix-data`) | Tactics, techniques, groups, tools hierarchy |
| **CTI Enrichment** | MISP Galaxy JSONs / PyMISP | Threat intelligence enrichment |
| **Schema Validation** | Pydantic v2 | Ability JSON schema + type safety |
| **STIX Parsing** | `stix2` (cti-python-stix2) | STIX 2.1 bundle ingestion |
| **Language** | Python 3.12+ | All components |
| **CLI** | `click` + `rich` | Command-line interface + structured logging |

### Python Dependencies

```
google-genai              # Gemini 3 Flash SDK (primary LLM)
openai>=1.30.0            # OpenAI-compatible fallback (Groq, Ollama)
neo4j>=5.20.0             # Neo4j Python driver
stix2>=3.0.0              # STIX 2.1 parsing
pymisp>=2.5.0             # MISP API client (optional)
pydantic>=2.7.0           # Schema validation + structured output
pydantic-settings>=2.0.0  # Environment-based config (BaseSettings)
python-dotenv>=1.0.0      # Environment variable management
rich>=13.7.0              # CLI output + structured logging
click>=8.1.0              # CLI framework
```

---

## Project Structure

```
cloud_security/
├── src/
│   ├── __init__.py
│   ├── config.py                      # Central config (env vars, model config)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── ability.py                 # Ability, Executor, MitreMapping (Pydantic v2)
│   │   └── enums.py                   # ApprovalStatus, AttackCategory, Platform, PrivilegeLevel
│   ├── layers/
│   │   ├── __init__.py
│   │   ├── layer1_ingestion.py        # STIX 2.1 parser → Neo4j loader
│   │   ├── layer2_enrichment.py       # MISP galaxy + CTI enrichment
│   │   ├── layer3_reasoning.py        # Gemini function-calling agent loop
│   │   ├── layer4_composition.py      # Ability builder (structured output)
│   │   ├── layer5_executor.py         # Executor & payload generation
│   │   ├── layer6_safety.py           # Validation, approval gating, audit
│   │   └── layer7_api.py              # JSON output + API submission
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── connection.py              # Neo4j driver wrapper
│   │   ├── schema.py                  # Constraints, indexes, node/edge definitions
│   │   ├── loader.py                  # STIX → Neo4j batch loader
│   │   └── queries.py                 # Cypher query library (parameterized)
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── base.py                    # Abstract LLM interface
│   │   ├── gemini_client.py           # Gemini 3 Flash via google-genai SDK
│   │   └── openai_compat.py           # OpenAI-compatible fallback (Groq, Ollama)
│   ├── tools/                         # Gemini function tools (agent actions)
│   │   ├── __init__.py
│   │   ├── graph_tools.py             # query_techniques_by_tactic, find_subtechniques
│   │   ├── cti_tools.py               # get_intrusion_sets, get_tools_for_technique
│   │   ├── misp_tools.py              # MISP galaxy lookup, event search
│   │   └── validation_tools.py        # validate_ability, check_safety_constraints
│   └── data/
│       ├── mitre/                     # Cached STIX JSON (enterprise-attack.json)
│       └── misp_galaxies/             # MISP galaxy JSON files (CTI fallback)
├── scripts/
│   ├── ingest_mitre.py                # One-time: parse STIX → load Neo4j
│   ├── ingest_misp_galaxies.py        # One-time: load MISP galaxy data
│   └── generate_abilities.py          # CLI: generate abilities by category/tactic
├── tests/
│   ├── test_models.py                 # Pydantic model validation tests
│   ├── test_graph_queries.py          # Cypher query correctness tests
│   ├── test_reasoning.py              # Agent loop integration tests
│   ├── test_safety.py                 # Safety constraint enforcement tests
│   └── groq_test.ipynb                # (existing) Groq API exploration
├── docs/
│   ├── architecture.md                # Full 7-layer architecture specification
│   ├── ability_schema.md              # Ability JSON schema reference
│   ├── knowledge_graph_schema.md      # Neo4j graph schema + Cypher patterns
│   ├── development_plan.md            # Day-by-day development roadmap
│   ├── safety_governance.md           # Safety model + approval state machine
│   ├── llm_integration_guide.md       # LLM provider configuration + swapping
│   ├── edge_cases_and_retro.md        # Edge cases, retrospective analysis
│   ├── day_1_docs/                    # (existing) Initial planning documents
│   └── initial_docs/                  # (existing) Repository analysis + draft plans
├── output/
│   └── abilities/                     # Generated ability JSON files
├── secrets/                           # (existing) Neo4j credentials
├── .env                               # Environment variables (keys, URIs)
├── .env.template                      # Template without secrets
├── requirements.txt
└── README.md                          # This file
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Python** | 3.12+ |
| **Neo4j** | Aura Free instance (already provisioned) or local Docker |
| **Gemini API Key** | Google AI Studio — Tier 1 (primary LLM) |
| **Groq API Key** | Groq Cloud (optional fallback) |
| **Internet** | Required for STIX data download, MISP galaxy sync, LLM API calls |

---

## Setup & Installation

### 1. Clone and enter the project

```bash
cd d:\Sriharsha\professional\cloud_security
```

### 2. Create virtual environment

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.template .env
# Edit .env with your actual keys
```

Required variables:
```dotenv
# LLM Configuration
LLM_PROVIDER=gemini                              # gemini | groq | ollama
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3-flash-preview
GROQ_API_KEY=your_groq_api_key                   # optional fallback
GROQ_MODEL=qwen/qwen3-32b                        # optional fallback

# Neo4j Configuration
NEO4J_URI=neo4j+s://89f9ecd3.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_neo4j_password
NEO4J_DATABASE=neo4j

# Backend API (optional — defaults to file output)
BACKEND_API_URL=                                  # set when backend is ready

# Ollama (optional — local LLM)
OLLAMA_MODEL=qwen3:32b                            # optional local model
OLLAMA_BASE_URL=http://localhost:11434/v1          # optional local endpoint

# Safety
MAX_ABILITIES_PER_BATCH=20
ENABLE_API_SUBMISSION=false                       # true when backend is ready
```

### 5. Ingest MITRE ATT&CK data into Neo4j

```bash
python scripts/ingest_mitre.py --source github --clear
```

This downloads STIX 2.1 data from GitHub, parses it, and loads ~1600 nodes + ~10K relationships into your Neo4j Aura instance. One-time operation.

### 6. (Optional) Load MISP galaxy enrichment data

```bash
python scripts/ingest_misp_galaxies.py
```

---

## Usage

### Generate abilities by attack category

```bash
# Generate 5 credential access abilities for Windows
python scripts/generate_abilities.py --category credential_access --platform windows --count 5

# Generate 3 abilities for every supported category
python scripts/generate_abilities.py --category all --platform all --count 3

# Generate for a specific MITRE technique
python scripts/generate_abilities.py --technique T1003 --platform windows
```

### Output

Generated abilities are written to `output/abilities/` as JSON files:
```
output/abilities/
├── credential_access_2026-02-20T143022.json
├── privilege_escalation_2026-02-20T144015.json
└── ...
```

Each file contains an array of validated Ability JSON objects ready for API submission.

---

## Attack Categories (Week 1 Scope)

| # | Category | MITRE Tactic Mapping | Example Techniques |
|---|---|---|---|
| 1 | Credential Access | TA0006 | T1003 (OS Credential Dumping), T1558 (Steal/Forge Kerberos Tickets) |
| 2 | Privilege Escalation | TA0004 | T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control) |
| 3 | Persistence | TA0003 | T1547 (Boot/Logon Autostart), T1053 (Scheduled Task/Job) |
| 4 | Lateral Movement | TA0008 | T1021 (Remote Services), T1570 (Lateral Tool Transfer) |
| 5 | Defense Evasion | TA0005 | T1036 (Masquerading), T1027 (Obfuscated Files) |
| 6 | Command & Control | TA0011 | T1071 (Application Layer Protocol), T1573 (Encrypted Channel) |
| 7 | Discovery | TA0007 | T1087 (Account Discovery), T1046 (Network Service Discovery) |
| 8 | Collection | TA0009 | T1005 (Data from Local System), T1039 (Data from Network Shared Drive) |
| 9 | Exfiltration | TA0010 | T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol) |
| 10 | Cloud IAM Abuse | TA0004 / TA0006 | T1078.004 (Cloud Accounts), T1548 (Abuse Elevation Control) |
| 11 | Active Directory Abuse | TA0006 / TA0008 | T1558.003 (Kerberoasting), T1003.006 (DCSync) |
| 12 | Web Application Simulation | TA0001 | T1190 (Exploit Public-Facing Application) |
| 13 | Network Signaling | TA0011 | T1071.004 (DNS), T1572 (Protocol Tunneling) |

---

## Ability JSON Output

Every generated ability follows this strict schema (see [docs/ability_schema.md](docs/ability_schema.md)):

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "LSASS Memory Credential Dumping via comsvcs.dll",
  "description": "Simulates credential dumping from LSASS process memory using comsvcs.dll MiniDump. This technique is commonly used by APT29 and APT28 for credential harvesting in enterprise Windows environments.",
  "attack_category": "credential_access",
  "mitre_mapping": {
    "tactic": "credential-access",
    "technique": "T1003",
    "sub_technique": "T1003.001"
  },
  "threat_intel_context": {
    "associated_groups": ["APT29", "APT28", "Lazarus Group"],
    "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
    "recent_campaigns": ["SolarWinds (2020)", "NotPetya lateral movement phase"],
    "detection_guidance": "Monitor for access to LSASS process. Enable Credential Guard. Alert on rundll32.exe loading comsvcs.dll with MiniDump export."
  },
  "executors": [
    {
      "name": "powershell",
      "platform": "windows",
      "privilege_required": "admin",
      "command": "# SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\sim_lsass.dmp full",
      "payload_description": "Uses comsvcs.dll MiniDump to create a minidump of the LSASS process. In simulation context, the dump file is written to a temp directory with a simulation marker.",
      "cleanup_procedure": "Remove-Item $env:TEMP\\sim_lsass.dmp -Force -ErrorAction SilentlyContinue"
    },
    {
      "name": "cmd",
      "platform": "windows",
      "privilege_required": "admin",
      "command": "REM SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump %LSASS_PID% %TEMP%\\sim_lsass.dmp full",
      "payload_description": "Command prompt variant using rundll32 with comsvcs.dll for LSASS memory dumping simulation.",
      "cleanup_procedure": "del /f %TEMP%\\sim_lsass.dmp"
    }
  ],
  "approval_status": "PENDING",
  "created_by": "AI",
  "simulation_only": true,
  "schema_version": "1.0",
  "generated_at": "2026-02-20T14:30:22Z",
  "agent_version": "0.1.0"
}
```

---

## Safety Model

Hard-enforced safety constraints (non-negotiable):

```
┌─────────────────────────────────────────┐
│         Approval State Machine          │
│                                         │
│        ┌─────────────┐                  │
│        │   PENDING   │                  │
│        └───┬───┬─────┘                  │
│            │   │                          │
│   safety   │   │  human review             │
│   fail     │   │                          │
│            ▼   ▼                          │
│     ┌────────┐ ┌───────────┐              │
│     │BLOCKED │ │ APPROVED  │─► EXECUTABLE │
│     └────────┘ └───────────┘              │
│                 │                          │
│            ┌────┴─────┐                  │
│            │ REJECTED  │                  │
│            └──────────┘                  │
│                                         │
│   Agent can ONLY produce PENDING.       │
│   Safety system produces BLOCKED.       │
│   Human reviewer: APPROVED / REJECTED.  │
│   Backend scheduler: EXECUTABLE.        │
└─────────────────────────────────────────┘
```

| Constraint | Enforcement |
|---|---|
| `approval_status = PENDING` | Hardcoded default. Blocked at validation if any other value on creation. |
| `simulation_only = true` | Hardcoded default. Blocked if false. |
| `created_by = AI` | Hardcoded default. Blocked if missing or different. |
| No destructive commands | Blocklist: `rm -rf /`, `format`, `DROP TABLE`, ransomware keywords, etc. |
| MITRE-valid techniques | Every `technique` ID cross-checked against the Neo4j knowledge graph. |
| Simulation markers | Every executor command must include `# SIMULATION ONLY` or `REM SIMULATION ONLY`. |
| Cleanup required | Every executor must define a `cleanup_procedure`. |
| No real credential theft | Commands use dummy artifacts, not real credential stores. |

> Full safety specification: [docs/safety_governance.md](docs/safety_governance.md)

---

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Full 7-layer architecture with data flows, component details, and design decisions |
| [docs/ability_schema.md](docs/ability_schema.md) | Complete Ability JSON schema reference with Pydantic models and field descriptions |
| [docs/knowledge_graph_schema.md](docs/knowledge_graph_schema.md) | Neo4j graph schema — node types, relationships, indexes, and Cypher query patterns |
| [docs/development_plan.md](docs/development_plan.md) | Day-by-day development roadmap with verification checkpoints |
| [docs/safety_governance.md](docs/safety_governance.md) | Safety model, approval state machine, command blocklist, audit metadata |
| [docs/llm_integration_guide.md](docs/llm_integration_guide.md) | LLM provider configuration — Gemini, Groq, Ollama setup and swapping |
| [docs/edge_cases_and_retro.md](docs/edge_cases_and_retro.md) | Edge cases, retrospective analysis, and scope alignment review |

---

## Development Roadmap

| Phase | Days | Deliverable |
|---|---|---|
| **Phase 1** — Architecture & Data Modeling | 1–2 | Project structure, Pydantic schemas, Neo4j graph schema |
| **Phase 2** — Knowledge Ingestion | 2–3 | STIX parser, Neo4j loader, ingestion script |
| **Phase 3** — Threat Intelligence Enrichment | 3–4 | MISP galaxy integration, CTI tools |
| **Phase 4** — Attack Reasoning Engine | 4–5 | Gemini function calling loop, graph query tools |
| **Phase 5** — Ability Composition + Executors | 5–6 | Structured output, executor builder, multi-platform |
| **Phase 6** — Safety & API Integration | 6–7 | Validation rules, approval gating, JSON output, batch submission |
| **Phase 7** — Testing & Demo | 7+ | End-to-end validation, all 13 categories, demo |

> Detailed plan: [docs/development_plan.md](docs/development_plan.md)

---

## License

Internal use only. Not for public distribution.
