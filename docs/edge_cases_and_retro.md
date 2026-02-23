# Edge Cases & Retrospective Analysis

> Identified: February 22, 2026 · Pre-implementation review against client scope doc

---

## Table of Contents

- [Overview](#overview)
- [P0 — Critical (Fixed in Docs)](#p0--critical-fixed-in-docs)
- [P1 — High (Fixed in Docs)](#p1--high-fixed-in-docs)
- [P2 — Medium (Fixed in Docs)](#p2--medium-fixed-in-docs)
- [P3 — Low (Documented, Fix Later)](#p3--low-documented-fix-later)
- [Scope Alignment Summary](#scope-alignment-summary)
- [What's On Track](#whats-on-track)

---

## Overview

This document captures all edge cases, inconsistencies, and gaps found during a cross-validation of:
- **Client scope**: [Project_scope_doc.md](day_1_docs/Project_scope_doc.md) (source of truth)
- **Architecture**: [architecture.md](architecture.md)
- **Ability schema**: [ability_schema.md](ability_schema.md)
- **Safety governance**: [safety_governance.md](safety_governance.md)
- **Development plan**: [development_plan.md](development_plan.md)
- **Knowledge graph schema**: [knowledge_graph_schema.md](knowledge_graph_schema.md)
- **LLM integration guide**: [llm_integration_guide.md](llm_integration_guide.md)

Items marked **FIXED** have been resolved via doc modifications. Items marked **DEFERRED** are documented for future attention.

---

## P0 — Critical (Fixed in Docs)

### EC-01: No Command Validity / Syntax Validation

**Problem**: The architecture defined what commands must NOT appear (blocklist) and what markers must appear (simulation markers), but had **no mechanism to verify that generated commands are actually valid and runnable** on their target platform.

The LLM can hallucinate:
- Non-existent cmdlets (`Invoke-Mimikatz` is not a native PowerShell cmdlet)
- Wrong syntax (mixed PowerShell/bash in one command)
- Incorrect parameter flags or escaping
- References to binaries not present on a default OS install
- Platform mismatches (Windows paths like `$env:TEMP` in a bash executor)

**Impact**: Abilities pass all safety checks but are syntactically broken or nonsensical at execution time. Undermines the "realism and correctness" promise in the client scope doc.

**Solution (FIXED)**: Added 4 new validation rules (15–18) to `safety_governance.md` and `architecture.md`:

| Rule | Type | Action |
|---|---|---|
| Platform Coherence (rule 15) | Hard check | BLOCK — executor name must match platform; no cross-shell syntax |
| Command Syntax (rule 16) | Soft check | WARN — parse in target shell grammar; flag for human review |
| Known Binary Check (rule 17) | Soft check | WARN — verify referenced binaries against per-platform allowlist |
| Executor Name Enum (rule 18) | Hard check | BLOCK — must be valid `ExecutorType` enum value |

Design choice: Syntax and binary checks are **warnings** not hard blocks, because LLM-generated commands may use legitimate but uncommon patterns. Human reviewer makes the final call. Only platform coherence mismatches hard-block.

**Files modified**: `safety_governance.md`, `architecture.md`, `development_plan.md`

---

### EC-02: `cleanup_procedure` vs `cleanup_commands` Schema Inconsistency

**Problem**: The Pydantic `Executor` model in `ability_schema.md` defined `cleanup_procedure: str` (a single string field). But `safety_governance.md` referenced `cleanup_commands: list` (a list of strings) in multiple places — the cleanup rules table, the cleanup examples JSON, and validation rule #8.

**Impact**: Implementation would have to choose one. Developers reading different docs would implement different field types, causing schema drift.

**Solution (FIXED)**: Aligned `safety_governance.md` to the canonical Pydantic model. Field name is `cleanup_procedure` (string). Multi-step cleanup is joined with newlines within the single string field. Updated:
- Validation rule #8 text
- Cleanup rules table
- Cleanup examples JSON
- Added explicit note: *"The canonical field name is `cleanup_procedure` (string), as defined in the Pydantic Executor model"*

**Files modified**: `safety_governance.md`

---

## P1 — High (Fixed in Docs)

### EC-03: Executor `name` Not Enum-Constrained

**Problem**: `Executor.name` was typed as `str`, not an enum. Nothing prevented the LLM from outputting `name: "ansible"`, `name: "ruby"`, or any arbitrary string. The scope doc says executors are "PowerShell, command prompt, Bash, or scripting languages" but this was not enforced in the schema.

**Solution (FIXED)**: Added `ExecutorType` enum to `ability_schema.md`:
```
POWERSHELL | CMD | BASH | ZSH | PYTHON | SH | AWS_CLI | AZ_CLI | GCLOUD_CLI | CURL
```
Changed `Executor.name` from `str` to `ExecutorType`. Added validation rule #18 (executor name enum check) to safety pipeline.

**Files modified**: `ability_schema.md`, `safety_governance.md`

---

### EC-04: Cloud/Identity Attacks — No Cloud Platform Support

**Problem**: The client scope explicitly requires *"IAM misconfigurations, token abuse, metadata service exploitation, and identity privilege escalation."* But the `Platform` enum only had `windows | linux | macos`. Cloud attacks use:
- AWS CLI (`aws sts get-session-token`)
- Azure CLI (`az account get-access-token`)  
- `curl` against metadata endpoints (`169.254.169.254`)

The `cloud_iam_abuse` `AttackCategory` existed but had no matching platform or executor type.

**Solution (FIXED)**: 
- Added `CLOUD_AWS`, `CLOUD_AZURE`, `CLOUD_GCP` to `Platform` enum in `ability_schema.md`
- Added `aws_cli`, `az_cli`, `gcloud_cli`, `curl` to `ExecutorType` enum  
- Added cloud executors to the Layer 5 platform matrix in `architecture.md`

**Files modified**: `ability_schema.md`, `architecture.md`

---

### EC-05: Backend API Contract Not Defined

**Problem**: The client scope says *"AI Agent will send the attack scenarios to existing APIs for human approval."* Layer 7 in architecture.md shows `POST /abilities` with a generic 201/400/500 response, but:
- What does the backend actually expect? What's its exact schema?
- What fields does the backend require vs. what we generate?
- What if the backend rejects an ability — retry? Modify? Log?
- Is there a health check endpoint?

**Impact**: This is a significant integration risk for Day 6–7. If the backend schema differs from our Ability schema, the entire API integration day is spent on mapping, not connecting.

**Solution (FIXED — partial)**: Added to the Risk Register in `development_plan.md`:
> "Backend API contract unknown | Integration failure on Day 6–7 | High | Get API spec from client early; mock API for testing"

**Status**: **DEFERRED for client clarification**. The API spec needs to come from the client. For MVP, file output mode is the default. API mode should be developed against a mock server until the real spec is available.

**Files modified**: `development_plan.md`

---

## P2 — Medium (Fixed in Docs)

### EC-06: No Blocklist Versioning

**Problem**: The command blocklist was described as "additive — new patterns can be added, existing patterns never removed." But there was no version tracking. If a safety incident occurs, you can't determine what blocklist version was active when a specific ability was generated.

**Solution (FIXED)**: 
- Added `Blocklist Versioning` section to `safety_governance.md` with `BLOCKLIST_VERSION = "1.0.0"` and version history table
- Added `blocklist_version` field to `GenerationTrace` model in `ability_schema.md`
- Updated audit metadata example in `architecture.md` to include `blocklist_version`

**Files modified**: `safety_governance.md`, `ability_schema.md`, `architecture.md`

---

### EC-07: `total_tokens` Ambiguity in GenerationTrace

**Problem**: `GenerationTrace.total_tokens` wasn't clear whether it meant:
- Tokens from the final response only
- Cumulative across all tool-calling iterations
- Including tool call/result tokens

**Impact**: Matters for cost tracking and production budgeting.

**Solution (FIXED)**: Updated the field description in `ability_schema.md` to explicitly state:
> "Total token consumption (input + output) cumulative across all tool-calling iterations, including tool call/result tokens"

**Files modified**: `ability_schema.md`

---

### EC-08: Validation Warnings Not Surfaced to Human Reviewer

**Problem**: The new soft validation rules (syntax check, binary check) produce warnings, but there was no field in the Ability schema to carry these warnings to the human reviewer.

**Solution (FIXED)**: Added `validation_warnings: List[str]` field to `GenerationTrace` model. This surfaces soft warnings alongside the ability JSON so the human reviewer knows what to focus on.

**Files modified**: `ability_schema.md`

---

## P3 — Low (Documented, Fix Later)

### EC-09: Tactic-to-AttackCategory Mapping Ambiguity

**Problem**: Some `AttackCategory` values map to multiple MITRE tactics:
- `cloud_iam_abuse` → TA0004 (Privilege Escalation) AND TA0006 (Credential Access)
- `active_directory_abuse` → TA0006 (Credential Access) AND TA0008 (Lateral Movement)

But `MitreMapping.tactic` is a single string. If an ability spans two tactics, which tactic gets recorded?

**Solution (DEFERRED)**: For MVP, use the **primary tactic** — the one most closely aligned with the specific technique being simulated. Document this convention in the system prompt. Post-MVP, consider changing `MitreMapping.tactic` to `List[str]` to support multi-tactic abilities.

---

### EC-10: No Semantic Deduplication Strategy

**Problem**: UUID5 based on `technique_id + platform + command_hash` handles exact dedup. But the LLM can generate two slightly different commands for the same technique+platform (different wording, same intent). Over multiple runs, near-duplicate abilities accumulate in Neo4j.

**Solution (DEFERRED)**: For MVP, hash-level dedup is sufficient. Post-MVP options:
1. Embedding-based similarity check (cosine distance on command embeddings)
2. Technique+platform+executor_type compound key with "latest wins" policy
3. Manual dedup during human review

---

### EC-11: MITRE ATT&CK Version Staleness

**Problem**: Docs pin to ATT&CK v18.1 — good. But there's no mechanism to:
- Detect when a new version is released
- Re-ingest updated data
- Handle techniques that get revoked between versions (abilities referencing now-revoked techniques)

**Solution (DEFERRED)**: For MVP, v18.1 is frozen. Post-MVP:
1. Add `mitre_attack_version` field to `GenerationTrace`
2. Script to diff STIX versions and flag revoked techniques
3. Re-ingest script with `--clear` flag already supports this workflow

---

### EC-12: Blocklist is Deny-Only (No Allowlist Mode)

**Problem**: The blocklist catches destructive patterns via regex deny-list. But LLMs are creative — they can generate harmful patterns not yet on the blocklist. Examples:
- `Compress-Archive` to zip entire directories (exfil prep, not blocked)
- `net user /add` to create backdoor accounts (real technique, not blocked)
- Novel obfuscation that bypasses all regex patterns

**Solution (DEFERRED)**: For MVP, blocklist + human review is the defense. Post-MVP:
1. Add **allowlist mode** for high-risk categories (exfiltration, persistence)
2. Only pre-approved command patterns allowed, everything else flagged
3. Allowlist can be maintained per `AttackCategory`

---

### EC-13: No Unit Test Plan

**Problem**: Docs mention "unit tests pass" at verification checkpoints but specify no:
- Test framework (pytest?)
- Test file structure
- Mock strategy for Neo4j/LLM dependencies
- CI/CD integration

**Solution (DEFERRED)**: Add `tests/` directory structure to Phase 1. Recommend:
```
tests/
├── conftest.py              # Shared fixtures (mock Neo4j, mock LLM)
├── test_models.py           # Pydantic model validation tests
├── test_safety.py           # Safety rule unit tests (all 18 rules)
├── test_graph_queries.py    # Cypher query correctness
├── test_ingestion.py        # STIX parser tests
└── test_composition.py      # Ability composition tests
```

---

### EC-14: Gemini 3 Flash is `preview`

**Problem**: The model ID `gemini-3-flash-preview` indicates a preview release. Preview models can change behavior, have breaking API changes, or be deprecated without notice.

**Solution (DEFERRED)**: Mitigated by the existing provider fallback architecture (Groq/Ollama). When stable Gemini 3 Flash is released, update the `.env` model name. No code change needed.

---

## Scope Alignment Summary

| Client Requirement | Architecture Coverage | Status |
|---|---|---|
| MITRE ATT&CK data consumption | Layer 1 + Knowledge Graph + STIX parser | COVERED |
| Threat intelligence enrichment | Layer 2 + MISP galaxies + Neo4j CTI tools | COVERED |
| AI generates, never executes | System prompt + safety layer + approval gates | COVERED |
| Human-in-the-loop approval | State machine PENDING→APPROVED, hard validation | COVERED |
| JSON-only output | Layer 7 + structured output | COVERED |
| All 10+ attack domains | 13 `AttackCategory` enums (exceeds scope) | COVERED |
| Cleanup/reversibility | Required per executor, safety rule #8 | COVERED |
| Audit trail | `GenerationTrace`, `safety_audit.jsonl` | COVERED |
| Multiple executors per ability | `List[Executor]` min=1 | COVERED |
| Schema versioning | `schema_version` field + strategy | COVERED |
| Generated command correctness | **NEW**: Rules 15–18 (platform coherence, syntax, binary check) | NOW COVERED |
| Cloud/identity attack support | **NEW**: Cloud platforms + CLI executors | NOW COVERED |
| Backend API integration | Layer 7 exists but API spec unknown | PARTIALLY COVERED |

---

## What's On Track

The 7-layer architecture is clean and well-separated. The safety model is strong. The knowledge graph design is appropriate for the data volume. LLM integration with function calling is the right approach for grounded reasoning. The development plan is realistic for a 1-week MVP.

**Key strengths**:
- Pydantic as single source of truth prevents schema drift
- Neo4j graph enables natural ATT&CK traversal queries
- Provider-agnostic LLM layer (switch with 1 env var)
- Safety pipeline is fail-closed by design
- MISP galaxy fallback means no infrastructure dependency for CTI

**After these fixes, the remaining risk surface is**:
1. Backend API contract (needs client input)
2. LLM command quality (mitigated by new rules 15–18, but fundamentally depends on model capability)
3. Preview model stability (mitigated by fallback providers)
