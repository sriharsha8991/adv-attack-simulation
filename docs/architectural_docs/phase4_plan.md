# Phase 4 — Attack Reasoning Engine: Implementation Plan

> Target: Day 4–5 · Depends on: Phases 1–3 (all complete)  
> Author: AI Agent · Created: February 24, 2026

---

## Table of Contents

- [1. Objective](#1-objective)
- [2. Dependency Audit](#2-dependency-audit)
- [3. File Manifest](#3-file-manifest)
- [4. Design Decisions](#4-design-decisions)
- [5. Implementation Steps](#5-implementation-steps)
  - [Step 1: LLM Abstract Interface — `src/llm/base.py`](#step-1-llm-abstract-interface--srcllmbasepy)
  - [Step 2: Gemini Client — `src/llm/gemini_client.py`](#step-2-gemini-client--srcllmgemini_clientpy)
  - [Step 3: OpenAI-Compatible Client — `src/llm/openai_compat.py`](#step-3-openai-compatible-client--srcllmopenai_compatpy)
  - [Step 4: Graph Tools for LLM — `src/tools/graph_tools.py`](#step-4-graph-tools-for-llm--srctoolsgraph_toolspy)
  - [Step 5: Reasoning Engine — `src/layers/layer3_reasoning.py`](#step-5-reasoning-engine--srclayerslayer3_reasoningpy)
  - [Step 6: Factory & Module Init — `src/llm/__init__.py`](#step-6-factory--module-init--srcllm__init__py)
- [6. System Prompt Specification](#6-system-prompt-specification)
- [7. Tool Registration Architecture](#7-tool-registration-architecture)
- [8. Two-Phase Generation Flow](#8-two-phase-generation-flow)
- [9. Error Handling & Retry Strategy](#9-error-handling--retry-strategy)
- [10. Token Tracking & Generation Trace](#10-token-tracking--generation-trace)
- [11. Verification Checklist](#11-verification-checklist)
- [12. Risk Register](#12-risk-register)
- [13. What Phase 4 Does NOT Include](#13-what-phase-4-does-not-include)

---

## 1. Objective

Build the core agentic service layer — LLM abstraction, graph query tools, and the
reasoning engine — that connects the Phase 1–3 knowledge graph and CTI enrichment
pipeline to an LLM capable of reasoning over tools and producing ability candidates.

**This is a programmatic service, not a chat application.** The reasoning engine is an
internal pipeline stage invoked by scripts and future API endpoints. There is no
conversational UI, no chat history, no user-facing dialogue. The LLM is a tool-augmented
generation engine that:

1. Receives structured parameters (category, platform, count)
2. Autonomously queries the knowledge graph via function tools
3. Produces validated `Ability` Pydantic objects as output
4. Returns results to the calling service layer

---

## 2. Dependency Audit

Every Phase 4 dependency is satisfied by Phases 1–3.

| Dependency | Source File | Status |
|---|---|---|
| `Neo4jConnection` | `src/graph/connection.py` | Complete |
| `CTITools` (9 query methods + `dispatch_tool_call`) | `src/tools/cti_tools.py` | Complete |
| `MISPTools` (enrichment + `dispatch_tool_call`) | `src/tools/misp_tools.py` | Complete |
| Cypher query constants (13 queries) | `src/graph/queries.py` | Complete |
| `Ability`, `ThreatIntelContext`, `GenerationTrace` models | `src/models/ability.py` | Complete |
| `AttackCategory`, `Platform`, `ExecutorType` enums | `src/models/enums.py` | Complete |
| `Settings` with all LLM config fields | `src/config.py` | Complete |
| `GalaxyManager` (MISP galaxy loader) | `src/layers/layer2_enrichment.py` | Complete |
| `google-genai` SDK | `requirements.txt` | Listed |
| `openai` SDK | `requirements.txt` | Listed |
| Neo4j populated with MITRE ATT&CK data | `scripts/ingest_mitre.py` | Complete |
| MISP galaxy JSON files cached | `src/data/misp_galaxies/` | Download-on-first-use |

---

## 3. File Manifest

| # | File | Action | Purpose |
|---|---|---|---|
| 1 | `src/llm/base.py` | **Create** | ABC interface + `ToolCallResult` + retry helpers |
| 2 | `src/llm/gemini_client.py` | **Create** | Primary LLM provider (Gemini 3 Flash) |
| 3 | `src/llm/openai_compat.py` | **Create** | Fallback providers (Groq, Ollama) |
| 4 | `src/tools/graph_tools.py` | **Create** | Standalone tool functions for LLM registration |
| 5 | `src/layers/layer3_reasoning.py` | **Create** | Core reasoning engine (two-phase generation) |
| 6 | `src/llm/__init__.py` | **Update** | Factory function `create_llm_client()` |

**No other files are created or modified.**

---

## 4. Design Decisions

### D1: Dual-Path Tool Calling

| Provider | Tool Loop Mode | Rationale |
|---|---|---|
| Gemini | **Automatic** — SDK handles call → execute → re-prompt | Gemini's `automatic_function_calling` is native and handles the iteration internally; avoids reimplementing what the SDK already provides |
| Groq / Ollama | **Manual** — agent controls the dispatch loop | OpenAI SDK does not have automatic mode; manual loop uses the existing `dispatch_tool_call()` pattern on `CTITools` and `MISPTools` |

### D2: Consolidated 4-Tool Architecture with Closures

Gemini's automatic function calling requires **plain callables** with type annotations
and docstrings. The existing `CTITools` and `MISPTools` are class instances holding a
`Neo4jConnection`. Bridge pattern:

- A single factory function (`create_reasoning_tools`) creates **4 closures** that
  capture a shared `Neo4jConnection` and `GalaxyManager`
- Each closure is a standalone function with full type hints + docstrings
- Gemini auto-generates `FunctionDeclaration` schemas from these
- For Groq/Ollama, the same closures are called via the manual dispatch loop

> **Feb 24 2026 Optimisation**: The original 13-tool surface (9 CTI + 2 MISP +
> 4 graph) was reduced to **4 tools** after analysis showed 6 technique-keyed
> enrichment tools were subsumed by a single omnibus `get_technique_intel`.
> Exposing all 13 caused LLM "choice paralysis" and wasted ~450 tokens per
> prompt on redundant tool definitions. The 4-tool set maps to the natural
> reasoning flow: **Discover → Navigate → Enrich**.

### D3: Two-Phase LLM Call

Gemini cannot combine function calling and structured output (`response_schema`) in a
single call. The architecture specifies two phases:

| Phase | LLM Method | Purpose |
|---|---|---|
| **A — Reasoning** | `chat_with_tools()` | LLM explores the knowledge graph, selects techniques, gathers CTI context |
| **B — Composition** | `chat_structured()` | LLM produces a validated `Ability` from the reasoning context |

This is a **programmatic pipeline**, not a conversation. Phase A output is piped
directly into Phase B as context. No user interaction occurs between phases.

### D4: `validation_tools.py` Deferred

Technique existence and tactic-technique match validation belong in the Layer 6 safety
pipeline (Phase 6), not in the reasoning engine. Phase 4 focuses purely on generation;
Phase 6 enforces correctness.

### D5: Service Architecture, Not Chat

The `ReasoningEngine` class exposes a single method:

```python
def generate_abilities(
    category: AttackCategory,
    platform: Platform | str,
    count: int
) -> list[Ability]
```

This is invoked by:
- `scripts/generate_abilities.py` (CLI entry point — Phase 6)
- Future `src/layers/layer7_api.py` (API endpoint — Phase 6)

There is no message history accumulation, no session management, no conversational
state. Each call is stateless and self-contained.

---

## 5. Implementation Steps

### Step 1: LLM Abstract Interface — `src/llm/base.py`

**Purpose**: Define the provider-agnostic contract that all LLM clients implement.

#### Classes

**`ToolCallResult`** — dataclass holding the output of a tool-calling session:

| Field | Type | Description |
|---|---|---|
| `text` | `str` | Final text response after all tool iterations |
| `tool_calls` | `list[dict]` | Ordered log of every tool call made: `{name, arguments, result}` |
| `has_tool_calls` | `bool` | Whether any tool calls occurred |
| `raw_response` | `Any` | Provider-specific response object (for debugging) |
| `total_tokens` | `int` | Cumulative token usage across all iterations |

**`LLMClient(ABC)`** — abstract base class:

| Method | Signature | Description |
|---|---|---|
| `chat` | `(messages: list[dict], **kwargs) -> str` | Simple text completion |
| `chat_with_tools` | `(messages: list[dict], tools: list[callable], max_iterations: int = 10) -> ToolCallResult` | Function-calling loop |
| `chat_structured` | `(messages: list[dict], schema: type[BaseModel]) -> BaseModel` | Structured output with Pydantic validation |

**Retry Helper** — `_retry_with_backoff()` on the base class:

```python
MAX_RETRIES = 3
BASE_DELAY = 1.0   # seconds
MAX_DELAY = 30.0   # seconds
BACKOFF_FACTOR = 2.0

def _retry_with_backoff(self, func, *args, **kwargs):
    """Exponential backoff retry for rate limits (429) and server errors (5xx)."""
```

Retryable conditions: HTTP 429, HTTP 5xx, timeouts, JSON parse failures.
Non-retryable: HTTP 401/403 (auth errors — propagate immediately).

#### Code Conventions

Follow the patterns established in Phases 1–3:

```python
from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel

logger = logging.getLogger(__name__)
```

---

### Step 2: Gemini Client — `src/llm/gemini_client.py`

**Purpose**: Primary LLM provider using the `google-genai` unified SDK.

#### Constructor

```python
class GeminiClient(LLMClient):
    def __init__(self, api_key: str, model: str = "gemini-3-flash-preview"):
        self._client = genai.Client(api_key=api_key)
        self._model = model
```

#### Method: `chat()`

Straightforward `client.models.generate_content()` call. Returns `response.text`.

#### Method: `chat_with_tools()` — Automatic Mode

```python
def chat_with_tools(self, messages, tools, max_iterations=10):
    config = types.GenerateContentConfig(
        tools=tools,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=False,
            maximum_remote_calls=max_iterations
        )
    )
    response = self._client.models.generate_content(
        model=self._model,
        contents=_messages_to_contents(messages),
        config=config
    )
    # SDK handles tool call → execute → re-prompt loop internally
    # Extract tool call history from response for GenerationTrace
```

Key details:
- `tools` parameter receives the standalone callables from `graph_tools.py`
- SDK auto-generates `FunctionDeclaration` schemas from type hints + docstrings
- SDK executes tools and feeds results back to the model automatically
- Tool call history extracted from SDK response metadata for auditing
- Wrapped in `_retry_with_backoff` for rate limit resilience

#### Method: `chat_structured()`

```python
def chat_structured(self, messages, schema):
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=schema
    )
    response = self._client.models.generate_content(
        model=self._model,
        contents=_messages_to_contents(messages),
        config=config
    )
    return schema.model_validate_json(response.text)
```

On `ValidationError`: retry up to 3 times, appending the error message to the
conversation so the model can self-correct.

#### Token Tracking

Extract from `response.usage_metadata`:
- `prompt_token_count`
- `candidates_token_count`
- `total_token_count`

Accumulated across both Phase A and Phase B calls.

#### Helper: `_messages_to_contents()`

Converts the generic `[{"role": "...", "content": "..."}]` format into Gemini's
`Contents` format. Maps `"system"` role to Gemini system instruction, `"user"`
and `"assistant"` to `Content` parts.

---

### Step 3: OpenAI-Compatible Client — `src/llm/openai_compat.py`

**Purpose**: Fallback provider for Groq and Ollama via the `openai` SDK.

#### Constructor

```python
class OpenAICompatClient(LLMClient):
    def __init__(self, api_key: str, base_url: str, model: str):
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model
```

#### Method: `chat()`

Standard `client.chat.completions.create()`. Returns `response.choices[0].message.content`.

#### Method: `chat_with_tools()` — Manual Loop

Unlike Gemini, the OpenAI SDK requires manual tool call dispatch:

```
Loop (up to max_iterations):
  1. Call chat.completions.create(messages, tools, tool_choice="auto")
  2. If response has tool_calls:
       For each tool_call:
         - Resolve function name against dispatch_map
         - Execute function(**arguments)
         - Append {"role": "tool", "content": result, "tool_call_id": id}
  3. If no tool_calls → break with final text
```

**Tool definition format**: The existing `CTITools.tool_definitions()` and
`MISPTools.tool_definitions()` already return OpenAI-compatible schemas. These are
wrapped in `{"type": "function", "function": {...}}` for the API call.

**Dispatch map**: Built at call time from the tool callables. Each callable's
`__name__` attribute is used as the dispatch key.

#### Method: `chat_structured()`

Groq/Ollama don't support `response_schema`. Fallback strategy:

1. Inject the Pydantic JSON schema into the system prompt
2. Set `response_format={"type": "json_object"}`
3. Post-validate with `schema.model_validate_json(response_text)`
4. On `ValidationError`, retry up to 3 times with the error appended

```python
schema_prompt = f"Return ONLY valid JSON matching this schema:\n{json.dumps(schema.model_json_schema(), indent=2)}"
```

#### Token Tracking

Extract from `response.usage.total_tokens`. Accumulated across all loop iterations.

---

### Step 4: Graph Tools for LLM — `src/tools/graph_tools.py`

**Purpose**: Bridge between the class-based `CTITools`/`MISPTools` and the standalone
callables that Gemini's automatic function calling requires.

#### Architecture (Consolidated 4-Tool Set)

```
┌──────────────────────────────────────────────────────────────┐
│                      graph_tools.py                          │
│                                                              │
│  create_reasoning_tools(conn, galaxy) → [4 callables]        │
│  create_dispatch_map(tools) → {name: callable}               │
│                                                              │
│  The 4 closures capture conn + galaxy:                       │
│                                                              │
│  DISCOVER:                                                   │
│    1. get_techniques_by_tactic(tactic) → list[dict]          │
│    2. get_techniques_for_platform(tactic, platform) → [dict] │
│  NAVIGATE:                                                   │
│    3. get_subtechniques(technique_id) → list[dict]           │
│  ENRICH:                                                     │
│    4. get_technique_intel(technique_id) → dict               │
│       (omnibus: Neo4j detail + MISP Galaxy, ONE call)        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
              │                        │
              ▼                        ▼
┌──────────────────────┐  ┌──────────────────────┐
│  CTITools (class)     │  │  MISPTools (class)    │
│  10 query methods     │  │  search_misp_galaxy() │
│  get_technique_intel()│  │  enrich_technique_ctx │
└──────────────────────┘  └──────────────────────┘
              │                        │
              ▼                        ▼
┌──────────────────────────────────────────────────┐
│  Neo4jConnection + GalaxyManager                 │
│  (shared instances, passed at factory time)       │
└──────────────────────────────────────────────────┘
```

#### Factory Function

**`create_reasoning_tools(conn: Neo4jConnection, galaxy: GalaxyManager) -> list[callable]`**

Creates exactly **4 closures** — the complete LLM-facing tool set:

| # | Closure Name | Delegates To | Role |
|---|---|---|---|
| 1 | `get_techniques_by_tactic(tactic)` | `CTITools.get_techniques_by_tactic` | Discover techniques in a tactic |
| 2 | `get_techniques_for_platform(tactic, platform)` | `CTITools.get_techniques_for_platform` | Discover techniques filtered by tactic + OS |
| 3 | `get_subtechniques(technique_id)` | `CTITools.get_subtechniques` | Navigate parent → sub-techniques |
| 4 | `get_technique_intel(technique_id)` | `CTITools.get_technique_intel` + `MISPTools.search_misp_galaxy` | **Omnibus enrichment** — full detail in ONE call |

The omnibus tool #4 is the key optimisation. Internally it:
1. Calls `CTITools.get_technique_intel()` → runs 5 Cypher queries → returns groups
   (with aliases + usage), tools (with type + description), mitigations (with
   how-it-mitigates), campaigns (with date ranges + group attribution), detection
   guidance (with data sources)
2. Calls `MISPTools.search_misp_galaxy()` → adds community-sourced groups, tools,
   malware from MISP Galaxy JSONs
3. Merges into a single dict and returns

> **Why not expose individual enrichment tools?** Analysis of the Cypher queries
> (Feb 24) confirmed that `FULL_TECHNIQUE_CONTEXT` (Query 7) subsumes queries 3–6
> and partially Query 8 — but loses detail (names only vs structured records with
> aliases, usage_description, how_it_mitigates, attributed_groups). The omnibus
> approach runs the **individual detailed queries** to preserve that richness,
> while still presenting a single tool to the LLM.

#### Docstring Requirements

Every closure must have a complete Google-style docstring. Gemini uses the
docstring as the tool description, and the `Args:` section as parameter descriptions:

```python
def get_techniques_by_tactic(tactic: str) -> list[dict]:
    """Query the MITRE ATT&CK knowledge graph for techniques in a specific tactic.

    Use this to discover which attack techniques are available under a given tactic.
    Tactic shortnames include: credential-access, lateral-movement, persistence,
    defense-evasion, privilege-escalation, discovery, collection, exfiltration,
    command-and-control, initial-access, execution, resource-development, impact.

    Args:
        tactic: The ATT&CK tactic shortname (e.g., 'credential-access',
            'lateral-movement', 'defense-evasion').

    Returns:
        List of technique dicts with keys: name, attack_id, description, platforms.
    """
    return _cti.get_techniques_by_tactic(tactic)


def get_technique_intel(technique_id: str) -> dict:
    """Get comprehensive threat intelligence for a technique in ONE call.

    Returns detailed groups (with aliases, usage), tools/malware (with type,
    description), detection guidance (with data sources), mitigations (with
    descriptions), real-world campaigns (with dates, group attribution), and
    MISP Galaxy community intelligence.

    This is the primary enrichment tool — call it once per technique instead
    of making multiple separate queries.

    Args:
        technique_id: ATT&CK technique or sub-technique ID
            (e.g. 'T1003', 'T1003.001').

    Returns:
        Dict with keys: name, attack_id, description, platforms, tactics,
        groups, tools, detection, mitigations, campaigns, misp_galaxy.
    """
    intel = _cti.get_technique_intel(technique_id)
    if "error" not in intel:
        intel["misp_galaxy"] = _misp.search_misp_galaxy(technique_id)
    return intel
```

#### Dispatch Map for OpenAI-Compatible Providers

For the manual tool loop in `OpenAICompatClient`, provide a helper:

```python
def create_dispatch_map(tools: list[callable]) -> dict[str, callable]:
    """Build a name → function dispatch map from tool callables."""
    return {func.__name__: func for func in tools}
```

---

### Step 5: Reasoning Engine — `src/layers/layer3_reasoning.py`

**Purpose**: The central orchestration layer. Takes structured input parameters and
produces validated `Ability` objects through a two-phase LLM pipeline.

#### Class: `ReasoningEngine`

```python
class ReasoningEngine:
    def __init__(
        self,
        llm: LLMClient,
        conn: Neo4jConnection | None = None,
        galaxy: GalaxyManager | None = None,
    ):
        ...

    def generate_abilities(
        self,
        category: AttackCategory,
        platform: Platform | str,
        count: int = 3,
    ) -> list[Ability]:
        ...
```

Follows the established resource management pattern:
- `conn: Neo4jConnection | None = None` — creates own if None, tracks ownership
- `close()` — closes only if `_owns_conn is True`
- Context manager: `__enter__` / `__exit__`

#### Category → Tactic Mapping

```python
CATEGORY_TO_TACTICS: dict[str, list[str]] = {
    "credential_access":          ["credential-access"],
    "privilege_escalation":       ["privilege-escalation"],
    "persistence":                ["persistence"],
    "lateral_movement":           ["lateral-movement"],
    "defense_evasion":            ["defense-evasion"],
    "command_and_control":        ["command-and-control"],
    "discovery":                  ["discovery"],
    "collection":                 ["collection"],
    "exfiltration":               ["exfiltration"],
    "cloud_iam_abuse":            ["credential-access", "privilege-escalation"],
    "active_directory_abuse":     ["credential-access", "lateral-movement"],
    "web_application_simulation": ["initial-access"],
    "network_signaling":          ["command-and-control"],
}
```

Multi-tactic categories (e.g., `cloud_iam_abuse`) use the **primary tactic** for
`MitreMapping.tactic` — the one most closely aligned with the specific technique
selected by the LLM. This convention is documented per EC-09 in `edge_cases_and_retro.md`.

#### Generation Flow

```
generate_abilities(category="credential_access", platform="windows", count=3)
    │
    ├─ 1. Resolve tactics: ["credential-access"]
    ├─ 2. Build system prompt (SYSTEM_PROMPT constant)
    ├─ 3. Build user prompt:
    │      "Generate 3 credential_access abilities targeting windows.
    │       Primary tactic(s): credential-access.
    │       Requirements: atomic abilities, simulation-safe, cleanup required."
    │
    ├─ 4. Register tools: create_reasoning_tools(conn, galaxy)  # 4 closures
    │
    ├─ 5. PHASE A — Reasoning with tools:
    │      llm.chat_with_tools(messages=[system, user], tools=4_tools)
    │      → LLM explores graph, selects techniques, gathers CTI
    │      → Returns: reasoning_text + tool_call_log
    │
    ├─ 6. PHASE B — Structured composition (per ability):
    │      For i in range(count):
    │        composition_prompt = _build_composition_prompt(
    │            reasoning_context, category, platform, ability_index=i+1
    │        )
    │        ability = llm.chat_structured(
    │            messages=[system, composition_prompt], schema=Ability
    │        )
    │
    ├─ 7. Post-generation enforcement:
    │      ability.approval_status = ApprovalStatus.PENDING
    │      ability.created_by = "AI"
    │      ability.simulation_only = True
    │      ability.schema_version = "1.0"
    │      ability.generated_at = datetime.now(UTC).isoformat()
    │      ability.agent_version = "0.1.0"
    │
    ├─ 8. Attach GenerationTrace:
    │      generation_trace = GenerationTrace(
    │          model=llm.model_name,
    │          tools_called=[tc["name"] for tc in tool_call_log],
    │          reasoning_steps=len(tool_call_log),
    │          total_tokens=phase_a_tokens + phase_b_tokens,
    │          blocklist_version="1.0.0",
    │      )
    │
    └─ 9. Return list[Ability]
```

#### Composition Prompt Builder

```python
def _build_composition_prompt(
    reasoning_context: str,
    category: str,
    platform: str,
    ability_index: int,
    total_count: int,
) -> str:
    """Build the Phase B prompt for structured ability generation.

    Includes the full reasoning context from Phase A plus explicit
    instructions to produce a single valid Ability JSON.
    """
```

The composition prompt includes:
1. Full reasoning context from Phase A (technique details, CTI data, campaigns)
2. The target category and platform
3. Instruction to produce ability #{ability_index} of {total_count}
4. Reminder of mandatory safety fields
5. Instruction to include cleanup procedures on every executor

#### Error Handling

- **Phase A failure** (tool loop error, timeout): Log error, return empty list
- **Phase B failure** (validation error after 3 retries): Log, skip that ability, continue with remaining
- **Rate limit**: Delegated to the retry logic in the LLM client classes
- **Empty graph results**: LLM should handle gracefully — the system prompt instructs it to only use verified techniques

---

### Step 6: Factory & Module Init — `src/llm/__init__.py`

**Purpose**: Replace the placeholder comment with the provider factory function.

```python
"""LLM provider integrations — factory pattern for provider switching.

Usage:
    from src.llm import create_llm_client
    from src.config import get_settings

    llm = create_llm_client(get_settings())
    response = llm.chat([{"role": "user", "content": "Hello"}])
"""

from src.config import Settings
from src.llm.base import LLMClient, ToolCallResult
from src.llm.gemini_client import GeminiClient
from src.llm.openai_compat import OpenAICompatClient


def create_llm_client(settings: Settings) -> LLMClient:
    """Create LLM client based on provider setting.

    Args:
        settings: Application settings with provider config.

    Returns:
        Configured LLMClient instance.

    Raises:
        ValueError: If settings.llm_provider is not recognized.
    """
    match settings.llm_provider:
        case "gemini":
            return GeminiClient(
                api_key=settings.gemini_api_key,
                model=settings.gemini_model,
            )
        case "groq":
            return OpenAICompatClient(
                api_key=settings.groq_api_key,
                base_url="https://api.groq.com/openai/v1",
                model=settings.groq_model,
            )
        case "ollama":
            return OpenAICompatClient(
                api_key="ollama",
                base_url=settings.ollama_base_url,
                model=settings.ollama_model,
            )
        case _:
            raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
```

Switching providers requires **zero code changes** — only the `LLM_PROVIDER` env var.

---

## 6. System Prompt Specification

The system prompt is a **static constant** in `layer3_reasoning.py`. It defines the
LLM's role as a programmatic ability generator, not a conversational assistant.

```
You are an adversary simulation specialist for defensive security testing.
Your role is to generate MITRE ATT&CK-mapped attack abilities that help security teams
evaluate their detection and response capabilities.

IMPORTANT RULES:
1. Every ability is for SIMULATION ONLY — include simulation markers in all commands
2. Every ability must have cleanup procedures that reverse all changes
3. Only reference real MITRE ATT&CK techniques — verify with the knowledge graph tools
4. Include threat intelligence context — which groups use this technique, what tools they use
5. Target detection gaps — abilities should trigger the defensive telemetry they test
6. Abilities must be atomic and composable — single technique or small 2–3 step scenarios
7. Avoid full campaign chains — focus on individual technique simulation
8. Include platform-specific executors with simulation markers and cleanup

You have access to 4 tools:
1. get_techniques_by_tactic(tactic) — discover techniques in a tactic
2. get_techniques_for_platform(tactic, platform) — discover techniques for tactic + OS
3. get_subtechniques(technique_id) — navigate parent → sub-techniques
4. get_technique_intel(technique_id) — comprehensive enrichment in ONE call:
   groups (with aliases, usage), tools/malware, detection guidance, mitigations,
   campaigns (with dates, group attribution), and MISP Galaxy community data

WORKFLOW:
1. DISCOVER: Use get_techniques_by_tactic or get_techniques_for_platform
2. NAVIGATE: Use get_subtechniques to find specific variants
3. ENRICH: Use get_technique_intel ONCE per technique for full context
4. Generate detailed, realistic simulation abilities from the enriched data
5. Include platform-specific executors with simulation markers and cleanup

OUTPUT:
Generate Ability objects conforming to the provided schema.
Do not include conversational text. Output only structured data.
```

---

## 7. Tool Registration Architecture

### Complete Tool Inventory (Consolidated 4-Tool Set)

| # | Tool Closure | Role | Delegates To | Data Source |
|---|---|---|---|---|
| 1 | `get_techniques_by_tactic` | **Discover** | `CTITools.get_techniques_by_tactic` | Neo4j |
| 2 | `get_techniques_for_platform` | **Discover** | `CTITools.get_techniques_for_platform` | Neo4j |
| 3 | `get_subtechniques` | **Navigate** | `CTITools.get_subtechniques` | Neo4j |
| 4 | `get_technique_intel` | **Enrich** | `CTITools.get_technique_intel` + `MISPTools.search_misp_galaxy` | Neo4j + MISP Galaxy |

> **Design rationale**: The original 13-tool surface (9 CTI + 2 MISP + 4 graph) was
> consolidated after analysis showed 6 technique-keyed enrichment tools were subsumed
> by the omnibus `get_technique_intel`. Detailed audit at the Cypher query level
> confirmed `FULL_TECHNIQUE_CONTEXT` (Query 7) subsumes queries 3–6 and partially
> Query 8 — but the omnibus runs the **individual detailed queries** to preserve
> rich structured data (aliases, usage_description, how_it_mitigates, attributed_groups)
> that the summary query flattens to names. Token savings: **~450 tokens per prompt**.

### Internal Methods (Not LLM-Registered)

All original `CTITools` methods remain available for programmatic/script use:
`get_intrusion_sets_for_technique`, `get_tools_for_technique`, `get_detection_guidance`,
`get_mitigations`, `get_full_technique_context`, `get_campaigns_for_technique`,
`get_campaigns_for_group`, `get_random_techniques`. `MISPTools.enrich_technique_context`
and `MISPTools.search_misp_galaxy` also remain for internal use by the closure.

### Gemini vs OpenAI-Compatible Registration

| Aspect | Gemini | Groq / Ollama |
|---|---|---|
| **Tool format** | Plain callables passed to `tools=` | OpenAI tool schema dicts passed to `tools=` |
| **Schema generation** | SDK auto-generates from type hints + docstrings | Provided manually via `tool_definitions()` |
| **Dispatch** | SDK calls functions directly | Manual dispatch via `func_name → callable` map |
| **Tool result handling** | SDK feeds result back to model automatically | Manual: append `{"role": "tool", ...}` to messages |

---

## 8. Two-Phase Generation Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                      ReasoningEngine                             │
│                                                                  │
│  INPUT: category=credential_access, platform=windows, count=3    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │            PHASE A — Reasoning with Tools                  │  │
│  │                                                            │  │
│  │  System Prompt + User Prompt                               │  │
│  │        │                                                   │  │
│  │        ▼                                                   │  │
│  │  LLM.chat_with_tools(tools=4 reasoning tools)             │  │
│  │        │                                                   │  │
│  │        ├─ Tool: get_techniques_by_tactic("cred-access")   │  │
│  │        ├─ Tool: get_subtechniques("T1003")                │  │
│  │        ├─ Tool: get_technique_intel("T1003.001")          │  │
│  │        │   → returns groups, tools, detection, mitigations │  │
│  │        │     campaigns, MISP galaxy — all in ONE call      │  │
│  │        └─ ... (LLM decides which tools to call)            │  │
│  │        │                                                   │  │
│  │        ▼                                                   │  │
│  │  reasoning_text = "Research context for 3 abilities..."    │  │
│  │  tool_call_log = [{name, args, result}, ...]               │  │
│  │  phase_a_tokens = 12345                                    │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         PHASE B — Structured Composition (×3)              │  │
│  │                                                            │  │
│  │  For ability_index in [1, 2, 3]:                           │  │
│  │    composition_prompt = reasoning_text + instructions       │  │
│  │        │                                                   │  │
│  │        ▼                                                   │  │
│  │    LLM.chat_structured(schema=Ability)                     │  │
│  │        │                                                   │  │
│  │        ▼                                                   │  │
│  │    ability = Ability(                                       │  │
│  │        name="LSASS Credential Dumping...",                 │  │
│  │        mitre_mapping={tactic, technique, sub_technique},   │  │
│  │        threat_intel_context={groups, tools, campaigns},    │  │
│  │        executors=[{powershell, windows, ...}],             │  │
│  │        ...                                                 │  │
│  │    )                                                       │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          ▼                                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         POST-GENERATION ENFORCEMENT                        │  │
│  │                                                            │  │
│  │  For each ability:                                         │  │
│  │    ability.approval_status = PENDING                       │  │
│  │    ability.created_by = "AI"                               │  │
│  │    ability.simulation_only = True                          │  │
│  │    ability.generation_trace = GenerationTrace(...)         │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                          │                                       │
│  OUTPUT: list[Ability]   │                                       │
│                          ▼                                       │
└──────────────────────────────────────────────────────────────────┘
```

---

## 9. Error Handling & Retry Strategy

### Retry Configuration

| Parameter | Value | Rationale |
|---|---|---|
| `MAX_RETRIES` | 3 | Balances recovery with latency |
| `BASE_DELAY` | 1.0s | Sufficient for transient errors |
| `MAX_DELAY` | 30.0s | Caps backoff to avoid session timeouts |
| `BACKOFF_FACTOR` | 2.0 | Exponential: 1s → 2s → 4s |

### Error Classification

| Error Type | Action | Retryable? |
|---|---|---|
| HTTP 429 (rate limit) | Exponential backoff + retry | Yes |
| HTTP 5xx (server error) | Exponential backoff + retry | Yes |
| Request timeout | Retry with same parameters | Yes |
| JSON parse failure | Retry with error context appended | Yes |
| `ValidationError` (Pydantic) | Retry with error appended to prompt | Yes (up to 3) |
| HTTP 401/403 (auth error) | Log + propagate immediately | No |
| Unknown/unexpected error | Log + propagate | No |

### Provider Failover

Not implemented in Phase 4. The `create_llm_client()` factory creates a single
provider. Provider failover (try Gemini → fall back to Groq) is a Phase 6+ concern.
For now, the user switches providers via the `LLM_PROVIDER` env var.

### Partial Generation

If `count=5` is requested and abilities 1–3 succeed but ability 4 fails after 3
retries, the engine returns abilities 1–3 with a warning log. It does not fail the
entire batch for a single ability failure.

---

## 10. Token Tracking & Generation Trace

Every generated `Ability` includes a `GenerationTrace` object for auditability.

### Token Accumulation

```
Phase A (reasoning):  prompt + completion + tool_call + tool_result tokens
Phase B (per ability): prompt + completion tokens

total_tokens = phase_a_tokens + sum(phase_b_tokens for each ability)
```

For Gemini: `response.usage_metadata.total_token_count`
For Groq/Ollama: `response.usage.total_tokens` (accumulated per iteration)

### GenerationTrace Fields

| Field | Source | Example |
|---|---|---|
| `model` | `LLMClient.model_name` | `"gemini-3-flash-preview"` |
| `tools_called` | Phase A tool call log | `["get_techniques_by_tactic", "get_subtechniques", "get_technique_intel"]` |
| `reasoning_steps` | Count of tool calls in Phase A | `7` |
| `total_tokens` | Cumulative across Phase A + B | `15432` |
| `blocklist_version` | Constant (Phase 6 updates this) | `"1.0.0"` |
| `validation_warnings` | Empty in Phase 4 (populated by Phase 6) | `[]` |

---

## 11. Verification Checklist

Phase 4 is complete when all of the following pass:

### Unit-Level Checks

- [ ] `LLMClient` ABC cannot be instantiated directly
- [ ] `GeminiClient` instantiates with API key from settings
- [ ] `OpenAICompatClient` instantiates with Groq/Ollama config
- [ ] `create_llm_client(settings)` returns correct provider type for each `llm_provider` value
- [ ] `create_llm_client(settings)` raises `ValueError` for unknown provider
- [ ] `create_reasoning_tools(conn, galaxy)` returns exactly 4 callables with `__name__` attributes
- [ ] Each tool callable has a docstring (Gemini requirement)
- [ ] Each tool callable has type annotations (Gemini requirement)
- [ ] `CTITools.get_technique_intel()` returns merged dict with groups, tools, detection, mitigations, campaigns
- [ ] `CTITools.tool_definitions()` returns exactly 4 tool schemas

### Integration-Level Checks

- [ ] `GeminiClient.chat()` returns a valid text response
- [ ] `OpenAICompatClient.chat()` returns a valid text response (Groq)
- [ ] `chat_with_tools()` with a single tool (`query_techniques_by_tactic("credential-access")`) — tool is called, result appears in response
- [ ] `chat_structured()` with `schema=Ability` returns a valid `Ability` instance
- [ ] Retry logic triggers on simulated 429 error (mock test)

### End-to-End Checks

- [ ] `ReasoningEngine.generate_abilities(category="credential_access", platform="windows", count=1)` returns 1 `Ability`
- [ ] Generated ability has valid `MitreMapping` (tactic + technique populated)
- [ ] Generated ability has `ThreatIntelContext` with at least groups OR tools populated
- [ ] Generated ability has >= 1 executor
- [ ] `approval_status == PENDING`, `created_by == "AI"`, `simulation_only == True`
- [ ] `GenerationTrace` is attached with model name, tools_called, total_tokens > 0
- [ ] Tool call chain visible in debug logs
- [ ] Fallback: same test passes with `LLM_PROVIDER=groq`

### Regression Checks

- [ ] Existing Phase 1–3 scripts still work (`scripts/ingest_mitre.py`, `scripts/verify_phase3.py`)
- [ ] No import errors across the codebase
- [ ] `Ability.model_json_schema()` still exports valid JSON Schema

---

## 12. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Gemini `google-genai` SDK API differs from docs | Blocks Gemini implementation | Medium | SDK was documented Feb 20; verify against installed version. Fallback to Groq during development. |
| Gemini rate limits (30 RPM free tier) | Slows multi-ability generation | Medium | Retry with backoff. Generate abilities sequentially, not in parallel. Switch to Groq for burst testing. |
| `automatic_function_calling` history not accessible | Cannot populate `GenerationTrace.tools_called` for Gemini | Low | Fall back to manual tool loop for Gemini if needed. |
| Gemini 3 Flash is `preview` — behavior may change | Non-deterministic outputs | Medium | Provider fallback to Groq. Pin to specific model ID. |
| Tool docstrings too short → Gemini misunderstands tools | Poor tool selection during reasoning | Medium | Write detailed docstrings with parameter examples and usage guidance. |
| Two-phase generation produces inconsistent results | Phase B ignores Phase A reasoning | Low | Composition prompt explicitly includes Phase A output and cross-references technique IDs. |
| OpenAI compat client manual loop misses edge cases | Groq/Ollama tool calling fails | Medium | Test with both providers. Handle `tool_calls=None` and empty responses gracefully. |

---

## 13. What Phase 4 Does NOT Include

These are explicitly deferred to later phases:

| Item | Deferred To | Reason |
|---|---|---|
| `validation_tools.py` (technique/tactic validation) | Phase 6 | Belongs in safety pipeline, not reasoning |
| Command blocklist checking | Phase 6 | Layer 6 safety concern |
| Platform coherence validation | Phase 6 | Layer 6 safety concern |
| CLI entry point (`scripts/generate_abilities.py`) | Phase 6 | Depends on Layers 4–6 complete |
| JSON file output | Phase 6 | Layer 7 API integration |
| Provider failover (auto-switch Gemini → Groq) | Phase 6+ | Nice-to-have, not MVP |
| Embedding-based deduplication | Post-MVP | EC-10 documented in edge_cases_and_retro.md |
| MITRE version tracking in trace | Post-MVP | EC-11 documented |
| Unit test suite | Post-MVP | EC-13 documented; manual verification for now |

---

*End of Phase 4 Plan. Implementation follows this document step-by-step.*
