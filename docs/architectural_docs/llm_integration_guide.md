# LLM Integration Guide

> Primary: Gemini 3 Flash · Fallback: Groq (OpenAI-compatible) · Local: Ollama

---

## Table of Contents

- [Provider Architecture](#provider-architecture)
- [Gemini 3 Flash (Primary)](#gemini-3-flash-primary)
- [Groq Fallback](#groq-fallback)
- [Ollama Local](#ollama-local)
- [Abstract LLM Client Interface](#abstract-llm-client-interface)
- [Provider Switching](#provider-switching)
- [Function Calling Integration](#function-calling-integration)
- [Structured Output with Pydantic](#structured-output-with-pydantic)
- [System Prompt Design](#system-prompt-design)
- [Error Handling & Retry Strategy](#error-handling--retry-strategy)
- [Model Recommendations](#model-recommendations)

---

## Provider Architecture

```
┌──────────────────────────────────────────────────┐
│                  LLMClient (ABC)                 │
│  ┌─────────────┬──────────────┬────────────────┐ │
│  │   chat()    │chat_with_    │chat_structured │ │
│  │             │  tools()     │     ()         │ │
│  └─────────────┴──────────────┴────────────────┘ │
└──────────────┬───────────────────────────────────┘
               │
       ┌───────┼──────────┐
       ▼       ▼          ▼
┌──────────┐ ┌────────┐ ┌────────┐
│  Gemini  │ │  Groq  │ │ Ollama │
│  Client  │ │ Client │ │ Client │
│          │ │        │ │        │
│google-   │ │openai  │ │openai  │
│genai SDK │ │ SDK    │ │ SDK    │
└──────────┘ └────────┘ └────────┘
```

All providers implement the same `LLMClient` interface. The active provider is selected by the `LLM_PROVIDER` environment variable.

---

## Gemini 3 Flash (Primary)

### Why Gemini 3 Flash

| Feature | Value |
|---|---|
| Model ID | `gemini-3-flash-preview` |
| Tier | Tier 1 (Free) |
| Context window | 1,048,576 tokens |
| Max output | 65,536 tokens |
| Function calling | Native — auto, manual, none modes |
| Structured output | Native — Pydantic schema as `response_schema` |
| Rate limit (free) | 30 RPM / 1M TPM |
| SDK | `google-genai` (unified SDK) |

### Installation

```bash
pip install google-genai
```

### Basic Setup

```python
from google import genai

client = genai.Client(api_key="YOUR_GEMINI_API_KEY")

# Simple chat
response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents="Explain MITRE ATT&CK T1003"
)
print(response.text)
```

### Function Calling Setup

```python
from google.genai import types

# Define tools as Python functions with type hints + docstrings
def query_techniques_by_tactic(tactic: str) -> list[dict]:
    """Query the MITRE ATT&CK knowledge graph for techniques in a specific tactic.
    
    Args:
        tactic: The tactic shortname (e.g., 'credential-access', 'lateral-movement')
    
    Returns:
        List of technique dicts with id, name, description, platforms
    """
    # Execute Cypher query against Neo4j
    return graph.query_techniques_by_tactic(tactic)

def get_technique_details(technique_id: str) -> dict:
    """Get full details for a specific MITRE ATT&CK technique.
    
    Args:
        technique_id: The technique ID (e.g., 'T1003', 'T1003.001')
    
    Returns:
        Dict with name, description, platforms, data_sources, detection
    """
    return graph.get_technique_details(technique_id)

# Register tools with Gemini
tools = [query_techniques_by_tactic, get_technique_details]

# The SDK auto-generates FunctionDeclarations from type hints + docstrings
response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents="Find credential access techniques for Windows",
    config=types.GenerateContentConfig(
        tools=tools,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=False  # SDK handles tool call → result → re-prompt automatically
        )
    )
)
```

### Structured Output Setup

```python
from google.genai import types
from src.models.ability import Ability

# Gemini returns output conforming to the Pydantic schema
response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents="Generate a credential access ability for T1558.003 on Windows",
    config=types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=Ability  # Pydantic model → Gemini uses its JSON schema
    )
)

# Parse response directly into Pydantic model
ability = Ability.model_validate_json(response.text)
```

### Combined: Function Calling + Structured Output

```python
# Phase 1: Agent reasons with tools (function calling)
reasoning_response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents=[system_prompt, user_prompt],
    config=types.GenerateContentConfig(
        tools=[graph_tools, cti_tools, misp_tools],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=False
        )
    )
)

# Phase 2: Compose structured ability from reasoning context
composition_prompt = f"""
Based on this research context:
{reasoning_response.text}

Generate a structured Ability JSON object.
"""

ability_response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents=composition_prompt,
    config=types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=Ability
    )
)

ability = Ability.model_validate_json(ability_response.text)
```

---

## Groq Fallback

### Why Groq

- OpenAI-compatible API — drop-in replacement
- Fast inference for iterative development
- Alternative when Gemini rate limits hit

### Installation

```bash
pip install openai
```

### Setup

```python
from openai import OpenAI

client = OpenAI(
    api_key="YOUR_GROQ_API_KEY",
    base_url="https://api.groq.com/openai/v1"
)

response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ],
    response_format={"type": "json_object"}
)
```

### Function Calling (Groq)

```python
tools = [
    {
        "type": "function",
        "function": {
            "name": "query_techniques_by_tactic",
            "description": "Query MITRE ATT&CK techniques by tactic shortname",
            "parameters": {
                "type": "object",
                "properties": {
                    "tactic": {
                        "type": "string",
                        "description": "Tactic shortname e.g. credential-access"
                    }
                },
                "required": ["tactic"]
            }
        }
    }
]

response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=messages,
    tools=tools,
    tool_choice="auto"
)

# Handle tool calls manually
if response.choices[0].message.tool_calls:
    for tool_call in response.choices[0].message.tool_calls:
        func_name = tool_call.function.name
        args = json.loads(tool_call.function.arguments)
        result = execute_tool(func_name, args)
        messages.append({"role": "tool", "content": json.dumps(result), "tool_call_id": tool_call.id})
```

### Structured Output (Groq)

Groq supports `response_format={"type": "json_object"}` but NOT Pydantic `response_schema`. Post-validate with Pydantic:

```python
response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=[
        {"role": "system", "content": f"Return JSON matching this schema:\n{Ability.model_json_schema()}"},
        {"role": "user", "content": prompt}
    ],
    response_format={"type": "json_object"}
)

ability = Ability.model_validate_json(response.choices[0].message.content)
```

---

## Ollama Local

### Why Ollama

- Fully local — no API keys, no rate limits, no data leaves machine
- Useful for offline development and testing
- OpenAI-compatible API

### Setup

```bash
# Install Ollama (see https://ollama.com)
ollama pull qwen3:32b
```

### Integration

```python
from openai import OpenAI

client = OpenAI(
    api_key="ollama",  # Required but unused
    base_url="http://localhost:11434/v1"
)

response = client.chat.completions.create(
    model="qwen3:32b",
    messages=messages
)
```

### Limitations

| Feature | Ollama Support |
|---|---|
| Chat completion | ✅ Full |
| JSON mode | ✅ `response_format={"type": "json_object"}` |
| Function calling | ⚠️ Model-dependent (Qwen3 supports it) |
| Structured output (schema) | ❌ Not supported — use post-validation |

---

## Abstract LLM Client Interface

File: `src/llm/base.py`

```python
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel


class ToolCallResult:
    """Result from a chat_with_tools call."""
    def __init__(self, text: str, tool_calls: list[dict] | None, raw_response: Any):
        self.text = text
        self.tool_calls = tool_calls
        self.has_tool_calls = tool_calls is not None and len(tool_calls) > 0
        self.raw_response = raw_response


class LLMClient(ABC):
    """Abstract base class for LLM provider clients."""
    
    @abstractmethod
    def chat(self, messages: list[dict], **kwargs) -> str:
        """Simple chat completion. Returns text response.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
        
        Returns:
            Response text string
        """
        ...
    
    @abstractmethod
    def chat_with_tools(
        self, 
        messages: list[dict], 
        tools: list[callable],
        max_iterations: int = 10
    ) -> ToolCallResult:
        """Chat with function calling / tool use.
        
        Args:
            messages: Conversation messages
            tools: List of callable functions to register as tools
            max_iterations: Max tool call rounds before forcing final answer
        
        Returns:
            ToolCallResult with final text and tool call history
        """
        ...
    
    @abstractmethod
    def chat_structured(
        self, 
        messages: list[dict], 
        schema: type[BaseModel]
    ) -> BaseModel:
        """Chat with structured output matching a Pydantic schema.
        
        Args:
            messages: Conversation messages
            schema: Pydantic model class for response validation
        
        Returns:
            Validated Pydantic model instance
        """
        ...
```

---

## Provider Switching

### Environment Configuration

```bash
# .env file

# Provider: "gemini" | "groq" | "ollama"
LLM_PROVIDER=gemini

# Gemini
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-3-flash-preview

# Groq (fallback)
GROQ_API_KEY=your-groq-api-key
GROQ_MODEL=qwen/qwen3-32b

# Ollama (local)
OLLAMA_MODEL=qwen3:32b
OLLAMA_BASE_URL=http://localhost:11434/v1
```

### Factory Pattern

File: `src/llm/__init__.py`

```python
from src.config import Settings
from src.llm.base import LLMClient
from src.llm.gemini_client import GeminiClient
from src.llm.openai_compat import OpenAICompatClient


def create_llm_client(settings: Settings) -> LLMClient:
    """Factory: create LLM client based on provider setting."""
    match settings.llm_provider:
        case "gemini":
            return GeminiClient(
                api_key=settings.gemini_api_key,
                model=settings.gemini_model
            )
        case "groq":
            return OpenAICompatClient(
                api_key=settings.groq_api_key,
                base_url="https://api.groq.com/openai/v1",
                model=settings.groq_model
            )
        case "ollama":
            return OpenAICompatClient(
                api_key="ollama",
                base_url=settings.ollama_base_url,
                model=settings.ollama_model
            )
        case _:
            raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
```

### Switching Providers

```bash
# Switch to Groq (just change one env var)
LLM_PROVIDER=groq python scripts/generate_abilities.py --category credential_access

# Switch to Ollama 
LLM_PROVIDER=ollama python scripts/generate_abilities.py --category credential_access
```

---

## Function Calling Integration

### Tool Registration Architecture

```
┌──────────────────────────┐
│   graph_tools.py         │
│ ┌──────────────────────┐ │
│ │query_techniques_by_  │ │     ┌──────────┐
│ │         tactic()     │─┼────►│          │
│ │find_subtechniques()  │ │     │  Gemini  │
│ │get_technique_details │ │     │  auto-   │
│ │get_platforms()       │ │     │  calls   │
│ └──────────────────────┘ │     │  these   │
├──────────────────────────┤     │  based   │
│   cti_tools.py           │     │  on      │
│ ┌──────────────────────┐ │     │  context │
│ │get_intrusion_sets()  │─┼────►│          │
│ │get_tools_for_tech()  │ │     │          │
│ │get_detection()       │ │     │          │
│ │get_mitigations()     │ │     │          │
│ └──────────────────────┘ │     └──────────┘
├──────────────────────────┤
│   misp_tools.py          │
│ ┌──────────────────────┐ │
│ │search_misp_galaxy()  │─┼────►
│ │enrich_technique()    │ │
│ └──────────────────────┘ │
└──────────────────────────┘
```

### Tool Design Rules

1. **Type hints required** — Gemini auto-generates schema from type annotations
2. **Docstrings required** — Gemini uses the docstring as the tool description
3. **Return JSON-serializable** — dicts, lists, strings, numbers only
4. **Single responsibility** — one tool does one thing
5. **Descriptive names** — `get_intrusion_sets_for_technique` not `get_groups`

### Complete Tool List

| Tool | Module | Purpose |
|---|---|---|
| `query_techniques_by_tactic` | graph_tools | List techniques for a tactic |
| `find_subtechniques` | graph_tools | List sub-techniques for a technique |
| `get_technique_details` | graph_tools | Full details for one technique |
| `get_platforms_for_technique` | graph_tools | Platform list for a technique |
| `get_intrusion_sets_for_technique` | cti_tools | Threat groups using a technique |
| `get_tools_for_technique` | cti_tools | Tools/malware for a technique |
| `get_detection_guidance` | cti_tools | Data sources and detection text |
| `get_mitigations` | cti_tools | Mitigations for a technique |
| `search_misp_galaxy` | misp_tools | MISP galaxy context lookup |
| `enrich_technique_context` | misp_tools | Combined enrichment (Neo4j + MISP) |
| `validate_technique_exists` | validation_tools | Check technique ID in graph |
| `validate_tactic_technique_match` | validation_tools | Check tactic/technique alignment |

---

## Structured Output with Pydantic

### How It Works (Gemini Native)

1. Pydantic model defines the schema with `Field(description=...)`
2. `Ability.model_json_schema()` exports the schema
3. Gemini uses the schema as `response_schema` parameter
4. Response JSON conforms to the schema
5. `Ability.model_validate_json(response.text)` parses the result

### Why Field Descriptions Matter

Gemini reads field descriptions to understand what to generate:

```python
class Ability(BaseModel):
    name: str = Field(
        description="Human-readable name for the ability, e.g. 'Kerberoasting via PowerShell'"
    )
    # Gemini sees: "name (string): Human-readable name for the ability..."
    # This guides generation quality significantly
```

### Fallback for Non-Gemini Providers

Groq/Ollama don't support `response_schema`. Instead:

1. Include schema in the system prompt
2. Request JSON output format
3. Post-validate with Pydantic
4. Retry on validation failure (up to 3 attempts)

```python
def chat_structured_fallback(self, messages, schema):
    schema_json = json.dumps(schema.model_json_schema(), indent=2)
    
    augmented_messages = [
        {"role": "system", "content": f"Return valid JSON matching this schema:\n{schema_json}"},
        *messages
    ]
    
    for attempt in range(3):
        response = self.chat(augmented_messages, response_format={"type": "json_object"})
        try:
            return schema.model_validate_json(response)
        except ValidationError as e:
            augmented_messages.append({"role": "user", "content": f"Invalid JSON: {e}. Fix and retry."})
    
    raise RuntimeError("Failed to generate valid structured output after 3 attempts")
```

---

## System Prompt Design

### Core System Prompt (Layer 3 — Reasoning Engine)

```python
SYSTEM_PROMPT = """You are an adversary simulation specialist for defensive security testing.
Your role is to generate MITRE ATT&CK-mapped attack abilities that help security teams
evaluate their detection and response capabilities.

IMPORTANT RULES:
1. Every ability is for SIMULATION ONLY — include simulation markers in all commands
2. Every ability must have cleanup procedures that reverse all changes  
3. Only reference real MITRE ATT&CK techniques — verify with the knowledge graph tools
4. Include threat intelligence context — which groups use this technique, what tools they use
5. Target detection gaps — abilities should trigger the defensive telemetry they test

You have access to the following tools:
- Knowledge graph tools: query techniques, sub-techniques, platforms
- CTI tools: threat groups, tools/malware, detection guidance, mitigations
- MISP tools: galaxy-enriched threat context

WORKFLOW:
1. Use knowledge graph tools to research the requested attack category
2. Select specific techniques and sub-techniques appropriate for the target platform
3. Enrich with threat intelligence context (groups, tools, campaigns)
4. Generate detailed, realistic simulation abilities
5. Include platform-specific executors with simulation markers and cleanup

OUTPUT:
Generate Ability objects conforming to the provided schema."""
```

---

## Error Handling & Retry Strategy

### Retry Configuration

```python
RETRY_CONFIG = {
    "max_retries": 3,
    "base_delay": 1.0,      # seconds
    "max_delay": 30.0,      # seconds
    "backoff_factor": 2.0,  # exponential backoff
    "retryable_errors": [
        "rate_limit",        # 429
        "server_error",      # 500, 502, 503
        "timeout",           # request timeout
        "invalid_json",      # structured output parse failure
    ]
}
```

### Error Handling Flow

```
LLM Call
  │
  ├─ Success ─────────────────────► Return result
  │
  ├─ Rate Limit (429) ───────────► Wait (exponential backoff) → Retry
  │
  ├─ Server Error (5xx) ─────────► Wait → Retry
  │
  ├─ Invalid JSON ────────────────► Augment prompt with error → Retry
  │
  ├─ Validation Error ───────────► Augment prompt with error → Retry
  │
  ├─ Auth Error (401/403) ───────► Log error → Switch provider if fallback configured
  │
  └─ Max retries exceeded ───────► Log error → Raise exception
```

### Provider Failover

```python
def call_with_failover(primary: LLMClient, fallback: LLMClient | None, messages, **kwargs):
    try:
        return primary.chat(messages, **kwargs)
    except AuthenticationError:
        if fallback:
            logger.warning("Primary LLM auth failed, switching to fallback")
            return fallback.chat(messages, **kwargs)
        raise
    except RateLimitError:
        if fallback:
            logger.warning("Primary LLM rate limited, switching to fallback")
            return fallback.chat(messages, **kwargs)
        raise
```

---

## Model Recommendations

### By Use Case

| Use Case | Recommended Model | Why |
|---|---|---|
| **Production generation** | Gemini 3 Flash | Native function calling + structured output, 1M context |
| **Fast iteration/testing** | Groq Qwen3-32B | Fastest inference, good tool use support |
| **Offline development** | Ollama Qwen3:32B | No API dependency, full privacy |
| **Complex reasoning** | Gemini 3 Flash | Largest context window, best multi-step reasoning |
| **Budget-constrained** | Gemini 3 Flash (free tier) | 30 RPM free, sufficient for batch generation |

### Model Capability Matrix

| Capability | Gemini 3 Flash | Groq Qwen3-32B | Ollama Qwen3:32B |
|---|---|---|---|
| Function calling | ✅ Native | ✅ OpenAI-compat | ⚠️ Model-dependent |
| Structured output | ✅ Schema-native | ⚠️ JSON mode only | ⚠️ JSON mode only |
| Context window | 1M tokens | 128K tokens | Depends on config |
| Output limit | 65K tokens | 8K tokens | Depends on config |
| Rate limit (free) | 30 RPM | 30 RPM | Unlimited |
| Latency | ~2-5s | ~1-3s | ~5-30s (hardware dep.) |
| Privacy | Cloud | Cloud | Local |
