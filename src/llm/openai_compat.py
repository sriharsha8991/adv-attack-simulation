"""OpenAI-compatible LLM client — fallback for Groq and Ollama.

Uses the ``openai`` SDK to communicate with any OpenAI-compatible API
endpoint.  Implements a **manual** tool-calling loop (the OpenAI SDK
does not have an automatic mode) and JSON-mode structured output with
Pydantic post-validation — all via a single unified ``generate()``
method.

Usage:
    from src.llm.openai_compat import OpenAICompatClient

    client = OpenAICompatClient(
        api_key="gsk_...",
        base_url="https://api.groq.com/openai/v1",
        model="qwen/qwen3-32b",
    )
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from src.llm.base import GenerateResult, LLMClient

logger = logging.getLogger(__name__)

# Maximum structured-output validation retries
_MAX_VALIDATION_RETRIES = 3


class OpenAICompatClient(LLMClient):
    """OpenAI-compatible LLM client for Groq and Ollama.

    Single ``generate()`` method adapts behaviour based on arguments:

    * No tools, no schema → plain text completion
    * ``tools`` provided → manual tool dispatch loop
    * ``schema`` provided → JSON mode + Pydantic post-validation
    """

    def __init__(self, api_key: str, base_url: str, model: str) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "openai package is required for Groq/Ollama support. "
                "Install it with: pip install openai"
            ) from exc
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model
        logger.info(
            "OpenAICompatClient initialized: model=%s, base_url=%s",
            model,
            base_url,
        )

    @property
    def model_name(self) -> str:
        return self._model

    # ──────────────────────────────────────────────────────────
    # Unified generate
    # ──────────────────────────────────────────────────────────

    def generate(
        self,
        messages: list[dict[str, str]],
        *,
        tools: list[Any] | None = None,
        schema: type[BaseModel] | None = None,
        max_iterations: int = 10,
        **kwargs: Any,
    ) -> GenerateResult:
        """Single unified generation method.

        Behaviour depends on which optional arguments are provided:

        * **No tools, no schema** — plain text completion.
        * **tools** — manual tool-calling loop: send tool definitions,
          dispatch calls, append results, repeat until the model stops
          calling tools or *max_iterations* is reached.
        * **schema** — JSON mode with ``response_format=json_object``
          plus Pydantic post-validation with up to 3 retry rounds.
        * **tools + schema** — tool loop first, then structured
          extraction on the final response.

        Returns:
            ``GenerateResult`` with text, optional parsed object,
            tool call log, and token count.
        """
        # ── Tool-calling branch ───────────────────────────────
        if tools:
            result = self._tool_loop(messages, tools, max_iterations, **kwargs)
            # If schema is also requested, parse the final text
            if schema and result.text:
                result.parsed = self._validate_structured(
                    result.text, schema,
                )
            return result

        # ── Structured output branch ──────────────────────────
        if schema:
            return self._structured_generate(messages, schema, **kwargs)

        # ── Plain text branch ─────────────────────────────────
        return self._plain_generate(messages, **kwargs)

    # ──────────────────────────────────────────────────────────
    # Plain text
    # ──────────────────────────────────────────────────────────

    def _plain_generate(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> GenerateResult:
        """Simple text completion — no tools, no schema."""

        def _call() -> Any:
            return self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                **kwargs,
            )

        response = self._retry_with_backoff(_call)
        tokens = response.usage.total_tokens if response.usage else 0
        return GenerateResult(
            text=response.choices[0].message.content or "",
            raw_response=response,
            total_tokens=tokens,
        )

    # ──────────────────────────────────────────────────────────
    # Manual tool-calling loop
    # ──────────────────────────────────────────────────────────

    def _tool_loop(
        self,
        messages: list[dict[str, str]],
        tools: list[Any],
        max_iterations: int,
        **kwargs: Any,
    ) -> GenerateResult:
        """Manual tool dispatch loop for OpenAI-compatible APIs.

        1. Sends messages + tool definitions to the model
        2. If the model returns tool_calls, dispatches each one
        3. Appends tool results and loops back
        4. Breaks when no tool_calls or *max_iterations* reached
        """
        dispatch_map = {func.__name__: func for func in tools}
        tool_schemas = _build_openai_tool_schemas(tools)

        working_messages: list[dict[str, Any]] = [dict(m) for m in messages]
        tool_call_log: list[dict[str, Any]] = []
        total_tokens = 0

        for iteration in range(1, max_iterations + 1):
            def _call() -> Any:
                return self._client.chat.completions.create(
                    model=self._model,
                    messages=working_messages,  # type: ignore[arg-type]
                    tools=tool_schemas or None,  # type: ignore[arg-type]
                    tool_choice="auto" if tool_schemas else None,
                    **kwargs,
                )

            response = self._retry_with_backoff(_call)

            if response.usage:
                total_tokens += response.usage.total_tokens or 0

            message = response.choices[0].message

            # No tool calls → done
            if not message.tool_calls:
                logger.info(
                    "Tool loop finished: %d iterations, %d calls, %d tokens",
                    iteration,
                    len(tool_call_log),
                    total_tokens,
                )
                return GenerateResult(
                    text=message.content or "",
                    tool_calls=tool_call_log,
                    raw_response=response,
                    total_tokens=total_tokens,
                )

            # Append assistant message with tool calls
            working_messages.append(message.model_dump())

            for tool_call in message.tool_calls:
                func_name = tool_call.function.name
                try:
                    arguments = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}

                func = dispatch_map.get(func_name)
                if func is None:
                    result = json.dumps({"error": f"Unknown tool: {func_name}"})
                    logger.warning("Unknown tool requested: %s", func_name)
                else:
                    try:
                        raw_result = func(**arguments)
                        result = json.dumps(raw_result, default=str)
                    except Exception as exc:
                        result = json.dumps({"error": str(exc)})
                        logger.error(
                            "Tool %s raised: %s", func_name, exc, exc_info=True
                        )

                tool_call_log.append({
                    "name": func_name,
                    "arguments": arguments,
                    "result": result,
                })

                working_messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })

        # Max iterations exhausted
        logger.warning(
            "Tool loop hit max_iterations=%d with %d calls",
            max_iterations,
            len(tool_call_log),
        )
        return GenerateResult(
            text="",
            tool_calls=tool_call_log,
            raw_response=None,
            total_tokens=total_tokens,
        )

    # ──────────────────────────────────────────────────────────
    # Structured output — JSON mode + Pydantic validation
    # ──────────────────────────────────────────────────────────

    def _structured_generate(
        self,
        messages: list[dict[str, str]],
        schema: type[BaseModel],
        **kwargs: Any,
    ) -> GenerateResult:
        """JSON-mode generation with Pydantic validation retries.

        Since Groq/Ollama don't support ``response_schema``, we:
        1. Inject the JSON schema into the system prompt
        2. Enable ``response_format={"type": "json_object"}``
        3. Post-validate with ``schema.model_validate_json()``
        4. Retry up to 3 times on validation failure
        """
        schema_json = json.dumps(schema.model_json_schema(), indent=2)
        schema_prompt = (
            f"Return ONLY valid JSON matching this exact schema. "
            f"Do not include any text before or after the JSON.\n\n"
            f"Schema:\n{schema_json}"
        )

        working_messages = _inject_schema_prompt(messages, schema_prompt)
        last_error: ValidationError | None = None
        total_tokens = 0

        for attempt in range(1, _MAX_VALIDATION_RETRIES + 1):
            def _call() -> Any:
                return self._client.chat.completions.create(
                    model=self._model,
                    messages=working_messages,  # type: ignore[arg-type]
                    response_format={"type": "json_object"},
                    **kwargs,
                )

            response = self._retry_with_backoff(_call)
            if response.usage:
                total_tokens += response.usage.total_tokens or 0

            raw_text = response.choices[0].message.content or ""

            try:
                parsed = schema.model_validate_json(raw_text)
                logger.info(
                    "Structured output validated (attempt %d/%d)",
                    attempt,
                    _MAX_VALIDATION_RETRIES,
                )
                return GenerateResult(
                    text=raw_text,
                    parsed=parsed,
                    raw_response=response,
                    total_tokens=total_tokens,
                )
            except ValidationError as exc:
                last_error = exc
                logger.warning(
                    "Validation failed (attempt %d/%d): %s errors",
                    attempt,
                    _MAX_VALIDATION_RETRIES,
                    exc.error_count(),
                )
                working_messages.append({"role": "assistant", "content": raw_text})
                working_messages.append({
                    "role": "user",
                    "content": (
                        f"The JSON you produced has validation errors:\n"
                        f"{exc}\n\n"
                        f"Fix the errors and return valid JSON matching the schema."
                    ),
                })

        raise last_error  # type: ignore[misc]

    # ──────────────────────────────────────────────────────────
    # Validation helper (for tools+schema combo)
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _validate_structured(text: str, schema: type[BaseModel]) -> BaseModel | None:
        """Try to parse *text* as the given Pydantic *schema*."""
        try:
            return schema.model_validate_json(text)
        except (ValidationError, Exception) as exc:
            logger.warning("Post-tool-loop schema validation failed: %s", exc)
            return None


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _inject_schema_prompt(
    messages: list[dict[str, str]],
    schema_prompt: str,
) -> list[dict[str, str]]:
    """Inject *schema_prompt* into the system message (or prepend one)."""
    working: list[dict[str, str]] = []
    has_system = False
    for msg in messages:
        if msg["role"] == "system":
            working.append({
                "role": "system",
                "content": msg["content"] + "\n\n" + schema_prompt,
            })
            has_system = True
        else:
            working.append(dict(msg))
    if not has_system:
        working.insert(0, {"role": "system", "content": schema_prompt})
    return working


def _build_openai_tool_schemas(tools: list[Any]) -> list[dict[str, Any]]:
    """Build OpenAI-format tool schemas from callable functions.

    Uses ``CTITools.tool_definitions()`` format mapped to OpenAI's
    ``{"type": "function", "function": {...}}`` wrapper.

    Falls back to introspecting function signatures if tool_definitions
    are not available.
    """
    from src.tools.cti_tools import CTITools

    # Use the canonical tool definitions from CTITools
    cti_defs = CTITools.tool_definitions()
    cti_by_name = {d["name"]: d for d in cti_defs}

    schemas: list[dict[str, Any]] = []
    for func in tools:
        name = func.__name__
        if name in cti_by_name:
            defn = cti_by_name[name]
            schemas.append({
                "type": "function",
                "function": {
                    "name": defn["name"],
                    "description": defn["description"],
                    "parameters": defn["parameters"],
                },
            })
        else:
            # Fallback: minimal schema from docstring
            schemas.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": (func.__doc__ or "").split("\n")[0],
                    "parameters": {"type": "object", "properties": {}},
                },
            })

    return schemas
