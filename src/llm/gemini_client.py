"""Gemini LLM client — primary provider via google-genai SDK.

Uses a **single** ``client.models.generate_content()`` call for all modes:
- Plain text (no tools, no schema)
- Automatic function calling (tools provided — SDK manages the loop)
- Structured output (response_schema — SDK returns ``response.parsed``)
- Tools + structured output combined (Gemini 3 feature)

Reference: https://ai.google.dev/gemini-api/docs/function-calling
Reference: https://ai.google.dev/gemini-api/docs/migrate

Usage:
    from src.llm.gemini_client import GeminiClient

    client = GeminiClient(api_key="...", model="gemini-3-flash-preview")
    result = client.generate(messages, tools=my_tools)
"""

from __future__ import annotations

import logging
from typing import Any

from google import genai
from google.genai import types
from pydantic import BaseModel, ValidationError

from src.llm.base import LLMClient, GenerateResult

logger = logging.getLogger(__name__)

# Maximum structured-output validation retries
_MAX_VALIDATION_RETRIES = 3


class GeminiClient(LLMClient):
    """Gemini LLM client using the ``google-genai`` unified SDK.

    One method does it all — ``generate()`` builds a
    ``GenerateContentConfig`` conditionally based on which optional
    arguments are provided:

    +------------+--------+---------------------------------------------+
    | tools      | schema | Behaviour                                   |
    +============+========+=============================================+
    | None       | None   | Plain text completion                       |
    +------------+--------+---------------------------------------------+
    | [funcs]    | None   | Automatic function calling (SDK loop)       |
    +------------+--------+---------------------------------------------+
    | None       | Model  | Structured JSON via response_schema         |
    +------------+--------+---------------------------------------------+
    | [funcs]    | Model  | Function calling + structured output        |
    +------------+--------+---------------------------------------------+
    """

    def __init__(self, api_key: str, model: str = "gemini-3-flash-preview") -> None:
        self._client = genai.Client(api_key=api_key)
        self._model = model
        logger.info("GeminiClient initialized with model=%s", model)

    @property
    def model_name(self) -> str:
        return self._model

    # ──────────────────────────────────────────────────────────
    # generate — single unified method
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

        Builds a ``GenerateContentConfig`` conditionally, then calls
        ``client.models.generate_content()`` which handles all modes
        in one call.

        Args:
            messages: ``[{"role": "system|user|assistant", "content": "..."}]``
            tools: Optional list of callable functions.  The SDK
                auto-generates schemas from type hints + docstrings and
                handles the call → execute → re-prompt cycle.
            schema: Optional Pydantic model class.  Activates
                ``response_schema`` for constrained JSON decoding.
                Result available in ``result.parsed``.
            max_iterations: Max tool round-trips (only when tools are set).

        Returns:
            ``GenerateResult`` with text, parsed object, tool calls, tokens.
        """
        system_instruction, contents = _messages_to_contents(messages)

        # ── Build config conditionally ────────────────────────
        config_kwargs: dict[str, Any] = {
            "systemInstruction": system_instruction,
            **kwargs,
        }

        if tools:
            config_kwargs["tools"] = tools
            config_kwargs["automaticFunctionCalling"] = (
                types.AutomaticFunctionCallingConfig(
                    disable=False,
                    maximumRemoteCalls=max_iterations,
                )
            )

        if schema:
            config_kwargs["responseMimeType"] = "application/json"
            config_kwargs["responseSchema"] = schema

        config = types.GenerateContentConfig(**config_kwargs)

        # ── Call generate_content (handles everything) ────────
        def _call() -> types.GenerateContentResponse:
            return self._client.models.generate_content(
                model=self._model,
                contents=contents,
                config=config,
            )

        response = self._retry_with_backoff(_call)

        # ── Extract results ───────────────────────────────────
        text = response.text or ""
        tool_call_log = _extract_tool_calls(response) if tools else []
        total_tokens = _extract_tokens(response)

        # Structured output — use SDK's response.parsed, fall back
        # to manual validation with retry on failure
        parsed = None
        if schema:
            parsed = getattr(response, "parsed", None)
            if parsed is None:
                parsed = self._validate_with_retry(
                    text, schema, contents, config
                )

        logger.info(
            "Gemini generate: tools=%s schema=%s tool_calls=%d tokens=%d",
            bool(tools),
            schema.__name__ if schema else None,
            len(tool_call_log),
            total_tokens,
        )

        return GenerateResult(
            text=text,
            parsed=parsed,
            tool_calls=tool_call_log,
            raw_response=response,
            total_tokens=total_tokens,
        )

    # ──────────────────────────────────────────────────────────
    # Validation retry for structured output
    # ──────────────────────────────────────────────────────────

    def _validate_with_retry(
        self,
        raw_text: str,
        schema: type[BaseModel],
        contents: list[types.Content],
        config: types.GenerateContentConfig,
    ) -> BaseModel:
        """Validate JSON against schema with retry on failure.

        Only called as a fallback when ``response.parsed`` is unavailable.
        Appends validation errors to the conversation so the model can
        self-correct.
        """
        for attempt in range(1, _MAX_VALIDATION_RETRIES + 1):
            try:
                return schema.model_validate_json(raw_text)
            except ValidationError as exc:
                logger.warning(
                    "Validation failed (attempt %d/%d): %s",
                    attempt,
                    _MAX_VALIDATION_RETRIES,
                    exc.error_count(),
                )
                if attempt == _MAX_VALIDATION_RETRIES:
                    raise

                # Append error context for self-correction
                contents.append(
                    types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=raw_text)],
                    )
                )
                contents.append(
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(
                            text=(
                                f"The JSON you produced has validation errors:\n"
                                f"{exc}\n\n"
                                f"Fix the errors and return valid JSON matching the schema."
                            ),
                        )],
                    )
                )

                # Retry the call
                response = self._retry_with_backoff(
                    lambda: self._client.models.generate_content(
                        model=self._model,
                        contents=contents,
                        config=config,
                    )
                )
                raw_text = response.text or ""

                # Check response.parsed on retry too
                parsed = getattr(response, "parsed", None)
                if parsed is not None:
                    return parsed

        # Should never reach here (ValidationError raised above)
        raise RuntimeError("Validation retry exhausted")


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _messages_to_contents(
    messages: list[dict[str, str]],
) -> tuple[str | None, list[types.Content]]:
    """Convert generic message format to Gemini Content objects.

    Splits out ``"system"`` role into a separate system instruction
    string.  Maps ``"user"`` and ``"assistant"`` to Gemini Content
    parts with roles ``"user"`` and ``"model"`` respectively.

    Returns:
        Tuple of (system_instruction, contents_list).
    """
    system_instruction: str | None = None
    contents: list[types.Content] = []

    for msg in messages:
        role = msg["role"]
        text = msg["content"]

        if role == "system":
            system_instruction = text
        elif role == "user":
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=text)],
                )
            )
        elif role == "assistant":
            contents.append(
                types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=text)],
                )
            )
        else:
            logger.warning("Unknown message role '%s', treating as user.", role)
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=text)],
                )
            )

    return system_instruction, contents


def _extract_tool_calls(response: types.GenerateContentResponse) -> list[dict[str, Any]]:
    """Extract tool call history from a Gemini response.

    When ``automatic_function_calling`` is enabled, the SDK stores the
    full call history in ``response.automatic_function_calling_history``.
    Falls back to scanning candidate parts.
    """
    tool_calls: list[dict[str, Any]] = []

    # Primary: automatic_function_calling_history
    history = getattr(response, "automatic_function_calling_history", None)
    if history:
        for turn in history:
            parts = getattr(turn, "parts", []) if hasattr(turn, "parts") else []
            for part in parts:
                fc = getattr(part, "function_call", None)
                fr = getattr(part, "function_response", None)
                if fc:
                    tool_calls.append({
                        "name": fc.name,
                        "arguments": dict(fc.args) if fc.args else {},
                        "result": None,
                    })
                if fr and tool_calls:
                    for tc in reversed(tool_calls):
                        if tc["name"] == fr.name and tc["result"] is None:
                            tc["result"] = (
                                dict(fr.response) if fr.response else None
                            )
                            break
        return tool_calls

    # Fallback: scan candidate parts
    try:
        for part in response.candidates[0].content.parts:
            fc = getattr(part, "function_call", None)
            if fc:
                tool_calls.append({
                    "name": fc.name,
                    "arguments": dict(fc.args) if fc.args else {},
                    "result": None,
                })
    except (AttributeError, IndexError):
        pass

    return tool_calls


def _extract_tokens(response: types.GenerateContentResponse) -> int:
    """Extract total token count from Gemini response metadata."""
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return 0
    return getattr(usage, "total_token_count", 0) or 0
