"""LLM abstract interface — provider-agnostic contract.

Defines the base class that all LLM clients (Gemini, Groq, Ollama) must
implement.  Uses a **single unified ``generate()`` method** that handles
plain text, tool calling, and structured output depending on the
arguments provided.

Usage:
    # Concrete clients are obtained via the factory in ``src.llm``:
    from src.llm import create_llm_client
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from src.config import (
    LLM_BACKOFF_FACTOR,
    LLM_BASE_DELAY,
    LLM_MAX_DELAY,
    LLM_MAX_RETRIES,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Retry configuration (from config)
# ──────────────────────────────────────────────────────────────
MAX_RETRIES = LLM_MAX_RETRIES
BASE_DELAY = LLM_BASE_DELAY
MAX_DELAY = LLM_MAX_DELAY
BACKOFF_FACTOR = LLM_BACKOFF_FACTOR


# ──────────────────────────────────────────────────────────────
# Unified result
# ──────────────────────────────────────────────────────────────

@dataclass
class GenerateResult:
    """Unified output from any LLM generation call.

    Captures the final text, optional parsed Pydantic object, ordered
    tool-call log, token usage, and the raw provider response.
    """

    text: str = ""
    parsed: Any = None  # Populated when schema is provided
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw_response: Any = None
    total_tokens: int = 0

    @property
    def has_tool_calls(self) -> bool:
        """Whether any tool calls were made during the session."""
        return len(self.tool_calls) > 0


# ──────────────────────────────────────────────────────────────
# Abstract base class
# ──────────────────────────────────────────────────────────────

class LLMClient(ABC):
    """Provider-agnostic LLM client contract.

    Every concrete provider (Gemini, Groq, Ollama) implements a single
    ``generate()`` method.  Behaviour changes based on the arguments:

    * **No tools, no schema** → plain text completion
    * **tools provided** → function-calling loop (automatic or manual)
    * **schema provided** → structured output with Pydantic validation
    * **tools + schema** → tool-augmented structured output (Gemini 3)
    """

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Return the model identifier string (e.g. 'gemini-3-flash-preview')."""

    # ── Core method ───────────────────────────────────────────

    @abstractmethod
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

        Args:
            messages: Conversation in ``[{"role": "...", "content": "..."}]``
                format.  Roles: ``system``, ``user``, ``assistant``.
            tools: Optional list of callable tool functions.  When
                provided, enables function calling.
            schema: Optional Pydantic model class.  When provided,
                constrains the model to produce JSON matching the schema
                and populates ``result.parsed``.
            max_iterations: Maximum tool-calling round-trips (only used
                when ``tools`` is provided).

        Returns:
            ``GenerateResult`` with text, parsed object, tool call log,
            and token count.
        """

    # ── Retry helper ──────────────────────────────────────────

    def _retry_with_backoff(
        self,
        func: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute *func* with exponential backoff on transient failures.

        Retryable: HTTP 429 (rate limit), HTTP 5xx (server error),
        connection / timeout errors.  Non-retryable: 401/403 (auth),
        unknown errors — propagated immediately.
        """
        delay = BASE_DELAY
        last_exc: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                exc_str = str(exc).lower()

                # Non-retryable auth errors
                if "401" in exc_str or "403" in exc_str or "unauthorized" in exc_str:
                    logger.error("Auth error (non-retryable): %s", exc)
                    raise

                # Retryable conditions
                is_retryable = any(
                    keyword in exc_str
                    for keyword in ("429", "rate", "500", "502", "503", "504", "timeout", "connection")
                )

                if not is_retryable:
                    logger.error("Non-retryable error: %s", exc)
                    raise

                if attempt < MAX_RETRIES:
                    logger.warning(
                        "Retryable error (attempt %d/%d), backing off %.1fs: %s",
                        attempt,
                        MAX_RETRIES,
                        delay,
                        exc,
                    )
                    time.sleep(delay)
                    delay = min(delay * BACKOFF_FACTOR, MAX_DELAY)
                else:
                    logger.error(
                        "All %d retries exhausted. Last error: %s",
                        MAX_RETRIES,
                        exc,
                    )

        raise last_exc  # type: ignore[misc]
