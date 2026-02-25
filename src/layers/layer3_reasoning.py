"""Layer 3 — Attack Reasoning Engine (two-phase LLM pipeline).

Orchestrates the generation of ``Ability`` objects through:

    Phase A — **Reasoning with tools**: The LLM explores the MITRE ATT&CK
    knowledge graph (via 4 tool closures), selects techniques, and gathers
    comprehensive threat intelligence.

    Phase B — **Structured composition**: For each ability, the LLM receives
    the Phase A reasoning context and produces a validated ``Ability`` JSON
    conforming to the Pydantic schema.

Usage:
    from src.layers.layer3_reasoning import ReasoningEngine
    from src.llm import create_llm_client
    from src.config import get_settings
    from src.models.enums import AttackCategory, Platform

    settings = get_settings()
    llm = create_llm_client(settings)

    with ReasoningEngine(llm=llm) as engine:
        abilities = engine.generate_abilities(
            category=AttackCategory.CREDENTIAL_ACCESS,
            platform=Platform.WINDOWS,
            count=3,
        )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from src.config import (
    AGENT_VERSION,
    BLOCKLIST_VERSION,
    CATEGORY_TO_TACTICS,
    SCHEMA_VERSION,
    SYSTEM_PROMPT,
    get_settings,
)
from src.graph.connection import Neo4jConnection
from src.layers.layer2_enrichment import GalaxyManager
from src.layers.layer6_safety import SafetyValidator
from src.llm.base import GenerateResult, LLMClient
from src.models.ability import Ability, GenerationTrace
from src.models.enums import ApprovalStatus, AttackCategory, Platform
from src.tools.graph_tools import create_reasoning_tools

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Reasoning Engine
# ──────────────────────────────────────────────────────────────


class ReasoningEngine:
    """Two-phase attack reasoning engine.

    Combines tool-augmented LLM reasoning with structured output generation
    to produce validated ``Ability`` objects from the MITRE ATT&CK knowledge
    graph.

    Args:
        llm: Configured LLM client (Gemini, Groq, or Ollama).
        conn: Optional Neo4j connection. Creates one if not provided.
        galaxy: Optional GalaxyManager. Creates and loads one if not provided.
    """

    def __init__(
        self,
        llm: LLMClient,
        conn: Neo4jConnection | None = None,
        galaxy: GalaxyManager | None = None,
    ) -> None:
        self._llm = llm

        # Resource management — own what we create
        self._conn = conn or Neo4jConnection()
        self._owns_conn = conn is None

        if galaxy is not None:
            self._galaxy = galaxy
        else:
            self._galaxy = GalaxyManager()
            self._galaxy.load_all()

        # Create tool closures
        self._tools = create_reasoning_tools(self._conn, self._galaxy)

        # Safety validator (shares the graph connection for MITRE lookups)
        self._validator = SafetyValidator(conn=self._conn)

        logger.info(
            "ReasoningEngine initialized: llm=%s, tools=%d",
            self._llm.model_name,
            len(self._tools),
        )

    def close(self) -> None:
        """Close owned resources."""
        if self._owns_conn:
            self._conn.close()
            logger.info("ReasoningEngine closed owned Neo4j connection.")

    @property
    def model_name(self) -> str:
        """Return the LLM model identifier (for API responses)."""
        return self._llm.model_name

    def __enter__(self) -> ReasoningEngine:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ──────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────

    def generate_abilities(
        self,
        category: AttackCategory | str,
        platform: Platform | str,
        count: int = 3,
    ) -> list[Ability]:
        """Generate attack abilities through the two-phase LLM pipeline.

        Phase A: Reasoning with tools — LLM explores the knowledge graph,
        selects techniques, and gathers CTI context.

        Phase B: Structured composition — for each ability, the LLM produces
        a validated ``Ability`` JSON using the Phase A context.

        Args:
            category: Attack category (enum or string value).
            platform: Target platform (enum or string value).
            count: Number of abilities to generate (default: 3).

        Returns:
            List of validated ``Ability`` objects. May be shorter than
            ``count`` if some abilities fail validation after retries.
        """
        # Normalize inputs
        cat_value = category.value if isinstance(category, AttackCategory) else str(category)
        plat_value = platform.value if isinstance(platform, Platform) else str(platform)

        tactics = CATEGORY_TO_TACTICS.get(cat_value, [])
        if not tactics:
            logger.error("No tactic mapping for category: %s", cat_value)
            return []

        logger.info(
            "Generating %d abilities: category=%s, platform=%s, tactics=%s",
            count,
            cat_value,
            plat_value,
            tactics,
        )

        # ── Phase A: Reasoning with tools ─────────────────────
        phase_a_result = self._phase_a_reasoning(cat_value, plat_value, tactics, count)
        logger.info("Phase A reasoning finished for category=%s, platform=%s", cat_value, plat_value)
        logger.info("Phase A result: %s", phase_a_result)
        if phase_a_result is None:
            return []

        reasoning_context = phase_a_result.text
        tool_call_log = phase_a_result.tool_calls
        phase_a_tokens = phase_a_result.total_tokens

        logger.info(
            "Phase A complete: %d tool calls, %d tokens, context length=%d chars",
            len(tool_call_log),
            phase_a_tokens,
            len(reasoning_context),
        )

        # ── Phase B: Structured composition ───────────────────
        abilities: list[Ability] = []
        total_phase_b_tokens = 0

        for i in range(1, count + 1):
            ability, phase_b_tokens = self._phase_b_compose(
                reasoning_context=reasoning_context,
                category=cat_value,
                platform=plat_value,
                ability_index=i,
                total_count=count,
            )
            total_phase_b_tokens += phase_b_tokens
            if ability is not None:
                # Post-generation enforcement
                ability = self._enforce_safety_fields(ability)

                # Safety validation pipeline (18 rules)
                if get_settings().enable_safety_layer:
                    validation = self._validator.validate(ability)

                    if not validation.passed:
                        ability.approval_status = ApprovalStatus.BLOCKED
                        logger.warning(
                            "Ability %d/%d BLOCKED by safety rules: %s",
                            i,
                            count,
                            [f.rule_name for f in validation.hard_failures],
                        )

                    # Collect soft warnings for human reviewers
                    warning_msgs = [w.detail for w in validation.warnings]
                else:
                    logger.info(
                        "Safety layer DISABLED — skipping validation for ability %d/%d",
                        i, count,
                    )
                    validation = None
                    warning_msgs = []

                # Attach generation trace
                ability.generation_trace = GenerationTrace(
                    model=self._llm.model_name,
                    tools_called=[tc["name"] for tc in tool_call_log],
                    reasoning_steps=len(tool_call_log),
                    total_tokens=phase_a_tokens + total_phase_b_tokens,
                    blocklist_version=BLOCKLIST_VERSION,
                    validation_warnings=warning_msgs,
                )

                abilities.append(ability)
                logger.info(
                    "Ability %d/%d generated: %s (%s)",
                    i,
                    count,
                    ability.name,
                    ability.mitre_mapping.technique,
                )
            else:
                logger.warning(
                    "Ability %d/%d failed — skipping (partial generation).",
                    i,
                    count,
                )

        logger.info(
            "Generation complete: %d/%d abilities produced, total_tokens=%d",
            len(abilities),
            count,
            phase_a_tokens + total_phase_b_tokens,
        )
        return abilities

    # ──────────────────────────────────────────────────────────
    # Phase A — Reasoning with tools
    # ──────────────────────────────────────────────────────────

    def _phase_a_reasoning(
        self,
        category: str,
        platform: str,
        tactics: list[str],
        count: int,
    ) -> GenerateResult | None:
        """Execute Phase A: tool-augmented reasoning.

        The LLM explores the knowledge graph to discover techniques,
        navigate sub-techniques, and gather CTI enrichment data.

        Returns:
            ``GenerateResult`` with reasoning text and tool call log,
            or ``None`` if Phase A fails.
        """
        tactics_str = ", ".join(tactics)
        user_prompt = (
            f"Generate {count} {category} abilities targeting {platform}.\n"
            f"Primary tactic(s): {tactics_str}.\n\n"
            f"Requirements:\n"
            f"- Each ability must be atomic (single technique or 2-3 step scenario)\n"
            f"- Each ability must be simulation-safe with cleanup procedures\n"
            f"- Select {count} DIFFERENT techniques — avoid duplicates\n"
            f"- Use the tools to discover techniques, explore sub-techniques, "
            f"and gather comprehensive threat intelligence\n"
            f"- For each selected technique, call get_technique_intel ONCE "
            f"to get full enrichment data\n\n"
            f"After researching, summarize your findings including:\n"
            f"- Which techniques you selected and why\n"
            f"- Key threat intel for each (groups, tools, campaigns)\n"
            f"- Detection guidance and mitigations\n"
            f"- Platform-specific execution approaches"
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        try:
            result = self._llm.generate(
                messages,
                tools=self._tools,
                max_iterations=10,
            )
            return result
        except Exception as exc:
            logger.error(
                "Phase A reasoning failed: %s", exc, exc_info=True
            )
            return None

    # ──────────────────────────────────────────────────────────
    # Phase B — Structured composition
    # ──────────────────────────────────────────────────────────

    def _phase_b_compose(
        self,
        reasoning_context: str,
        category: str,
        platform: str,
        ability_index: int,
        total_count: int,
    ) -> tuple[Ability | None, int]:
        """Execute Phase B: generate a single structured Ability.

        Uses ``generate(schema=Ability)`` to produce
        a validated Pydantic instance.

        Returns:
            Tuple of (validated ``Ability`` or ``None``, token count).
        """
        composition_prompt = _build_composition_prompt(
            reasoning_context=reasoning_context,
            category=category,
            platform=platform,
            ability_index=ability_index,
            total_count=total_count,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": composition_prompt},
        ]

        try:
            result = self._llm.generate(messages, schema=Ability)
            return result.parsed, result.total_tokens  # type: ignore[return-value]
        except ValidationError as exc:
            logger.error(
                "Phase B validation failed for ability %d/%d after retries: %s",
                ability_index,
                total_count,
                exc.error_count(),
            )
            return None, 0
        except Exception as exc:
            logger.error(
                "Phase B composition failed for ability %d/%d: %s",
                ability_index,
                total_count,
                exc,
                exc_info=True,
            )
            return None, 0

    # ──────────────────────────────────────────────────────────
    # Post-generation enforcement
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _enforce_safety_fields(ability: Ability) -> Ability:
        """Override safety-critical fields regardless of LLM output.

        These fields are non-negotiable — the agent can ONLY produce
        PENDING abilities with AI attribution and simulation_only=True.
        """
        ability.approval_status = ApprovalStatus.PENDING
        ability.created_by = "AI"
        ability.simulation_only = True
        ability.schema_version = SCHEMA_VERSION
        ability.generated_at = datetime.now(timezone.utc).isoformat()
        ability.agent_version = AGENT_VERSION
        return ability


# ──────────────────────────────────────────────────────────────
# Composition prompt builder
# ──────────────────────────────────────────────────────────────

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

    Args:
        reasoning_context: Full text output from Phase A (technique details,
            CTI data, campaigns, detection guidance).
        category: Attack category string (e.g., 'credential_access').
        platform: Target platform string (e.g., 'windows').
        ability_index: 1-based index of this ability in the batch.
        total_count: Total number of abilities being generated.

    Returns:
        Formatted composition prompt string.
    """
    return (
        f"## Research Context\n\n"
        f"{reasoning_context}\n\n"
        f"---\n\n"
        f"## Task\n\n"
        f"Using the research context above, generate ability **{ability_index} of "
        f"{total_count}** for the **{category}** category targeting **{platform}**.\n\n"
        f"Choose a DIFFERENT technique from the research for each ability — "
        f"this is ability #{ability_index}.\n\n"
        f"## Requirements\n\n"
        f"1. **attack_category** must be `{category}`\n"
        f"2. **mitre_mapping** must reference a real technique from the research\n"
        f"3. **threat_intel_context** must include groups, tools, campaigns from the "
        f"enrichment data — do NOT fabricate intelligence\n"
        f"4. **executors** must include at least one {platform}-specific executor with:\n"
        f"   - A complete, syntactically valid, directly executable command\n"
        f"   - Real OS binary names, correct flags, proper escaping, real filesystem paths\n"
        f"   - Do NOT insert inline comments inside command or cleanup_procedure strings\n"
        f"   - Do NOT use placeholder values like `<target>` or `$VICTIM_IP`\n"
        f"   - A cleanup_procedure that reverses all changes (also directly executable)\n"
        f"5. **payload_description** must contain all explanatory/contextual text\n"
        f"6. **simulation_only** must be `true`\n"
        f"7. **approval_status** must be `PENDING`\n"
        f"8. **created_by** must be `AI`\n\n"
        f"Return a single Ability JSON object."
    )
