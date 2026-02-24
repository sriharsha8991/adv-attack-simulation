"""Graph tool factory — creates LLM-facing closures over Neo4j + MISP Galaxy.

Bridges the class-based ``CTITools`` / ``MISPTools`` and the standalone
callables that Gemini's automatic function calling and OpenAI-compatible
manual dispatch loops require.

The factory produces exactly **4 closures** — the consolidated LLM tool set:

    Discover:  get_techniques_by_tactic, get_techniques_for_platform
    Navigate:  get_subtechniques
    Enrich:    get_technique_intel (omnibus — Neo4j detail + MISP Galaxy)

Usage:
    from src.tools.graph_tools import create_reasoning_tools, create_dispatch_map

    tools = create_reasoning_tools(conn, galaxy)
    dispatch = create_dispatch_map(tools)
"""

from __future__ import annotations

import logging
from typing import Any

from src.graph.connection import Neo4jConnection
from src.layers.layer2_enrichment import GalaxyManager
from src.tools.cti_tools import CTITools
from src.tools.misp_tools import MISPTools

logger = logging.getLogger(__name__)


def create_reasoning_tools(
    conn: Neo4jConnection,
    galaxy: GalaxyManager,
) -> list[Any]:
    """Create the 4 LLM-facing tool closures capturing shared resources.

    Each closure delegates to ``CTITools`` or ``MISPTools`` methods.
    Closures have full Google-style docstrings so Gemini can auto-generate
    tool schemas from type hints + docstrings.

    Args:
        conn: Active Neo4j connection (shared across all closures).
        galaxy: Loaded GalaxyManager instance (shared across all closures).

    Returns:
        List of exactly 4 callable closures with ``__name__``, ``__doc__``,
        and type annotations set.
    """
    _cti = CTITools(conn=conn)
    _misp = MISPTools(conn=conn, galaxy_manager=galaxy)

    # ── Tool 1: Discover techniques by tactic ─────────────────

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
        logger.info("Tool call: get_techniques_by_tactic(tactic=%r)", tactic)
        return _cti.get_techniques_by_tactic(tactic)

    # ── Tool 2: Discover techniques by tactic + platform ──────

    def get_techniques_for_platform(tactic: str, platform: str) -> list[dict]:
        """Query ATT&CK techniques filtered by tactic AND target platform.

        Use this when generating abilities for a specific operating system.
        Combines tactic filtering with platform filtering in one call.
        Platform names are capitalised: 'Windows', 'Linux', 'macOS'.

        Args:
            tactic: The ATT&CK tactic shortname (e.g., 'credential-access').
            platform: Target platform name (e.g., 'Windows', 'Linux', 'macOS').

        Returns:
            List of technique dicts with keys: name, attack_id, description.
        """
        logger.info(
            "Tool call: get_techniques_for_platform(tactic=%r, platform=%r)",
            tactic,
            platform,
        )
        return _cti.get_techniques_for_platform(tactic, platform)

    # ── Tool 3: Navigate to sub-techniques ────────────────────

    def get_subtechniques(technique_id: str) -> list[dict]:
        """Get sub-techniques for a parent ATT&CK technique.

        Use this to discover specific attack variants. For example T1003
        (OS Credential Dumping) has sub-techniques T1003.001 (LSASS Memory),
        T1003.002 (Security Account Manager), T1003.003 (NTDS), etc.

        Args:
            technique_id: Parent technique ID (e.g., 'T1003', 'T1110').

        Returns:
            List of sub-technique dicts with keys: name, attack_id, description, platforms.
        """
        logger.info("Tool call: get_subtechniques(technique_id=%r)", technique_id)
        return _cti.get_subtechniques(technique_id)

    # ── Tool 4: Omnibus enrichment ────────────────────────────

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
        logger.info("Tool call: get_technique_intel(technique_id=%r)", technique_id)
        intel = _cti.get_technique_intel(technique_id)
        if "error" not in intel:
            intel["misp_galaxy"] = _misp.search_misp_galaxy(technique_id)
        return intel

    tools = [
        get_techniques_by_tactic,
        get_techniques_for_platform,
        get_subtechniques,
        get_technique_intel,
    ]

    logger.info(
        "Created %d reasoning tools: %s",
        len(tools),
        [f.__name__ for f in tools],
    )
    return tools


def create_dispatch_map(tools: list[Any]) -> dict[str, Any]:
    """Build a name → function dispatch map from tool callables.

    Used by ``OpenAICompatClient`` for manual tool dispatch.

    Args:
        tools: List of callable tool functions (from ``create_reasoning_tools``).

    Returns:
        Dict mapping function ``__name__`` to the callable.
    """
    return {func.__name__: func for func in tools}
