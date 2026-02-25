"""CTI Tools — Neo4j-backed threat intelligence query functions.

These functions are designed to be registered as LLM function tools
(Phase 4+). Each executes a parameterized Cypher query from
src/graph/queries.py against the MITRE ATT&CK knowledge graph.

Usage:
    from src.tools.cti_tools import CTITools

    cti = CTITools()
    groups = cti.get_intrusion_sets_for_technique("T1003")
    tools = cti.get_tools_for_technique("T1003.001")
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.graph.connection import Neo4jConnection
from src.graph import queries

logger = logging.getLogger(__name__)


class CTITools:
    """Neo4j-backed CTI query tools.

    Wraps parameterized Cypher queries to provide structured threat
    intelligence data for any valid ATT&CK technique ID.

    Can be used standalone or registered as LLM function tools.
    """

    def __init__(self, conn: Neo4jConnection | None = None) -> None:
        """Initialize with an existing connection or create a new one.

        Args:
            conn: Optional existing Neo4jConnection. If None, creates one.
                  Caller is responsible for closing if passed in.
        """
        self._conn = conn or Neo4jConnection()
        self._owns_conn = conn is None

    def close(self) -> None:
        """Close the connection if we own it."""
        if self._owns_conn:
            self._conn.close()

    def __enter__(self) -> CTITools:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ──────────────────────────────────────────────────────────
    # Core query tools
    # ──────────────────────────────────────────────────────────

    def get_intrusion_sets_for_technique(
        self, technique_id: str
    ) -> list[dict[str, Any]]:
        """Get APT groups / intrusion sets that use a technique.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1003.001').

        Returns:
            List of dicts with keys: group_name, aliases, usage_description.
        """
        results = self._conn.run_query(
            queries.INTRUSION_SETS_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        logger.info(
            "Found %d intrusion sets for %s.", len(results), technique_id
        )
        return results

    def get_tools_for_technique(
        self, technique_id: str
    ) -> list[dict[str, Any]]:
        """Get tools and malware associated with a technique.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1003.001').

        Returns:
            List of dicts with keys: name, type, description, usage_description.
        """
        results = self._conn.run_query(
            queries.TOOLS_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        logger.info(
            "Found %d tools/malware for %s.", len(results), technique_id
        )
        return results

    def get_detection_guidance(self, technique_id: str) -> dict[str, Any]:
        """Get detection guidance for a technique.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003').

        Returns:
            Dict with keys: detection_text, data_sources.
        """
        results = self._conn.run_query(
            queries.DETECTION_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        if results:
            record = results[0]
            logger.info(
                "Detection guidance found for %s (%d data sources).",
                technique_id,
                len(record.get("data_sources", [])),
            )
            return {
                "detection_text": record.get("detection_text") or "",
                "data_sources": record.get("data_sources", []),
            }
        logger.warning("No detection guidance found for %s.", technique_id)
        return {"detection_text": "", "data_sources": []}

    def get_mitigations(self, technique_id: str) -> list[dict[str, Any]]:
        """Get mitigations for a technique.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003').

        Returns:
            List of dicts with keys: mitigation_name, description,
            how_it_mitigates.
        """
        results = self._conn.run_query(
            queries.MITIGATIONS_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        logger.info(
            "Found %d mitigations for %s.", len(results), technique_id
        )
        return results

    def get_subtechniques(self, technique_id: str) -> list[dict[str, Any]]:
        """Get sub-techniques for a parent technique.

        Args:
            technique_id: Parent technique ID (e.g. 'T1003').

        Returns:
            List of dicts with: name, attack_id, description, platforms.
        """
        results = self._conn.run_query(
            queries.SUBTECHNIQUES_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        logger.info(
            "Found %d sub-techniques for %s.", len(results), technique_id
        )
        return results

    def get_techniques_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Get all techniques for a tactic.

        Args:
            tactic: Tactic shortname (e.g. 'credential-access').

        Returns:
            List of dicts with: name, attack_id, description, platforms.
        """
        results = self._conn.run_query(
            queries.TECHNIQUES_BY_TACTIC,
            {"tactic": tactic},
        )
        logger.info(
            "Found %d techniques for tactic '%s'.", len(results), tactic
        )
        return results

    def get_full_technique_context(
        self, technique_id: str
    ) -> dict[str, Any]:
        """Get comprehensive context for a technique (single query).

        Combines groups, tools, data sources, mitigations, detection
        guidance in one Cypher call. Ideal for building ThreatIntelContext.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            Dict with: name, attack_id, description, platforms, tactics,
            groups, tools, data_sources, mitigations, detection_text.
        """
        results = self._conn.run_query(
            queries.FULL_TECHNIQUE_CONTEXT,
            {"technique_id": technique_id},
        )
        if results:
            logger.info("Full context retrieved for %s.", technique_id)
            return results[0]
        logger.warning("No technique found for ID: %s", technique_id)
        return {}

    def get_random_techniques(
        self, tactic: str, count: int = 5
    ) -> list[dict[str, Any]]:
        """Get random techniques for a tactic (for sampling).

        Args:
            tactic: Tactic shortname.
            count: Number of random techniques to return.

        Returns:
            List of dicts with: name, attack_id, description, platforms.
        """
        results = self._conn.run_query(
            queries.RANDOM_TECHNIQUES_BY_TACTIC,
            {"tactic": tactic, "count": count},
        )
        return results

    def get_techniques_for_platform(
        self, tactic: str, platform: str
    ) -> list[dict[str, Any]]:
        """Get techniques filtered by tactic and platform.

        Args:
            tactic: Tactic shortname.
            platform: Platform name (e.g. 'Windows', 'Linux').

        Returns:
            List of dicts with: name, attack_id, description.
        """
        results = self._conn.run_query(
            queries.TECHNIQUES_FOR_PLATFORM,
            {"tactic": tactic, "platform": platform},
        )
        return results

    def get_campaigns_for_technique(
        self, technique_id: str
    ) -> list[dict[str, Any]]:
        """Get real-world campaigns that used a specific technique.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1003.001').

        Returns:
            List of dicts with: campaign_name, external_id, description,
            first_seen, last_seen, attributed_groups.
        """
        results = self._conn.run_query(
            queries.CAMPAIGNS_FOR_TECHNIQUE,
            {"technique_id": technique_id},
        )
        logger.info(
            "Found %d campaigns for %s.", len(results), technique_id
        )
        return results

    def get_campaigns_for_group(
        self, group_name: str
    ) -> list[dict[str, Any]]:
        """Get campaigns attributed to a specific APT group.

        Args:
            group_name: Intrusion set name (e.g. 'APT29').

        Returns:
            List of dicts with: campaign_name, external_id, description,
            first_seen, last_seen.
        """
        results = self._conn.run_query(
            queries.CAMPAIGNS_FOR_GROUP,
            {"group_name": group_name},
        )
        logger.info(
            "Found %d campaigns for group '%s'.", len(results), group_name
        )
        return results

    # ──────────────────────────────────────────────────────────
    # Omnibus enrichment tool
    # ──────────────────────────────────────────────────────────

    def get_technique_intel(
        self, technique_id: str
    ) -> dict[str, Any]:
        """Get comprehensive, detailed intelligence for a technique in one call.

        This is the **omnibus enrichment tool** — the single entry point for
        all technique-level threat intelligence.  It replaces the need for
        separate calls to ``get_intrusion_sets_for_technique``,
        ``get_tools_for_technique``, ``get_detection_guidance``,
        ``get_mitigations``, and ``get_campaigns_for_technique``.

        Internally it executes 5 targeted Cypher queries and merges the
        results into one rich dictionary:

        * ``FULL_TECHNIQUE_CONTEXT`` — technique metadata + summary names
        * ``INTRUSION_SETS_FOR_TECHNIQUE`` — groups with aliases and usage
        * ``TOOLS_FOR_TECHNIQUE`` — tools/malware with type and usage
        * ``MITIGATIONS_FOR_TECHNIQUE`` — mitigations with descriptions
        * ``CAMPAIGNS_FOR_TECHNIQUE`` — campaigns with dates + attribution

        Detection guidance (``detection_text``, ``data_sources``) is
        already fully captured in ``FULL_TECHNIQUE_CONTEXT`` so no extra
        query is needed.

        Args:
            technique_id: ATT&CK technique or sub-technique ID
                (e.g. 'T1003', 'T1003.001').

        Returns:
            Dict with keys:

            * **name**, **attack_id**, **description**, **platforms**,
              **tactics** — technique metadata
            * **groups** — ``list[dict]`` with ``group_name``, ``aliases``,
              ``usage_description``
            * **tools** — ``list[dict]`` with ``name``, ``type``,
              ``description``, ``usage_description``
            * **detection** — ``dict`` with ``detection_text``,
              ``data_sources``
            * **mitigations** — ``list[dict]`` with ``mitigation_name``,
              ``description``, ``how_it_mitigates``
            * **campaigns** — ``list[dict]`` with ``campaign_name``,
              ``external_id``, ``description``, ``first_seen``,
              ``last_seen``, ``attributed_groups``

            Returns ``{"error": "..."}`` if the technique is not found.
        """
        # 1. Base metadata + summary names
        base = self.get_full_technique_context(technique_id)
        if not base:
            logger.warning("Technique %s not found in graph.", technique_id)
            return {"error": f"Technique {technique_id} not found in knowledge graph"}

        # 2. Detailed records in parallel (richer than the summary names above)
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_groups = pool.submit(self.get_intrusion_sets_for_technique, technique_id)
            f_tools = pool.submit(self.get_tools_for_technique, technique_id)
            f_mitigations = pool.submit(self.get_mitigations, technique_id)
            f_campaigns = pool.submit(self.get_campaigns_for_technique, technique_id)

            groups = f_groups.result()
            tools = f_tools.result()
            mitigations = f_mitigations.result()
            campaigns = f_campaigns.result()

        result = {
            # Technique metadata
            "name": base.get("name", ""),
            "attack_id": base.get("attack_id", ""),
            "description": base.get("description", ""),
            "platforms": base.get("platforms", []),
            "tactics": base.get("tactics", []),
            # Detailed enrichment
            "groups": groups,
            "tools": tools,
            "detection": {
                "detection_text": base.get("detection_text") or "",
                "data_sources": base.get("data_sources", []),
            },
            "mitigations": mitigations,
            "campaigns": campaigns,
        }

        logger.info(
            "Technique intel for %s: %d groups, %d tools, %d mitigations, "
            "%d campaigns.",
            technique_id,
            len(groups),
            len(tools),
            len(mitigations),
            len(campaigns),
        )
        return result

    # ──────────────────────────────────────────────────────────
    # Tool definitions for LLM function calling
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def tool_definitions() -> list[dict[str, Any]]:
        """Return the **consolidated 4-tool set** for LLM registration.

        Design rationale (Feb 24 2026 optimisation):

        The original 9 + 2 tool surface was reduced to 4 tools after
        analysis showed 6 technique-keyed tools were subsumed by
        ``get_technique_intel`` (the omnibus enrichment query).  Exposing
        all of them caused LLM "choice paralysis" and wasted ~450 tokens
        per prompt on redundant tool definitions.

        The 4-tool set maps to the natural reasoning flow::

            Discover  → get_techniques_by_tactic / get_techniques_for_platform
            Navigate  → get_subtechniques
            Enrich    → get_technique_intel (ONE call, full detail)

        Individual methods (``get_intrusion_sets_for_technique``, etc.)
        remain available for programmatic / script use but are **not**
        registered with the LLM.
        """
        return [
            {
                "name": "get_techniques_by_tactic",
                "description": (
                    "Get all ATT&CK techniques belonging to a specific tactic. "
                    "Use tactic shortnames: 'credential-access', 'lateral-movement', "
                    "'persistence', 'defense-evasion', 'privilege-escalation', "
                    "'discovery', 'collection', 'exfiltration', 'command-and-control', "
                    "'initial-access', 'execution', 'resource-development', 'impact'."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tactic": {
                            "type": "string",
                            "description": (
                                "ATT&CK tactic shortname (e.g. 'credential-access', "
                                "'defense-evasion', 'persistence')"
                            ),
                        }
                    },
                    "required": ["tactic"],
                },
            },
            {
                "name": "get_techniques_for_platform",
                "description": (
                    "Get ATT&CK techniques filtered by tactic AND platform. "
                    "Useful when generating abilities for a specific OS. "
                    "Platform names are capitalised: 'Windows', 'Linux', 'macOS'."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tactic": {
                            "type": "string",
                            "description": "ATT&CK tactic shortname",
                        },
                        "platform": {
                            "type": "string",
                            "description": (
                                "Platform name (e.g. 'Windows', 'Linux', 'macOS')"
                            ),
                        },
                    },
                    "required": ["tactic", "platform"],
                },
            },
            {
                "name": "get_subtechniques",
                "description": (
                    "Get sub-techniques for a parent ATT&CK technique. "
                    "Use to discover specific variants (e.g. T1003 → "
                    "T1003.001 LSASS Memory, T1003.002 SAM, etc.)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "Parent technique ID (e.g. 'T1003')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_technique_intel",
                "description": (
                    "Get comprehensive intelligence for a specific technique in "
                    "ONE call. Returns: technique metadata (name, description, "
                    "platforms, tactics), APT groups with aliases and usage "
                    "details, tools/malware with descriptions, detection guidance "
                    "with data sources, mitigations with descriptions, and "
                    "real-world campaigns with date ranges and group attribution. "
                    "This is the primary enrichment tool — use it once per "
                    "technique instead of making multiple separate queries."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": (
                                "ATT&CK technique or sub-technique ID "
                                "(e.g. 'T1003', 'T1003.001')"
                            ),
                        }
                    },
                    "required": ["technique_id"],
                },
            },
        ]

    def dispatch_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Dispatch an LLM function tool call to the correct method.

        Maps only the 4 LLM-registered tools from ``tool_definitions()``.

        Args:
            tool_name: Name of the tool to call.
            arguments: Dict of arguments for the tool.

        Returns:
            Result of the tool call.

        Raises:
            ValueError: If tool_name is not recognized.
        """
        dispatch_map: dict[str, Any] = {
            "get_techniques_by_tactic": self.get_techniques_by_tactic,
            "get_techniques_for_platform": self.get_techniques_for_platform,
            "get_subtechniques": self.get_subtechniques,
            "get_technique_intel": self.get_technique_intel,
        }

        func = dispatch_map.get(tool_name)
        if func is None:
            raise ValueError(f"Unknown CTI tool: {tool_name}")

        return func(**arguments)
