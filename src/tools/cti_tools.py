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
    # Tool definitions for LLM function calling
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def tool_definitions() -> list[dict[str, Any]]:
        """Return function tool definitions for LLM registration.

        These follow the OpenAI/Gemini function calling schema.
        Can be passed directly to the LLM client's tools parameter.
        """
        return [
            {
                "name": "get_intrusion_sets_for_technique",
                "description": (
                    "Get APT groups and intrusion sets known to use a specific "
                    "ATT&CK technique. Returns group names, aliases, and usage context."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003', 'T1003.001')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_tools_for_technique",
                "description": (
                    "Get tools and malware associated with a specific ATT&CK technique. "
                    "Returns tool names, types, and usage descriptions."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_detection_guidance",
                "description": (
                    "Get detection guidance and data sources for a specific "
                    "ATT&CK technique. Helps build defensive context."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_mitigations",
                "description": (
                    "Get mitigations for a specific ATT&CK technique. "
                    "Returns mitigation names and how they reduce risk."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_subtechniques",
                "description": (
                    "Get sub-techniques for a parent ATT&CK technique. "
                    "Returns sub-technique names, IDs, and descriptions."
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
                "name": "get_techniques_by_tactic",
                "description": (
                    "Get all techniques belonging to a specific ATT&CK tactic. "
                    "Use tactic shortnames like 'credential-access', 'lateral-movement'."
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
                "name": "get_full_technique_context",
                "description": (
                    "Get comprehensive threat intelligence context for a technique "
                    "in a single call: groups, tools, data sources, mitigations, "
                    "campaigns, detection guidance. Best for building a complete picture."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_campaigns_for_technique",
                "description": (
                    "Get real-world campaigns and operations that used a specific "
                    "ATT&CK technique. Returns campaign names, date ranges, "
                    "and attributed APT groups. Essential for temporal threat context."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID (e.g. 'T1003', 'T1003.001')",
                        }
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "get_campaigns_for_group",
                "description": (
                    "Get campaigns attributed to a specific APT group / intrusion set. "
                    "Useful for understanding the operational history of a threat actor."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "group_name": {
                            "type": "string",
                            "description": "Intrusion set name (e.g. 'APT29', 'Lazarus Group')",
                        }
                    },
                    "required": ["group_name"],
                },
            },
        ]

    def dispatch_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Dispatch an LLM function tool call to the correct method.

        Args:
            tool_name: Name of the tool to call.
            arguments: Dict of arguments for the tool.

        Returns:
            Result of the tool call.

        Raises:
            ValueError: If tool_name is not recognized.
        """
        dispatch_map = {
            "get_intrusion_sets_for_technique": self.get_intrusion_sets_for_technique,
            "get_tools_for_technique": self.get_tools_for_technique,
            "get_detection_guidance": self.get_detection_guidance,
            "get_mitigations": self.get_mitigations,
            "get_subtechniques": self.get_subtechniques,
            "get_techniques_by_tactic": self.get_techniques_by_tactic,
            "get_full_technique_context": self.get_full_technique_context,
            "get_campaigns_for_technique": self.get_campaigns_for_technique,
            "get_campaigns_for_group": self.get_campaigns_for_group,
        }

        func = dispatch_map.get(tool_name)
        if func is None:
            raise ValueError(f"Unknown CTI tool: {tool_name}")

        return func(**arguments)
