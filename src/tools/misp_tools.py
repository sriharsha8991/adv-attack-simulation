"""MISP Galaxy enrichment tools — combines Neo4j + MISP galaxy data.

Provides the bridge between raw Neo4j CTI queries and MISP Galaxy
context to produce fully populated ThreatIntelContext objects.

The enrichment pipeline merges three data sources:
1. Neo4j knowledge graph (groups, tools, mitigations, detection, campaigns)
2. MISP Galaxy static JSON files (additional groups, tools, malware)
3. STIX Campaign objects (real-world operations with date ranges)

Usage:
    from src.tools.misp_tools import MISPTools

    with MISPTools() as misp:
        context = misp.enrich_technique_context("T1003")
        print(context.recent_campaigns)  # Structured campaign data
"""

from __future__ import annotations

import logging
from typing import Any

from src.graph.connection import Neo4jConnection
from src.layers.layer2_enrichment import GalaxyManager
from src.models.ability import CampaignUsage, ThreatIntelContext
from src.tools.cti_tools import CTITools

logger = logging.getLogger(__name__)

# Maximum description snippet length for campaign entries
_MAX_SNIPPET_LEN = 300


class MISPTools:
    """Combines Neo4j knowledge graph queries with MISP Galaxy data.

    Provides enrichment functions that merge both data sources into
    unified ThreatIntelContext objects for ability generation.  The
    ``enrich_technique_context`` method is the primary entry point and
    produces a fully-populated ``ThreatIntelContext`` with structured
    campaign data sourced from real STIX Campaign objects.
    """

    def __init__(
        self,
        conn: Neo4jConnection | None = None,
        galaxy_manager: GalaxyManager | None = None,
    ) -> None:
        """Initialize with optional existing connection and galaxy manager.

        Args:
            conn: Optional Neo4jConnection. Creates one if None.
            galaxy_manager: Optional pre-loaded GalaxyManager. Creates and
                loads one if None.
        """
        self._conn = conn or Neo4jConnection()
        self._owns_conn = conn is None
        self._cti = CTITools(conn=self._conn)

        if galaxy_manager is not None:
            self._galaxy = galaxy_manager
        else:
            self._galaxy = GalaxyManager()
            self._galaxy.load_all()

    def close(self) -> None:
        """Close resources."""
        if self._owns_conn:
            self._conn.close()

    def __enter__(self) -> MISPTools:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ──────────────────────────────────────────────────────────
    # MISP Galaxy lookup
    # ──────────────────────────────────────────────────────────

    def search_misp_galaxy(self, technique_id: str) -> dict[str, Any]:
        """Search MISP Galaxy data for a technique.

        Returns aggregated galaxy context including groups, tools,
        malware, and attack pattern metadata.

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003', 'T1003.001').

        Returns:
            Dict with keys: technique_id, attack_pattern, groups, tools, malware.
        """
        ctx = self._galaxy.get_technique_context(technique_id)
        logger.info(
            "MISP Galaxy lookup for %s: %d groups, %d tools, %d malware.",
            technique_id,
            len(ctx.get("groups", [])),
            len(ctx.get("tools", [])),
            len(ctx.get("malware", [])),
        )
        return ctx

    # ──────────────────────────────────────────────────────────
    # Combined enrichment
    # ──────────────────────────────────────────────────────────

    def enrich_technique_context(
        self, technique_id: str
    ) -> ThreatIntelContext:
        """Build a complete ThreatIntelContext by merging Neo4j + MISP data.

        This is the primary enrichment entry point.  It:
        1. Queries Neo4j for groups, tools, detection, mitigations
        2. Queries Neo4j for real STIX Campaign objects (with dates + attribution)
        3. Queries MISP Galaxy for additional groups, tools, malware
        4. Deduplicates and merges into a ThreatIntelContext

        Args:
            technique_id: ATT&CK technique ID (e.g. 'T1003').

        Returns:
            Fully populated ThreatIntelContext with structured campaigns.
        """
        # --- Neo4j data ---
        neo4j_ctx = self._cti.get_full_technique_context(technique_id)

        neo4j_groups: list[str] = neo4j_ctx.get("groups", [])
        neo4j_tools: list[str] = neo4j_ctx.get("tools", [])
        detection_text: str = neo4j_ctx.get("detection_text") or ""
        data_sources: list[str] = neo4j_ctx.get("data_sources", [])
        mitigations: list[str] = neo4j_ctx.get("mitigations", [])

        # --- Campaign data from Neo4j (real STIX campaigns) ---
        campaign_records = self._cti.get_campaigns_for_technique(technique_id)
        campaigns = _build_campaign_objects(campaign_records)

        # --- MISP Galaxy data ---
        galaxy_ctx = self.search_misp_galaxy(technique_id)

        galaxy_groups = [
            g.get("name", "") for g in galaxy_ctx.get("groups", [])
        ]
        galaxy_tools = [
            t.get("name", "") for t in galaxy_ctx.get("tools", [])
        ]
        galaxy_malware = [
            m.get("name", "") for m in galaxy_ctx.get("malware", [])
        ]

        # --- Merge & deduplicate ---
        all_groups = _dedupe(neo4j_groups + galaxy_groups)
        all_tools = _dedupe(neo4j_tools + galaxy_tools + galaxy_malware)

        # Build detection guidance string
        detection_guidance = _build_detection_guidance(
            detection_text, data_sources, mitigations
        )

        context = ThreatIntelContext(
            associated_groups=all_groups,
            associated_tools=all_tools,
            recent_campaigns=campaigns,
            detection_guidance=detection_guidance,
        )

        logger.info(
            "Enriched %s: %d groups, %d tools, %d campaigns.",
            technique_id,
            len(context.associated_groups),
            len(context.associated_tools),
            len(context.recent_campaigns),
        )
        return context




# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────


def _dedupe(items: list[str]) -> list[str]:
    """Deduplicate a list preserving order, ignoring empty strings."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _build_campaign_objects(
    records: list[dict[str, Any]],
) -> list[CampaignUsage]:
    """Convert Neo4j campaign query records into CampaignUsage models.

    Each record comes from ``CAMPAIGNS_FOR_TECHNIQUE`` and contains:
    campaign_name, external_id, description, first_seen, last_seen,
    attributed_groups.
    """
    campaigns: list[CampaignUsage] = []
    seen_names: set[str] = set()

    for rec in records:
        name = rec.get("campaign_name", "")
        if not name or name in seen_names:
            continue
        seen_names.add(name)

        # Truncate description to a readable snippet
        desc = rec.get("description") or ""
        snippet: str | None = None
        if desc:
            snippet = desc[:_MAX_SNIPPET_LEN].rstrip()
            if len(desc) > _MAX_SNIPPET_LEN:
                snippet += "..."

        first_seen = rec.get("first_seen")
        last_seen = rec.get("last_seen")

        campaigns.append(
            CampaignUsage(
                campaign_name=name,
                first_seen=str(first_seen) if first_seen else None,
                last_seen=str(last_seen) if last_seen else None,
                attributed_groups=rec.get("attributed_groups", []),
                description_snippet=snippet,
            )
        )

    return campaigns


def _build_detection_guidance(
    detection_text: str,
    data_sources: list[str],
    mitigations: list[str],
) -> str | None:
    """Assemble detection guidance string from individual components."""
    parts: list[str] = []

    if detection_text:
        # Truncate extremely long detection text
        text = detection_text[:1000].rstrip()
        if len(detection_text) > 1000:
            text += "..."
        parts.append(text)

    if data_sources:
        parts.append(f"Data sources: {', '.join(data_sources)}.")

    if mitigations:
        parts.append(f"Mitigations: {', '.join(mitigations)}.")

    return " ".join(parts) if parts else None
