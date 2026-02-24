"""
Neo4j batch loader — loads parsed STIX data into the knowledge graph.

Uses the UNWIND + MERGE pattern for idempotent batch loading.
All loaders accept the Neo4jConnection wrapper and a list of dicts.

Usage:
    from src.graph.loader import load_all_nodes, load_all_relationships

    with Neo4jConnection() as conn:
        stats = load_all_nodes(conn, parsed_data)
        stats.update(load_all_relationships(conn, relationships, tactic_links))
"""

from __future__ import annotations

import logging
from typing import Any

from src.graph.connection import Neo4jConnection

logger = logging.getLogger(__name__)

# Default batch size for UNWIND operations — keeps under Aura transaction limits
BATCH_SIZE = 500


# ──────────────────────────────────────────────────────────────
# Cypher Templates — Node Loading
# ──────────────────────────────────────────────────────────────

LOAD_TACTICS = """
UNWIND $items AS item
MERGE (tac:Tactic {stix_id: item.stix_id})
SET tac.name = item.name,
    tac.shortname = item.shortname,
    tac.external_id = item.external_id,
    tac.description = item.description
"""

LOAD_TECHNIQUES = """
UNWIND $items AS item
MERGE (t:Technique {stix_id: item.stix_id})
SET t.name = item.name,
    t.attack_id = item.attack_id,
    t.description = item.description,
    t.platforms = item.platforms,
    t.detection = item.detection,
    t.is_subtechnique = item.is_subtechnique
"""

LOAD_SUBTECHNIQUES = """
UNWIND $items AS item
MERGE (s:SubTechnique {stix_id: item.stix_id})
SET s.name = item.name,
    s.attack_id = item.attack_id,
    s.description = item.description,
    s.platforms = item.platforms,
    s.detection = item.detection,
    s.is_subtechnique = item.is_subtechnique
"""

LOAD_INTRUSION_SETS = """
UNWIND $items AS item
MERGE (g:IntrusionSet {stix_id: item.stix_id})
SET g.name = item.name,
    g.aliases = item.aliases,
    g.description = item.description
"""

LOAD_TOOLS = """
UNWIND $items AS item
MERGE (t:Tool {stix_id: item.stix_id})
SET t.name = item.name,
    t.description = item.description,
    t.platforms = item.platforms
"""

LOAD_MALWARE = """
UNWIND $items AS item
MERGE (m:Malware {stix_id: item.stix_id})
SET m.name = item.name,
    m.description = item.description,
    m.platforms = item.platforms
"""

LOAD_DATA_SOURCES = """
UNWIND $items AS item
MERGE (d:DataSource {stix_id: item.stix_id})
SET d.name = item.name,
    d.description = item.description
"""
#Mitigation is a defensive control category. they are like preventive measures but they are designed to detect and respond to attacks that have already occurred. They can include things like intrusion detection systems, security information and event management (SIEM) systems, and incident response teams. 
# #Detective controls are important for identifying and mitigating attacks that have bypassed preventive controls, and for minimizing the damage caused by successful attacks.
LOAD_MITIGATIONS = """
UNWIND $items AS item
MERGE (mt:Mitigation {stix_id: item.stix_id})
SET mt.name = item.name,
    mt.description = item.description
"""

LOAD_CAMPAIGNS = """
UNWIND $items AS item
MERGE (c:Campaign {stix_id: item.stix_id})
SET c.name = item.name,
    c.external_id = item.external_id,
    c.description = item.description,
    c.first_seen = item.first_seen,
    c.last_seen = item.last_seen
"""

# ──────────────────────────────────────────────────────────────
# Cypher Templates — Relationship Loading
# ──────────────────────────────────────────────────────────────

LINK_TECHNIQUE_TACTIC = """
UNWIND $links AS link
MATCH (t {stix_id: link.technique_stix_id})
WHERE t:Technique OR t:SubTechnique
MATCH (tac:Tactic {shortname: link.tactic_shortname})
MERGE (t)-[:PART_OF]->(tac)
"""

LINK_SUBTECHNIQUE_TECHNIQUE = """
UNWIND $rels AS rel
MATCH (st:SubTechnique {stix_id: rel.source_ref})
MATCH (t:Technique {stix_id: rel.target_ref})
MERGE (st)-[:PART_OF]->(t)
"""

LINK_USES = """
UNWIND $rels AS rel
MATCH (src {stix_id: rel.source_ref})
MATCH (tgt {stix_id: rel.target_ref})
MERGE (src)-[r:USES]->(tgt)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
"""

LINK_MITIGATES = """
UNWIND $rels AS rel
MATCH (m:Mitigation {stix_id: rel.source_ref})
MATCH (t {stix_id: rel.target_ref})
WHERE t:Technique OR t:SubTechnique
MERGE (m)-[r:MITIGATES]->(t)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
"""

LINK_DETECTED_BY = """
UNWIND $rels AS rel
MATCH (ds:DataSource {stix_id: rel.source_ref})
MATCH (t {stix_id: rel.target_ref})
WHERE t:Technique OR t:SubTechnique
MERGE (t)-[r:DETECTED_BY]->(ds)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
"""

LINK_CAMPAIGN_USES = """
UNWIND $rels AS rel
MATCH (c:Campaign {stix_id: rel.source_ref})
MATCH (tgt {stix_id: rel.target_ref})
MERGE (c)-[r:CAMPAIGN_USES]->(tgt)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
"""

LINK_ATTRIBUTED_TO = """
UNWIND $rels AS rel
MATCH (c:Campaign {stix_id: rel.source_ref})
MATCH (g:IntrusionSet {stix_id: rel.target_ref})
MERGE (c)-[r:ATTRIBUTED_TO]->(g)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
"""


# ──────────────────────────────────────────────────────────────
# Batch Helper
# ──────────────────────────────────────────────────────────────


def _load_batch(
    conn: Neo4jConnection,
    cypher: str,
    items: list[dict[str, Any]],
    label: str,
    param_name: str = "items",
    batch_size: int = BATCH_SIZE,
) -> int:
    """Execute a Cypher UNWIND statement in batches.

    Args:
        conn: Neo4j connection wrapper.
        cypher: Cypher template using $items or $rels or $links.
        items: List of dicts to load.
        label: Label for logging (e.g. "Tactics").
        param_name: Parameter name in the Cypher template.
        batch_size: Number of items per transaction.

    Returns:
        Total number of items processed.
    """
    total = len(items)
    if total == 0:
        logger.info("No %s to load.", label)
        return 0

    loaded = 0
    for i in range(0, total, batch_size):
        batch = items[i : i + batch_size]
        conn.run_write(cypher, {param_name: batch})
        loaded += len(batch)
        if total > batch_size:
            logger.debug("  %s: %d/%d", label, loaded, total)

    logger.info("Loaded %d %s.", total, label)
    return total


# ──────────────────────────────────────────────────────────────
# Node Loaders
# ──────────────────────────────────────────────────────────────


def load_tactics(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_TACTICS, items, "Tactics")


def load_techniques(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_TECHNIQUES, items, "Techniques")


def load_subtechniques(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_SUBTECHNIQUES, items, "SubTechniques")


def load_intrusion_sets(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_INTRUSION_SETS, items, "IntrusionSets")


def load_tools(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_TOOLS, items, "Tools")


def load_malware(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_MALWARE, items, "Malware")


def load_data_sources(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_DATA_SOURCES, items, "DataSources")


def load_mitigations(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_MITIGATIONS, items, "Mitigations")


def load_campaigns(conn: Neo4jConnection, items: list[dict]) -> int:
    return _load_batch(conn, LOAD_CAMPAIGNS, items, "Campaigns")


# ──────────────────────────────────────────────────────────────
# Relationship Loaders
# ──────────────────────────────────────────────────────────────


def load_tactic_links(conn: Neo4jConnection, links: list[dict]) -> int:
    """Load Technique/SubTechnique → Tactic PART_OF links (from kill_chain_phases)."""
    return _load_batch(conn, LINK_TECHNIQUE_TACTIC, links, "Tactic links", param_name="links")


def load_subtechnique_links(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load SubTechnique → Technique PART_OF links (from STIX subtechnique-of)."""
    return _load_batch(conn, LINK_SUBTECHNIQUE_TECHNIQUE, rels, "SubTechnique→Technique links", param_name="rels")


def load_uses_relationships(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load USES relationships (IntrusionSet/Tool/Malware → Technique)."""
    return _load_batch(conn, LINK_USES, rels, "USES relationships", param_name="rels")


def load_mitigates_relationships(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load Mitigation → Technique MITIGATES relationships."""
    return _load_batch(conn, LINK_MITIGATES, rels, "MITIGATES relationships", param_name="rels")


def load_detected_by_relationships(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load Technique → DataSource DETECTED_BY relationships.

    Note: STIX 'detects' goes DataSource→Technique, but our schema reverses
    direction to Technique-[:DETECTED_BY]->DataSource.
    """
    return _load_batch(conn, LINK_DETECTED_BY, rels, "DETECTED_BY relationships", param_name="rels")


def load_campaign_uses_relationships(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load Campaign → Technique/Tool/Malware CAMPAIGN_USES relationships."""
    return _load_batch(conn, LINK_CAMPAIGN_USES, rels, "CAMPAIGN_USES relationships", param_name="rels")


def load_attributed_to_relationships(conn: Neo4jConnection, rels: list[dict]) -> int:
    """Load Campaign → IntrusionSet ATTRIBUTED_TO relationships."""
    return _load_batch(conn, LINK_ATTRIBUTED_TO, rels, "ATTRIBUTED_TO relationships", param_name="rels")


# ──────────────────────────────────────────────────────────────
# Orchestrators
# ──────────────────────────────────────────────────────────────


def load_all_nodes(
    conn: Neo4jConnection,
    parsed: dict[str, list[dict]],
) -> dict[str, int]:
    """Load all 8 node types from parsed STIX data.

    Args:
        conn: Neo4j connection.
        parsed: Dict with keys matching node type names, values are lists of dicts.
            Expected keys: tactics, techniques, subtechniques, intrusion_sets,
            tools, malware, data_sources, mitigations

    Returns:
        Dict mapping node type → count loaded.
    """
    stats = {}
    loaders = [
        ("tactics", load_tactics),
        ("techniques", load_techniques),
        ("subtechniques", load_subtechniques),
        ("intrusion_sets", load_intrusion_sets),
        ("tools", load_tools),
        ("malware", load_malware),
        ("data_sources", load_data_sources),
        ("mitigations", load_mitigations),
        ("campaigns", load_campaigns),
    ]
    for key, loader_fn in loaders:
        items = parsed.get(key, [])
        stats[key] = loader_fn(conn, items)
    return stats


def load_all_relationships(
    conn: Neo4jConnection,
    grouped_rels: dict[str, list[dict]],
    tactic_links: list[dict],
) -> dict[str, int]:
    """Load all relationship types in the correct order.

    Args:
        conn: Neo4j connection.
        grouped_rels: Dict keyed by STIX relationship_type.
        tactic_links: Technique→Tactic links from kill_chain_phases.

    Returns:
        Dict mapping relationship type → count loaded.
    """
    stats = {}

    # 1. Technique/SubTechnique → Tactic (from kill_chain_phases — special case)
    stats["tactic_links"] = load_tactic_links(conn, tactic_links)

    # 2. SubTechnique → Technique (STIX subtechnique-of)
    subtechnique_rels = grouped_rels.get("subtechnique-of", [])
    stats["subtechnique_links"] = load_subtechnique_links(conn, subtechnique_rels)

    # 3. USES relationships (IntrusionSet/Tool/Malware → Technique)
    uses_rels = grouped_rels.get("uses", [])
    stats["uses"] = load_uses_relationships(conn, uses_rels)

    # 4. MITIGATES (Mitigation → Technique)
    mitigates_rels = grouped_rels.get("mitigates", [])
    stats["mitigates"] = load_mitigates_relationships(conn, mitigates_rels)

    # 5. DETECTED_BY (reversed from STIX 'detects': DataSource → Technique)
    detects_rels = grouped_rels.get("detects", [])
    stats["detected_by"] = load_detected_by_relationships(conn, detects_rels)

    # 6. CAMPAIGN_USES (Campaign → Technique/Tool/Malware)
    # STIX stores campaign 'uses' alongside other 'uses' rels, but source_ref
    # starts with 'campaign--'. We filter from the existing 'uses' bucket.
    campaign_uses = [
        r for r in uses_rels if r.get("source_ref", "").startswith("campaign--")
    ]
    stats["campaign_uses"] = load_campaign_uses_relationships(conn, campaign_uses)

    # 7. ATTRIBUTED_TO (Campaign → IntrusionSet)
    attributed_rels = grouped_rels.get("attributed-to", [])
    stats["attributed_to"] = load_attributed_to_relationships(conn, attributed_rels)

    return stats
