"""Neo4j graph schema — indexes, constraints, and setup.

Creates the knowledge graph schema defined in knowledge_graph_schema.md.
All operations are idempotent (IF NOT EXISTS).

Usage:
    from src.graph.schema import setup_schema, clear_graph
    from src.graph.connection import Neo4jConnection

    with Neo4jConnection() as conn:
        clear_graph(conn)
        setup_schema(conn)
"""

from __future__ import annotations

import logging

from src.graph.connection import Neo4jConnection

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Indexes (16 total)
# ──────────────────────────────────────────────────────────────

INDEX_STATEMENTS = [
    # Primary lookup indexes
    "CREATE INDEX idx_tactic_shortname IF NOT EXISTS FOR (tac:Tactic) ON (tac.shortname)",
    "CREATE INDEX idx_technique_attack_id IF NOT EXISTS FOR (t:Technique) ON (t.attack_id)",
    "CREATE INDEX idx_subtechnique_attack_id IF NOT EXISTS FOR (s:SubTechnique) ON (s.attack_id)",
    # STIX ID indexes (for relationship loading via MERGE/MATCH)
    "CREATE INDEX idx_tactic_stix IF NOT EXISTS FOR (tac:Tactic) ON (tac.stix_id)",
    "CREATE INDEX idx_technique_stix IF NOT EXISTS FOR (t:Technique) ON (t.stix_id)",
    "CREATE INDEX idx_subtechnique_stix IF NOT EXISTS FOR (s:SubTechnique) ON (s.stix_id)",
    "CREATE INDEX idx_intrusion_stix IF NOT EXISTS FOR (g:IntrusionSet) ON (g.stix_id)",
    "CREATE INDEX idx_tool_stix IF NOT EXISTS FOR (t:Tool) ON (t.stix_id)",
    "CREATE INDEX idx_malware_stix IF NOT EXISTS FOR (m:Malware) ON (m.stix_id)",
    "CREATE INDEX idx_datasource_stix IF NOT EXISTS FOR (d:DataSource) ON (d.stix_id)",
    "CREATE INDEX idx_mitigation_stix IF NOT EXISTS FOR (mt:Mitigation) ON (mt.stix_id)",
    "CREATE INDEX idx_campaign_stix IF NOT EXISTS FOR (c:Campaign) ON (c.stix_id)",
    # Name indexes (for search)
    "CREATE INDEX idx_intrusion_name IF NOT EXISTS FOR (g:IntrusionSet) ON (g.name)",
    "CREATE INDEX idx_tool_name IF NOT EXISTS FOR (t:Tool) ON (t.name)",
    "CREATE INDEX idx_malware_name IF NOT EXISTS FOR (m:Malware) ON (m.name)",
    "CREATE INDEX idx_campaign_name IF NOT EXISTS FOR (c:Campaign) ON (c.name)",
    "CREATE INDEX idx_campaign_external_id IF NOT EXISTS FOR (c:Campaign) ON (c.external_id)",
    # Generated ability indexes
    "CREATE INDEX idx_ability_id IF NOT EXISTS FOR (a:Ability) ON (a.id)",
    "CREATE INDEX idx_ability_category IF NOT EXISTS FOR (a:Ability) ON (a.attack_category)",
]


# ──────────────────────────────────────────────────────────────
# Uniqueness Constraints (5 total)
# ──────────────────────────────────────────────────────────────

CONSTRAINT_STATEMENTS = [
    "CREATE CONSTRAINT uniq_technique_stix IF NOT EXISTS FOR (t:Technique) REQUIRE t.stix_id IS UNIQUE",
    "CREATE CONSTRAINT uniq_subtechnique_stix IF NOT EXISTS FOR (s:SubTechnique) REQUIRE s.stix_id IS UNIQUE",
    "CREATE CONSTRAINT uniq_tactic_stix IF NOT EXISTS FOR (tac:Tactic) REQUIRE tac.stix_id IS UNIQUE",
    "CREATE CONSTRAINT uniq_intrusion_stix IF NOT EXISTS FOR (g:IntrusionSet) REQUIRE g.stix_id IS UNIQUE",
    "CREATE CONSTRAINT uniq_campaign_stix IF NOT EXISTS FOR (c:Campaign) REQUIRE c.stix_id IS UNIQUE",
    "CREATE CONSTRAINT uniq_ability_id IF NOT EXISTS FOR (a:Ability) REQUIRE a.id IS UNIQUE",
]


# ──────────────────────────────────────────────────────────────
# Public Functions
# ──────────────────────────────────────────────────────────────


def create_constraints(conn: Neo4jConnection) -> int:
    """Create all uniqueness constraints (idempotent).

    Constraints are created BEFORE indexes because a uniqueness constraint
    implicitly creates an index on the constrained property.

    Returns:
        Number of constraint statements executed.
    """
    logger.info("Creating %d uniqueness constraints ...", len(CONSTRAINT_STATEMENTS))
    for stmt in CONSTRAINT_STATEMENTS:
        conn.run_write(stmt)
        logger.debug("  %s", stmt.split("FOR")[0].strip())
    logger.info("All %d constraints created.", len(CONSTRAINT_STATEMENTS))
    return len(CONSTRAINT_STATEMENTS)


def create_indexes(conn: Neo4jConnection) -> int:
    """Create all indexes (idempotent).

    Returns:
        Number of index statements executed.
    """
    logger.info("Creating %d indexes ...", len(INDEX_STATEMENTS))
    for stmt in INDEX_STATEMENTS:
        conn.run_write(stmt)
        logger.debug("  %s", stmt.split("FOR")[0].strip())
    logger.info("All %d indexes created.", len(INDEX_STATEMENTS))
    return len(INDEX_STATEMENTS)


def clear_graph(conn: Neo4jConnection) -> int:
    """Delete all nodes and relationships via the connection's batched delete.

    Returns:
        Total number of nodes deleted.
    """
    logger.info("Clearing entire graph ...")
    total = conn.clear_all()
    logger.info("Graph cleared: %d nodes deleted.", total)
    return total


def setup_schema(conn: Neo4jConnection) -> dict[str, int]:
    """Full schema setup: constraints first, then indexes.

    Returns:
        Dict with counts: {"constraints": N, "indexes": N}
    """
    n_constraints = create_constraints(conn)
    n_indexes = create_indexes(conn)
    return {"constraints": n_constraints, "indexes": n_indexes}
