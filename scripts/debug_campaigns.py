"""Debug: check campaign→group attributions and technique links."""

import logging

from src.graph.connection import Neo4jConnection

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    conn = Neo4jConnection()

    # All attributions
    r = conn.run_query(
        "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet) "
        "RETURN c.name AS campaign, g.name AS group LIMIT 30"
    )
    logger.info("All attributions (%d):", len(r))
    for row in r:
        logger.info("  %s → %s", row["campaign"], row["group"])

    # APT29 campaign techniques
    r2 = conn.run_query(
        "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet {name: 'APT29'}) "
        "OPTIONAL MATCH (c)-[:CAMPAIGN_USES]->(t) WHERE t:Technique OR t:SubTechnique "
        "RETURN c.name AS campaign, collect(t.attack_id) AS techs"
    )
    logger.info("\nAPT29 campaign techniques:")
    for row in r2:
        logger.info("  %s: %d techniques - %s", row["campaign"], len(row["techs"]), row["techs"][:5])

    conn.close()


if __name__ == "__main__":
    main()

conn.close()
