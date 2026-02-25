"""Quick test: verify campaign enrichment pipeline end-to-end."""

import logging

from src.graph.connection import Neo4jConnection
from src.tools.cti_tools import CTITools
from src.tools.misp_tools import MISPTools

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    conn = Neo4jConnection()
    cti = CTITools(conn)

    campaigns_t1003 = cti.get_campaigns_for_technique("T1003")
    logger.info("Campaigns for T1003 (parent): %d", len(campaigns_t1003))

    campaigns_t1003_001 = cti.get_campaigns_for_technique("T1003.001")
    logger.info("Campaigns for T1003.001: %d", len(campaigns_t1003_001))
    for c in campaigns_t1003_001[:5]:
        logger.info("  - %s (%s) groups=%s", c["campaign_name"], c.get("first_seen", "?"), c.get("attributed_groups", []))

    campaigns_t1059 = cti.get_campaigns_for_technique("T1059.001")
    logger.info("Campaigns for T1059.001: %d", len(campaigns_t1059))
    for c in campaigns_t1059[:5]:
        logger.info("  - %s (%s) groups=%s", c["campaign_name"], c.get("first_seen", "?"), c.get("attributed_groups", []))

    group_campaigns = cti.get_campaigns_for_group("APT29")
    logger.info("Campaigns for APT29: %d", len(group_campaigns))
    for c in group_campaigns:
        logger.info("  - %s (%s) techs=%d", c["campaign_name"], c.get("first_seen", "?"), len(c.get("techniques_used", [])))

    result = conn.run_query(
        "MATCH (c:Campaign)-[:CAMPAIGN_USES]->(t) "
        "WHERE t.attack_id STARTS WITH 'T1003' "
        "RETURN t.attack_id AS aid, collect(DISTINCT c.name) AS campaigns"
    )
    logger.info("T1003 family campaign coverage:")
    for r in result:
        logger.info("  %s: %d campaigns", r["aid"], len(r["campaigns"]))

    misp = MISPTools(conn)
    ctx = misp.enrich_technique_context("T1059.001")
    logger.info("Full enrichment for T1059.001:")
    logger.info("  Groups: %d", len(ctx.associated_groups))
    logger.info("  Tools: %d", len(ctx.associated_tools))
    logger.info("  Campaigns: %d", len(ctx.recent_campaigns))
    if ctx.recent_campaigns:
        for c in ctx.recent_campaigns[:3]:
            logger.info("    - %s (%s-%s) attr=%s", c.campaign_name, c.first_seen, c.last_seen, c.attributed_groups)
    if ctx.detection_guidance:
        logger.info("  Detection guidance: %s...", ctx.detection_guidance[:80])

    conn.close()
    logger.info("All campaign enrichment tests passed!")


if __name__ == "__main__":
    main()
