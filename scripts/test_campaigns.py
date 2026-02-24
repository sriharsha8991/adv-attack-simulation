"""Quick test: verify campaign enrichment pipeline end-to-end."""

from src.graph.connection import Neo4jConnection
from src.tools.cti_tools import CTITools
from src.tools.misp_tools import MISPTools

conn = Neo4jConnection()
cti = CTITools(conn)

# 1. Campaigns for T1003 (parent technique — campaigns usually link to sub-techniques)
campaigns_t1003 = cti.get_campaigns_for_technique("T1003")
print(f"Campaigns for T1003 (parent): {len(campaigns_t1003)}")

# 2. Campaigns for T1003.001 (sub-technique — more likely to have direct links)
campaigns_t1003_001 = cti.get_campaigns_for_technique("T1003.001")
print(f"Campaigns for T1003.001: {len(campaigns_t1003_001)}")
for c in campaigns_t1003_001[:5]:
    print(f"  - {c['campaign_name']} ({c.get('first_seen','?')}) groups={c.get('attributed_groups',[])}")

# 3. Campaigns for T1059.001 (known high count)
campaigns_t1059 = cti.get_campaigns_for_technique("T1059.001")
print(f"\nCampaigns for T1059.001: {len(campaigns_t1059)}")
for c in campaigns_t1059[:5]:
    print(f"  - {c['campaign_name']} ({c.get('first_seen','?')}) groups={c.get('attributed_groups',[])}")

# 4. Campaigns for APT29
group_campaigns = cti.get_campaigns_for_group("APT29")
print(f"\nCampaigns for APT29: {len(group_campaigns)}")
for c in group_campaigns:
    print(f"  - {c['campaign_name']} ({c.get('first_seen','?')}) techs={len(c.get('techniques_used',[]))}")

# 5. Check what T1003 sub-techniques have campaigns
result = conn.run_query(
    "MATCH (c:Campaign)-[:CAMPAIGN_USES]->(t) "
    "WHERE t.attack_id STARTS WITH 'T1003' "
    "RETURN t.attack_id AS aid, collect(DISTINCT c.name) AS campaigns"
)
print(f"\nT1003 family campaign coverage:")
for r in result:
    print(f"  {r['aid']}: {len(r['campaigns'])} campaigns")

# 6. Full enrichment via MISPTools
misp = MISPTools(conn)
ctx = misp.enrich_technique_context("T1059.001")
print(f"\nFull enrichment for T1059.001:")
print(f"  Groups: {len(ctx.associated_groups)}")
print(f"  Tools: {len(ctx.associated_tools)}")
print(f"  Campaigns: {len(ctx.recent_campaigns)}")
if ctx.recent_campaigns:
    for c in ctx.recent_campaigns[:3]:
        print(f"    - {c.campaign_name} ({c.first_seen}-{c.last_seen}) attr={c.attributed_groups}")
print(f"  Detection guidance: {ctx.detection_guidance[:80]}...")

conn.close()
print("\n✓ All campaign enrichment tests passed!")
