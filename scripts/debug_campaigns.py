"""Debug: check campaign→group attributions and technique links."""

from src.graph.connection import Neo4jConnection

conn = Neo4jConnection()

# All attributions
r = conn.run_query(
    "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet) "
    "RETURN c.name AS campaign, g.name AS group LIMIT 30"
)
print(f"All attributions ({len(r)}):")
for row in r:
    print(f"  {row['campaign']} → {row['group']}")

# APT29 campaign techniques
r2 = conn.run_query(
    "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet {name: 'APT29'}) "
    "OPTIONAL MATCH (c)-[:CAMPAIGN_USES]->(t) WHERE t:Technique OR t:SubTechnique "
    "RETURN c.name AS campaign, collect(t.attack_id) AS techs"
)
print(f"\nAPT29 campaign techniques:")
for row in r2:
    print(f"  {row['campaign']}: {len(row['techs'])} techniques - {row['techs'][:5]}")

conn.close()
