"""Parameterized Cypher query library for the knowledge graph.

These queries are used by the agent's function tools (Phase 3+).
Defined here as constants to keep Cypher centralized and testable.
"""

# ──────────────────────────────────────────────────────────────
# Query 1: Get Techniques by Tactic
# ──────────────────────────────────────────────────────────────
TECHNIQUES_BY_TACTIC = """
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: $tactic})
WHERE NOT t.is_subtechnique
RETURN t.name AS name, t.attack_id AS attack_id,
       t.description AS description, t.platforms AS platforms
ORDER BY t.attack_id
"""

# ──────────────────────────────────────────────────────────────
# Query 2: Get Sub-techniques for a Technique
# ──────────────────────────────────────────────────────────────
SUBTECHNIQUES_FOR_TECHNIQUE = """
MATCH (st:SubTechnique)-[:PART_OF]->(t:Technique {attack_id: $technique_id})
RETURN st.name AS name, st.attack_id AS attack_id,
       st.description AS description, st.platforms AS platforms
ORDER BY st.attack_id
"""

# ──────────────────────────────────────────────────────────────
# Query 3: Get Intrusion Sets Using a Technique
# ──────────────────────────────────────────────────────────────
INTRUSION_SETS_FOR_TECHNIQUE = """
MATCH (g:IntrusionSet)-[r:USES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
RETURN g.name AS group_name, g.aliases AS aliases,
       r.description AS usage_description
ORDER BY g.name
"""

# ──────────────────────────────────────────────────────────────
# Query 4: Get Tools/Malware for a Technique
# ──────────────────────────────────────────────────────────────
TOOLS_FOR_TECHNIQUE = """
MATCH (s)-[r:USES]->(t {attack_id: $technique_id})
WHERE (s:Tool OR s:Malware) AND (t:Technique OR t:SubTechnique)
RETURN s.name AS name, labels(s)[0] AS type,
       s.description AS description,
       r.description AS usage_description
ORDER BY s.name
"""

# ──────────────────────────────────────────────────────────────
# Query 5: Get Detection Guidance for a Technique
# ──────────────────────────────────────────────────────────────
DETECTION_FOR_TECHNIQUE = """
MATCH (t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
OPTIONAL MATCH (t)-[:DETECTED_BY]->(ds:DataSource)
RETURN t.detection AS detection_text,
       collect(ds.name) AS data_sources
"""

# ──────────────────────────────────────────────────────────────
# Query 6: Get Mitigations for a Technique
# ──────────────────────────────────────────────────────────────
MITIGATIONS_FOR_TECHNIQUE = """
MATCH (m:Mitigation)-[r:MITIGATES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
RETURN m.name AS mitigation_name, m.description AS description,
       r.description AS how_it_mitigates
ORDER BY m.name
"""

# ──────────────────────────────────────────────────────────────
# Query 7: Full Context for a Technique (combined)
# ──────────────────────────────────────────────────────────────
FULL_TECHNIQUE_CONTEXT = """
MATCH (t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
OPTIONAL MATCH (t)-[:PART_OF]->(tac:Tactic)
OPTIONAL MATCH (g:IntrusionSet)-[:USES]->(t)
OPTIONAL MATCH (s)-[:USES]->(t) WHERE s:Tool OR s:Malware
OPTIONAL MATCH (t)-[:DETECTED_BY]->(ds:DataSource)
OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
OPTIONAL MATCH (c:Campaign)-[:CAMPAIGN_USES]->(t)
RETURN t.name AS name, t.attack_id AS attack_id,
       t.description AS description, t.platforms AS platforms,
       collect(DISTINCT tac.shortname) AS tactics,
       collect(DISTINCT g.name) AS groups,
       collect(DISTINCT s.name) AS tools,
       collect(DISTINCT ds.name) AS data_sources,
       collect(DISTINCT m.name) AS mitigations,
       t.detection AS detection_text,
       collect(DISTINCT {name: c.name, first_seen: c.first_seen,
                         last_seen: c.last_seen, external_id: c.external_id}) AS campaigns
"""

# ──────────────────────────────────────────────────────────────
# Query 8: Campaigns for a Technique
# ──────────────────────────────────────────────────────────────
CAMPAIGNS_FOR_TECHNIQUE = """
MATCH (c:Campaign)-[:CAMPAIGN_USES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
RETURN c.name AS campaign_name,
       c.external_id AS external_id,
       c.description AS description,
       c.first_seen AS first_seen,
       c.last_seen AS last_seen,
       collect(DISTINCT g.name) AS attributed_groups
ORDER BY c.first_seen DESC
"""

# ──────────────────────────────────────────────────────────────
# Query 9: Campaigns for an Intrusion Set (APT group)
# ──────────────────────────────────────────────────────────────
CAMPAIGNS_FOR_GROUP = """
MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet {name: $group_name})
OPTIONAL MATCH (c)-[:CAMPAIGN_USES]->(t)
WHERE t:Technique OR t:SubTechnique
RETURN c.name AS campaign_name,
       c.external_id AS external_id,
       c.description AS description,
       c.first_seen AS first_seen,
       c.last_seen AS last_seen,
       collect(DISTINCT t.attack_id) AS techniques_used
ORDER BY c.first_seen DESC
"""

# ──────────────────────────────────────────────────────────────
# Query 10: Random Techniques by Tactic (for sampling)
# ──────────────────────────────────────────────────────────────
RANDOM_TECHNIQUES_BY_TACTIC = """
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: $tactic})
WHERE NOT t.is_subtechnique
WITH t, rand() AS r
ORDER BY r
LIMIT $count
RETURN t.name AS name, t.attack_id AS attack_id,
       t.description AS description, t.platforms AS platforms
"""

# ──────────────────────────────────────────────────────────────
# Query 11: Techniques for Platform
# ──────────────────────────────────────────────────────────────
TECHNIQUES_FOR_PLATFORM = """
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: $tactic})
WHERE $platform IN t.platforms AND NOT t.is_subtechnique
RETURN t.name AS name, t.attack_id AS attack_id,
       t.description AS description
ORDER BY t.attack_id
"""

# ──────────────────────────────────────────────────────────────
# Query 12: Existing Abilities for Category (deduplication)
# ──────────────────────────────────────────────────────────────
ABILITIES_FOR_CATEGORY = """
MATCH (a:Ability {attack_category: $attack_category})
RETURN a.id AS id, a.name AS name,
       a.attack_category AS attack_category,
       a.approval_status AS status
ORDER BY a.name
"""

# ──────────────────────────────────────────────────────────────
# Verification Queries (used by ingestion script)
# ──────────────────────────────────────────────────────────────
COUNT_NODES_BY_LABEL = """
MATCH (n)
RETURN labels(n)[0] AS label, count(n) AS count
ORDER BY count DESC
"""

COUNT_RELATIONSHIPS_BY_TYPE = """
MATCH ()-[r]->()
RETURN type(r) AS type, count(r) AS count
ORDER BY count DESC
"""

SAMPLE_CREDENTIAL_ACCESS = """
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: "credential-access"})
RETURN t.name AS name, t.attack_id AS attack_id
ORDER BY t.attack_id
LIMIT 10
"""
