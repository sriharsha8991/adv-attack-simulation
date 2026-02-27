# Knowledge Graph Schema — Neo4j + MITRE ATT&CK

> Complete specification of the Neo4j graph schema, data loading patterns, and Cypher query library

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Node Types](#2-node-types)
- [3. Relationship Types](#3-relationship-types)
- [4. Visual Schema](#4-visual-schema)
- [5. Indexes & Constraints](#5-indexes--constraints)
- [6. Data Loading Pipeline](#6-data-loading-pipeline)
- [7. Cypher Query Library](#7-cypher-query-library)
- [8. STIX-to-Neo4j Mapping Reference](#8-stix-to-neo4j-mapping-reference)
- [9. Scale & Limits](#9-scale--limits)

---

## 1. Overview

The knowledge graph stores the complete MITRE ATT&CK Enterprise dataset as an interconnected graph in Neo4j. This enables the AI agent to perform structured reasoning about attack techniques through graph traversal rather than flat-file lookup.

**Data Source**: [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) — STIX 2.1 JSON bundle  
**Database**: Neo4j Aura Free (Instance: `89f9ecd3`, Name: `Instance-pentest`)

### Why a Graph?

The MITRE ATT&CK framework is inherently a graph:

| Query | Graph (Cypher) | Flat JSON |
|---|---|---|
| "Techniques APT29 uses for credential access on Windows" | 1 query, 1 traversal | 3 nested loops + 2 joins |
| "All tools that implement T1003 sub-techniques" | 1 query | Parse every tool, scan technique refs |
| "Which groups use both T1003 AND T1059?" | Set intersection via pattern match | Full scan + set operations |
| "Data sources for detecting lateral movement techniques" | 2-hop traversal | Multiple index lookups |

---

## 2. Node Types

### Infrastructure (from STIX 2.1)

| Label | Properties | STIX Source Type | Count (v18.1) |
|---|---|---|---|
| `:Tactic` | `name`, `shortname`, `stix_id`, `external_id`, `description` | `x-mitre-tactic` | 14 |
| `:Technique` | `name`, `attack_id`, `stix_id`, `description`, `platforms[]`, `detection`, `is_subtechnique=false` | `attack-pattern` | 216 |
| `:SubTechnique` | `name`, `attack_id`, `stix_id`, `description`, `platforms[]`, `detection`, `is_subtechnique=true` | `attack-pattern` | 475 |
| `:IntrusionSet` | `name`, `stix_id`, `aliases[]`, `description` | `intrusion-set` | ~150 |
| `:Tool` | `name`, `stix_id`, `description`, `platforms[]` | `tool` | ~100 |
| `:Malware` | `name`, `stix_id`, `description`, `platforms[]` | `malware` | ~600 |
| `:DataSource` | `name`, `stix_id`, `description` | `x-mitre-data-source` | ~40 |
| `:Mitigation` | `name`, `stix_id`, `description` | `course-of-action` | ~45 |
| `:Campaign` | `name`, `stix_id`, `external_id`, `description`, `first_seen`, `last_seen` | `campaign` | ~52 |

### Generated (by Agent)

| Label | Properties | Source | Lifecycle |
|---|---|---|---|
| `:Ability` | `id`, `name`, `attack_category`, `approval_status`, `simulation_only`, `created_by`, `generated_at` | Agent output | Created per generation |
| `:Executor` | `name`, `platform`, `privilege_required`, `command_hash` | Agent output | Linked to Ability |

### Property Detail

#### `:Tactic`
```
{
  name: "Credential Access",
  shortname: "credential-access",    // Used for queries
  stix_id: "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
  external_id: "TA0006",
  description: "The adversary is trying to steal account names and passwords..."
}
```

#### `:Technique`
```
{
  name: "OS Credential Dumping",
  attack_id: "T1003",               // Primary lookup key
  stix_id: "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6b4f739468e",
  description: "Adversaries may attempt to dump credentials...",
  platforms: ["Windows", "Linux", "macOS"],
  detection: "Monitor for unexpected processes interacting with LSASS...",
  is_subtechnique: false
}
```

#### `:SubTechnique`
```
{
  name: "LSASS Memory",
  attack_id: "T1003.001",
  stix_id: "attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90",
  description: "Adversaries may attempt to access credential material stored in LSASS...",
  platforms: ["Windows"],
  detection: "Monitor for access to LSASS...",
  is_subtechnique: true
}
```

#### `:IntrusionSet`
```
{
  name: "APT29",
  stix_id: "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
  aliases: ["The Dukes", "Cozy Bear", "NOBELIUM", "Midnight Blizzard"],
  description: "APT29 is threat group that has been attributed to Russia's SVR..."
}
```

#### `:Campaign`
```
{
  name: "SolarWinds Compromise",
  stix_id: "campaign--808d6b30-df4e-4341-8571-726b1c90f443",
  external_id: "C0024",
  description: "The SolarWinds Compromise was a sophisticated supply chain...",
  first_seen: "2019-08",
  last_seen: "2021-01"
}
```

---

## 3. Relationship Types

### Core Relationships

| Relationship | From → To | STIX Source | Meaning |
|---|---|---|---|
| `[:PART_OF]` | Technique → Tactic | `kill_chain_phases` field | Technique belongs to tactic |
| `[:PART_OF]` | SubTechnique → Technique | `relationship_type: subtechnique-of` | Sub-technique parent |
| `[:USES]` | IntrusionSet → Technique | `relationship_type: uses` | APT group uses technique |
| `[:USES]` | IntrusionSet → Tool | `relationship_type: uses` | APT group uses tool |
| `[:USES]` | IntrusionSet → Malware | `relationship_type: uses` | APT group uses malware |
| `[:USES]` | Tool → Technique | `relationship_type: uses` | Tool implements technique |
| `[:USES]` | Malware → Technique | `relationship_type: uses` | Malware implements technique |
| `[:CAMPAIGN_USES]` | Campaign → Technique/Tool/Malware | `relationship_type: uses` (source_ref=campaign--) | Campaign employs technique/software |
| `[:ATTRIBUTED_TO]` | Campaign → IntrusionSet | `relationship_type: attributed-to` | Campaign attributed to threat group |

### Supplementary Relationships

| Relationship | From → To | STIX Source | Meaning |
|---|---|---|---|
| `[:DETECTED_BY]` | Technique → DataSource | `relationship_type: detects` (reversed) | Detection data source |
| `[:MITIGATES]` | Mitigation → Technique | `relationship_type: mitigates` | Mitigation applies to technique |
| `[:TARGETS]` | Technique → Platform | Derived from `platforms[]` | OS targeting |

### Generated Relationships (by Agent)

| Relationship | From → To | Meaning |
|---|---|---|
| `[:IMPLEMENTS]` | Ability → Technique | Ability simulates this technique |
| `[:EXECUTES]` | Executor → Ability | Executor belongs to ability |

### Relationship Properties

Some relationships carry properties from the STIX `relationship` object:

```
(g:IntrusionSet)-[:USES {description: "APT29 has used Mimikatz to harvest credentials...", stix_id: "relationship--xxx"}]->(t:Technique)
```

---

## 4. Visual Schema

```
                                (:Tactic)
                              /     |     \
                 [:PART_OF]  /      |      \  [:PART_OF]
                            /       |       \
                 (:Technique)  (:Technique)  (:Technique)
                    / | \          |              |
     [:PART_OF]   /  |  \         |              | [:USES]
                 /   |   \        |              |
   (:SubTechnique)   |   (:SubTechnique)    (:IntrusionSet)
                     |                      /    |    \
          [:USES]    |        [:USES]      /     |     \  [:USES]
                     |                    /      |      \
              (:Tool/Malware) ◄──────────     (:Tool)  (:Malware)

   (:Mitigation) ──[:MITIGATES]──► (:Technique)
   (:Technique) ──[:DETECTED_BY]──► (:DataSource)

   (:Campaign) ──[:CAMPAIGN_USES]──► (:Technique/Tool/Malware)
   (:Campaign) ──[:ATTRIBUTED_TO]──► (:IntrusionSet)

   --- Agent-generated ---
   (:Ability) ──[:IMPLEMENTS]──► (:Technique)
   (:Executor) ──[:EXECUTES]──► (:Ability)
```

### Cardinality

| Relationship | Cardinality | Notes |
|---|---|---|
| Technique → Tactic | Many-to-Many | A technique can appear in multiple tactics |
| SubTechnique → Technique | Many-to-One | Each sub-technique has one parent |
| IntrusionSet → Technique | Many-to-Many | Groups use multiple techniques, techniques used by multiple groups |
| Tool → Technique | Many-to-Many | Tools implement techniques, techniques have multiple tools |
| Campaign → Technique | Many-to-Many | Campaigns employ multiple techniques |
| Campaign → IntrusionSet | Many-to-One | Campaign attributed to a threat group |
| Ability → Technique | Many-to-One | Each ability implements one technique (atomic) |

---

## 5. Indexes & Constraints

### Required Indexes (Performance-Critical)

```cypher
// Primary lookup indexes
CREATE INDEX idx_tactic_shortname FOR (tac:Tactic) ON (tac.shortname);
CREATE INDEX idx_technique_attack_id FOR (t:Technique) ON (t.attack_id);
CREATE INDEX idx_subtechnique_attack_id FOR (s:SubTechnique) ON (s.attack_id);

// STIX ID indexes (for relationship loading)
CREATE INDEX idx_tactic_stix FOR (tac:Tactic) ON (tac.stix_id);
CREATE INDEX idx_technique_stix FOR (t:Technique) ON (t.stix_id);
CREATE INDEX idx_subtechnique_stix FOR (s:SubTechnique) ON (s.stix_id);
CREATE INDEX idx_intrusion_stix FOR (g:IntrusionSet) ON (g.stix_id);
CREATE INDEX idx_tool_stix FOR (t:Tool) ON (t.stix_id);
CREATE INDEX idx_malware_stix FOR (m:Malware) ON (m.stix_id);
CREATE INDEX idx_datasource_stix FOR (d:DataSource) ON (d.stix_id);
CREATE INDEX idx_mitigation_stix FOR (mt:Mitigation) ON (mt.stix_id);

// Campaign indexes
CREATE INDEX idx_campaign_stix FOR (c:Campaign) ON (c.stix_id);
CREATE INDEX idx_campaign_name FOR (c:Campaign) ON (c.name);
CREATE INDEX idx_campaign_external_id FOR (c:Campaign) ON (c.external_id);

// Name indexes (for search)
CREATE INDEX idx_intrusion_name FOR (g:IntrusionSet) ON (g.name);
CREATE INDEX idx_tool_name FOR (t:Tool) ON (t.name);
CREATE INDEX idx_malware_name FOR (m:Malware) ON (m.name);

// Generated ability indexes
CREATE INDEX idx_ability_id FOR (a:Ability) ON (a.id);
CREATE INDEX idx_ability_category FOR (a:Ability) ON (a.attack_category);
```

### Uniqueness Constraints

```cypher
CREATE CONSTRAINT uniq_technique_stix FOR (t:Technique) REQUIRE t.stix_id IS UNIQUE;
CREATE CONSTRAINT uniq_subtechnique_stix FOR (s:SubTechnique) REQUIRE s.stix_id IS UNIQUE;
CREATE CONSTRAINT uniq_tactic_stix FOR (tac:Tactic) REQUIRE tac.stix_id IS UNIQUE;
CREATE CONSTRAINT uniq_intrusion_stix FOR (g:IntrusionSet) REQUIRE g.stix_id IS UNIQUE;
CREATE CONSTRAINT uniq_ability_id FOR (a:Ability) REQUIRE a.id IS UNIQUE;
CREATE CONSTRAINT uniq_campaign_stix FOR (c:Campaign) REQUIRE c.stix_id IS UNIQUE;
```

---

## 6. Data Loading Pipeline

### Overview

```
┌──────────────────────┐
│  enterprise-attack    │
│  .json (STIX 2.1)    │  50 MB, ~14,000 objects
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  stix2 MemoryStore   │  Parse + filter revoked/deprecated
│  + Filter            │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Transform to dicts  │  STIX object → Neo4j property dict
│  per node type       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Neo4j UNWIND MERGE  │  Batch load per node type
│  (parameterized)     │  Then batch load relationships
└──────────────────────┘
```

### Loading Order (Dependencies)

```
1. Create indexes + constraints
2. Load Tactics          (0 dependencies)
3. Load Techniques       (0 dependencies)
4. Load SubTechniques    (0 dependencies)
5. Load IntrusionSets    (0 dependencies)
6. Load Tools            (0 dependencies)
7. Load Malware          (0 dependencies)
8. Load DataSources      (0 dependencies)
9. Load Mitigations      (0 dependencies)
10. Load Campaigns        (0 dependencies)
-- All nodes loaded, now relationships --
11. Link Technique → Tactic      (via kill_chain_phases)
12. Link SubTechnique → Technique (via STIX relationship)
13. Link IntrusionSet → Technique (via STIX relationship)
14. Link IntrusionSet → Tool      (via STIX relationship)
15. Link IntrusionSet → Malware   (via STIX relationship)
16. Link Tool → Technique         (via STIX relationship)
17. Link Malware → Technique      (via STIX relationship)
18. Link Mitigation → Technique   (via STIX relationship)
19. Link Technique → DataSource   (via STIX relationship)
20. Link Campaign → Technique/Tool/Malware (CAMPAIGN_USES, via STIX relationship)
21. Link Campaign → IntrusionSet  (ATTRIBUTED_TO, via STIX relationship)
```

### Batch Load Pattern

```python
# Transform STIX technique to dict
def transform_technique(stix_obj):
    return {
        "stix_id": stix_obj.id,
        "name": stix_obj.name,
        "attack_id": get_attack_id(stix_obj),  # from external_references
        "description": stix_obj.description or "",
        "platforms": getattr(stix_obj, 'x_mitre_platforms', []),
        "detection": getattr(stix_obj, 'x_mitre_detection', ""),
        "is_subtechnique": getattr(stix_obj, 'x_mitre_is_subtechnique', False),
    }

# Batch load into Neo4j
LOAD_TECHNIQUES_CYPHER = """
UNWIND $items AS item
MERGE (t:Technique {stix_id: item.stix_id})
SET t.name = item.name,
    t.attack_id = item.attack_id,
    t.description = item.description,
    t.platforms = item.platforms,
    t.detection = item.detection,
    t.is_subtechnique = item.is_subtechnique
"""

# Execute
driver.execute_query(LOAD_TECHNIQUES_CYPHER, items=technique_dicts)
```

### Relationship Load Pattern

STIX `relationship` objects define edges:
```json
{
  "type": "relationship",
  "relationship_type": "uses",
  "source_ref": "intrusion-set--899ce53f-...",  // APT29
  "target_ref": "attack-pattern--0a3ead4e-...", // T1003
  "description": "APT29 has used credential dumping..."
}
```

Cypher:
```cypher
UNWIND $rels AS rel
MATCH (src {stix_id: rel.source_ref})
MATCH (tgt {stix_id: rel.target_ref})
MERGE (src)-[r:USES]->(tgt)
SET r.description = rel.description,
    r.stix_id = rel.stix_id
```

### Tactic Linking (Special Case)

Tactics are linked to techniques via the `kill_chain_phases` field (not STIX relationships):

```python
# Extract from technique STIX object
kill_chain = technique.get("kill_chain_phases", [])
for phase in kill_chain:
    if phase["kill_chain_name"] == "mitre-attack":
        tactic_shortname = phase["phase_name"]
        # Link: (Technique)-[:PART_OF]->(Tactic {shortname: tactic_shortname})
```

Cypher:
```cypher
UNWIND $links AS link
MATCH (t:Technique {stix_id: link.technique_stix_id})
MATCH (tac:Tactic {shortname: link.tactic_shortname})
MERGE (t)-[:PART_OF]->(tac)
```

---

## 7. Cypher Query Library

These are the parameterized queries used by the agent's function tools.

### Query 1: Get Techniques by Tactic

```cypher
// Used by: graph_tools.query_techniques_by_tactic(tactic)
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: $tactic})
WHERE NOT t.is_subtechnique
RETURN t.name AS name, t.attack_id AS attack_id,
       t.description AS description, t.platforms AS platforms
ORDER BY t.attack_id
```

### Query 2: Get Sub-techniques for a Technique

```cypher
// Used by: graph_tools.find_subtechniques(technique_id)
MATCH (st:SubTechnique)-[:PART_OF]->(t:Technique {attack_id: $technique_id})
RETURN st.name AS name, st.attack_id AS attack_id,
       st.description AS description, st.platforms AS platforms
ORDER BY st.attack_id
```

### Query 3: Get Intrusion Sets Using a Technique

```cypher
// Used by: cti_tools.get_intrusion_sets_for_technique(technique_id)
MATCH (g:IntrusionSet)-[r:USES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
RETURN g.name AS group_name, g.aliases AS aliases,
       r.description AS usage_description
ORDER BY g.name
```

### Query 4: Get Tools/Malware for a Technique

```cypher
// Used by: cti_tools.get_tools_for_technique(technique_id)
MATCH (s)-[r:USES]->(t {attack_id: $technique_id})
WHERE (s:Tool OR s:Malware) AND (t:Technique OR t:SubTechnique)
RETURN s.name AS name, labels(s)[0] AS type,
       s.description AS description,
       r.description AS usage_description
ORDER BY s.name
```

### Query 5: Get Detection Guidance for a Technique

```cypher
// Used by: cti_tools.get_detection_guidance(technique_id)
MATCH (t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
OPTIONAL MATCH (t)-[:DETECTED_BY]->(ds:DataSource)
RETURN t.detection AS detection_text,
       collect(ds.name) AS data_sources
```

### Query 6: Get Mitigations for a Technique

```cypher
// Used by: cti_tools.get_mitigations(technique_id)
MATCH (m:Mitigation)-[r:MITIGATES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
RETURN m.name AS mitigation_name, m.description AS description,
       r.description AS how_it_mitigates
ORDER BY m.name
```

### Query 7: Full Technique Context (Composite)

```cypher
// Used by: graph_tools.get_technique_details(technique_id)
// Returns everything the agent needs to compose an ability
MATCH (t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique

OPTIONAL MATCH (t)-[:PART_OF]->(parent)
OPTIONAL MATCH (g:IntrusionSet)-[:USES]->(t)
OPTIONAL MATCH (s)-[:USES]->(t) WHERE s:Tool OR s:Malware
OPTIONAL MATCH (t)-[:DETECTED_BY]->(ds:DataSource)
OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
OPTIONAL MATCH (c:Campaign)-[:CAMPAIGN_USES]->(t)

RETURN t.name AS name,
       t.attack_id AS attack_id,
       t.description AS description,
       t.platforms AS platforms,
       t.detection AS detection,
       parent.name AS parent_name,
       parent.attack_id AS parent_id,
       collect(DISTINCT g.name) AS groups,
       collect(DISTINCT s.name) AS tools,
       collect(DISTINCT ds.name) AS data_sources,
       collect(DISTINCT m.name) AS mitigations,
       collect(DISTINCT {name: c.name, first_seen: c.first_seen, last_seen: c.last_seen}) AS campaigns
```

### Query 8: Campaigns for a Technique

```cypher
// Used by: cti_tools.get_campaigns_for_technique(technique_id)
MATCH (c:Campaign)-[r:CAMPAIGN_USES]->(t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
RETURN c.name AS campaign_name,
       c.external_id AS campaign_id,
       c.first_seen AS first_seen,
       c.last_seen AS last_seen,
       c.description AS description,
       collect(DISTINCT g.name) AS attributed_groups
ORDER BY c.first_seen DESC
```

### Query 9: Campaigns for a Group

```cypher
// Used by: cti_tools.get_campaigns_for_group(group_name)
MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
WHERE toLower(g.name) = toLower($group_name)
   OR any(alias IN g.aliases WHERE toLower(alias) = toLower($group_name))
OPTIONAL MATCH (c)-[:CAMPAIGN_USES]->(t)
WHERE t:Technique OR t:SubTechnique
RETURN c.name AS campaign_name,
       c.external_id AS campaign_id,
       c.first_seen AS first_seen,
       c.last_seen AS last_seen,
       collect(DISTINCT t.attack_id) AS techniques_used
ORDER BY c.first_seen DESC
```

### Query 10: Validate Technique Exists

```cypher
// Used by: validation_tools.validate_technique_exists(technique_id)
MATCH (t {attack_id: $technique_id})
WHERE t:Technique OR t:SubTechnique
RETURN count(t) > 0 AS exists
```

### Query 11: All Tactics with Technique Counts

```cypher
// Used by: graph_tools.get_all_tactics()
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic)
RETURN tac.name AS tactic_name, tac.shortname AS tactic_shortname,
       tac.external_id AS tactic_id, count(t) AS technique_count
ORDER BY tac.external_id
```

### Query 12: Find Abilities by Technique (Provenance)

```cypher
// Used by: graph_tools.get_abilities_for_technique(technique_id)
MATCH (a:Ability)-[:IMPLEMENTS]->(t {attack_id: $technique_id})
RETURN a.id AS ability_id, a.name AS ability_name,
       a.attack_category AS attack_category, a.generated_at AS generated_at
ORDER BY a.generated_at DESC
```

### Query 13: Platform-Filtered Techniques by Tactic

```cypher
// Used by: graph_tools.query_techniques_by_tactic_and_platform(tactic, platform)
MATCH (t:Technique)-[:PART_OF]->(tac:Tactic {shortname: $tactic})
WHERE $platform IN t.platforms AND NOT t.is_subtechnique
RETURN t.name, t.attack_id, t.description, t.platforms
ORDER BY t.attack_id
```

### Query 14: Groups That Use Both Technique A and B

```cypher
// For finding overlap in group TTPs
MATCH (g:IntrusionSet)-[:USES]->(t1 {attack_id: $technique_a}),
      (g)-[:USES]->(t2 {attack_id: $technique_b})
RETURN g.name, g.aliases
```

---

## 8. STIX-to-Neo4j Mapping Reference

### Object Type Filtering

```python
from stix2 import Filter

FILTERS = {
    "tactics": [Filter('type', '=', 'x-mitre-tactic')],
    "techniques": [
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_is_subtechnique', '=', False)
    ],
    "subtechniques": [
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_is_subtechnique', '=', True)
    ],
    "intrusion_sets": [Filter('type', '=', 'intrusion-set')],
    "tools": [Filter('type', '=', 'tool')],
    "malware": [Filter('type', '=', 'malware')],
    "data_sources": [Filter('type', '=', 'x-mitre-data-source')],
    "mitigations": [Filter('type', '=', 'course-of-action')],
    "campaigns": [Filter('type', '=', 'campaign')],
    "relationships": [Filter('type', '=', 'relationship')],
}
```

### Excluding Revoked & Deprecated Objects

```python
def remove_revoked_deprecated(stix_objects):
    return [
        obj for obj in stix_objects
        if not getattr(obj, 'revoked', False)
        and not getattr(obj, 'x_mitre_deprecated', False)
    ]
```

### Extracting ATT&CK ID from STIX

```python
def get_attack_id(stix_obj):
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"]
    return None
```

---

## 9. Scale & Limits

### Current Data Volume (ATT&CK v18.1)

| Entity | Count |
|---|---|
| Tactic nodes | 14 |
| Technique nodes | 216 |
| SubTechnique nodes | 475 |
| IntrusionSet nodes | ~150 |
| Tool nodes | ~100 |
| Malware nodes | ~600 |
| DataSource nodes | ~40 |
| Mitigation nodes | ~45 |
| Campaign nodes | ~52 |
| **Total nodes** | **~1,757** |
| **Total relationships** | **~21,814** |

### Neo4j Aura Free Limits

| Limit | Maximum | Our Usage | Headroom |
|---|---|---|---|
| Nodes | 200,000 | ~1,757 | 99.1% free |
| Relationships | 400,000 | ~21,814 | 94.5% free |
| Storage | 1 GB | ~50 MB | Ample |

Generated abilities add ~1 node + ~1 relationship each. At 1,000 generated abilities, we'd still use <1.5% of capacity.
