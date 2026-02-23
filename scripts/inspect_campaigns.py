"""Inspect campaign data in STIX bundle."""
import stix2
from collections import Counter

store = stix2.MemoryStore()
store.load_from_file("src/data/mitre/enterprise-attack.json")

techs = store.query([stix2.Filter("type", "=", "attack-pattern")])
t1003_ids = []
for t in techs:
    if hasattr(t, "external_references"):
        for ref in t.external_references:
            eid = getattr(ref, "external_id", "")
            if eid.startswith("T1003"):
                t1003_ids.append((eid, t.id))

print("T1003 family STIX IDs:")
for eid, sid in t1003_ids:
    print(f"  {eid}: {sid}")

all_rels = store.query([stix2.Filter("type", "=", "relationship")])
stix_ids = [sid for _, sid in t1003_ids]

print("\nCampaigns using T1003.xxx:")
for r in all_rels:
    if getattr(r, "target_ref", "") in stix_ids and "campaign" in str(getattr(r, "source_ref", "")):
        src = store.get(r.source_ref)
        tgt_eid = next(eid for eid, sid in t1003_ids if sid == r.target_ref)
        name = getattr(src, "name", "?")
        first = getattr(src, "first_seen", "?")
        last = getattr(src, "last_seen", "?")
        print(f"  Campaign '{name}' ({first} - {last}) uses {tgt_eid}")

# Top techniques by campaign usage
tech_counts = Counter()
for r in all_rels:
    sr = str(getattr(r, "source_ref", ""))
    tr = str(getattr(r, "target_ref", ""))
    if "campaign" in sr and "attack-pattern" in tr:
        tech_counts[r.target_ref] += 1

print(f"\nTop 10 techniques by campaign usage:")
for sid, count in tech_counts.most_common(10):
    t = store.get(sid)
    eid = "?"
    name = getattr(t, "name", "?")
    if hasattr(t, "external_references"):
        for ref in t.external_references:
            if hasattr(ref, "external_id"):
                eid = ref.external_id
                break
    print(f"  {eid} - {name}: used in {count} campaigns")

# Coverage: what % of campaigns have technique links
campaigns = store.query([stix2.Filter("type", "=", "campaign")])
campaigns_with_techs = set()
for r in all_rels:
    sr = str(getattr(r, "source_ref", ""))
    tr = str(getattr(r, "target_ref", ""))
    if "campaign" in sr and "attack-pattern" in tr:
        campaigns_with_techs.add(r.source_ref)

print(f"\nCampaigns with technique links: {len(campaigns_with_techs)}/{len(campaigns)}")
print(f"Unique techniques referenced by campaigns: {len(tech_counts)}")
print(f"Total campaign->technique edges: {sum(tech_counts.values())}")
