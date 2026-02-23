"""Quick inspection of Galaxy data richness."""
import json
from pathlib import Path

cache = Path("src/data/misp_galaxies")
print("Cached files:", [f.name for f in cache.iterdir()])

# Attack pattern meta fields
data = json.loads(Path(cache / "mitre-attack-pattern.json").read_text(encoding="utf-8"))
for val in data["values"]:
    if "T1003" in val.get("value", "") and "LSASS" in val.get("value", ""):
        meta = val.get("meta", {})
        print("\n=== T1003.001 (LSASS) Attack Pattern ===")
        print("Meta keys:", list(meta.keys()))
        for k, v in meta.items():
            if k != "refs":
                print(f"  {k}: {v}")
        refs = meta.get("refs", [])
        print(f"  refs count: {len(refs)}")
        if refs:
            print(f"  refs[0]: {refs[0]}")
        break

# Check all unique meta keys across intrusion sets
print("\n=== Intrusion Set Meta Keys Survey ===")
is_data = json.loads(Path(cache / "mitre-intrusion-set.json").read_text(encoding="utf-8"))
all_meta_keys = set()
has_country = 0
has_cfr = 0
has_date = 0
for val in is_data["values"]:
    meta = val.get("meta", {})
    all_meta_keys.update(meta.keys())
    if meta.get("country"):
        has_country += 1
    if any("cfr" in k for k in meta):
        has_cfr += 1
    if any("date" in k.lower() for k in meta):
        has_date += 1

print(f"All unique meta keys: {sorted(all_meta_keys)}")
print(f"Groups with country: {has_country}/{len(is_data['values'])}")
print(f"Groups with CFR data: {has_cfr}/{len(is_data['values'])}")
print(f"Groups with date fields: {has_date}/{len(is_data['values'])}")

# Show a group that has rich data (CFR fields)
for val in is_data["values"]:
    meta = val.get("meta", {})
    if meta.get("cfr-suspected-victims"):
        print(f"\n=== Rich Group: {val['value']} ===")
        for k, v in meta.items():
            if k != "refs" and k != "synonyms":
                print(f"  {k}: {v}")
        break

# Check the STIX bundle for campaigns
print("\n=== STIX Bundle - Campaigns ===")
import stix2
store = stix2.MemoryStore()
store.load_from_file("src/data/mitre/enterprise-attack.json")
campaigns = store.query([stix2.Filter("type", "=", "campaign")])
print(f"Campaign objects: {len(campaigns)}")
if campaigns:
    c = campaigns[0]
    if isinstance(c, dict):
        print(f"  Sample: {c.get('name', 'N/A')} - {c.get('description', 'N/A')[:200]}")
        print(f"  Keys: {list(c.keys())}")
    else:
        print(f"  Sample: {c.name}")
        print(f"  Keys: {dir(c)}")

    # Show first 10 campaign names
    print("\nAll campaigns:")
    for c in campaigns[:15]:
        name = c.get("name", c.name) if isinstance(c, dict) else c.name
        first_seen = c.get("first_seen", "?") if isinstance(c, dict) else getattr(c, "first_seen", "?")
        last_seen = c.get("last_seen", "?") if isinstance(c, dict) else getattr(c, "last_seen", "?")
        print(f"  {name} ({first_seen} - {last_seen})")
    if len(campaigns) > 15:
        print(f"  ... and {len(campaigns) - 15} more")
