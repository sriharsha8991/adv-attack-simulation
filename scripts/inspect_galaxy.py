"""Quick inspection of Galaxy data richness."""

import json
import logging
from pathlib import Path

import stix2

from src.config import DEFAULT_STIX_CACHE_PATH, DEFAULT_GALAXY_CACHE_DIR

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    cache = DEFAULT_GALAXY_CACHE_DIR
    logger.info("Cached files: %s", [f.name for f in cache.iterdir()])

    # Attack pattern meta fields
    data = json.loads(Path(cache / "mitre-attack-pattern.json").read_text(encoding="utf-8"))
    for val in data["values"]:
        if "T1003" in val.get("value", "") and "LSASS" in val.get("value", ""):
            meta = val.get("meta", {})
            logger.info("\n=== T1003.001 (LSASS) Attack Pattern ===")
            logger.info("Meta keys: %s", list(meta.keys()))
            for k, v in meta.items():
                if k != "refs":
                    logger.info("  %s: %s", k, v)
            refs = meta.get("refs", [])
            logger.info("  refs count: %d", len(refs))
            if refs:
                logger.info("  refs[0]: %s", refs[0])
            break

    # Check all unique meta keys across intrusion sets
    logger.info("\n=== Intrusion Set Meta Keys Survey ===")
    is_data = json.loads(Path(cache / "mitre-intrusion-set.json").read_text(encoding="utf-8"))
    all_meta_keys: set[str] = set()
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

    logger.info("All unique meta keys: %s", sorted(all_meta_keys))
    logger.info("Groups with country: %d/%d", has_country, len(is_data["values"]))
    logger.info("Groups with CFR data: %d/%d", has_cfr, len(is_data["values"]))
    logger.info("Groups with date fields: %d/%d", has_date, len(is_data["values"]))

    # Show a group that has rich data (CFR fields)
    for val in is_data["values"]:
        meta = val.get("meta", {})
        if meta.get("cfr-suspected-victims"):
            logger.info("\n=== Rich Group: %s ===", val["value"])
            for k, v in meta.items():
                if k != "refs" and k != "synonyms":
                    logger.info("  %s: %s", k, v)
            break

    # Check the STIX bundle for campaigns
    logger.info("\n=== STIX Bundle - Campaigns ===")
    store = stix2.MemoryStore()
    store.load_from_file(str(DEFAULT_STIX_CACHE_PATH))
    campaigns = store.query([stix2.Filter("type", "=", "campaign")])
    logger.info("Campaign objects: %d", len(campaigns))
    if campaigns:
        c = campaigns[0]
        if isinstance(c, dict):
            logger.info("  Sample: %s - %s", c.get("name", "N/A"), c.get("description", "N/A")[:200])
            logger.info("  Keys: %s", list(c.keys()))
        else:
            logger.info("  Sample: %s", c.name)
            logger.info("  Keys: %s", dir(c))

        # Show first 10 campaign names
        logger.info("\nAll campaigns:")
        for c in campaigns[:15]:
            name = c.get("name", c.name) if isinstance(c, dict) else c.name
            first_seen = c.get("first_seen", "?") if isinstance(c, dict) else getattr(c, "first_seen", "?")
            last_seen = c.get("last_seen", "?") if isinstance(c, dict) else getattr(c, "last_seen", "?")
            logger.info("  %s (%s - %s)", name, first_seen, last_seen)
        if len(campaigns) > 15:
            logger.info("  ... and %d more", len(campaigns) - 15)


if __name__ == "__main__":
    main()
