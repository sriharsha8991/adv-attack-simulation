"""MITRE ATT&CK STIX 2.1 parser — Layer 1 Knowledge Ingestion.

Downloads enterprise-attack.json from GitHub, parses via stix2.MemoryStore,
filters revoked/deprecated objects, and transforms STIX objects into
Neo4j-compatible dicts for batch loading.

Usage:
    from src.layers.layer1_ingestion import (
        download_stix_bundle, load_stix_store,
        parse_tactics, parse_techniques, parse_subtechniques,
        parse_intrusion_sets, parse_tools, parse_malware,
        parse_data_sources, parse_mitigations,
        parse_relationships, parse_tactic_technique_links,
    )
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from stix2 import MemoryStore, Filter
from urllib3.util.retry import Retry

from src.config import (
    DEFAULT_STIX_CACHE_PATH,
    DOWNLOAD_CHUNK_SIZE,
    STIX_DOWNLOAD_TIMEOUT,
    STIX_FILTERS,
    STIX_GITHUB_URL,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Download & Load
# ──────────────────────────────────────────────────────────────


def download_stix_bundle(
    url: str = STIX_GITHUB_URL,
    cache_path: Path = DEFAULT_STIX_CACHE_PATH,
    force: bool = False,
) -> Path:
    """Download the enterprise-attack STIX bundle and cache locally.

    Args:
        url: GitHub raw URL for enterprise-attack.json.
        cache_path: Local file path to save the bundle.
        force: Re-download even if cached file exists.

    Returns:
        Path to the local cached file.
    """
    if cache_path.exists() and not force:
        size_mb = cache_path.stat().st_size / (1024 * 1024)
        logger.info("Using cached STIX bundle: %s (%.1f MB)", cache_path, size_mb)
        return cache_path

    logger.info("Downloading STIX bundle from %s ...", url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Retry transient failures (429, 500, 502, 503, 504) with backoff
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1.0, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))

    response = session.get(url, timeout=STIX_DOWNLOAD_TIMEOUT, stream=True)
    response.raise_for_status()

    total_bytes = 0
    with open(cache_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
            f.write(chunk)
            total_bytes += len(chunk)

    size_mb = total_bytes / (1024 * 1024)
    logger.info("Downloaded %.1f MB → %s", size_mb, cache_path)
    return cache_path


def load_stix_store(path: Path) -> MemoryStore:
    """Load a STIX JSON bundle file into a MemoryStore.

    Args:
        path: Path to enterprise-attack.json.

    Returns:
        stix2.MemoryStore populated with all STIX objects.
    """
    logger.info("Loading STIX bundle from %s ...", path)
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    src = MemoryStore(stix_data=objects, allow_custom=True)

    logger.info("Loaded %d STIX objects into MemoryStore.", len(objects))
    return src


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Universal accessor — works on both dicts and stix2 objects."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _remove_revoked_deprecated(stix_objects: list) -> list:
    """Filter out revoked and deprecated STIX objects."""
    return [
        obj
        for obj in stix_objects
        if not _get(obj, "revoked", False)
        and not _get(obj, "x_mitre_deprecated", False)
    ]


def _get_attack_id(stix_obj: Any) -> str | None:
    """Extract the ATT&CK ID (e.g. T1003) from external_references."""
    for ref in _get(stix_obj, "external_references", []):
        source = _get(ref, "source_name", "")
        ext_id = _get(ref, "external_id", "")
        if source == "mitre-attack" and ext_id:
            return ext_id
    return None


def _safe_str(obj: Any, attr: str, default: str = "") -> str:
    """Safely get a string attribute, returning default if missing/None."""
    val = _get(obj, attr, default)
    return val if val is not None else default


def _safe_list(obj: Any, attr: str) -> list:
    """Safely get a list attribute, returning [] if missing/None."""
    val = _get(obj, attr, [])
    return list(val) if val is not None else []


# ──────────────────────────────────────────────────────────────
# Node Parsers
# ──────────────────────────────────────────────────────────────


def parse_tactics(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Tactics from the STIX store.

    Returns list of dicts with keys:
        name, shortname, stix_id, external_id, description
    """
    raw = src.query(STIX_FILTERS["tactics"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        attack_id = _get_attack_id(obj)
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "shortname": _get(obj, "x_mitre_shortname", ""),
                "external_id": attack_id or "",
                "description": _safe_str(obj, "description"),
            }
        )
    logger.info("Parsed %d tactics.", len(results))
    return results


def parse_techniques(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Techniques (not sub-techniques).

    Returns list of dicts with keys:
        name, attack_id, stix_id, description, platforms, detection, is_subtechnique
    """
    raw = src.query(STIX_FILTERS["techniques"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "attack_id": _get_attack_id(obj) or "",
                "description": _safe_str(obj, "description"),
                "platforms": _safe_list(obj, "x_mitre_platforms"),
                "detection": _safe_str(obj, "x_mitre_detection"),
                "is_subtechnique": False,
            }
        )
    logger.info("Parsed %d techniques.", len(results))
    return results


def parse_subtechniques(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Sub-techniques.

    Returns list of dicts with same keys as techniques, is_subtechnique=True.
    """
    raw = src.query(STIX_FILTERS["subtechniques"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "attack_id": _get_attack_id(obj) or "",
                "description": _safe_str(obj, "description"),
                "platforms": _safe_list(obj, "x_mitre_platforms"),
                "detection": _safe_str(obj, "x_mitre_detection"),
                "is_subtechnique": True,
            }
        )
    logger.info("Parsed %d sub-techniques.", len(results))
    return results


def parse_intrusion_sets(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Intrusion Sets (APT groups).

    Returns list of dicts with keys:
        name, stix_id, aliases, description
    """
    raw = src.query(STIX_FILTERS["intrusion_sets"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "aliases": _safe_list(obj, "aliases"),
                "description": _safe_str(obj, "description"),
            }
        )
    logger.info("Parsed %d intrusion sets.", len(results))
    return results


def parse_tools(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Tools.

    Returns list of dicts with keys:
        name, stix_id, description, platforms
    """
    raw = src.query(STIX_FILTERS["tools"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "description": _safe_str(obj, "description"),
                "platforms": _safe_list(obj, "x_mitre_platforms"),
            }
        )
    logger.info("Parsed %d tools.", len(results))
    return results


def parse_malware(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Malware.

    Returns list of dicts with keys:
        name, stix_id, description, platforms
    """
    raw = src.query(STIX_FILTERS["malware"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "description": _safe_str(obj, "description"),
                "platforms": _safe_list(obj, "x_mitre_platforms"),
            }
        )
    logger.info("Parsed %d malware.", len(results))
    return results


def parse_data_sources(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Data Sources.

    Returns list of dicts with keys:
        name, stix_id, description
    """
    raw = src.query(STIX_FILTERS["data_sources"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "description": _safe_str(obj, "description"),
            }
        )
    logger.info("Parsed %d data sources.", len(results))
    return results


def parse_mitigations(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Mitigations (course-of-action).

    Returns list of dicts with keys:
        name, stix_id, description
    """
    raw = src.query(STIX_FILTERS["mitigations"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "description": _safe_str(obj, "description"),
            }
        )
    logger.info("Parsed %d mitigations.", len(results))
    return results


def parse_campaigns(src: MemoryStore) -> list[dict[str, Any]]:
    """Parse all non-revoked Campaigns.

    STIX campaign objects contain real-world operation names, date ranges,
    and descriptions that provide temporal context for technique usage.

    Returns list of dicts with keys:
        name, stix_id, external_id, description, first_seen, last_seen
    """
    raw = src.query(STIX_FILTERS["campaigns"])
    filtered = _remove_revoked_deprecated(raw)
    results = []
    for obj in filtered:
        first_seen = _get(obj, "first_seen")
        last_seen = _get(obj, "last_seen")
        results.append(
            {
                "stix_id": _get(obj, "id"),
                "name": _get(obj, "name"),
                "external_id": _get_attack_id(obj) or "",
                "description": _safe_str(obj, "description"),
                "first_seen": str(first_seen) if first_seen else "",
                "last_seen": str(last_seen) if last_seen else "",
            }
        )
    logger.info("Parsed %d campaigns.", len(results))
    return results


# ──────────────────────────────────────────────────────────────
# Relationship Parsers
# ──────────────────────────────────────────────────────────────


def parse_relationships(src: MemoryStore) -> dict[str, list[dict[str, Any]]]:
    """Parse all non-revoked STIX relationships, grouped by relationship_type.

    Returns dict keyed by relationship_type (e.g. 'uses', 'mitigates', 'detects',
    'subtechnique-of'), each containing a list of dicts:
        stix_id, source_ref, target_ref, relationship_type, description
    """
    raw = src.query(STIX_FILTERS["relationships"])
    filtered = _remove_revoked_deprecated(raw)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for obj in filtered:
        rel_type = _get(obj, "relationship_type")
        entry = {
            "stix_id": _get(obj, "id"),
            "source_ref": _get(obj, "source_ref"),
            "target_ref": _get(obj, "target_ref"),
            "relationship_type": rel_type,
            "description": _safe_str(obj, "description"),
        }
        grouped.setdefault(rel_type, []).append(entry)

    for rel_type, rels in grouped.items():
        logger.info("Parsed %d '%s' relationships.", len(rels), rel_type)
    return grouped


def parse_tactic_technique_links(
    src: MemoryStore,
    tactics: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Build Technique→Tactic PART_OF links from kill_chain_phases.

    This is a SPECIAL CASE — tactic-technique linking uses the kill_chain_phases
    field on attack-pattern objects, NOT STIX relationship objects.

    Args:
        src: MemoryStore with loaded STIX data.
        tactics: List of parsed tactic dicts (need shortname→stix_id lookup).

    Returns:
        List of dicts with keys: technique_stix_id, tactic_shortname
    """
    # Build shortname → tactic lookup
    tactic_lookup = {t["shortname"]: t["stix_id"] for t in tactics}

    # Get ALL attack-patterns (techniques + sub-techniques)
    all_patterns = src.query([Filter("type", "=", "attack-pattern")])
    all_patterns = _remove_revoked_deprecated(all_patterns)

    links = []
    for obj in all_patterns:
        kill_chain = _get(obj, "kill_chain_phases", [])
        if not kill_chain:
            continue
        for phase in kill_chain:
            chain_name = _get(phase, "kill_chain_name", "")
            phase_name = _get(phase, "phase_name", "")
            if chain_name == "mitre-attack" and phase_name in tactic_lookup:
                links.append(
                    {
                        "technique_stix_id": _get(obj, "id"),
                        "tactic_shortname": phase_name,
                    }
                )

    logger.info(
        "Parsed %d technique→tactic links (from kill_chain_phases).", len(links)
    )
    return links
