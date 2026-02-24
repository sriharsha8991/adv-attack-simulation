"""Layer 2 — MISP Galaxy Enrichment.

Downloads and parses MISP Galaxy cluster JSON files from GitHub.
Provides lookup functions keyed by ATT&CK technique ID for enriching
ability generation with real-world threat intelligence context.

Usage:
    from src.layers.layer2_enrichment import GalaxyManager

    gm = GalaxyManager()
    gm.download_all()
    context = gm.get_technique_context("T1003")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from src.config import DEFAULT_GALAXY_CACHE_DIR, GALAXY_BASE_URL, GALAXY_FILES

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Galaxy Manager
# ──────────────────────────────────────────────────────────────


class GalaxyManager:
    """Downloads, caches, and provides lookup access to MISP Galaxy data.

    Galaxy cluster files are downloaded once from GitHub and cached locally.
    Subsequent loads read from the cache directory.
    """

    def __init__(self, cache_dir: str | Path | None = None) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else DEFAULT_GALAXY_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Lookup indexes: technique_id → list of related items
        self._attack_patterns: dict[str, dict[str, Any]] = {}
        self._intrusion_sets: dict[str, list[dict[str, Any]]] = {}
        self._tools: dict[str, list[dict[str, Any]]] = {}
        self._malware: dict[str, list[dict[str, Any]]] = {}
        self._loaded = False

    # --- Download ---

    def download_file(self, galaxy_key: str, force: bool = False) -> Path:
        """Download a single galaxy file from GitHub.

        Args:
            galaxy_key: Key from GALAXY_FILES dict (e.g. 'attack_pattern').
            force: Re-download even if cached file exists.

        Returns:
            Path to the cached file.
        """
        filename = GALAXY_FILES[galaxy_key]
        local_path = self._cache_dir / filename

        if local_path.exists() and not force:
            logger.info("Galaxy file already cached: %s", local_path.name)
            return local_path

        url = f"{GALAXY_BASE_URL}/{filename}"
        logger.info("Downloading %s ...", url)

        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            local_path.write_bytes(resp.content)

        size_mb = local_path.stat().st_size / (1024 * 1024)
        logger.info("Saved %s (%.1f MB)", local_path.name, size_mb)
        return local_path

    def download_all(self, force: bool = False) -> dict[str, Path]:
        """Download all required galaxy files.

        Returns:
            Dict mapping galaxy_key → local Path.
        """
        paths: dict[str, Path] = {}
        for key in GALAXY_FILES:
            paths[key] = self.download_file(key, force=force)
        logger.info("All %d galaxy files ready.", len(paths))
        return paths

    # --- Parsing ---

    @staticmethod
    def _extract_attack_ids(cluster_value: dict[str, Any]) -> list[str]:
        """Extract ATT&CK technique IDs from a galaxy cluster value.

        Galaxy values encode technique IDs in different fields depending
        on galaxy type. We check meta.external_id and the value name.
        """
        ids: list[str] = []

        meta = cluster_value.get("meta", {})

        # external_id is a list in many galaxy clusters
        for eid in meta.get("external_id", []):
            if isinstance(eid, str) and eid.startswith("T"):
                ids.append(eid)

        # Some clusters use mitre_attack_id
        mitre_id = meta.get("mitre_attack_id")
        if isinstance(mitre_id, str) and mitre_id.startswith("T"):
            if mitre_id not in ids:
                ids.append(mitre_id)

        # Fallback: extract from value name like "Technique Name - T1234"
        value_name = cluster_value.get("value", "")
        if " - T" in value_name:
            parts = value_name.rsplit(" - ", 1)
            if len(parts) == 2:
                potential_id = parts[1].strip()
                if potential_id.startswith("T") and potential_id not in ids:
                    ids.append(potential_id)

        return ids

    def _parse_attack_patterns(self, path: Path) -> int:
        """Parse mitre-attack-pattern.json into lookup dict.

        Builds: self._attack_patterns[technique_id] = {name, description, ...}
        """
        data = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for val in data.get("values", []):
            technique_ids = self._extract_attack_ids(val)
            for tid in technique_ids:
                self._attack_patterns[tid] = {
                    "name": val.get("value", ""),
                    "description": val.get("description", ""),
                    "uuid": val.get("uuid", ""),
                    "meta": val.get("meta", {}),
                    "related": val.get("related", []),
                }
                count += 1
        logger.info("Indexed %d attack pattern entries.", count)
        return count

    def _parse_intrusion_sets(self, path: Path) -> int:
        """Parse mitre-intrusion-set.json into technique → groups lookup.

        MISP galaxy intrusion-set values have 'related' entries that
        reference attack-pattern UUIDs. We cross-reference these.
        """
        data = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for val in data.get("values", []):
            group_info = {
                "name": val.get("value", ""),
                "description": val.get("description", ""),
                "uuid": val.get("uuid", ""),
                "aliases": val.get("meta", {}).get("synonyms", []),
                "country": val.get("meta", {}).get("country", ""),
            }

            # Map this group to techniques via 'related' cross-references
            for rel in val.get("related", []):
                dest_uuid = rel.get("dest-uuid", "")
                rel_type = rel.get("type", "")
                if rel_type == "uses" and dest_uuid:
                    # Look up the technique ID from attack_patterns by UUID
                    for tid, ap in self._attack_patterns.items():
                        if ap.get("uuid") == dest_uuid:
                            self._intrusion_sets.setdefault(tid, []).append(group_info)
                            count += 1
                            break
        logger.info("Indexed %d intrusion-set→technique links.", count)
        return count

    def _parse_tools(self, path: Path) -> int:
        """Parse mitre-tool.json into technique → tools lookup."""
        data = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for val in data.get("values", []):
            tool_info = {
                "name": val.get("value", ""),
                "description": val.get("description", ""),
                "uuid": val.get("uuid", ""),
            }
            for rel in val.get("related", []):
                dest_uuid = rel.get("dest-uuid", "")
                rel_type = rel.get("type", "")
                if rel_type == "uses" and dest_uuid:
                    for tid, ap in self._attack_patterns.items():
                        if ap.get("uuid") == dest_uuid:
                            self._tools.setdefault(tid, []).append(tool_info)
                            count += 1
                            break
        logger.info("Indexed %d tool→technique links.", count)
        return count

    def _parse_malware(self, path: Path) -> int:
        """Parse mitre-malware.json into technique → malware lookup."""
        data = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for val in data.get("values", []):
            mal_info = {
                "name": val.get("value", ""),
                "description": val.get("description", ""),
                "uuid": val.get("uuid", ""),
            }
            for rel in val.get("related", []):
                dest_uuid = rel.get("dest-uuid", "")
                rel_type = rel.get("type", "")
                if rel_type == "uses" and dest_uuid:
                    for tid, ap in self._attack_patterns.items():
                        if ap.get("uuid") == dest_uuid:
                            self._malware.setdefault(tid, []).append(mal_info)
                            count += 1
                            break
        logger.info("Indexed %d malware→technique links.", count)
        return count

    def load_all(self, force_download: bool = False) -> dict[str, int]:
        """Download (if needed) and parse all galaxy files.

        Must be called before any lookup methods.

        Returns:
            Dict of counts per galaxy type.
        """
        paths = self.download_all(force=force_download)

        # Parse attack patterns FIRST (needed for UUID cross-references)
        counts: dict[str, int] = {}
        counts["attack_patterns"] = self._parse_attack_patterns(paths["attack_pattern"])
        counts["intrusion_sets"] = self._parse_intrusion_sets(paths["intrusion_set"])
        counts["tools"] = self._parse_tools(paths["tool"])
        counts["malware"] = self._parse_malware(paths["malware"])

        self._loaded = True
        logger.info("Galaxy data loaded: %s", counts)
        return counts

    # --- Lookup Methods ---

    def _ensure_loaded(self) -> None:
        """Ensure galaxy data has been loaded."""
        if not self._loaded:
            raise RuntimeError(
                "Galaxy data not loaded. Call load_all() first."
            )

    def get_attack_pattern(self, technique_id: str) -> dict[str, Any] | None:
        """Get MISP galaxy attack pattern info for a technique ID.

        Args:
            technique_id: e.g. 'T1003' or 'T1003.001'

        Returns:
            Dict with name, description, meta, related — or None.
        """
        self._ensure_loaded()
        return self._attack_patterns.get(technique_id)

    def get_groups_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get MISP galaxy intrusion sets / APT groups for a technique.

        Args:
            technique_id: e.g. 'T1003'

        Returns:
            List of dicts with name, description, aliases, country.
        """
        self._ensure_loaded()
        return self._intrusion_sets.get(technique_id, [])

    def get_tools_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get MISP galaxy tools associated with a technique.

        Args:
            technique_id: e.g. 'T1003'

        Returns:
            List of dicts with name, description.
        """
        self._ensure_loaded()
        return self._tools.get(technique_id, [])

    def get_malware_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get MISP galaxy malware associated with a technique.

        Args:
            technique_id: e.g. 'T1003'

        Returns:
            List of dicts with name, description.
        """
        self._ensure_loaded()
        return self._malware.get(technique_id, [])

    def get_technique_context(self, technique_id: str) -> dict[str, Any]:
        """Get combined MISP galaxy context for a technique.

        Returns a dict with all galaxy data aggregated:
            - attack_pattern: base info
            - groups: list of APT groups
            - tools: list of tools
            - malware: list of malware
        """
        self._ensure_loaded()
        return {
            "technique_id": technique_id,
            "attack_pattern": self.get_attack_pattern(technique_id),
            "groups": self.get_groups_for_technique(technique_id),
            "tools": self.get_tools_for_technique(technique_id),
            "malware": self.get_malware_for_technique(technique_id),
        }

    # --- Stats ---

    def stats(self) -> dict[str, int]:
        """Return counts of indexed entries."""
        return {
            "attack_patterns": len(self._attack_patterns),
            "intrusion_sets_links": sum(len(v) for v in self._intrusion_sets.values()),
            "tools_links": sum(len(v) for v in self._tools.values()),
            "malware_links": sum(len(v) for v in self._malware.values()),
            "techniques_with_groups": len(self._intrusion_sets),
            "techniques_with_tools": len(self._tools),
            "techniques_with_malware": len(self._malware),
        }
