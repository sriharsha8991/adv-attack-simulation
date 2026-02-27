"""Batch Ability Generator — technique-driven, high-concurrency sweep.

Queries the MITRE ATT&CK knowledge graph for every technique (+
sub-technique) per tactic, enriches each directly via CTI/MISP tools
(skipping the LLM Phase A), then composes one Ability per technique
via the LLM Phase B — all at up to ``BATCH_CONCURRENCY`` parallel
LLM calls (default 100, tuned for Gemini tier-3).

This is a **separate service** — it does NOT modify the existing
``ReasoningEngine`` or the FastAPI ``/generate`` endpoint.

Usage (programmatic):
    from src.services.batch_generator import BatchGenerator

    gen = BatchGenerator()
    gen.run()                          # full sweep, all categories
    gen.run(categories=["credential_access"])   # single category

Usage (CLI):
    python scripts/generate_all.py --dry-run
    python scripts/generate_all.py --category credential_access
    python scripts/generate_all.py              # full sweep
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.config import (
    AGENT_VERSION,
    BATCH_CONCURRENCY,
    BATCH_OUTPUT_DIR,
    BLOCKLIST_VERSION,
    CATEGORY_TO_TACTICS,
    GENERATION_MATRIX,
    SCHEMA_VERSION,
    SYSTEM_PROMPT,
    get_settings,
)
from src.graph.connection import Neo4jConnection
from src.layers.layer2_enrichment import GalaxyManager
from src.layers.layer6_safety import SafetyValidator
from src.llm import create_llm_client
from src.llm.base import LLMClient, GenerateResult
from src.models.ability import Ability, GenerationTrace
from src.models.enums import ApprovalStatus
from src.tools.cti_tools import CTITools
from src.tools.misp_tools import MISPTools

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Data containers
# ──────────────────────────────────────────────────────────────

@dataclass
class TechniqueTarget:
    """A single technique × platform generation target."""

    technique_id: str
    technique_name: str
    category: str
    platform: str
    tactic: str
    is_subtechnique: bool = False
    parent_id: str | None = None


@dataclass
class BatchStats:
    """Accumulated statistics for a batch run."""

    total_targets: int = 0
    generated: int = 0
    failed: int = 0
    blocked: int = 0
    skipped_categories: int = 0
    elapsed_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────
# Composition prompt (standalone — does not touch ReasoningEngine)
# ──────────────────────────────────────────────────────────────

BATCH_COMPOSITION_PROMPT = """\
## Technique Intelligence

{enrichment_context}

---

## Task

Generate a single adversary simulation ability for technique **{technique_id} — {technique_name}** \
targeting **{platform}** in the **{category}** category.

## Requirements

1. **attack_category** must be `{category}`
2. **mitre_mapping.technique** must be `{technique_id}`
{subtechnique_line}3. **threat_intel_context** must include groups, tools, campaigns from the intelligence above — do NOT fabricate
4. **executors** must include at least one {platform}-specific executor with:
   - A complete, syntactically valid, directly executable command
   - Real OS binary names, correct flags, proper escaping, real filesystem paths
   - Do NOT insert inline comments inside command or cleanup_procedure strings
   - Do NOT use placeholder values like `<target>` or `$VICTIM_IP`
   - A cleanup_procedure that reverses all changes (also directly executable)
5. **payload_description** must contain all explanatory/contextual text
6. **simulation_only** must be `true`
7. **approval_status** must be `PENDING`
8. **created_by** must be `AI`

Return a single Ability JSON object."""


def _format_enrichment(
    intel: dict[str, Any],
    misp_ctx: Any | None = None,
) -> str:
    """Format technique intel + optional MISP context into LLM-readable text."""
    parts: list[str] = []

    parts.append(f"### {intel.get('attack_id', '?')} — {intel.get('name', '?')}")
    parts.append(f"**Description:** {intel.get('description', 'N/A')}")

    platforms = intel.get("platforms", [])
    if platforms:
        parts.append(f"**Platforms:** {', '.join(platforms)}")

    tactics = intel.get("tactics", [])
    if tactics:
        parts.append(f"**Tactics:** {', '.join(tactics)}")

    # Groups
    groups = intel.get("groups", [])
    if groups:
        parts.append("\n**APT Groups:**")
        for g in groups[:15]:
            aliases = g.get("aliases", [])
            alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""
            usage = g.get("usage_description", "")
            usage_str = f" — {usage[:200]}" if usage else ""
            parts.append(f"- {g.get('group_name', '?')}{alias_str}{usage_str}")

    # Tools
    tools = intel.get("tools", [])
    if tools:
        parts.append("\n**Tools/Malware:**")
        for t in tools[:10]:
            desc = t.get("usage_description") or t.get("description", "")
            parts.append(f"- {t.get('name', '?')} ({t.get('type', '?')}): {desc[:200]}")

    # Detection
    detection = intel.get("detection", {})
    det_text = detection.get("detection_text", "")
    data_sources = detection.get("data_sources", [])
    if det_text:
        parts.append(f"\n**Detection:** {det_text[:500]}")
    if data_sources:
        parts.append(f"**Data Sources:** {', '.join(data_sources)}")

    # Mitigations
    mitigations = intel.get("mitigations", [])
    if mitigations:
        parts.append("\n**Mitigations:**")
        for m in mitigations[:8]:
            parts.append(f"- {m.get('mitigation_name', '?')}: {m.get('how_it_mitigates', '')[:200]}")

    # Campaigns
    campaigns = intel.get("campaigns", [])
    if campaigns:
        parts.append("\n**Campaigns:**")
        for c in campaigns[:8]:
            attrs = c.get("attributed_groups", [])
            attr_str = f" (by {', '.join(attrs)})" if attrs else ""
            parts.append(
                f"- {c.get('campaign_name', '?')}{attr_str} "
                f"({c.get('first_seen', '?')} – {c.get('last_seen', '?')})"
            )

    # MISP Galaxy extras
    if misp_ctx is not None:
        extra_groups = [g for g in getattr(misp_ctx, "associated_groups", []) if g]
        extra_tools = [t for t in getattr(misp_ctx, "associated_tools", []) if t]
        if extra_groups:
            parts.append(f"\n**MISP Galaxy Groups:** {', '.join(extra_groups[:20])}")
        if extra_tools:
            parts.append(f"**MISP Galaxy Tools:** {', '.join(extra_tools[:20])}")

    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────
# BatchGenerator
# ──────────────────────────────────────────────────────────────

class BatchGenerator:
    """High-concurrency, technique-driven ability generator.

    Separate from ``ReasoningEngine`` — shares no state, uses its own
    LLM client, Neo4j connection, and tool instances.

    Args:
        concurrency: Max parallel LLM calls. Default from config.
    """

    def __init__(self, concurrency: int | None = None) -> None:
        self._settings = get_settings()
        self._concurrency = concurrency or BATCH_CONCURRENCY
        self._output_dir = BATCH_OUTPUT_DIR
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # Shared resources (created once, reused across all targets)
        self._conn = Neo4jConnection()
        self._galaxy = GalaxyManager()
        self._galaxy.load_all()
        self._cti = CTITools(conn=self._conn)
        self._misp = MISPTools(conn=self._conn, galaxy_manager=self._galaxy)
        self._validator = SafetyValidator(conn=self._conn)
        self._llm = create_llm_client(self._settings)

        logger.info(
            "BatchGenerator ready: concurrency=%d, model=%s",
            self._concurrency,
            self._llm.model_name,
        )

    def close(self) -> None:
        """Release all resources."""
        self._conn.close()
        logger.info("BatchGenerator closed.")

    def __enter__(self) -> BatchGenerator:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ──────────────────────────────────────────────────────────
    # Phase 1: Discovery — build the full technique manifest
    # ──────────────────────────────────────────────────────────

    def discover_targets(
        self,
        categories: list[str] | None = None,
    ) -> list[TechniqueTarget]:
        """Query the knowledge graph for all technique × platform targets.

        For each category in the generation matrix:
        1. Resolve its tactics via CATEGORY_TO_TACTICS
        2. Query get_techniques_by_tactic for parent techniques
        3. Query get_subtechniques for each parent
        4. Cross with meaningful platforms from GENERATION_MATRIX
        5. Deduplicate (technique_id, platform) pairs globally

        Args:
            categories: Optional subset of categories. None = all.

        Returns:
            Deduplicated list of TechniqueTarget objects.
        """
        matrix = GENERATION_MATRIX
        if categories:
            matrix = {k: v for k, v in matrix.items() if k in categories}

        seen: set[tuple[str, str]] = set()
        targets: list[TechniqueTarget] = []

        for category, platforms in matrix.items():
            tactics = CATEGORY_TO_TACTICS.get(category, [])
            if not tactics:
                logger.warning("No tactic mapping for category: %s", category)
                continue

            for tactic in tactics:
                parent_techniques = self._cti.get_techniques_by_tactic(tactic)
                logger.info(
                    "  [%s / %s] %d parent techniques found",
                    category, tactic, len(parent_techniques),
                )

                for tech in parent_techniques:
                    tid = tech["attack_id"]
                    tech_platforms = [p.lower() for p in tech.get("platforms", [])]

                    # Add parent technique for matching platforms
                    for plat in platforms:
                        plat_match = self._platform_matches(plat, tech_platforms)
                        key = (tid, plat)
                        if plat_match and key not in seen:
                            seen.add(key)
                            targets.append(TechniqueTarget(
                                technique_id=tid,
                                technique_name=tech["name"],
                                category=category,
                                platform=plat,
                                tactic=tactic,
                                is_subtechnique=False,
                            ))

                    # Expand sub-techniques
                    subs = self._cti.get_subtechniques(tid)
                    for sub in subs:
                        sid = sub["attack_id"]
                        sub_platforms = [p.lower() for p in sub.get("platforms", [])]
                        for plat in platforms:
                            plat_match = self._platform_matches(plat, sub_platforms)
                            key = (sid, plat)
                            if plat_match and key not in seen:
                                seen.add(key)
                                targets.append(TechniqueTarget(
                                    technique_id=sid,
                                    technique_name=sub["name"],
                                    category=category,
                                    platform=plat,
                                    tactic=tactic,
                                    is_subtechnique=True,
                                    parent_id=tid,
                                ))

        logger.info(
            "Discovery complete: %d unique technique×platform targets across %d categories",
            len(targets), len(matrix),
        )
        return targets

    @staticmethod
    def _platform_matches(target_platform: str, technique_platforms: list[str]) -> bool:
        """Check if a target platform matches any of the technique's platforms.

        Handles the mapping between our platform names and MITRE's:
        - windows ↔ Windows
        - linux ↔ Linux
        - macos ↔ macOS
        - cloud_aws ↔ IaaS, SaaS (best effort)
        - cloud_azure ↔ Azure AD, IaaS, SaaS, Office 365
        - cloud_gcp ↔ IaaS, SaaS
        """
        platform_map: dict[str, list[str]] = {
            "windows": ["windows"],
            "linux": ["linux"],
            "macos": ["macos"],
            "cloud_aws": ["iaas", "saas", "aws"],
            "cloud_azure": ["azure ad", "iaas", "saas", "office 365", "azure"],
            "cloud_gcp": ["iaas", "saas", "google workspace", "gcp"],
        }
        matchers = platform_map.get(target_platform, [target_platform])
        return any(m in tp for tp in technique_platforms for m in matchers)

    # ──────────────────────────────────────────────────────────
    # Phase 2: Enrichment — direct graph query (no LLM Phase A)
    # ──────────────────────────────────────────────────────────

    def _enrich_technique(self, technique_id: str) -> tuple[dict[str, Any], Any]:
        """Fetch full enrichment for a technique (graph + MISP).

        Returns:
            Tuple of (cti_intel_dict, ThreatIntelContext_or_None).
        """
        intel = self._cti.get_technique_intel(technique_id)
        if "error" in intel:
            return intel, None

        try:
            misp_ctx = self._misp.enrich_technique_context(technique_id)
        except Exception as exc:
            logger.warning("MISP enrichment failed for %s: %s", technique_id, exc)
            misp_ctx = None

        return intel, misp_ctx

    # ──────────────────────────────────────────────────────────
    # Phase 3: Composition — single LLM call per technique
    # ──────────────────────────────────────────────────────────

    def _compose_ability(self, target: TechniqueTarget) -> Ability | None:
        """Generate a single Ability for one technique × platform target.

        1. Enrich the technique via direct graph + MISP queries
        2. Format enrichment into LLM-readable context
        3. Call LLM Phase B with schema=Ability
        4. Enforce safety fields + optional validation
        5. Return the Ability (or None on failure)
        """
        tid = target.technique_id

        # --- Enrichment ---
        intel, misp_ctx = self._enrich_technique(tid)
        if "error" in intel:
            logger.warning("Skipping %s: %s", tid, intel["error"])
            return None

        enrichment_text = _format_enrichment(intel, misp_ctx)

        # --- Build prompt ---
        subtechnique_line = ""
        if target.is_subtechnique and target.parent_id:
            subtechnique_line = (
                f"   - **mitre_mapping.sub_technique** must be `{tid}`\n"
            )

        prompt = BATCH_COMPOSITION_PROMPT.format(
            enrichment_context=enrichment_text,
            technique_id=target.parent_id if target.is_subtechnique else tid,
            technique_name=target.technique_name,
            platform=target.platform,
            category=target.category,
            subtechnique_line=subtechnique_line,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        # --- LLM call ---
        try:
            result: GenerateResult = self._llm.generate(messages, schema=Ability)
            ability: Ability | None = result.parsed
        except (ValidationError, Exception) as exc:
            logger.error("Composition failed for %s (%s): %s", tid, target.platform, exc)
            return None

        if ability is None:
            return None

        # --- Post-generation enforcement ---
        ability.approval_status = ApprovalStatus.PENDING
        ability.created_by = "AI"
        ability.simulation_only = True
        ability.schema_version = SCHEMA_VERSION
        ability.generated_at = datetime.now(timezone.utc).isoformat()
        ability.agent_version = AGENT_VERSION

        # --- Safety validation (if enabled) ---
        if self._settings.enable_safety_layer:
            validation = self._validator.validate(ability)
            if not validation.passed:
                ability.approval_status = ApprovalStatus.BLOCKED
                logger.warning(
                    "BLOCKED %s/%s: %s",
                    tid, target.platform,
                    [f.rule_name for f in validation.hard_failures],
                )
            warning_msgs = [w.detail for w in validation.warnings]
        else:
            warning_msgs = []

        # --- Attach trace ---
        ability.generation_trace = GenerationTrace(
            model=self._llm.model_name,
            tools_called=["get_technique_intel", "enrich_technique_context"],
            reasoning_steps=0,
            total_tokens=result.total_tokens,
            blocklist_version=BLOCKLIST_VERSION,
            validation_warnings=warning_msgs,
        )

        return ability

    # ──────────────────────────────────────────────────────────
    # Phase 4: Parallel execution + persistence
    # ──────────────────────────────────────────────────────────

    def run(
        self,
        categories: list[str] | None = None,
        resume: bool = False,
        dry_run: bool = False,
    ) -> BatchStats:
        """Execute the full batch generation sweep.

        Args:
            categories: Optional subset of categories. None = all.
            resume: If True, skip categories that already have output files.
            dry_run: If True, discover targets and print manifest without
                generating anything.

        Returns:
            BatchStats with totals and error details.
        """
        stats = BatchStats()
        t_start = time.monotonic()

        # --- Discovery ---
        all_targets = self.discover_targets(categories)
        stats.total_targets = len(all_targets)

        if dry_run:
            self._print_manifest(all_targets)
            stats.elapsed_seconds = time.monotonic() - t_start
            return stats

        # --- Group targets by category ---
        by_category: dict[str, list[TechniqueTarget]] = {}
        for t in all_targets:
            by_category.setdefault(t.category, []).append(t)

        # --- Process each category ---
        total_categories = len(by_category)
        for cat_idx, (category, cat_targets) in enumerate(by_category.items(), 1):
            cat_dir = self._output_dir / category
            manifest_path = cat_dir / "_manifest.json"

            if resume and manifest_path.exists():
                logger.info(
                    "[%d/%d] SKIP %s — manifest already exists",
                    cat_idx, total_categories, category,
                )
                stats.skipped_categories += 1
                continue

            logger.info(
                "[%d/%d] Generating %s — %d targets",
                cat_idx, total_categories, category, len(cat_targets),
            )

            abilities = self._generate_category(cat_targets, stats)

            # --- Persist (one file per ability) ---
            self._save_category(category, abilities, cat_dir)

            logger.info(
                "[%d/%d] %s complete — %d abilities saved to %s/",
                cat_idx, total_categories, category,
                len(abilities), category,
            )

        stats.elapsed_seconds = time.monotonic() - t_start
        self._log_summary(stats)
        return stats

    def _generate_category(
        self,
        targets: list[TechniqueTarget],
        stats: BatchStats,
    ) -> list[Ability]:
        """Generate abilities for all targets in a category using thread pool.

        Fires up to ``self._concurrency`` parallel LLM calls.
        """
        abilities: list[Ability] = []

        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            future_to_target: dict[Future[Ability | None], TechniqueTarget] = {
                pool.submit(self._compose_ability, target): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    ability = future.result()
                    if ability is not None:
                        abilities.append(ability)
                        stats.generated += 1
                        if ability.approval_status == ApprovalStatus.BLOCKED:
                            stats.blocked += 1
                        logger.info(
                            "  OK  %s / %s — %s",
                            target.technique_id,
                            target.platform,
                            ability.name,
                        )
                    else:
                        stats.failed += 1
                        err = f"{target.technique_id}/{target.platform}: composition returned None"
                        stats.errors.append(err)
                        logger.warning("  FAIL %s", err)
                except Exception as exc:
                    stats.failed += 1
                    err = f"{target.technique_id}/{target.platform}: {exc}"
                    stats.errors.append(err)
                    logger.error("  ERROR %s", err, exc_info=True)

        return abilities

    # ──────────────────────────────────────────────────────────
    # Persistence
    # ──────────────────────────────────────────────────────────

    def _save_category(
        self,
        category: str,
        abilities: list[Ability],
        cat_dir: Path,
    ) -> None:
        """Save each ability as an individual JSON file inside a category folder.

        Structure:
            output/abilities/<category>/
                <technique_id>_<platform>.json   (one per ability)
                _manifest.json                   (lightweight index)
        """
        cat_dir.mkdir(parents=True, exist_ok=True)

        techniques_covered: set[str] = set()
        file_index: list[dict[str, str]] = []

        for ability in abilities:
            # Determine platform
            plat = "unknown"
            if ability.executors:
                plat = ability.executors[0].platform.value

            # Build filename: T1003.001_windows.json  (dots kept, slashes avoided)
            tid = ability.mitre_mapping.sub_technique or ability.mitre_mapping.technique
            safe_tid = tid.replace("/", "_")
            filename = f"{safe_tid}_{plat}.json"
            filepath = cat_dir / filename

            # Write individual ability file
            filepath.write_text(
                json.dumps(ability.model_dump(mode="json"), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            techniques_covered.add(ability.mitre_mapping.technique)
            if ability.mitre_mapping.sub_technique:
                techniques_covered.add(ability.mitre_mapping.sub_technique)

            file_index.append({
                "file": filename,
                "technique_id": tid,
                "platform": plat,
                "name": ability.name,
            })

        # Write lightweight manifest
        manifest = {
            "category": category,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": self._llm.model_name,
            "total_abilities": len(abilities),
            "techniques_covered": sorted(techniques_covered),
            "files": file_index,
        }

        manifest_path = cat_dir / "_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ──────────────────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _print_manifest(targets: list[TechniqueTarget]) -> None:
        """Print the discovery manifest (for --dry-run)."""
        by_cat: dict[str, dict[str, list[str]]] = {}
        for t in targets:
            cat_dict = by_cat.setdefault(t.category, {})
            cat_dict.setdefault(t.platform, []).append(t.technique_id)

        print("\n" + "=" * 72)
        print("  BATCH GENERATION MANIFEST (dry run)")
        print("=" * 72)
        grand_total = 0
        for cat, plat_dict in sorted(by_cat.items()):
            cat_total = sum(len(ids) for ids in plat_dict.values())
            grand_total += cat_total
            print(f"\n  {cat} ({cat_total} targets)")
            for plat, ids in sorted(plat_dict.items()):
                print(f"    {plat:15s}  {len(ids):3d} techniques  [{ids[0]}..{ids[-1]}]")

        print(f"\n{'─' * 72}")
        print(f"  TOTAL: {grand_total} technique×platform targets")
        print(f"  Estimated LLM calls: {grand_total}")
        print("=" * 72 + "\n")

    @staticmethod
    def _log_summary(stats: BatchStats) -> None:
        """Log final run statistics."""
        logger.info("=" * 60)
        logger.info("  BATCH GENERATION COMPLETE")
        logger.info("=" * 60)
        logger.info("  Total targets:    %d", stats.total_targets)
        logger.info("  Generated:        %d", stats.generated)
        logger.info("  Blocked:          %d", stats.blocked)
        logger.info("  Failed:           %d", stats.failed)
        logger.info("  Skipped (resume): %d", stats.skipped_categories)
        logger.info("  Elapsed:          %.1fs", stats.elapsed_seconds)
        if stats.errors:
            logger.info("  Errors (%d):", len(stats.errors))
            for err in stats.errors[:20]:
                logger.info("    - %s", err)
        logger.info("=" * 60)
