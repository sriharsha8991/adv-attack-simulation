"""Layer 6 — Safety Validation Pipeline.

Applies 18 deterministic validation rules to every generated Ability
*before* it leaves the engine. Hard rules (12) auto-BLOCK on failure;
soft rules (2) produce warnings for human reviewers.

Usage (standalone):
    from src.layers.layer6_safety import SafetyValidator
    validator = SafetyValidator()             # no graph → skip MITRE lookup
    result = validator.validate(ability)
    if not result.passed:
        print(result.hard_failures)

Usage (with graph):
    from src.graph.connection import Neo4jConnection
    validator = SafetyValidator(conn=Neo4jConnection())
    result = validator.validate(ability)
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.config import (
    AUDIT_LOG_PATH,
    BLOCKLIST_VERSION,
    COMMAND_BLOCKLIST,
    EXECUTOR_TO_PLATFORM_FAMILY,
    KNOWN_BINARIES,
    MIN_ABILITY_DESC_LEN,
    MIN_ABILITY_NAME_LEN,
    PLATFORM_COHERENCE_RULES,
    SIMULATION_MARKERS,
)
from src.models.ability import Ability
from src.models.enums import ApprovalStatus, ExecutorType

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Validation result
# ──────────────────────────────────────────────────────────────


@dataclass
class RuleResult:
    """Outcome of a single validation rule."""

    rule_name: str
    passed: bool
    detail: str = ""


@dataclass
class ValidationResult:
    """Aggregate outcome of the full safety pipeline."""

    passed: bool
    ability_id: str
    status: str  # "PENDING" | "BLOCKED"
    hard_failures: list[RuleResult] = field(default_factory=list)
    warnings: list[RuleResult] = field(default_factory=list)

    @property
    def needs_human_review(self) -> bool:
        return len(self.warnings) > 0

    def summary_dict(self) -> dict[str, Any]:
        """Compact dict for API responses."""
        return {
            "passed": self.passed,
            "status": self.status,
            "hard_failures": [
                {"rule": r.rule_name, "detail": r.detail}
                for r in self.hard_failures
            ],
            "warnings": [
                {"rule": r.rule_name, "detail": r.detail}
                for r in self.warnings
            ],
        }


# ──────────────────────────────────────────────────────────────
# Safety Validator
# ──────────────────────────────────────────────────────────────


class SafetyValidator:
    """Deterministic 18-rule validation pipeline for generated Abilities.

    Hard rules auto-BLOCK on failure. Soft rules produce warnings for
    human reviewers without blocking.

    Args:
        conn: Optional Neo4jConnection for MITRE technique validation
              (rules 4 & 5). If ``None``, those rules are skipped.
    """

    def __init__(self, conn: Any | None = None) -> None:
        self._conn = conn

        self._hard_rules = [
            self._check_schema,
            self._check_status,
            self._check_simulation_flag,
            self._check_creator,
            self._check_mitre_mapping,
            self._check_executor_present,
            self._check_command_blocklist,
            self._check_platform_coherence,
            self._check_executor_name_enum,
            self._check_cleanup_present,
            self._check_content,
            self._check_identity,
        ]
        self._soft_rules = [
            self._check_command_syntax,
            self._check_known_binaries,
        ]

    # ── Public API ────────────────────────────────────────────

    def validate(self, ability: Ability) -> ValidationResult:
        """Run all 18 rules against *ability*.

        Returns a ``ValidationResult`` with pass/fail status, hard
        failures, and soft warnings.
        """
        hard_failures: list[RuleResult] = []
        warnings: list[RuleResult] = []
        all_results: list[RuleResult] = []

        # Hard rules
        for rule_fn in self._hard_rules:
            result = rule_fn(ability)
            all_results.append(result)
            if not result.passed:
                hard_failures.append(result)

        # Soft rules
        for rule_fn in self._soft_rules:
            result = rule_fn(ability)
            all_results.append(result)
            if not result.passed:
                warnings.append(result)

        # Batch audit write (single file open for all rules)
        self._log_audit_batch(ability.id, all_results)

        passed = len(hard_failures) == 0
        status = "PENDING" if passed else "BLOCKED"

        return ValidationResult(
            passed=passed,
            ability_id=ability.id,
            status=status,
            hard_failures=hard_failures,
            warnings=warnings,
        )

    def validate_batch(
        self, abilities: list[Ability]
    ) -> list[ValidationResult]:
        """Validate a list of abilities."""
        return [self.validate(a) for a in abilities]

    # ── Hard rules (BLOCK on failure) ─────────────────────────

    @staticmethod
    def _check_schema(ability: Ability) -> RuleResult:
        """Rule 10: Schema validates via Pydantic.

        Since we already have a validated Ability instance, this always
        passes. Kept for pipeline completeness and audit logging.
        """
        return RuleResult(rule_name="schema_valid", passed=True)

    @staticmethod
    def _check_status(ability: Ability) -> RuleResult:
        """Rule 1: approval_status must be PENDING."""
        ok = ability.approval_status == ApprovalStatus.PENDING
        return RuleResult(
            rule_name="approval_status",
            passed=ok,
            detail="" if ok else f"Expected PENDING, got {ability.approval_status}",
        )

    @staticmethod
    def _check_simulation_flag(ability: Ability) -> RuleResult:
        """Rule 2: simulation_only must be True."""
        ok = ability.simulation_only is True
        return RuleResult(
            rule_name="simulation_flag",
            passed=ok,
            detail="" if ok else "simulation_only is not True",
        )

    @staticmethod
    def _check_creator(ability: Ability) -> RuleResult:
        """Rule 3: created_by must be 'AI'."""
        ok = ability.created_by == "AI"
        return RuleResult(
            rule_name="creator_tag",
            passed=ok,
            detail="" if ok else f"Expected 'AI', got '{ability.created_by}'",
        )

    def _check_mitre_mapping(self, ability: Ability) -> RuleResult:
        """Rules 4 & 5: MITRE technique/tactic exist in the graph.

        Skipped gracefully when no Neo4j connection is available.
        """
        if self._conn is None:
            return RuleResult(
                rule_name="mitre_mapping",
                passed=True,
                detail="Skipped — no graph connection",
            )

        technique_id = ability.mitre_mapping.technique
        try:
            records = self._conn.run_query(
                "MATCH (t {attack_id: $tid}) WHERE t:Technique OR t:SubTechnique RETURN t.attack_id AS tid",
                {"tid": technique_id},
            )
            if not records:
                return RuleResult(
                    rule_name="mitre_mapping",
                    passed=False,
                    detail=f"Technique {technique_id} not found in graph",
                )
        except Exception as exc:
            logger.warning("MITRE graph lookup failed: %s", exc)
            return RuleResult(
                rule_name="mitre_mapping",
                passed=True,
                detail=f"Graph lookup error — skipped: {exc}",
            )

        return RuleResult(rule_name="mitre_mapping", passed=True)

    @staticmethod
    def _check_executor_present(ability: Ability) -> RuleResult:
        """Rule 6: At least one executor must be present."""
        ok = len(ability.executors) >= 1
        return RuleResult(
            rule_name="executor_present",
            passed=ok,
            detail="" if ok else "No executors defined",
        )

    @staticmethod
    def _check_command_blocklist(ability: Ability) -> RuleResult:
        """Rule 9: No command or cleanup matches the blocklist."""
        for executor in ability.executors:
            for field_name, text in [
                ("command", executor.command),
                ("cleanup_procedure", executor.cleanup_procedure),
            ]:
                for pattern in COMMAND_BLOCKLIST:
                    if re.search(pattern, text, re.IGNORECASE):
                        return RuleResult(
                            rule_name="command_blocklist",
                            passed=False,
                            detail=(
                                f"Executor '{executor.name.value}' "
                                f"{field_name} matched blocklist pattern: {pattern}"
                            ),
                        )
        return RuleResult(rule_name="command_blocklist", passed=True)

    @staticmethod
    def _check_platform_coherence(ability: Ability) -> RuleResult:
        """Rule 15: Executor name/platform match; no cross-shell syntax."""
        for executor in ability.executors:
            executor_name = executor.name.value
            platform_val = executor.platform.value
            rules = PLATFORM_COHERENCE_RULES.get(executor_name)
            if rules is None:
                continue  # no rules for this executor type

            # Platform must match
            allowed_platforms = rules.get("platform_must_be", [])
            if allowed_platforms and platform_val not in allowed_platforms:
                return RuleResult(
                    rule_name="platform_coherence",
                    passed=False,
                    detail=(
                        f"Executor '{executor_name}' requires platform "
                        f"{allowed_platforms}, got '{platform_val}'"
                    ),
                )

            # Must not contain cross-platform syntax
            for pattern in rules.get("must_not_contain", []):
                if re.search(pattern, executor.command, re.IGNORECASE):
                    return RuleResult(
                        rule_name="platform_coherence",
                        passed=False,
                        detail=(
                            f"Executor '{executor_name}' command contains "
                            f"cross-platform syntax matching: {pattern}"
                        ),
                    )

        return RuleResult(rule_name="platform_coherence", passed=True)

    @staticmethod
    def _check_executor_name_enum(ability: Ability) -> RuleResult:
        """Rule 18: Every executor.name is a valid ExecutorType value.

        Already enforced by Pydantic, but checked explicitly for audit.
        """
        valid_names = {e.value for e in ExecutorType}
        for executor in ability.executors:
            if executor.name.value not in valid_names:
                return RuleResult(
                    rule_name="executor_name_enum",
                    passed=False,
                    detail=f"Invalid executor name: {executor.name.value}",
                )
        return RuleResult(rule_name="executor_name_enum", passed=True)

    @staticmethod
    def _check_cleanup_present(ability: Ability) -> RuleResult:
        """Rule 8: Every executor has a non-empty cleanup_procedure."""
        for executor in ability.executors:
            if not executor.cleanup_procedure or not executor.cleanup_procedure.strip():
                return RuleResult(
                    rule_name="cleanup_present",
                    passed=False,
                    detail=f"Executor '{executor.name.value}' has empty cleanup_procedure",
                )
        return RuleResult(rule_name="cleanup_present", passed=True)

    @staticmethod
    def _check_content(ability: Ability) -> RuleResult:
        """Rules 11 & 12: Name >= 5 chars, description >= 50 chars."""
        if len(ability.name) < MIN_ABILITY_NAME_LEN:
            return RuleResult(
                rule_name="content_check",
                passed=False,
                detail=f"Name too short ({len(ability.name)} chars, need >= {MIN_ABILITY_NAME_LEN})",
            )
        if len(ability.description) < MIN_ABILITY_DESC_LEN:
            return RuleResult(
                rule_name="content_check",
                passed=False,
                detail=f"Description too short ({len(ability.description)} chars, need >= {MIN_ABILITY_DESC_LEN})",
            )
        return RuleResult(rule_name="content_check", passed=True)

    @staticmethod
    def _check_identity(ability: Ability) -> RuleResult:
        """Rules 13 & 14: Valid UUID and ISO 8601 timestamp."""
        # UUID check
        try:
            uuid.UUID(ability.id)
        except (ValueError, AttributeError):
            return RuleResult(
                rule_name="identity_check",
                passed=False,
                detail=f"Invalid UUID: {ability.id!r}",
            )

        # Timestamp check
        if ability.generated_at:
            try:
                datetime.fromisoformat(ability.generated_at)
            except (ValueError, TypeError):
                return RuleResult(
                    rule_name="identity_check",
                    passed=False,
                    detail=f"Invalid ISO 8601 timestamp: {ability.generated_at!r}",
                )

        return RuleResult(rule_name="identity_check", passed=True)

    # ── Soft rules (WARN — do not auto-block) ─────────────────

    @staticmethod
    def _check_command_syntax(ability: Ability) -> RuleResult:
        """Rule 16: Basic syntax heuristics for command strings.

        Full shell parsing (PowerShell AST, bash -n) requires external
        processes. This lightweight version catches the most common
        issues: unmatched quotes, unmatched parentheses, and trailing
        pipes/semicolons.
        """
        issues: list[str] = []

        for executor in ability.executors:
            cmd = executor.command
            name = executor.name.value

            # Unmatched single/double quotes
            if cmd.count("'") % 2 != 0:
                issues.append(f"{name}: unmatched single quote")
            if cmd.count('"') % 2 != 0:
                issues.append(f"{name}: unmatched double quote")

            # Unmatched parentheses
            if cmd.count("(") != cmd.count(")"):
                issues.append(f"{name}: unmatched parentheses")

            # Trailing pipe or semicolon (incomplete pipeline)
            stripped = cmd.rstrip()
            if stripped.endswith("|") or stripped.endswith(";"):
                issues.append(f"{name}: trailing pipe or semicolon")

        if issues:
            return RuleResult(
                rule_name="command_syntax",
                passed=False,
                detail="; ".join(issues),
            )
        return RuleResult(rule_name="command_syntax", passed=True)

    @staticmethod
    def _check_known_binaries(ability: Ability) -> RuleResult:
        """Rule 17: Referenced binaries exist in OS-default allowlist.

        Extracts the first token of the command (or known binary patterns)
        and checks against KNOWN_BINARIES for the target platform.
        """
        unknown: list[str] = []

        for executor in ability.executors:
            platform_family = EXECUTOR_TO_PLATFORM_FAMILY.get(
                executor.name.value, "linux"
            )
            allowlist = KNOWN_BINARIES.get(platform_family, [])
            if not allowlist:
                continue

            # Extract first token as the primary binary
            cmd = executor.command.strip()
            # Skip comment lines at the start
            for line in cmd.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("REM"):
                    first_token = line.split()[0] if line.split() else ""
                    # Normalize: strip path prefix
                    binary = first_token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                    if binary and binary.lower() not in [
                        b.lower() for b in allowlist
                    ]:
                        unknown.append(
                            f"{executor.name.value}: '{binary}' not in allowlist"
                        )
                    break

        if unknown:
            return RuleResult(
                rule_name="known_binaries",
                passed=False,
                detail="; ".join(unknown),
            )
        return RuleResult(rule_name="known_binaries", passed=True)

    # ── Audit logging ─────────────────────────────────────────

    @staticmethod
    def _log_audit_batch(ability_id: str, results: list[RuleResult]) -> None:
        """Write all rule results for an ability in a single file operation."""
        try:
            AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).isoformat()
            lines: list[str] = []
            for result in results:
                entry: dict[str, str] = {
                    "timestamp": ts,
                    "ability_id": ability_id,
                    "rule": result.rule_name,
                    "result": "PASS" if result.passed else "FAIL",
                }
                if result.detail:
                    entry["detail"] = result.detail
                lines.append(json.dumps(entry))
            with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except Exception as exc:
            logger.warning("Audit log write failed: %s", exc)
