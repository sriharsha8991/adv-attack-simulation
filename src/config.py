"""Central configuration — loads from .env via pydantic-settings.

All application constants (URLs, paths, safety rules, prompt templates)
are consolidated here so every layer imports from a single source of truth.

Usage:
    from src.config import get_settings
    settings = get_settings()
    print(settings.neo4j_uri)

    from src.config import SYSTEM_PROMPT, COMMAND_BLOCKLIST
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict
from stix2 import Filter

# ──────────────────────────────────────────────────────────────
# Path anchors (resolved relative to this file → src/)
# ──────────────────────────────────────────────────────────────

_SRC_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    # --- LLM Provider ---
    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3-flash-preview"
    groq_api_key: str = ""
    groq_model: str = "qwen/qwen3-32b"
    ollama_model: str = "qwen3:32b"
    ollama_base_url: str = "http://localhost:11434/v1"

    # --- Neo4j ---
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    # --- Safety & Generation ---
    max_abilities_per_batch: int = 20
    enable_safety_layer: bool = False
    enable_api_submission: bool = False
    backend_api_url: str = ""

    # --- API Server ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # --- Groq ---
    groq_base_url: str = "https://api.groq.com/openai/v1"

    # --- Logging ---
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore unrecognized env vars (e.g. AURA_INSTANCEID)
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return singleton Settings instance (cached after first call)."""
    return Settings()


# ══════════════════════════════════════════════════════════════
# Versioning
# ══════════════════════════════════════════════════════════════

SCHEMA_VERSION: str = "1.0"
AGENT_VERSION: str = "0.1.0"


# ══════════════════════════════════════════════════════════════
# LLM Retry / Backoff
# ══════════════════════════════════════════════════════════════

LLM_MAX_RETRIES: int = 3
LLM_BASE_DELAY: float = 1.0       # seconds
LLM_MAX_DELAY: float = 30.0       # seconds
LLM_BACKOFF_FACTOR: float = 2.0
MAX_VALIDATION_RETRIES: int = 3


# ══════════════════════════════════════════════════════════════
# HTTP / Download
# ══════════════════════════════════════════════════════════════

STIX_DOWNLOAD_TIMEOUT: int = 120   # seconds
DOWNLOAD_CHUNK_SIZE: int = 8192
GALAXY_DOWNLOAD_TIMEOUT: float = 60.0  # seconds


# ══════════════════════════════════════════════════════════════
# Graph Loading
# ══════════════════════════════════════════════════════════════

GRAPH_BATCH_SIZE: int = 500


# ══════════════════════════════════════════════════════════════
# Content Validation Thresholds
# ══════════════════════════════════════════════════════════════

MIN_ABILITY_NAME_LEN: int = 5
MIN_ABILITY_DESC_LEN: int = 50
MAX_SNIPPET_LEN: int = 300
MAX_DETECTION_TEXT_LEN: int = 1000


# ══════════════════════════════════════════════════════════════
# Layer 1 — STIX Ingestion constants
# ══════════════════════════════════════════════════════════════

STIX_GITHUB_URL: str = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

DEFAULT_STIX_CACHE_PATH: Path = _SRC_DIR / "data" / "mitre" / "enterprise-attack.json"

STIX_FILTERS: dict[str, list[Filter]] = {
    "tactics": [Filter("type", "=", "x-mitre-tactic")],
    "techniques": [
        Filter("type", "=", "attack-pattern"),
        Filter("x_mitre_is_subtechnique", "=", False),
    ],
    "subtechniques": [
        Filter("type", "=", "attack-pattern"),
        Filter("x_mitre_is_subtechnique", "=", True),
    ],
    "intrusion_sets": [Filter("type", "=", "intrusion-set")],
    "tools": [Filter("type", "=", "tool")],
    "malware": [Filter("type", "=", "malware")],
    "data_sources": [Filter("type", "=", "x-mitre-data-source")],
    "mitigations": [Filter("type", "=", "course-of-action")],
    "campaigns": [Filter("type", "=", "campaign")],
    "relationships": [Filter("type", "=", "relationship")],
}


# ══════════════════════════════════════════════════════════════
# Layer 2 — MISP Galaxy Enrichment constants
# ══════════════════════════════════════════════════════════════

GALAXY_BASE_URL: str = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
)

GALAXY_FILES: dict[str, str] = {
    "attack_pattern": "mitre-attack-pattern.json",
    "intrusion_set": "mitre-intrusion-set.json",
    "tool": "mitre-tool.json",
    "malware": "mitre-malware.json",
}

DEFAULT_GALAXY_CACHE_DIR: Path = _SRC_DIR / "data" / "misp_galaxies"


# ══════════════════════════════════════════════════════════════
# Layer 3 — Reasoning Engine constants
# ══════════════════════════════════════════════════════════════

CATEGORY_TO_TACTICS: dict[str, list[str]] = {
    "credential_access":          ["credential-access"],
    "privilege_escalation":       ["privilege-escalation"],
    "persistence":                ["persistence"],
    "lateral_movement":           ["lateral-movement"],
    "defense_evasion":            ["defense-evasion"],
    "command_and_control":        ["command-and-control"],
    "discovery":                  ["discovery"],
    "collection":                 ["collection"],
    "exfiltration":               ["exfiltration"],
    "cloud_iam_abuse":            ["credential-access", "privilege-escalation"],
    "active_directory_abuse":     ["credential-access", "lateral-movement"],
    "web_application_simulation": ["initial-access"],
    "network_signaling":          ["command-and-control"],
}

# ══════════════════════════════════════════════════════════════
# Batch Generation — Smart Matrix & Concurrency
# ══════════════════════════════════════════════════════════════

GENERATION_MATRIX: dict[str, list[str]] = {
    "credential_access":          ["windows", "linux", "macos"],
    "privilege_escalation":       ["windows", "linux", "macos"],
    "persistence":                ["windows", "linux", "macos"],
    "lateral_movement":           ["windows", "linux"],
    "defense_evasion":            ["windows", "linux", "macos"],
    "command_and_control":        ["windows", "linux", "macos"],
    "discovery":                  ["windows", "linux", "macos", "cloud_aws", "cloud_azure", "cloud_gcp"],
    "collection":                 ["windows", "linux", "macos"],
    "exfiltration":               ["windows", "linux"],
    "cloud_iam_abuse":            ["cloud_aws", "cloud_azure", "cloud_gcp"],
    "active_directory_abuse":     ["windows"],
    "web_application_simulation": ["linux", "windows"],
    "network_signaling":          ["windows", "linux"],
}

BATCH_CONCURRENCY: int = 100       # max parallel LLM calls (Gemini tier-3)
BATCH_OUTPUT_DIR: Path = _SRC_DIR.parent / "output" / "abilities"

SYSTEM_PROMPT: str = """\
You are an adversary simulation specialist for defensive security testing.
Your role is to generate MITRE ATT&CK-mapped attack abilities that help security teams
evaluate their detection and response capabilities.

IMPORTANT RULES:
1. Every ability must have cleanup procedures that reverse all changes
2. Only reference real MITRE ATT&CK techniques — verify with the knowledge graph tools
3. Include threat intelligence context — which groups use this technique, what tools they use
4. Target detection gaps — abilities should trigger the defensive telemetry they test
5. Abilities must be atomic and composable — single technique or small 2–3 step scenarios
6. Avoid full campaign chains — focus on individual technique simulation
7. Commands must be COPY-PASTE EXECUTABLE in the target interpreter — syntactically valid,
   real OS binary names, correct flags and arguments, proper escaping, no placeholders like
   <target> or <ip>, no inline comments explaining the code
8. Put all explanatory text in payload_description, NOT inside the command or cleanup strings
9. Prefer techniques that create or modify reversible artifacts (temp files, scheduled tasks,
   registry keys) so cleanup is straightforward

You have access to 4 tools:
1. get_techniques_by_tactic(tactic) — discover techniques in a tactic
2. get_techniques_for_platform(tactic, platform) — discover techniques for tactic + OS
3. get_subtechniques(technique_id) — navigate parent → sub-techniques
4. get_technique_intel(technique_id) — comprehensive enrichment in ONE call:
   groups (with aliases, usage), tools/malware, detection guidance, mitigations,
   campaigns (with dates, group attribution), and MISP Galaxy community data

WORKFLOW:
1. DISCOVER: Use get_techniques_by_tactic or get_techniques_for_platform
2. NAVIGATE: Use get_subtechniques to find specific variants
3. ENRICH: Use get_technique_intel ONCE per technique for full context
4. Generate detailed abilities from the enriched data
5. Include platform-specific executors with cleanup procedures

OUTPUT:
Generate Ability objects conforming to the provided schema.
Do not include conversational text. Output only structured data."""


# ══════════════════════════════════════════════════════════════
# Layer 6 — Safety & Governance constants
# ══════════════════════════════════════════════════════════════

BLOCKLIST_VERSION: str = "1.0.0"

COMMAND_BLOCKLIST: list[str] = [
    # # Destructive disk operations
    # r"rm\s+-rf\s+/(?!\w)",
    # r"format\s+[a-zA-Z]:",
    # r"dd\s+if=.*of=/dev/sd",
    # r"mkfs\.\w+\s+/dev/",
    # # Ransomware / encryption
    # r"openssl\s+enc.*-aes.*-in\s+/",
    # r"gpg\s+--encrypt.*\*/",
    # r"cipher\s+/w:",
    # # Credential exfiltration to external
    # r"curl.*pastebin\.com",
    # r"wget.*transfer\.sh",
    # r"curl.*webhook\.site",
    # r"Invoke-WebRequest.*ngrok",
    # # Bootloader / firmware
    # r"dd.*of=/dev/sda$",
    # r"bcdedit\s+/set.*boot",
    # r"flashrom",
    # # Active network attacks
    # r"nmap\s+(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01]))",
    # r"masscan\s+",
    # r"hping3\s+",
    # # Kernel / driver manipulation
    # r"insmod\s+",
    # r"modprobe\s+",
    # r"sc\s+create.*binpath",
    # # Credential theft to external
    # r"mimikatz.*sekurlsa.*logonpasswords.*>.*\\\\",
    # r"reg\s+save.*sam.*\\\\",
]

SIMULATION_MARKERS: list[str] = [
    "# SIMULATION",
    "# ADVERSARY-SIMULATION",
    "# CALDERA-COMPATIBLE",
    "# SIMULATION-ONLY-DO-NOT-EXECUTE",
    "Write-Host '[SIMULATION]'",
    "echo '[SIMULATION]'",
    "REM SIMULATION",
    ":: SIMULATION",
]

PLATFORM_COHERENCE_RULES: dict[str, dict[str, Any]] = {
    "powershell": {
        "must_not_contain": [r"#!/bin/bash", r"#!/bin/sh", r"#!/usr/bin/env"],
        "should_contain_any": [
            r"\$env:", r"Get-", r"Set-", r"New-", r"Remove-",
            r"Write-Host", r"Invoke-",
        ],
        "platform_must_be": ["windows"],
    },
    "cmd": {
        "must_not_contain": [r"\$env:", r"Get-Process", r"#!/bin/"],
        "should_contain_any": [
            r"REM ", r"echo ", r"set ", r"del ", r"copy ", r"%\w+%",
        ],
        "platform_must_be": ["windows"],
    },
    "bash": {
        "must_not_contain": [r"\$env:", r"Get-Process", r"Write-Host", r"REM "],
        "should_contain_any": [
            r"#!/bin/bash", r"echo ", r"cat ", r"grep ",
            r"export ", r"\$\{?\w+\}?",
        ],
        "platform_must_be": ["linux", "macos"],
    },
    "zsh": {
        "must_not_contain": [r"\$env:", r"Write-Host", r"REM "],
        "platform_must_be": ["macos", "linux"],
    },
    "aws_cli": {
        "should_contain_any": [
            r"aws\s+", r"aws\s+sts", r"aws\s+iam", r"aws\s+s3",
        ],
        "platform_must_be": ["cloud_aws", "linux", "macos", "windows"],
    },
    "az_cli": {
        "should_contain_any": [
            r"az\s+", r"az\s+account", r"az\s+ad", r"az\s+role",
        ],
        "platform_must_be": ["cloud_azure", "linux", "macos", "windows"],
    },
    "gcloud_cli": {
        "should_contain_any": [r"gcloud\s+"],
        "platform_must_be": ["cloud_gcp", "linux", "macos", "windows"],
    },
}

KNOWN_BINARIES: dict[str, list[str]] = {
    "windows": [
        "rundll32.exe", "reg.exe", "certutil.exe", "whoami.exe", "net.exe",
        "net1.exe", "schtasks.exe", "wmic.exe", "powershell.exe", "cmd.exe",
        "tasklist.exe", "nltest.exe", "dsquery.exe", "setspn.exe", "klist.exe",
        "bitsadmin.exe", "mshta.exe", "cscript.exe", "wscript.exe", "msiexec.exe",
        "regsvr32.exe", "installutil.exe", "sc.exe", "netsh.exe", "bcdedit.exe",
        "vssadmin.exe", "esentutl.exe", "ntdsutil.exe", "csvde.exe", "ldifde.exe",
    ],
    "linux": [
        "whoami", "id", "cat", "grep", "awk", "sed", "find", "ls", "ps",
        "curl", "wget", "openssl", "ssh", "scp", "chmod", "chown", "crontab",
        "systemctl", "journalctl", "passwd", "shadow", "useradd", "usermod",
        "iptables", "nmap", "tcpdump", "nc", "netcat", "python3", "perl",
    ],
    "macos": [
        "whoami", "id", "cat", "grep", "security", "dscl", "defaults",
        "launchctl", "osascript", "plutil", "profiles", "curl", "openssl",
    ],
}

EXECUTOR_TO_PLATFORM_FAMILY: dict[str, str] = {
    "powershell": "windows",
    "cmd": "windows",
    "bash": "linux",
    "sh": "linux",
    "zsh": "macos",
    "python": "linux",
    "aws_cli": "linux",
    "az_cli": "linux",
    "gcloud_cli": "linux",
    "manual": "linux",
}

AUDIT_LOG_PATH: Path = _SRC_DIR.parent / "output" / "safety_audit.jsonl"
