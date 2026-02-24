"""Ability data models — single source of truth.

These Pydantic models are used for:
1. Gemini structured output (response_schema=Ability)
2. JSON validation on generation
3. API contract definition
4. Neo4j serialization
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from .enums import (
    ApprovalStatus,
    AttackCategory,
    ExecutorType,
    Platform,
    PrivilegeLevel,
)


class MitreMapping(BaseModel):
    """MITRE ATT&CK framework mapping for an ability."""

    tactic: str = Field(
        description=(
            "ATT&CK tactic shortname (e.g., 'credential-access', 'lateral-movement'). "
            "Must match a Tactic node shortname in the knowledge graph."
        )
    )
    technique: str = Field(
        description=(
            "ATT&CK technique ID (e.g., 'T1003', 'T1059'). "
            "Must exist as a Technique node in the knowledge graph."
        )
    )
    sub_technique: Optional[str] = Field(
        default=None,
        description=(
            "ATT&CK sub-technique ID (e.g., 'T1003.001', 'T1059.001'). "
            "If set, must exist as a SubTechnique node in the knowledge graph."
        ),
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "tactic": "credential-access",
                    "technique": "T1003",
                    "sub_technique": "T1003.001",
                }
            ]
        }
    }


class Executor(BaseModel):
    """A single execution method for an ability.

    Each executor represents one way the simulated attack could be carried out.
    """

    name: ExecutorType = Field(
        description=(
            "Interpreter to execute the command. Must match the target platform: "
            "powershell/cmd for windows, bash/sh for linux, zsh/bash for macos, "
            "aws_cli/az_cli/gcloud_cli for cloud platforms."
        )
    )
    platform: Platform = Field(
        description=(
            "Target OS or cloud environment where this executor runs."
        )
    )
    privilege_required: PrivilegeLevel = Field(
        description="Minimum privilege level required to execute the command."
    )
    command: str = Field(
        description=(
            "Complete, copy-paste executable command for the target interpreter. "
            "Must be syntactically valid and runnable as-is in the declared shell. "
            "Use real OS binary names, correct flags, proper escaping, and real "
            "filesystem paths. No placeholder values like <target> or <ip>. "
            "No inline comments explaining what the command does. "
            "Prefer techniques that create or modify reversible artifacts "
            "(temp files, scheduled tasks, registry keys)."
        )
    )
    payload_description: str = Field(
        description=(
            "Human-readable explanation of what this executor does, which "
            "technique it simulates, and what defensive telemetry it triggers. "
            "All explanatory text goes here, NOT inside the command field."
        )
    )
    cleanup_procedure: str = Field(
        description=(
            "Complete, copy-paste executable cleanup command that undoes exactly "
            "what the command field does. Must be runnable as-is in the same "
            "interpreter. No placeholders, no inline comments."
        )
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "powershell",
                    "platform": "windows",
                    "privilege_required": "admin",
                    "command": (
                        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
                        "MiniDump (Get-Process lsass).Id "
                        "$env:TEMP\\lsass_dump.dmp full"
                    ),
                    "payload_description": (
                        "Dumps LSASS process memory via comsvcs.dll MiniDump export. "
                        "Triggers Sysmon Event ID 10 (ProcessAccess) and Windows "
                        "Defender Credential Guard alerts. Used by APT29 and APT28."
                    ),
                    "cleanup_procedure": (
                        "Remove-Item -Path $env:TEMP\\lsass_dump.dmp "
                        "-Force -ErrorAction SilentlyContinue"
                    ),
                }
            ]
        }
    }


class CampaignUsage(BaseModel):
    """A real-world campaign that used a specific technique.

    Sourced from MITRE ATT&CK Campaign objects in the STIX bundle.
    Provides temporal context: who used what, when.
    """

    campaign_name: str = Field(
        description="Name of the campaign/operation (e.g. 'SolarWinds Compromise').",
    )
    first_seen: Optional[str] = Field(
        default=None,
        description="ISO 8601 date when the campaign was first observed.",
    )
    last_seen: Optional[str] = Field(
        default=None,
        description="ISO 8601 date when the campaign was last observed.",
    )
    attributed_groups: List[str] = Field(
        default_factory=list,
        description="APT groups attributed to this campaign.",
    )
    description_snippet: Optional[str] = Field(
        default=None,
        description="Brief excerpt from the campaign description (max 300 chars).",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "campaign_name": "SolarWinds Compromise",
                    "first_seen": "2019-08-01T05:00:00+00:00",
                    "last_seen": "2021-01-01T06:00:00+00:00",
                    "attributed_groups": ["APT29"],
                    "description_snippet": (
                        "A sophisticated supply chain cyber operation conducted "
                        "by APT29 that was discovered in mid-December 2020."
                    ),
                }
            ]
        }
    }


class ThreatIntelContext(BaseModel):
    """Real-world threat intelligence context for an ability.

    Sourced from Neo4j knowledge graph (IntrusionSets, Tools) and MISP galaxies.
    """

    associated_groups: List[str] = Field(
        default_factory=list,
        description=(
            "APT groups / intrusion sets known to use this technique. "
            "Sourced from MITRE ATT&CK IntrusionSet→USES→Technique relationships."
        ),
    )
    associated_tools: List[str] = Field(
        default_factory=list,
        description=(
            "Tools and malware associated with this technique. "
            "Sourced from MITRE ATT&CK Tool/Malware→USES→Technique relationships."
        ),
    )
    recent_campaigns: List[CampaignUsage] = Field(
        default_factory=list,
        description=(
            "Structured real-world campaigns that used this technique. "
            "Sourced from MITRE ATT&CK Campaign objects with date ranges "
            "and group attribution."
        ),
    )
    detection_guidance: Optional[str] = Field(
        default=None,
        description=(
            "How defenders can detect this technique. "
            "Sourced from ATT&CK data sources and detection fields."
        ),
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "associated_groups": ["APT29", "APT28", "Lazarus Group"],
                    "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
                    "recent_campaigns": [
                        {
                            "campaign_name": "SolarWinds Compromise",
                            "first_seen": "2019-08-01T05:00:00+00:00",
                            "last_seen": "2021-01-01T06:00:00+00:00",
                            "attributed_groups": ["APT29"],
                            "description_snippet": (
                                "A sophisticated supply chain cyber operation "
                                "conducted by APT29."
                            ),
                        },
                        {
                            "campaign_name": "Operation Wocao",
                            "first_seen": "2017-12-01T05:00:00+00:00",
                            "last_seen": "2019-12-01T05:00:00+00:00",
                            "attributed_groups": [],
                            "description_snippet": None,
                        },
                    ],
                    "detection_guidance": (
                        "Monitor for access to LSASS process. Enable Credential Guard. "
                        "Alert on rundll32.exe loading comsvcs.dll with MiniDump export."
                    ),
                }
            ]
        }
    }


class GenerationTrace(BaseModel):
    """Audit trail of how the ability was generated."""

    model: str = Field(description="LLM model used for generation")
    tools_called: List[str] = Field(
        default_factory=list,
        description="List of function tools invoked during generation",
    )
    reasoning_steps: int = Field(
        default=0,
        description="Number of reasoning iterations in the agent loop",
    )
    total_tokens: int = Field(
        default=0,
        description=(
            "Total token consumption (input + output) cumulative across "
            "all tool-calling iterations, including tool call/result tokens"
        ),
    )
    blocklist_version: str = Field(
        default="1.0.0",
        description=(
            "Version of the command blocklist active at generation time. "
            "Required for safety audit trail."
        ),
    )
    validation_warnings: List[str] = Field(
        default_factory=list,
        description=(
            "List of soft validation warnings (syntax check, unknown binary). "
            "Empty if no warnings. Helps human reviewer focus attention."
        ),
    )


class Ability(BaseModel):
    """A complete, self-contained description of a simulated cyberattack scenario.

    This is the primary output of the AI agent and the primary input to the
    backend platform API. Each Ability represents a single technique or a small
    multi-step atomic scenario (2-3 steps). Avoid full campaign chains.
    """

    # === Identity ===
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description=(
            "Unique ability identifier (UUID). "
            "Use UUID5 for deterministic IDs based on technique+platform+command."
        ),
    )
    name: str = Field(
        description=(
            "Human-readable ability name. Should clearly describe the technique "
            "being simulated (e.g., 'LSASS Memory Credential Dumping via comsvcs.dll')."
        )
    )
    description: str = Field(
        description=(
            "Detailed description of what this ability simulates, why it matters, "
            "and how real-world attackers use this technique. 2-4 sentences."
        )
    )

    # === Classification ===
    attack_category: AttackCategory = Field(
        description="One of the 13 supported attack categories."
    )
    mitre_mapping: MitreMapping = Field(
        description="MITRE ATT&CK framework mapping: tactic, technique, sub-technique."
    )

    # === Intelligence ===
    threat_intel_context: ThreatIntelContext = Field(
        description=(
            "Real-world threat intelligence context: who uses this technique, "
            "what tools they use, and how to detect it."
        )
    )

    # === Execution ===
    executors: List[Executor] = Field(
        min_length=1,
        description=(
            "One or more execution methods. Each executor targets a specific "
            "platform with a specific command. At least one executor is required."
        ),
    )

    # === Safety (Hard defaults — non-negotiable) ===
    approval_status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description=(
            "Must be PENDING on creation. Agent cannot set any other value. "
            "Backend enforces state transitions."
        ),
    )
    created_by: str = Field(
        default="AI",
        description="Must be 'AI' for agent-generated abilities. Audit trail field.",
    )
    simulation_only: bool = Field(
        default=True,
        description=(
            "Must be true. Abilities are always simulation-safe. "
            "Setting to false is a hard validation failure."
        ),
    )

    # === Metadata ===
    schema_version: str = Field(
        default="1.0",
        description="Schema version for forward compatibility.",
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp of when the ability was generated.",
    )
    agent_version: str = Field(
        default="0.1.0",
        description="Version of the AI agent that generated this ability.",
    )
    generation_trace: Optional[GenerationTrace] = Field(
        default=None,
        description="Audit trail of the generation process (model, tools called, tokens).",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "name": "LSASS Memory Credential Dumping via comsvcs.dll",
                    "description": (
                        "Dumps LSASS process memory using the comsvcs.dll MiniDump "
                        "export to harvest cached credentials. This sub-technique "
                        "(T1003.001) is used by APT29, APT28, and Wizard Spider in "
                        "enterprise Windows environments to extract NTLM hashes and "
                        "Kerberos tickets from memory."
                    ),
                    "attack_category": "credential_access",
                    "mitre_mapping": {
                        "tactic": "credential-access",
                        "technique": "T1003",
                        "sub_technique": "T1003.001",
                    },
                    "threat_intel_context": {
                        "associated_groups": ["APT29", "APT28", "Wizard Spider"],
                        "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
                        "recent_campaigns": [
                            {
                                "campaign_name": "SolarWinds Compromise",
                                "first_seen": "2019-08-01T05:00:00+00:00",
                                "last_seen": "2021-01-01T06:00:00+00:00",
                                "attributed_groups": ["APT29"],
                                "description_snippet": None,
                            }
                        ],
                        "detection_guidance": (
                            "Monitor for access to LSASS process via Sysmon Event ID 10. "
                            "Enable Credential Guard. Alert on rundll32.exe loading "
                            "comsvcs.dll with MiniDump export."
                        ),
                    },
                    "executors": [
                        {
                            "name": "powershell",
                            "platform": "windows",
                            "privilege_required": "admin",
                            "command": (
                                "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
                                "MiniDump (Get-Process lsass).Id "
                                "$env:TEMP\\lsass_dump.dmp full"
                            ),
                            "payload_description": (
                                "Dumps LSASS process memory via comsvcs.dll MiniDump. "
                                "Triggers Sysmon Event ID 10 and Defender alerts."
                            ),
                            "cleanup_procedure": (
                                "Remove-Item -Path $env:TEMP\\lsass_dump.dmp "
                                "-Force -ErrorAction SilentlyContinue"
                            ),
                        }
                    ],
                    "approval_status": "PENDING",
                    "created_by": "AI",
                    "simulation_only": True,
                    "schema_version": "1.0",
                }
            ]
        }
    }
