# Ability JSON Schema Reference

> Version 1.0 · Single source of truth for the Ability data model

---

## Table of Contents

- [Overview](#overview)
- [Pydantic Models (Python)](#pydantic-models-python)
- [JSON Schema](#json-schema)
- [Field Reference](#field-reference)
- [Enums](#enums)
- [Examples](#examples)
- [Validation Rules](#validation-rules)
- [Schema Versioning](#schema-versioning)

---

## Overview

An **Ability** is a self-contained description of a simulated cyberattack scenario. It includes everything needed for a human reviewer to understand, approve, and (optionally) execute the simulation:

- **What** is being simulated (name, description, attack category)
- **Why** it matters (MITRE mapping, threat intelligence context)
- **How** it would be executed (executors with commands per platform)
- **Safety metadata** (approval status, simulation flags, audit trail)

Abilities are the primary output of the AI agent and the primary input to the backend platform API.

---

## Pydantic Models (Python)

These models are the **single source of truth** — used for:
1. Gemini structured output (`response_schema=Ability`)
2. JSON validation on generation
3. API contract definition
4. Neo4j serialization

### `src/models/enums.py`

```python
from enum import Enum


class ApprovalStatus(str, Enum):
    """Approval state machine states.
    Agent can ONLY produce PENDING.
    Backend enforces transitions.
    """
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTABLE = "EXECUTABLE"
    BLOCKED = "BLOCKED"


class AttackCategory(str, Enum):
    """Supported attack categories (Week 1 scope)."""
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_AND_CONTROL = "command_and_control"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    CLOUD_IAM_ABUSE = "cloud_iam_abuse"
    ACTIVE_DIRECTORY_ABUSE = "active_directory_abuse"
    WEB_APPLICATION_SIMULATION = "web_application_simulation"
    NETWORK_SIGNALING = "network_signaling"


class Platform(str, Enum):
    """Target operating system / environment platforms."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"


class ExecutorType(str, Enum):
    """Allowed executor interpreter types.
    Constrains Executor.name to prevent LLM from generating arbitrary values.
    """
    POWERSHELL = "powershell"
    CMD = "cmd"
    BASH = "bash"
    ZSH = "zsh"
    PYTHON = "python"
    SH = "sh"
    AWS_CLI = "aws_cli"
    AZ_CLI = "az_cli"
    GCLOUD_CLI = "gcloud_cli"
    CURL = "curl"


class PrivilegeLevel(str, Enum):
    """Required privilege level for executor."""
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    ROOT = "root"
```

### `src/models/ability.py`

```python
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from .enums import ApprovalStatus, AttackCategory, Platform, PrivilegeLevel


class MitreMapping(BaseModel):
    """MITRE ATT&CK framework mapping for an ability."""

    tactic: str = Field(
        description="ATT&CK tactic shortname (e.g., 'credential-access', 'lateral-movement'). "
                    "Must match a Tactic node shortname in the knowledge graph."
    )
    technique: str = Field(
        description="ATT&CK technique ID (e.g., 'T1003', 'T1059'). "
                    "Must exist as a Technique node in the knowledge graph."
    )
    sub_technique: Optional[str] = Field(
        default=None,
        description="ATT&CK sub-technique ID (e.g., 'T1003.001', 'T1059.001'). "
                    "If set, must exist as a SubTechnique node in the knowledge graph."
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "tactic": "credential-access",
                    "technique": "T1003",
                    "sub_technique": "T1003.001"
                }
            ]
        }


class Executor(BaseModel):
    """A single execution method for an ability.
    Each executor represents one way the simulated attack could be carried out.
    """

    name: ExecutorType = Field(
        description="Executor type: 'powershell', 'cmd', 'bash', 'zsh', 'python', 'aws_cli', 'az_cli', etc. "
                    "Must be a valid ExecutorType enum value. Determines the interpreter used to run the command."
    )
    platform: Platform = Field(
        description="Target platform: 'windows', 'linux', 'macos', 'cloud_aws', 'cloud_azure', 'cloud_gcp'."
    )
    privilege_required: PrivilegeLevel = Field(
        description="Minimum privilege level required: 'user', 'admin', 'system', 'root'."
    )
    command: str = Field(
        description="The simulation command to execute. MUST include a simulation marker "
                    "(e.g., '# SIMULATION ONLY — T1003.001'). Must use dummy artifacts and "
                    "be reversible. Must NOT contain real exploit payloads or destructive operations."
    )
    payload_description: str = Field(
        description="Human-readable description of what this executor does in simulation context. "
                    "Explains the technique being simulated and expected behavior."
    )
    cleanup_procedure: str = Field(
        description="Command(s) to reverse any changes made by the simulation. "
                    "REQUIRED for every executor — must undo all modifications."
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "name": "powershell",
                    "platform": "windows",
                    "privilege_required": "admin",
                    "command": "# SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\sim_lsass.dmp full",
                    "payload_description": "Uses comsvcs.dll MiniDump to create a minidump of the LSASS process. Simulation-safe: dump written to temp directory with simulation marker.",
                    "cleanup_procedure": "Remove-Item $env:TEMP\\sim_lsass.dmp -Force -ErrorAction SilentlyContinue"
                }
            ]
        }


class ThreatIntelContext(BaseModel):
    """Real-world threat intelligence context for an ability.
    Sourced from Neo4j knowledge graph (IntrusionSets, Tools) and MISP galaxies.
    """

    associated_groups: List[str] = Field(
        default_factory=list,
        description="APT groups / intrusion sets known to use this technique. "
                    "Sourced from MITRE ATT&CK IntrusionSet→USES→Technique relationships."
    )
    associated_tools: List[str] = Field(
        default_factory=list,
        description="Tools and malware associated with this technique. "
                    "Sourced from MITRE ATT&CK Tool/Malware→USES→Technique relationships."
    )
    recent_campaigns: List[str] = Field(
        default_factory=list,
        description="Known real-world campaigns that used this technique. "
                    "Sourced from MISP events and CTI feeds."
    )
    detection_guidance: Optional[str] = Field(
        default=None,
        description="How defenders can detect this technique. "
                    "Sourced from ATT&CK data sources and detection fields."
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "associated_groups": ["APT29", "APT28", "Lazarus Group"],
                    "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
                    "recent_campaigns": ["SolarWinds (2020)", "NotPetya lateral movement phase"],
                    "detection_guidance": "Monitor for access to LSASS process. Enable Credential Guard. Alert on rundll32.exe loading comsvcs.dll with MiniDump export."
                }
            ]
        }


class GenerationTrace(BaseModel):
    """Audit trail of how the ability was generated."""

    model: str = Field(description="LLM model used for generation")
    tools_called: List[str] = Field(
        default_factory=list,
        description="List of function tools invoked during generation"
    )
    reasoning_steps: int = Field(
        default=0,
        description="Number of reasoning iterations in the agent loop"
    )
    total_tokens: int = Field(
        default=0,
        description="Total token consumption (input + output) cumulative across "
                    "all tool-calling iterations, including tool call/result tokens"
    )
    blocklist_version: str = Field(
        default="1.0.0",
        description="Version of the command blocklist active at generation time. "
                    "Required for safety audit trail."
    )
    validation_warnings: List[str] = Field(
        default_factory=list,
        description="List of soft validation warnings (syntax check, unknown binary). "
                    "Empty if no warnings. Helps human reviewer focus attention."
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
        description="Unique ability identifier (UUID). "
                    "Use UUID5 for deterministic IDs based on technique+platform+command."
    )
    name: str = Field(
        description="Human-readable ability name. Should clearly describe the technique "
                    "being simulated (e.g., 'LSASS Memory Credential Dumping via comsvcs.dll')."
    )
    description: str = Field(
        description="Detailed description of what this ability simulates, why it matters, "
                    "and how real-world attackers use this technique. 2-4 sentences."
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
        description="Real-world threat intelligence context: who uses this technique, "
                    "what tools they use, and how to detect it."
    )

    # === Execution ===
    executors: List[Executor] = Field(
        min_length=1,
        description="One or more execution methods. Each executor targets a specific "
                    "platform with a specific command. At least one executor is required."
    )

    # === Safety (Hard defaults — non-negotiable) ===
    approval_status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description="Must be PENDING on creation. Agent cannot set any other value. "
                    "Backend enforces state transitions."
    )
    created_by: str = Field(
        default="AI",
        description="Must be 'AI' for agent-generated abilities. Audit trail field."
    )
    simulation_only: bool = Field(
        default=True,
        description="Must be true. Abilities are always simulation-safe. "
                    "Setting to false is a hard validation failure."
    )

    # === Metadata ===
    schema_version: str = Field(
        default="1.0",
        description="Schema version for forward compatibility."
    )
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp of when the ability was generated."
    )
    agent_version: str = Field(
        default="0.1.0",
        description="Version of the AI agent that generated this ability."
    )
    generation_trace: Optional[GenerationTrace] = Field(
        default=None,
        description="Audit trail of the generation process (model, tools called, tokens)."
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "name": "LSASS Memory Credential Dumping via comsvcs.dll",
                    "description": "Simulates credential dumping from LSASS process memory using comsvcs.dll MiniDump. This technique is commonly used by APT29 and APT28 for credential harvesting in enterprise Windows environments.",
                    "attack_category": "credential_access",
                    "mitre_mapping": {
                        "tactic": "credential-access",
                        "technique": "T1003",
                        "sub_technique": "T1003.001"
                    },
                    "threat_intel_context": {
                        "associated_groups": ["APT29", "APT28", "Lazarus Group"],
                        "associated_tools": ["Mimikatz", "ProcDump", "comsvcs.dll"],
                        "recent_campaigns": ["SolarWinds (2020)"],
                        "detection_guidance": "Monitor for access to LSASS process. Enable Credential Guard."
                    },
                    "executors": [
                        {
                            "name": "powershell",
                            "platform": "windows",
                            "privilege_required": "admin",
                            "command": "# SIMULATION ONLY — T1003.001\nrundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\sim_lsass.dmp full",
                            "payload_description": "Uses comsvcs.dll MiniDump for LSASS memory dump simulation.",
                            "cleanup_procedure": "Remove-Item $env:TEMP\\sim_lsass.dmp -Force -ErrorAction SilentlyContinue"
                        }
                    ],
                    "approval_status": "PENDING",
                    "created_by": "AI",
                    "simulation_only": True,
                    "schema_version": "1.0"
                }
            ]
        }
```

---

## JSON Schema

Export the JSON Schema for API documentation or external validation:

```python
import json
from src.models.ability import Ability

schema = Ability.model_json_schema()
print(json.dumps(schema, indent=2))
```

### Full JSON Schema (exported)

```json
{
  "$defs": {
    "ApprovalStatus": {
      "enum": ["PENDING", "APPROVED", "REJECTED", "EXECUTABLE", "BLOCKED"],
      "type": "string"
    },
    "AttackCategory": {
      "enum": [
        "credential_access", "privilege_escalation", "persistence",
        "lateral_movement", "defense_evasion", "command_and_control",
        "discovery", "collection", "exfiltration", "cloud_iam_abuse",
        "active_directory_abuse", "web_application_simulation", "network_signaling"
      ],
      "type": "string"
    },
    "ExecutorType": {
      "enum": [
        "powershell", "cmd", "bash", "zsh", "python", "sh",
        "aws_cli", "az_cli", "gcloud_cli", "curl"
      ],
      "type": "string"
    },
    "Platform": {
      "enum": ["windows", "linux", "macos", "cloud_aws", "cloud_azure", "cloud_gcp"],
      "type": "string"
    },
    "PrivilegeLevel": {
      "enum": ["user", "admin", "system", "root"],
      "type": "string"
    },
    "MitreMapping": {
      "properties": {
        "tactic": { "type": "string" },
        "technique": { "type": "string" },
        "sub_technique": { "type": ["string", "null"], "default": null }
      },
      "required": ["tactic", "technique"],
      "type": "object"
    },
    "Executor": {
      "properties": {
        "name": { "$ref": "#/$defs/ExecutorType" },
        "platform": { "$ref": "#/$defs/Platform" },
        "privilege_required": { "$ref": "#/$defs/PrivilegeLevel" },
        "command": { "type": "string" },
        "payload_description": { "type": "string" },
        "cleanup_procedure": { "type": "string" }
      },
      "required": ["name", "platform", "privilege_required", "command", "payload_description", "cleanup_procedure"],
      "type": "object"
    },
    "ThreatIntelContext": {
      "properties": {
        "associated_groups": { "items": { "type": "string" }, "type": "array", "default": [] },
        "associated_tools": { "items": { "type": "string" }, "type": "array", "default": [] },
        "recent_campaigns": { "items": { "type": "string" }, "type": "array", "default": [] },
        "detection_guidance": { "type": ["string", "null"], "default": null }
      },
      "type": "object"
    },
    "GenerationTrace": {
      "properties": {
        "model": { "type": "string" },
        "tools_called": { "items": { "type": "string" }, "type": "array", "default": [] },
        "reasoning_steps": { "type": "integer", "default": 0 },
        "total_tokens": { "type": "integer", "default": 0 },
        "blocklist_version": { "type": "string", "default": "1.0.0" },
        "validation_warnings": { "items": { "type": "string" }, "type": "array", "default": [] }
      },
      "required": ["model"],
      "type": "object"
    }
  },
  "properties": {
    "id": { "type": "string" },
    "name": { "type": "string" },
    "description": { "type": "string" },
    "attack_category": { "$ref": "#/$defs/AttackCategory" },
    "mitre_mapping": { "$ref": "#/$defs/MitreMapping" },
    "threat_intel_context": { "$ref": "#/$defs/ThreatIntelContext" },
    "executors": { "items": { "$ref": "#/$defs/Executor" }, "minItems": 1, "type": "array" },
    "approval_status": { "$ref": "#/$defs/ApprovalStatus", "default": "PENDING" },
    "created_by": { "type": "string", "default": "AI" },
    "simulation_only": { "type": "boolean", "default": true },
    "schema_version": { "type": "string", "default": "1.0" },
    "generated_at": { "type": "string" },
    "agent_version": { "type": "string", "default": "0.1.0" },
    "generation_trace": { "anyOf": [{ "$ref": "#/$defs/GenerationTrace" }, { "type": "null" }], "default": null }
  },
  "required": ["name", "description", "attack_category", "mitre_mapping", "threat_intel_context", "executors"],
  "type": "object"
}
```

---

## Field Reference

### Top-Level Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string (UUID) | No | Auto-generated UUID4 | Unique identifier. Use UUID5 for deterministic IDs. |
| `name` | string | **Yes** | — | Human-readable name describing the simulated technique |
| `description` | string | **Yes** | — | 2–4 sentence description of purpose, technique, and real-world relevance |
| `attack_category` | AttackCategory | **Yes** | — | One of 13 supported categories |
| `mitre_mapping` | MitreMapping | **Yes** | — | ATT&CK tactic + technique + sub-technique |
| `threat_intel_context` | ThreatIntelContext | **Yes** | — | Real-world threat intelligence enrichment |
| `executors` | List[Executor] | **Yes** | — | 1+ execution methods (min 1 required) |
| `approval_status` | ApprovalStatus | No | `PENDING` | **MUST be PENDING on creation** |
| `created_by` | string | No | `"AI"` | **MUST be "AI" for agent output** |
| `simulation_only` | boolean | No | `true` | **MUST be true** |
| `schema_version` | string | No | `"1.0"` | Schema version for compatibility |
| `generated_at` | string (ISO 8601) | No | Current UTC timestamp | Generation timestamp |
| `agent_version` | string | No | `"0.1.0"` | Agent version that produced this ability |
| `generation_trace` | GenerationTrace | No | `null` | Audit trail (model, tools, tokens) |

### MitreMapping Fields

| Field | Type | Required | Example |
|---|---|---|---|
| `tactic` | string | **Yes** | `"credential-access"` |
| `technique` | string | **Yes** | `"T1003"` |
| `sub_technique` | string \| null | No | `"T1003.001"` |

### Executor Fields

| Field | Type | Required | Example |
|---|---|---|---|
| `name` | ExecutorType | **Yes** | `"powershell"`, `"bash"`, `"cmd"`, `"aws_cli"`, `"az_cli"` |
| `platform` | Platform | **Yes** | `"windows"`, `"linux"`, `"macos"`, `"cloud_aws"` |
| `privilege_required` | PrivilegeLevel | **Yes** | `"admin"`, `"user"`, `"root"` |
| `command` | string | **Yes** | Simulation command with safety marker |
| `payload_description` | string | **Yes** | Human-readable description of the simulation |
| `cleanup_procedure` | string | **Yes** | Command(s) to reverse changes |

### ThreatIntelContext Fields

| Field | Type | Required | Example |
|---|---|---|---|
| `associated_groups` | List[string] | No (default []) | `["APT29", "APT28"]` |
| `associated_tools` | List[string] | No (default []) | `["Mimikatz", "ProcDump"]` |
| `recent_campaigns` | List[string] | No (default []) | `["SolarWinds (2020)"]` |
| `detection_guidance` | string \| null | No (default null) | Detection advice |

---

## Enums

### ApprovalStatus

| Value | Description | Who Sets It |
|---|---|---|
| `PENDING` | Awaiting human review | **Agent** (only valid creation state) |
| `APPROVED` | Human approved for execution | Backend |
| `REJECTED` | Human rejected | Backend |
| `EXECUTABLE` | Ready for execution pipeline | Backend |
| `BLOCKED` | Permanently blocked | Backend |

### AttackCategory

| Value | MITRE Tactic | Description |
|---|---|---|
| `credential_access` | TA0006 | Credential dumping, Kerberos attacks, password stores |
| `privilege_escalation` | TA0004 | Exploit elevation, abuse elevation controls |
| `persistence` | TA0003 | Autostart, scheduled tasks, account creation |
| `lateral_movement` | TA0008 | Remote services, lateral tool transfer |
| `defense_evasion` | TA0005 | Masquerading, obfuscation, indicator removal |
| `command_and_control` | TA0011 | C2 channels, encrypted channels, protocol tunneling |
| `discovery` | TA0007 | Account discovery, network scanning |
| `collection` | TA0009 | Data from local/network systems |
| `exfiltration` | TA0010 | Exfil over C2, alternative protocols |
| `cloud_iam_abuse` | TA0004/TA0006 | Cloud account abuse, token theft, metadata |
| `active_directory_abuse` | TA0006/TA0008 | Kerberoasting, DCSync, Golden Ticket |
| `web_application_simulation` | TA0001 | Exploit public-facing apps (injection, API abuse) |
| `network_signaling` | TA0011 | DNS-based C2, protocol tunneling |

### Platform

| Value | OS / Environment | Executor Types |
|---|---|---|
| `windows` | Windows | powershell, cmd |
| `linux` | Linux | bash, sh |
| `macos` | macOS | zsh, bash |
| `cloud_aws` | AWS | aws_cli, curl, python |
| `cloud_azure` | Azure | az_cli, curl, python |
| `cloud_gcp` | GCP | gcloud_cli, curl, python |

### PrivilegeLevel

| Value | Description |
|---|---|
| `user` | Standard unprivileged user account |
| `admin` | Administrator / sudo access |
| `system` | Windows SYSTEM / Linux root-equivalent service |
| `root` | Linux/macOS root |

---

## Examples

### Example 1: Credential Access — Kerberoasting

```json
{
  "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "name": "Kerberoasting via SetSPN and Rubeus",
  "description": "Simulates Kerberoasting attack to extract service account TGS tickets for offline cracking. Commonly used by FIN6 and Wizard Spider for lateral privilege escalation in Active Directory environments.",
  "attack_category": "active_directory_abuse",
  "mitre_mapping": {
    "tactic": "credential-access",
    "technique": "T1558",
    "sub_technique": "T1558.003"
  },
  "threat_intel_context": {
    "associated_groups": ["FIN6", "Wizard Spider", "APT29"],
    "associated_tools": ["Rubeus", "Impacket", "GetUserSPNs.py"],
    "recent_campaigns": ["Ryuk ransomware lateral movement (2019-2021)"],
    "detection_guidance": "Monitor for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption. Alert on service ticket requests from non-service accounts."
  },
  "executors": [
    {
      "name": "powershell",
      "platform": "windows",
      "privilege_required": "user",
      "command": "# SIMULATION ONLY — T1558.003\n# List SPNs in the domain\nsetspn -T $env:USERDNSDOMAIN -Q */*\n# Request TGS ticket (simulation — does not export)\nAdd-Type -AssemblyName System.IdentityModel\nNew-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/sim-db.corp.local:1433'",
      "payload_description": "Enumerates Service Principal Names and requests a Kerberos TGS ticket for a simulated SPN. Does not export or crack the ticket. Triggers Event ID 4769 for detection validation.",
      "cleanup_procedure": "# No persistent changes made. TGS ticket expires with session."
    }
  ],
  "approval_status": "PENDING",
  "created_by": "AI",
  "simulation_only": true,
  "schema_version": "1.0"
}
```

### Example 2: Defense Evasion — Masquerading

```json
{
  "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "name": "Process Masquerading via Renamed System Binary",
  "description": "Simulates defense evasion by renaming a legitimate system binary to mimic trusted processes. Commonly used by APT32 and Turla to evade process-level detection.",
  "attack_category": "defense_evasion",
  "mitre_mapping": {
    "tactic": "defense-evasion",
    "technique": "T1036",
    "sub_technique": "T1036.003"
  },
  "threat_intel_context": {
    "associated_groups": ["APT32", "Turla", "Lazarus Group"],
    "associated_tools": ["Custom loaders", "Renamed system utilities"],
    "recent_campaigns": ["OceanLotus campaigns (2018-2023)"],
    "detection_guidance": "Compare process image path with expected path for the process name. Monitor for file renames of system binaries. Use YARA rules for binary hash vs. name mismatches."
  },
  "executors": [
    {
      "name": "powershell",
      "platform": "windows",
      "privilege_required": "user",
      "command": "# SIMULATION ONLY — T1036.003\n$simDir = \"$env:TEMP\\sim_masquerade\"\nNew-Item -ItemType Directory -Path $simDir -Force\nCopy-Item C:\\Windows\\System32\\calc.exe \"$simDir\\svchost.exe\"\nWrite-Host \"SIMULATION: Renamed calc.exe as svchost.exe at $simDir\"",
      "payload_description": "Copies calc.exe to a temp directory with a name mimicking svchost.exe. Demonstrates how attackers masquerade processes. No actual malicious behavior.",
      "cleanup_procedure": "Remove-Item -Recurse -Force \"$env:TEMP\\sim_masquerade\" -ErrorAction SilentlyContinue"
    },
    {
      "name": "bash",
      "platform": "linux",
      "privilege_required": "user",
      "command": "# SIMULATION ONLY — T1036.003\nmkdir -p /tmp/sim_masquerade\ncp /usr/bin/whoami /tmp/sim_masquerade/systemd\necho 'SIMULATION: Renamed whoami as systemd at /tmp/sim_masquerade'",
      "payload_description": "Copies whoami binary with a name mimicking systemd. Demonstrates Linux masquerading technique. No privilege escalation or code execution.",
      "cleanup_procedure": "rm -rf /tmp/sim_masquerade"
    }
  ],
  "approval_status": "PENDING",
  "created_by": "AI",
  "simulation_only": true,
  "schema_version": "1.0"
}
```

---

## Validation Rules

All 18 rules are enforced by Layer 6 (Safety & Governance) before any ability is output. Rules 1–15 and 18 are hard blocks; rules 16–17 produce warnings for human review.

| # | Rule | Check | Failure Action |
|---|---|---|---|
| 1 | `approval_status == PENDING` | Must be PENDING on creation | **BLOCKED** |
| 2 | `simulation_only == true` | Must be true | **BLOCKED** |
| 3 | `created_by == "AI"` | Must be "AI" | **BLOCKED** |
| 4 | MITRE technique valid | `technique` must exist in Neo4j graph | **BLOCKED** |
| 5 | MITRE tactic valid | `tactic` must match technique's kill chain phase | **BLOCKED** |
| 6 | Executor present | `len(executors) >= 1` | **BLOCKED** |
| 7 | Simulation marker | Every `command` must contain `SIMULATION ONLY` | **BLOCKED** |
| 8 | Cleanup procedure | Every executor has non-empty `cleanup_procedure` | **BLOCKED** |
| 9 | Command blocklist | No command matches blocklist regex | **BLOCKED** |
| 10 | Schema valid | Pydantic `Ability.model_validate()` succeeds | **BLOCKED** |
| 11 | Description length | `len(description) >= 50` | **BLOCKED** |
| 12 | Name present | `len(name) >= 5` | **BLOCKED** |
| 13 | UUID format | `id` is valid UUIDv4 or UUIDv5 | **BLOCKED** |
| 14 | Timestamp valid | `generated_at` is valid ISO 8601 datetime | **BLOCKED** |
| 15 | Platform coherence | Executor name/platform match; no cross-shell syntax | **BLOCKED** |
| 16 | Command syntax | Command parses in target shell grammar | **WARN** — flag for review |
| 17 | Known binary check | Referenced binaries exist in OS-default allowlist | **WARN** — flag for review |
| 18 | Executor name valid | `executor.name` is valid `ExecutorType` enum value | **BLOCKED** |

---

## Schema Versioning

| Version | Date | Changes |
|---|---|---|
| `1.0` | Feb 2026 | Initial schema release |

### Versioning Strategy

- `schema_version` field on every ability for forward compatibility
- Breaking changes increment major version (e.g., 1.0 → 2.0)
- Additive changes increment minor version (e.g., 1.0 → 1.1)
- Backend should accept abilities matching its supported major version
- Export JSON Schema via `Ability.model_json_schema()` for backend contract validation
