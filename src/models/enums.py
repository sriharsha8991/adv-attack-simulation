"""Enum definitions — single source of truth for all categorical values.

These enums constrain LLM outputs and are used in:
- Pydantic model validation
- Gemini structured output schemas
- API request/response contracts
- Neo4j property values
"""

from enum import Enum


class ApprovalStatus(str, Enum):
    """Approval state machine states.

    Agent can ONLY produce PENDING.
    Backend enforces transitions:
        PENDING → APPROVED (human)
        PENDING → REJECTED (human)
        PENDING → BLOCKED  (safety pipeline — automated)
        APPROVED → EXECUTABLE (backend, after final checks)
    """

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTABLE = "EXECUTABLE"
    BLOCKED = "BLOCKED"


class AttackCategory(str, Enum):
    """Supported attack categories (Week 1 scope).

    Each maps to one or more MITRE ATT&CK tactic shortnames.
    See architecture.md Section 12 for the full mapping table.
    """

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
