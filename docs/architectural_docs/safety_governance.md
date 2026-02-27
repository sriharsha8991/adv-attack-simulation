# Safety & Governance Specification

> All generated abilities are advisory artifacts. Nothing executes without explicit human approval.

---

## Table of Contents

- [Guiding Principles](#guiding-principles)
- [Approval State Machine](#approval-state-machine)
- [Hard Validation Rules](#hard-validation-rules)
- [Command Blocklist](#command-blocklist)
- [Simulation Marker Requirements](#simulation-marker-requirements)
- [Cleanup Procedure Requirements](#cleanup-procedure-requirements)
- [Audit Metadata](#audit-metadata)
- [Non-Negotiable Constraints](#non-negotiable-constraints)
- [Safety Validation Pipeline](#safety-validation-pipeline)
- [Incident Response](#incident-response)

---

## Guiding Principles

1. **Human-in-the-Loop**: Every generated ability requires human review before any execution is possible.
2. **Simulation Only**: All commands include simulation markers. No real exploitation.
3. **Transparent Lineage**: Every ability records its full generation trace — model used, tool calls made, data sources consulted.
4. **Fail Closed**: If any safety check fails, the ability is BLOCKED. Never fail open.
5. **Defense Purpose**: Every ability exists to test defenses, not to enable attacks.

---

## Approval State Machine

```
                    ┌──────────────┐
           ┌───────►│   REJECTED   │
           │        │              │
           │        └──────┬───────┘
           │               │
           │          human overrides
           │               │
           │               ▼
    ┌──────┴───────┐     ┌──────────────┐     ┌──────────────┐
    │   PENDING    │────►│   APPROVED   │────►│  EXECUTABLE  │
    │              │     │              │     │              │
    │  (AI output) │     │(human review)│     │(scheduler OK)│
    └──────────────┘     └──────────────┘     └──────────────┘
           │
           │ safety_check_fails
           │
           ▼
    ┌──────────────┐
    │   BLOCKED    │
    │              │
    │ (auto-block) │
    └──────────────┘
```

### State Definitions

| State | Who Sets | Meaning | Allowed Transitions |
|---|---|---|---|
| `PENDING` | AI (always) | Ability generated, awaiting human review | → APPROVED, → REJECTED, → BLOCKED |
| `APPROVED` | Human reviewer | Human verified ability is safe and useful | → EXECUTABLE, → REJECTED |
| `REJECTED` | Human reviewer | Human determined ability is unsafe or invalid | → PENDING (with revision) |
| `BLOCKED` | Safety system | Auto-blocked due to safety rule violation | → PENDING (after fix) |
| `EXECUTABLE` | Scheduler/backend | Approved and scheduled for controlled execution | Terminal state |

### Invariants

- **AI never sets APPROVED, REJECTED, or EXECUTABLE** — only PENDING or BLOCKED
- Every state transition is logged with timestamp + actor + reason
- BLOCKED abilities can only return to PENDING after safety violations are corrected, never directly to APPROVED

---

## Hard Validation Rules

All 18 rules are applied to every generated ability. **All must pass** or the ability is BLOCKED (rules 1–15, 18) or flagged for human review (rules 16–17).

| # | Rule | Check | Failure Action |
|---|---|---|---|
| 1 | Approval Status | `approval_status == "PENDING"` | BLOCK — AI must never self-approve |
| 2 | Simulation Flag | `simulation_only == true` | BLOCK — all abilities must be simulation-only |
| 3 | Creator Tag | `created_by == "AI"` | BLOCK — provenance must be machine-tagged |
| 4 | MITRE Technique Valid | technique_id exists in Neo4j graph | BLOCK — no phantom techniques |
| 5 | MITRE Tactic Valid | tactic matches technique's kill chain phase | BLOCK — tactic/technique mismatch |
| 6 | Executor Present | `len(executors) >= 1` | BLOCK — abilities must have execution instructions |
| 7 | Simulation Marker | Every executor command contains simulation marker | BLOCK — no unmarked commands |
| 8 | Cleanup Present | Every executor has non-empty `cleanup_procedure` | BLOCK — no abilities without cleanup |
| 9 | Command Blocklist | No command matches blocklist regex | BLOCK — dangerous commands forbidden |
| 10 | Schema Valid | `Ability.model_validate(data)` succeeds | BLOCK — schema violation |
| 11 | Description Length | `len(description) >= 50` | BLOCK — descriptions must be meaningful |
| 12 | Name Present | `len(name) >= 5` | BLOCK — abilities must have a name |
| 13 | UUID Format | `id` is valid UUIDv4 or UUIDv5 | BLOCK — proper identification required |
| 14 | Timestamp Valid | `generated_at` is valid ISO 8601 datetime | BLOCK — audit trail requires timestamps |
| 15 | Platform Coherence | Executor name/platform match; no cross-shell syntax | BLOCK — platform mismatch |
| 16 | Command Syntax | Command parses in target shell grammar | WARN — flag for human review |
| 17 | Known Binary Check | Referenced binaries exist in OS-default allowlist | WARN — flag for human review |
| 18 | Executor Name Valid | `executor.name` is valid `ExecutorType` enum value | BLOCK — invalid executor type |

---

## Command Blocklist

Commands that are **never allowed** in generated abilities, even in simulation mode.

### Blocklist Regex Patterns

```python
COMMAND_BLOCKLIST = [
    # Destructive disk operations
    r"rm\s+-rf\s+/(?!\w)",           # rm -rf / (root wipe)
    r"format\s+[a-zA-Z]:",           # format C: (Windows disk format)
    r"dd\s+if=.*of=/dev/sd",         # dd to disk devices
    r"mkfs\.\w+\s+/dev/",            # filesystem format commands
    
    # Ransomware / encryption
    r"openssl\s+enc.*-aes.*-in\s+/", # bulk encryption of root filesystem
    r"gpg\s+--encrypt.*\*/",         # bulk GPG encryption
    r"cipher\s+/w:",                 # Windows cipher wipe
    
    # Credential exfiltration to external
    r"curl.*pastebin\.com",          # exfil to pastebin
    r"wget.*transfer\.sh",           # exfil to transfer.sh
    r"curl.*webhook\.site",          # exfil to webhook
    r"Invoke-WebRequest.*ngrok",     # exfil through ngrok
    
    # Bootloader / firmware
    r"dd.*of=/dev/sda$",             # overwrite MBR
    r"bcdedit\s+/set.*boot",         # modify boot config
    r"flashrom",                      # firmware flash
    
    # Active network attacks
    r"nmap\s+(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01]))", # nmap to non-RFC1918
    r"masscan\s+",                   # mass scanning
    r"hping3\s+",                    # packet crafting
    
    # Kernel / driver manipulation
    r"insmod\s+",                    # load kernel module
    r"modprobe\s+",                  # load kernel module
    r"sc\s+create.*binpath",         # create Windows service with binary
    
    # Credential theft to external
    r"mimikatz.*sekurlsa.*logonpasswords.*>.*\\\\", # mimikatz to network share
    r"reg\s+save.*sam.*\\\\",        # SAM dump to network share
]
```

### Blocklist Enforcement

```python
import re

def check_command_blocklist(command: str) -> tuple[bool, str | None]:
    """Check if a command matches any blocklist pattern.
    
    Returns:
        (is_safe, matched_pattern) — (True, None) if safe, (False, pattern) if blocked
    """
    for pattern in COMMAND_BLOCKLIST:
        if re.search(pattern, command, re.IGNORECASE):
            return False, pattern
    return True, None
```

### Important Notes

- Blocklist is applied to **raw command text** before any execution context
- Patterns are case-insensitive
- Both `command` and `cleanup_procedure` fields are checked
- Blocklist is **additive** — new patterns can be added, existing patterns never removed
- Blocklist carries a version number (see [Blocklist Versioning](#blocklist-versioning) below)
- If a command **must** reference a blocked pattern for educational documentation, wrap it in a comment marker: `# DOCUMENTATION-ONLY: <command>`

### Blocklist Versioning

Every ability's `generation_trace` must record the blocklist version that was active at generation time. This ensures auditability if a safety incident occurs.

```python
BLOCKLIST_VERSION = "1.0.0"  # Increment on every addition

# Stored in generation_trace:
# "blocklist_version": "1.0.0"
```

| Version | Date | Change |
|---|---|---|
| `1.0.0` | Feb 2026 | Initial blocklist (22 patterns) |

When a new pattern is added, increment the patch version (e.g., `1.0.0` → `1.0.1`). When a structural change occurs (new category), increment minor (e.g., `1.0.x` → `1.1.0`).

---

## Command Validity & Syntax Validation

> **Purpose**: The blocklist catches *dangerous* commands. This section catches *broken* commands — syntactically invalid, platform-mismatched, or referencing non-existent binaries. Without this, abilities pass all safety checks but fail at execution time.

### Why This Matters

The LLM can hallucinate:
- Non-existent cmdlets (e.g., `Invoke-Mimikatz` is not a native PowerShell cmdlet)
- Wrong syntax (mixed PowerShell/bash syntax in one command)
- Incorrect parameter flags or escaping
- References to binaries not present on a default OS install
- Platform mismatches (Windows paths in a bash executor)

### Validation Rules

| # | Rule | Check | Implementation |
|---|---|---|---|
| 15 | Platform Coherence | Executor `name` matches `platform`; command syntax matches executor type | Regex rules (see below) |
| 16 | Syntax Check | Command parses without errors in the target shell grammar | PowerShell: `[System.Management.Automation.Language.Parser]::ParseInput()` via subprocess. Bash: `bash -n <<< "$cmd"`. Python: `ast.parse()` |
| 17 | Known Binary Check | Referenced executables exist in an OS-default allowlist | Allowlist per platform (see below) |
| 18 | Executor-Name Valid | `executor.name` is a valid `ExecutorType` enum value | Pydantic enum validation |

### Platform Coherence Rules

```python
PLATFORM_COHERENCE_RULES = {
    "powershell": {
        "must_not_contain": [r"#!/bin/bash", r"#!/bin/sh", r"#!/usr/bin/env"],
        "should_contain_any": [r"\$env:", r"Get-", r"Set-", r"New-", r"Remove-", r"Write-Host", r"Invoke-"],
        "platform_must_be": ["windows"],
    },
    "cmd": {
        "must_not_contain": [r"\$env:", r"Get-Process", r"#!/bin/"],
        "should_contain_any": [r"REM ", r"echo ", r"set ", r"del ", r"copy ", r"%\w+%"],
        "platform_must_be": ["windows"],
    },
    "bash": {
        "must_not_contain": [r"\$env:", r"Get-Process", r"Write-Host", r"REM "],
        "should_contain_any": [r"#!/bin/bash", r"echo ", r"cat ", r"grep ", r"export ", r"\$\{?\w+\}?"],
        "platform_must_be": ["linux", "macos"],
    },
    "zsh": {
        "must_not_contain": [r"\$env:", r"Write-Host", r"REM "],
        "platform_must_be": ["macos", "linux"],
    },
    "aws_cli": {
        "should_contain_any": [r"aws\s+", r"aws\s+sts", r"aws\s+iam", r"aws\s+s3"],
        "platform_must_be": ["cloud_aws", "linux", "macos", "windows"],
    },
    "az_cli": {
        "should_contain_any": [r"az\s+", r"az\s+account", r"az\s+ad", r"az\s+role"],
        "platform_must_be": ["cloud_azure", "linux", "macos", "windows"],
    },
}
```

### Known Binary Allowlists (per platform)

```python
# Partial — extend as needed. Binaries not on this list trigger a WARNING (not BLOCK),
# flagging for human reviewer attention.

KNOWN_BINARIES = {
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
```

### Implementation: Validation Severity Levels

| Check | Severity | Action |
|---|---|---|
| Platform coherence `must_not_contain` violated | **ERROR** | BLOCK ability |
| Platform coherence `platform_must_be` violated | **ERROR** | BLOCK ability |
| Syntax parse failure (PowerShell/bash/python) | **WARNING** | Flag for human review, do not auto-block |
| Unknown binary (not in allowlist) | **WARNING** | Flag for human review, do not auto-block |
| Platform coherence `should_contain_any` not satisfied | **INFO** | Log only, do not block |

> **Design Choice**: Syntax validation and unknown-binary checks produce **warnings**, not hard blocks. LLM-generated commands may use legitimate but uncommon patterns. The human reviewer makes the final call. Only platform coherence violations hard-block.

### Integration with Safety Pipeline

These rules (15–18) are inserted into the existing safety validation pipeline between step 7 (Blocklist Check) and step 8 (Cleanup Check).

---

## Simulation Marker Requirements

Every executor command must contain at least one simulation marker to distinguish generated abilities from real attack commands.

### Required Markers (at least one per executor)

```python
SIMULATION_MARKERS = [
    "# SIMULATION",
    "# ADVERSARY-SIMULATION",
    "# CALDERA-COMPATIBLE",
    "# SIMULATION-ONLY-DO-NOT-EXECUTE",
    "Write-Host '[SIMULATION]'",     # PowerShell
    "echo '[SIMULATION]'",           # Bash
    "REM SIMULATION",                # Windows CMD
    ":: SIMULATION",                 # Windows CMD comment
]
```

### Marker Validation

```python
def validate_simulation_markers(executor: Executor) -> bool:
    """Check that every executor command contains a simulation marker."""
    command_text = executor.command.lower()
    has_marker = any(
        marker.lower() in command_text 
        for marker in SIMULATION_MARKERS
    )
    return has_marker
```

### Marker Placement Rules

1. **First line**: The simulation marker must appear as the first line of the command block
2. **Every block**: If a command has multiple logical sections, each section starts with a marker
3. **Cleanup too**: Cleanup commands also contain simulation markers
4. **Parser-safe**: Markers are placed as comments in the target language's syntax

Example:
```powershell
# SIMULATION - Kerberoasting Detection Test
# ADVERSARY-SIMULATION - MITRE T1558.003
Write-Host '[SIMULATION] Starting Kerberoasting simulation'
$SPNs = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
foreach ($SPN in $SPNs) {
    Write-Host "[SIMULATION] Found SPN: $($SPN.ServicePrincipalName)"
    # In real attack: Request-SPNTicket would be called here
    Write-Host "[SIMULATION] Would request TGS ticket for: $($SPN.Name)"
}
Write-Host '[SIMULATION] Complete - Review security logs for Event ID 4769'
```

---

## Cleanup Procedure Requirements

Every executor must include a cleanup procedure that reverses any changes made during simulation.

### Cleanup Rules

| Rule | Description |
|---|---|
| Every executor has cleanup | `cleanup_procedure` field is a non-empty string |
| Cleanup matches action | If a file is created, cleanup deletes it |
| Cleanup matches scope | If a registry key is set, cleanup removes it |
| Cleanup is safe | Cleanup procedure passes the same blocklist check |
| Cleanup logs itself | Cleanup procedure includes logging/echo statements |

> **Note**: The canonical field name is `cleanup_procedure` (string), as defined in the Pydantic `Executor` model in `src/models/ability.py`. Multi-step cleanup should be joined with newlines within the single string field.

### Cleanup Examples

```json
{
  "command": "# SIMULATION\nNew-Item -Path 'C:\\Windows\\Temp\\simulation_test.txt' -Value 'test'",
  "cleanup_procedure": "# SIMULATION CLEANUP\nRemove-Item -Path 'C:\\Windows\\Temp\\simulation_test.txt' -Force -ErrorAction SilentlyContinue\nWrite-Host '[SIMULATION] Cleanup complete'"
}
```

---

## Audit Metadata

Every ability carries full generation traceability.

### Required Audit Fields

Every ability's `generation_trace` field conforms to the `GenerationTrace` Pydantic model (see [ability_schema.md](ability_schema.md)):

```json
{
  "generated_at": "2026-02-20T14:30:00Z",
  "agent_version": "0.1.0",
  "schema_version": "1.0",
  "generation_trace": {
    "model": "gemini-3-flash-preview",
    "tools_called": [
      "query_techniques_by_tactic('credential-access')",
      "get_technique_details('T1558.003')",
      "get_intrusion_sets_for_technique('T1558.003')",
      "get_detection_guidance('T1558.003')"
    ],
    "reasoning_steps": 9,
    "total_tokens": 4200,
    "blocklist_version": "1.0.0",
    "validation_warnings": []
  }
}
```

> **Note**: `generated_at`, `agent_version`, and `schema_version` are top-level Ability fields.
> The `generation_trace` object contains only LLM/pipeline audit data as defined by `GenerationTrace`.

### Audit Log Format

Safety decisions are logged to `output/safety_audit.jsonl`:

```jsonl
{"timestamp": "2026-02-20T14:30:01Z", "ability_id": "abc-123", "rule": "simulation_marker", "result": "PASS"}
{"timestamp": "2026-02-20T14:30:01Z", "ability_id": "abc-123", "rule": "command_blocklist", "result": "PASS"}
{"timestamp": "2026-02-20T14:30:01Z", "ability_id": "def-456", "rule": "command_blocklist", "result": "FAIL", "detail": "matched: curl.*pastebin"}
```

---

## Non-Negotiable Constraints

These rules are hardcoded and cannot be overridden by configuration, prompts, or user input.

| # | Constraint | Enforcement |
|---|---|---|
| 1 | AI output is always `PENDING` | Hardcoded in composition layer. No config to change. |
| 2 | AI output is always `simulation_only: true` | Hardcoded in composition layer. No config to change. |
| 3 | AI output is always `created_by: "AI"` | Hardcoded in composition layer. No config to change. |
| 4 | Command blocklist is always checked | Safety layer cannot be disabled. Pipeline enforces. |
| 5 | Human approval required before execution | API layer rejects PENDING abilities for execution endpoint. |
| 6 | No real credentials in abilities | LLM system prompt + post-validation regex. |
| 7 | No external network targets | Blocklist + validation restricts to RFC 1918 ranges. |
| 8 | Full generation trace on every ability | Composition layer auto-populates. Non-optional field. |
| 9 | Cleanup required on every executor | Safety layer blocks abilities without cleanup. |
| 10 | Audit log on every safety check | Safety layer writes to JSONL unconditionally. |

---

## Safety Validation Pipeline

The safety layer runs as a sequential pipeline. Each check is independent and mandatory.

```
Ability (from composition)
    │
    ▼
┌────────────────────┐
│ 1. Schema Validate │──FAIL──► BLOCKED
│    (Pydantic)      │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 2. Status Check    │──FAIL──► BLOCKED
│    (PENDING only)  │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 3. Simulation Flag │──FAIL──► BLOCKED
│    (true only)     │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 4. Creator Check   │──FAIL──► BLOCKED
│    (AI only)       │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 5. MITRE Validate  │──FAIL──► BLOCKED
│    (graph lookup)  │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 6. Marker Check    │──FAIL──► BLOCKED
│    (simulation)    │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 7. Blocklist Check │──FAIL──► BLOCKED
│    (regex scan)    │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 7a. Platform       │──FAIL──► BLOCKED
│    Coherence       │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 7b. Executor Name  │──FAIL──► BLOCKED
│    Enum Valid      │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 7c. Syntax Check   │──WARN──► FLAG for human review
│    (shell parse)   │
└────────┬───────────┘
         │ PASS/WARN
         ▼
┌────────────────────┐
│ 7d. Binary Check   │──WARN──► FLAG for human review
│    (allowlist)     │
└────────┬───────────┘
         │ PASS/WARN
         ▼
┌────────────────────┐
│ 8. Cleanup Check   │──FAIL──► BLOCKED
│    (non-empty)     │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 9. Content Check   │──FAIL──► BLOCKED
│    (name, desc)    │
└────────┬───────────┘
         │ PASS
         ▼
┌────────────────────┐
│ 10. ID + Timestamp │──FAIL──► BLOCKED
│     (format check) │
└────────┬───────────┘
         │ PASS
         ▼
    ✅ VALIDATED
    (write to output + audit log)
```

### Implementation Pattern

```python
class SafetyValidator:
    def __init__(self, graph_client):
        self.graph = graph_client
        # Hard rules (BLOCK on failure)
        self.hard_rules = [
            self._check_schema,
            self._check_status,
            self._check_simulation_flag,
            self._check_creator,
            self._check_mitre_mapping,
            self._check_simulation_markers,
            self._check_command_blocklist,
            self._check_platform_coherence,   # NEW — rule 15
            self._check_executor_name_enum,   # NEW — rule 18
            self._check_cleanup,
            self._check_content,
            self._check_identity,
        ]
        # Soft rules (WARN — flag for human review, do not auto-block)
        self.soft_rules = [
            self._check_command_syntax,        # NEW — rule 16
            self._check_known_binaries,        # NEW — rule 17
        ]
    
    def validate(self, ability: Ability) -> ValidationResult:
        results = []
        warnings = []
        
        for rule in self.hard_rules:
            result = rule(ability)
            results.append(result)
            self._log_audit(ability.id, rule.__name__, result)
        
        for rule in self.soft_rules:
            result = rule(ability)
            warnings.append(result)
            self._log_audit(ability.id, rule.__name__, result, level="WARN")
        
        all_hard_passed = all(r.passed for r in results)
        has_warnings = any(not w.passed for w in warnings)
        
        return ValidationResult(
            passed=all_hard_passed,
            ability_id=ability.id,
            checks=results,
            warnings=warnings,
            needs_human_review=has_warnings,
            final_status="PENDING" if all_hard_passed else "BLOCKED"
        )
```

---

## Incident Response

If a safety violation bypasses automated checks:

1. **Immediate**: Remove the affected ability from output directory
2. **Investigate**: Review audit log to identify which check failed
3. **Patch**: Add new blocklist pattern or validation rule
4. **Revalidate**: Run all existing abilities through updated safety pipeline
5. **Document**: Record the incident in `output/safety_incidents.md`

Safety violations are **not** security incidents in the traditional sense — they are quality issues in an advisory-output system. However, they must be treated with urgency because the output is intended for security-sensitive contexts.
