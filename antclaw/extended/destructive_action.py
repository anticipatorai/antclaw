"""
antclaw/extended/destructive_action.py
─────────────────────────────────────────
Destructive Action Detection.

REAL INCIDENT (Summer Yue tweet, Feb 23 2026 — 9.8M views):
  OpenClaw told to "confirm before acting" proceeded to bulk-delete hundreds
  of emails. User had to physically run to their Mac mini to kill the process.
  The agent was NOT injected — it just executed destructive commands autonomously
  without human confirmation, faster than the user could stop it.

ALSO CONFIRMED: OpenClaw agents with full disk access and terminal permissions
routinely perform irreversible actions (delete, overwrite, send, transfer)
without adequate checkpointing. Kaspersky/Trend Micro documented these as
the #1 non-injection risk in production deployments.

This detector flags:
  - Destructive shell commands before execution
  - Bulk/mass operations on data
  - Irreversible actions without confirmation markers
  - Operations on sensitive file paths
  - Mass communication (bulk email/message sends)
"""
from __future__ import annotations
import re
import time

# ── Destructive command patterns ─────────────────────────────────────────────

# File/data deletion
_DELETE_PATTERN = re.compile(
    r'\b(rm\s+(-rf?|-fr?|--force|--recursive)\s*\S+|'
    r'del\s+/[fqs]\s*\S+|'                           # Windows del /f /q /s
    r'rmdir\s+/s\s*\S+|'                             # Windows rmdir /s
    r'shred\s+\S+|'                                   # secure delete
    r'wipe\s+\S+|'                                    # wipe tool
    r'trash\s+.*(--max|--all|-a)\s*\S+|'             # trash CLI bulk
    r'find\s+.*-delete|'                              # find + delete
    r'os\.remove\s*\(|os\.unlink\s*\(|'              # Python file delete
    r'shutil\.(rmtree|remove)\s*\()',                 # Python tree delete
    re.IGNORECASE,
)

# Email/message bulk operations — the inbox incident
_BULK_EMAIL_OPERATION = re.compile(
    r'(trash\s+.*inbox|'
    r'delete\s+.*\b(all|every|inbox|emails?)\b|'
    r'archive\s+.*\b(all|every|inbox|emails?)\b|'
    r'--max\s+\d{2,}|'                               # bulk limit flags (--max 20+)
    r'mark.*as.*delete|'
    r'purge.*inbox|'
    r'empty.*(?:inbox|trash|folder)|'
    r'bulk.*(delete|remove|archive)|'
    r'gog\s+gmail\s+.*-a\s)',                        # confirmed command from incident
    re.IGNORECASE,
)

# Overwrite / data destruction
_OVERWRITE_PATTERN = re.compile(
    r'(>\s*/dev/[a-z]+|'                             # redirect to device
    r'dd\s+if=.*of=|'                                # dd disk overwrite
    r'mkfs\s+\S+|'                                   # format filesystem
    r'format\s+[A-Z]:|'                              # Windows format
    r'fdisk\s+\S+|'
    r'truncate\s+--size\s*0|'
    r':\s*>\s*\S+\.(?:db|sql|json|csv|log))',        # redirect-truncate data file
    re.IGNORECASE,
)

# Permission/ownership escalation
_PERMISSION_CHANGE = re.compile(
    r'(chmod\s+(777|a\+[rwx]|o\+[rwx]|0777)\s+\S+|'
    r'chown\s+root\s+\S+|'
    r'sudo\s+(rm|chmod|chown|dd|mkfs|fdisk)|'
    r'icacls\s+.*\/grant\s+Everyone)',                # Windows grant everyone
    re.IGNORECASE,
)

# Mass external sends — bulk email/message sending
_MASS_SEND = re.compile(
    r'(send\s+(all|every|bulk|mass|emails?|everything)\s.*(to\s+\S+@\S+|externally)|'
    r'send.*from\s+(inbox|mailbox).*to\s+\S+@|'
    r'forward.*\b(all|every)\b.*\b(email|message)\b.*to|'
    r'reply.all|bcc\s*:\s*\*)',
    re.IGNORECASE,
)

# Network/data exfiltration actions
_DATA_TRANSFER = re.compile(
    r'(curl\s+.*-T\s+|'                              # curl upload
    r'curl\s+.*--data-binary\s+@|'                   # curl binary upload
    r'rsync\s+.*\s+\w+@\w+:|'                        # rsync to remote
    r'scp\s+.*\s+\w+@\w+:|'                          # scp to remote
    r'ftp\s+.*put\s+|'                               # ftp upload
    r'aws\s+s3\s+cp.*s3://|'                         # S3 upload
    r'gsutil\s+cp.*gs://)',                           # GCS upload
    re.IGNORECASE,
)

# Database destructive operations
_DATABASE_DESTROY = re.compile(
    r'(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s+|'
    r'TRUNCATE\s+(TABLE\s+)?\w+|'
    r'DELETE\s+FROM\s+\w+\s*;|'                      # DELETE without WHERE
    r'DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1)',     # DELETE all rows
    re.IGNORECASE,
)

# Loop/bulk markers that amplify destructive operations
_BULK_LOOP_MARKER = re.compile(
    r'(keep\s+loop(ing)?|'
    r'repeat\s+until|'
    r'while\s+true|'
    r'for\s+each.*in\s+(all|every)|'
    r'loop\s+until\s+(done|complete|empty|finished)|'
    r'continue\s+until\s+(all|every|inbox\s+is\s+empty))',
    re.IGNORECASE,
)

# Sensitive paths that should never be touched autonomously
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "~/.ssh/", "~/.gnupg/", "~/.aws/",
    "~/.config/", "~/Library/Keychains/",
    "C:\\Windows\\System32", "C:\\Users\\",
    ".env", "secrets.", "credentials.",
    "id_rsa", "id_ed25519", ".pem", ".p12",
]


def _check_sensitive_path(text: str) -> list[dict]:
    findings = []
    text_lower = text.lower()
    for path in SENSITIVE_PATHS:
        if path.lower() in text_lower:
            findings.append({
                "type": "operation_on_sensitive_path",
                "path": path,
                "severity": "critical",
                "detail": f"Destructive operation targets sensitive path: {path}",
            })
            break
    return findings


def detect(command_or_text: str, session_id: str = "") -> dict:
    """
    Scan a command or agent response for destructive action patterns.

    Args:
        command_or_text: The tool call, shell command, or agent response text.
        session_id:      Session identifier for context.

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []
    text = command_or_text

    # ── 1. File deletion ──────────────────────────────────────────────────────
    if _DELETE_PATTERN.search(text):
        findings.append({
            "type": "destructive_file_deletion",
            "severity": "critical",
            "detail": "Command contains destructive file deletion operation",
            "preview": text[:150],
        })

    # ── 2. Bulk email operations (Summer Yue incident) ────────────────────────
    if _BULK_EMAIL_OPERATION.search(text):
        findings.append({
            "type": "bulk_email_destruction",
            "severity": "critical",
            "detail": "Bulk email delete/archive/trash operation detected — requires confirmation",
            "preview": text[:150],
        })

    # ── 3. Data overwrite ─────────────────────────────────────────────────────
    if _OVERWRITE_PATTERN.search(text):
        findings.append({
            "type": "destructive_overwrite",
            "severity": "critical",
            "detail": "Command will overwrite or destroy data irreversibly",
            "preview": text[:150],
        })

    # ── 4. Permission escalation ──────────────────────────────────────────────
    if _PERMISSION_CHANGE.search(text):
        findings.append({
            "type": "dangerous_permission_change",
            "severity": "high",
            "detail": "Command changes file permissions to unsafe level",
            "preview": text[:150],
        })

    # ── 5. Mass send ──────────────────────────────────────────────────────────
    if _MASS_SEND.search(text):
        findings.append({
            "type": "mass_communication_send",
            "severity": "critical",
            "detail": "Bulk email/message send — could expose data or spam contacts",
            "preview": text[:150],
        })

    # ── 6. Data exfiltration transfer ─────────────────────────────────────────
    if _DATA_TRANSFER.search(text):
        findings.append({
            "type": "data_transfer_to_remote",
            "severity": "high",
            "detail": "Data upload/transfer to remote host detected",
            "preview": text[:150],
        })

    # ── 7. Database destruction ───────────────────────────────────────────────
    if _DATABASE_DESTROY.search(text):
        findings.append({
            "type": "database_destructive_operation",
            "severity": "critical",
            "detail": "SQL operation will destroy or wipe database tables",
            "preview": text[:150],
        })

    # ── 8. Bulk loop amplifier ────────────────────────────────────────────────
    if _BULK_LOOP_MARKER.search(text):
        findings.append({
            "type": "bulk_loop_amplifier",
            "severity": "high",
            "detail": "Command contains loop-until-done pattern — amplifies destructive ops",
            "preview": text[:150],
        })

    # ── 9. Sensitive path check ───────────────────────────────────────────────
    findings.extend(_check_sensitive_path(text))

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": severity,
        "session_id": session_id or "—",
        "layer": "destructive_action",
        "scan_ms": elapsed_ms,
    }
