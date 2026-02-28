import re
import time

# ── Patterns that should NEVER appear in memory content ───────────────────────

# Instructions disguised as memories
_INSTRUCTION_IN_MEMORY = re.compile(
    r'(from now on|always remember to|never tell|do not reveal|ignore previous|'
    r'your new (instructions|rules|persona|identity)|'
    r'when (asked|someone asks|the user asks).*?(say|respond|tell|claim)|'
    r'pretend (that|to be)|act as if|you (must|should|shall) always)',
    re.IGNORECASE | re.DOTALL,
)

# System-level overrides embedded in memory
_SYSTEM_OVERRIDE_IN_MEMORY = re.compile(
    r'(system\s*:|<\s*system\s*>|\[SYSTEM\]|## System|# Instructions|'
    r'## Rules|## Persona|## Identity|## Override)',
    re.IGNORECASE,
)

# Persistence triggers — attacker trying to make injection survive session resets
_PERSISTENCE_TRIGGER = re.compile(
    r'(save (this|these) (instructions?|rules?|settings?)|'
    r'remember (this|these) (forever|permanently|always)|'
    r'store (this|these) in (memory|your memory|long.?term)|'
    r'add (this|these) to (your )?(memory|notes|reminders)|'
    r'update (your )?(memory|profile|settings) (to|with))',
    re.IGNORECASE,
)

# Credential patterns — attacker trying to persist stolen credentials in memory
_CREDENTIAL_IN_MEMORY = re.compile(
    r'(api.?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}|'
    r'token\s*[:=]\s*[A-Za-z0-9_\-]{16,}|'
    r'password\s*[:=]\s*\S{8,}|'
    r'secret\s*[:=]\s*[A-Za-z0-9_\-]{16,}|'
    r'sk-[A-Za-z0-9]{32,}|'          # OpenAI key format
    r'anthropic-[A-Za-z0-9_\-]{20,})',  # Anthropic key format
    re.IGNORECASE,
)

# Backdoor triggers — activate specific behaviour on a codeword
_BACKDOOR_TRIGGER = re.compile(
    r'(when (you see|you receive|someone (says|sends|types))|'
    r'if (anyone|the user|someone) (says|asks|mentions)|'
    r'trigger\s*word\s*[:=]|activation\s*(phrase|word|code)\s*[:=]|'
    r'the word\s+\w+|upon receiving|when triggered)',
    re.IGNORECASE,
)

# Exfiltration via memory — attacker stores data to later retrieve via another channel
_EXFIL_STAGING = re.compile(
    r'(send (this|the following|above) to|'
    r'forward (this|the following) to|'
    r'email (this|the following) to|'
    r'post (this|the following) to|'
    r'upload (this|the following) to)',
    re.IGNORECASE,
)

# Suspicious memory file path patterns (OpenClaw stores memory as .md files)
_SUSPICIOUS_MEMORY_PATH = re.compile(
    r'(\.\.[\\/]|'                        # path traversal
    r'/etc/|/proc/|/sys/|'               # unix system paths
    r'C:\\Windows\\|C:\\System|'          # windows system paths
    r'\.(sh|bash|ps1|exe|py|js)\s*$)',    # executable extensions
    re.IGNORECASE,
)


def detect(content: str, operation: str = "write", memory_path: str = "") -> dict:
    """
    Scan memory content for poisoning attempts.

    Args:
        content:     Text content being written to or read from memory.
        operation:   "write" (agent writing to memory) or "read" (agent reading memory).
        memory_path: File path of the memory file being accessed (optional).

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []

    # ── 1. Instruction injection in memory content ────────────────────────────
    if _INSTRUCTION_IN_MEMORY.search(content):
        findings.append({
            "type": "instruction_injection_in_memory",
            "operation": operation,
            "severity": "critical",
            "detail": "Memory contains instruction-like patterns — possible poisoning",
            "preview": content[:120],
        })

    # ── 2. System override headers in memory ──────────────────────────────────
    if _SYSTEM_OVERRIDE_IN_MEMORY.search(content):
        findings.append({
            "type": "system_override_in_memory",
            "operation": operation,
            "severity": "critical",
            "detail": "Memory contains system/instruction headers",
            "preview": content[:120],
        })

    # ── 3. Persistence triggers ───────────────────────────────────────────────
    if _PERSISTENCE_TRIGGER.search(content):
        findings.append({
            "type": "persistence_trigger_in_memory",
            "operation": operation,
            "severity": "high",
            "detail": "Content instructs agent to save to long-term memory",
            "preview": content[:120],
        })

    # ── 4. Credentials stored in memory ──────────────────────────────────────
    if _CREDENTIAL_IN_MEMORY.search(content):
        findings.append({
            "type": "credential_stored_in_memory",
            "operation": operation,
            "severity": "critical",
            "detail": "API key, token, or password pattern found in memory content",
        })

    # ── 5. Backdoor trigger installed ────────────────────────────────────────
    if _BACKDOOR_TRIGGER.search(content):
        findings.append({
            "type": "backdoor_trigger_in_memory",
            "operation": operation,
            "severity": "critical",
            "detail": "Memory contains conditional trigger pattern — possible backdoor",
            "preview": content[:120],
        })

    # ── 6. Exfil staging via memory ───────────────────────────────────────────
    if _EXFIL_STAGING.search(content):
        findings.append({
            "type": "exfiltration_staging_in_memory",
            "operation": operation,
            "severity": "high",
            "detail": "Memory instructs agent to forward/send content externally",
            "preview": content[:120],
        })

    # ── 7. Suspicious memory file path ───────────────────────────────────────
    if memory_path and _SUSPICIOUS_MEMORY_PATH.search(memory_path):
        findings.append({
            "type": "suspicious_memory_file_path",
            "path": memory_path[:200],
            "severity": "high",
            "detail": "Memory file path contains traversal or system path",
        })

    # ── 8. Abnormal memory content length ────────────────────────────────────
    if len(content) > 10_000:
        findings.append({
            "type": "abnormal_memory_size",
            "size_chars": len(content),
            "severity": "warning",
            "detail": "Memory entry unusually large — possible data staging",
        })

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "warning"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": severity,
        "operation": operation,
        "memory_path": memory_path or "—",
        "layer": "memory_poison",
        "scan_ms": elapsed_ms,
    }
