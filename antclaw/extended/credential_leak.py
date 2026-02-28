import re
import time


# ── Credential patterns ───────────────────────────────────────────────────────

CREDENTIAL_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, label, severity)

    # LLM API keys
    (r'sk-[A-Za-z0-9]{32,}', "openai_api_key", "critical"),
    (r'sk-ant-[A-Za-z0-9\-_]{32,}', "anthropic_api_key", "critical"),
    (r'sk-proj-[A-Za-z0-9\-_]{32,}', "openai_project_key", "critical"),

    # Telegram
    (r'\d{8,12}:[A-Za-z0-9_\-]{35}', "telegram_bot_token", "critical"),

    # Slack
    (r'xox[bpoas]-[A-Za-z0-9\-]{10,}', "slack_token", "critical"),

    # GitHub
    (r'gh[pousr]_[A-Za-z0-9]{36,}', "github_token", "critical"),
    (r'github_pat_[A-Za-z0-9_]{82}', "github_pat", "critical"),

    # AWS
    (r'AKIA[A-Z0-9]{16}', "aws_access_key", "critical"),
    (r'(?i)aws.{0,20}secret.{0,20}["\']?[A-Za-z0-9/+=]{40}', "aws_secret", "critical"),

    # Google / GCP
    (r'AIza[A-Za-z0-9_\-]{35}', "google_api_key", "critical"),
    (r'ya29\.[A-Za-z0-9_\-]{50,}', "google_oauth_token", "critical"),

    # Discord
    (r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}', "discord_token", "critical"),

    # Generic JWT
    (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "jwt_token", "high"),

    # Generic API key patterns
    (r'(?i)(api[_\-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', "generic_api_key", "high"),
    (r'(?i)(access[_\-]?token|oauth[_\-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', "oauth_token", "high"),
    (r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{20,}', "bearer_token", "high"),

    # Passwords
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?\S{8,}', "password_in_content", "high"),

    # Private keys
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "private_key", "critical"),
    (r'-----BEGIN CERTIFICATE-----', "certificate", "medium"),

    # Crypto seed phrases (12/24 word patterns)
    (r'\b([a-z]+\s){11}[a-z]+\b', "possible_crypto_seed_12w", "high"),

    # Database connection strings
    (r'(?i)(mongodb|postgresql|mysql|redis|amqp)://[^\s"\']{10,}', "db_connection_string", "critical"),
    (r'(?i)Server\s*=.*Password\s*=\s*\S+', "mssql_connection_string", "critical"),
]

_COMPILED_PATTERNS = [
    (re.compile(pattern), label, severity)
    for pattern, label, severity in CREDENTIAL_PATTERNS
]

# ── Sensitive data patterns (PII) ─────────────────────────────────────────────

PII_PATTERNS: list[tuple[str, str, str]] = [
    (r'\b\d{3}-\d{2}-\d{4}\b', "ssn_us", "high"),
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b', "credit_card_visa", "high"),
    (r'\b5[1-5][0-9]{14}\b', "credit_card_mastercard", "high"),
    (r'\b3[47][0-9]{13}\b', "credit_card_amex", "high"),
    (r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b', "iban", "medium"),
]

_COMPILED_PII = [
    (re.compile(pattern), label, severity)
    for pattern, label, severity in PII_PATTERNS
]

# ── Context that makes credential exposure worse ──────────────────────────────
_EXFIL_CONTEXT = re.compile(
    r'(send|forward|post|upload|share|email|message|curl|fetch|http)',
    re.IGNORECASE,
)


def detect(content: str, operation: str = "output", destination: str = "") -> dict:
    """
    Scan content for exposed credentials and sensitive data.

    Args:
        content:     Text to scan (agent output, memory write, tool call params).
        operation:   Context: "output", "memory_write", "tool_call", "api_send"
        destination: Where the content is going (URL, email, etc.)

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []

    # ── Credential patterns ────────────────────────────────────────────────────
    for pattern, label, base_severity in _COMPILED_PATTERNS:
        match = pattern.search(content)
        if match:
            # Escalate if being sent externally
            severity = base_severity
            if operation in ("api_send", "tool_call") and _EXFIL_CONTEXT.search(destination or ""):
                severity = "critical"

            findings.append({
                "type": "credential_exposure",
                "credential_type": label,
                "operation": operation,
                "severity": severity,
                "destination": destination[:100] if destination else "—",
                "preview": _redact(match.group(0)),
            })

    # ── PII patterns ──────────────────────────────────────────────────────────
    for pattern, label, severity in _COMPILED_PII:
        if pattern.search(content):
            findings.append({
                "type": "pii_exposure",
                "pii_type": label,
                "operation": operation,
                "severity": severity,
                "destination": destination[:100] if destination else "—",
            })

    # ── Bulk credential dump indicators ───────────────────────────────────────
    cred_count = sum(
        1 for pattern, _, _ in _COMPILED_PATTERNS
        if pattern.search(content)
    )
    if cred_count >= 3:
        findings.append({
            "type": "bulk_credential_dump",
            "credential_types_found": cred_count,
            "severity": "critical",
            "detail": "Multiple credential types found — possible config file exfiltration",
        })

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
        "operation": operation,
        "layer": "credential_leak",
        "scan_ms": elapsed_ms,
    }


def _redact(value: str) -> str:
    """Show first 4 + last 2 chars, mask the rest."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 6) + value[-2:]
