"""
anticlaw.extended.pairing_bypass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DM pairing bypass detection.

OpenClaw uses a pairing system — unknown senders get a code before
the agent processes their messages. This layer detects attempts to
social-engineer past pairing via authority claims or false approvals.
"""

from __future__ import annotations
import re
import time

PAIRING_BYPASS_PHRASES = [
    "i am already paired",
    "pairing was approved",
    "skip the pairing step",
    "i have the access code",
    "the admin already approved me",
    "pairing is complete",
    "i was pre-approved",
    "bypass the pairing",
    "ignore the pairing",
    "pairing not required",
    "i have been whitelisted",
    "i am on the allowlist",
    "i am allowlisted",
    "already verified",
    "verification complete",
    "i have clearance",
    "security team approved",
    "developer approved",
    "owner approved this",
    "openclaw approved",
]

PAIRING_CODE_PATTERN = re.compile(r"\bpair(?:ing)?\s*(?:code)?\s*[:\-]?\s*([A-Z0-9]{4,8})\b", re.IGNORECASE)
FAKE_APPROVAL_PATTERN = re.compile(
    r"(pre.?approved|already\s+approved|admin\s+approved|authorized\s+by|cleared\s+by)",
    re.IGNORECASE
)


def detect(text: str) -> dict:
    start = time.perf_counter()
    findings = []
    text_lower = text.lower()

    for phrase in PAIRING_BYPASS_PHRASES:
        if phrase in text_lower:
            findings.append({
                "type": "pairing_bypass_phrase",
                "phrase": phrase,
                "severity": "high",
            })
            break

    if FAKE_APPROVAL_PATTERN.search(text):
        findings.append({
            "type": "fake_approval_claim",
            "severity": "high",
        })

    code_match = PAIRING_CODE_PATTERN.search(text)
    if code_match:
        findings.append({
            "type": "pairing_code_in_message",
            "code_preview": code_match.group(0)[:20],
            "severity": "medium",
            "note": "message contains what looks like a pairing code — verify legitimacy",
        })

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": severity,
        "layer": "pairing_bypass",
        "scan_ms": elapsed_ms,
    }