"""
antclaw/extended/data_classifier.py
──────────────────────────────────────
Confidential Data Classifier & Leak Prevention.

REAL INCIDENT (Feb 22, 2026 — AwesomeAgents.ai / Lukasz Olejnik):
  An OpenClaw agent logged into a CYBERSECURITY FIRM'S internal threat
  intelligence platform, found a confidential analytical report, and
  published it on the open web — perfectly, correctly, flawlessly.

  The agent was NOT compromised. NOT injected. NOT jailbroken.
  It did EXACTLY what it was designed to do.
  Nobody told it the data was confidential.

This is the "ClawdINT incident" — no CVE, no patch, no fix.
The only defense is detecting that confidential content is about to leave
the system before it does.

This detector:
  - Classifies content by sensitivity level
  - Detects confidentiality markers being ignored
  - Flags internal/proprietary data in outbound content
  - Detects TLP (Traffic Light Protocol) violations
"""
from __future__ import annotations
import re
import time

# ── TLP (Traffic Light Protocol) markers ──────────────────────────────────────
# FIRST.org TLP v2.0 — used in cybersecurity and enterprise documents

TLP_PATTERNS = {
    "TLP:RED":    ("critical", "Only for named recipients — NEVER share"),
    "TLP:AMBER":  ("high",     "Limited sharing — recipients community only"),
    "TLP:AMBER+STRICT": ("critical", "AMBER with strict no-forward restriction"),
    "TLP:GREEN":  ("medium",   "Community sharing only — not public"),
    "TLP:CLEAR":  ("none",     "No restriction — public"),
    "TLP:WHITE":  ("none",     "No restriction — legacy TLP"),
}

_TLP_REGEX = re.compile(
    r'\bTLP\s*:\s*(RED|AMBER\+STRICT|AMBER|GREEN|CLEAR|WHITE)\b',
    re.IGNORECASE,
)

# ── Confidentiality markers ───────────────────────────────────────────────────
_CONFIDENTIAL_MARKERS = re.compile(
    r'\b(CONFIDENTIAL|STRICTLY CONFIDENTIAL|PRIVATE|PROPRIETARY|'
    r'INTERNAL ONLY|INTERNAL USE ONLY|NOT FOR DISTRIBUTION|'
    r'DO NOT DISTRIBUTE|DO NOT SHARE|DO NOT FORWARD|'
    r'RESTRICTED|CLASSIFIED|SENSITIVE|'
    r'TRADE SECRET|ATTORNEY.CLIENT PRIVILEGED|PRIVILEGED AND CONFIDENTIAL|'
    r'FOR INTERNAL USE|COMPANY CONFIDENTIAL|BUSINESS CONFIDENTIAL)\b',
    re.IGNORECASE,
)

# ── Data classification headers ───────────────────────────────────────────────
_CLASSIFICATION_HEADER = re.compile(
    r'^(Classification|Data Classification|Sensitivity|Clearance)\s*:\s*'
    r'(Confidential|Restricted|Private|Internal|Secret|Top Secret)',
    re.IGNORECASE | re.MULTILINE,
)

# ── Proprietary indicators ────────────────────────────────────────────────────
_PROPRIETARY_PATTERNS = re.compile(
    r'(©|\(c\)|All Rights Reserved|Proprietary and Confidential|'
    r'This (document|report|file|information) (is|contains) (confidential|proprietary|sensitive)|'
    r'unauthorized (disclosure|distribution|sharing|use) (is|are) (prohibited|forbidden|not permitted))',
    re.IGNORECASE,
)

# ── Internal document indicators ──────────────────────────────────────────────
_INTERNAL_DOCUMENT = re.compile(
    r'(Internal\s+Memo|Internal\s+Report|Internal\s+Only|'
    r'For\s+Internal\s+Use|Draft\s+[-–]\s+Not\s+for\s+Distribution|'
    r'Pre-?decisional|Deliberative\s+Process|'
    r'Board\s+(of\s+Directors\s+)?Confidential|'
    r'Executive\s+Summary\s+[-–]\s+Confidential|'
    r'Due\s+Diligence\s+(Report|Summary)|'
    r'M&A\s+(Confidential|Analysis)|'
    r'Merger\s+(Confidential|Analysis))',
    re.IGNORECASE,
)

# ── Threat intelligence specific markers ──────────────────────────────────────
# The ClawdINT incident was specifically threat intel
_THREAT_INTEL_MARKERS = re.compile(
    r'(Indicator of Compromise|IoC|TTPs|MITRE\s+ATT&CK|'
    r'Threat\s+Actor|APT\s*\d+|Adversary\s+Profile|'
    r'Malware\s+Sample\s+Analysis|Incident\s+Response\s+Report|'
    r'Vulnerability\s+Research\s+(Report|Disclosure)|'
    r'Zero.?Day\s+(Research|Advisory|Disclosure)|'
    r'CVE-\d{4}-\d{4,}\s+Analysis|'
    r'Pen(etration)?\s+Test\s+(Report|Results)|'
    r'Red\s+Team\s+(Report|Findings))',
    re.IGNORECASE,
)

# ── PII / personal data ───────────────────────────────────────────────────────
_PII_MARKERS = re.compile(
    r'(Date of Birth|DOB|Social Security|SSN|'
    r'Passport Number|Driver.?s License|'
    r'Medical Record|Health Insurance|HIPAA|PHI|PII|'
    r'Financial Statement|Bank Account|Account Number)',
    re.IGNORECASE,
)

# ── Destination risk ──────────────────────────────────────────────────────────
PUBLIC_DESTINATIONS = {
    "web", "internet", "public", "blog", "post", "publish",
    "twitter", "linkedin", "github", "reddit", "medium",
    "clawdint", "clawhub", "public_api",
}


def _destination_is_public(destination: str) -> bool:
    dest_lower = destination.lower()
    return any(d in dest_lower for d in PUBLIC_DESTINATIONS)


def detect(content: str, destination: str = "", operation: str = "output") -> dict:
    """
    Classify content sensitivity and detect potential leaks.

    Args:
        content:     Text about to be sent/published/stored externally.
        destination: Where it's going (URL, channel, service name).
        operation:   "output", "publish", "email", "api_send", "memory_write"

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []
    is_public_dest = _destination_is_public(destination)

    # ── 1. TLP violation ──────────────────────────────────────────────────────
    tlp_match = _TLP_REGEX.search(content)
    if tlp_match:
        tlp_level = tlp_match.group(1).upper()
        tlp_key = f"TLP:{tlp_level}"
        base_severity, tlp_desc = TLP_PATTERNS.get(tlp_key, ("high", "Unknown TLP"))
        severity = base_severity

        # Escalate if going to public destination
        if is_public_dest and tlp_level not in ("CLEAR", "WHITE"):
            severity = "critical"
            findings.append({
                "type": "tlp_violation",
                "tlp_level": tlp_key,
                "tlp_description": tlp_desc,
                "destination": destination[:100],
                "severity": severity,
                "detail": f"Content marked {tlp_key} is being sent to public destination",
            })
        elif tlp_level in ("RED", "AMBER"):
            findings.append({
                "type": "tlp_restricted_content",
                "tlp_level": tlp_key,
                "tlp_description": tlp_desc,
                "destination": destination[:100] if destination else "—",
                "severity": severity,
                "detail": f"Content marked {tlp_key} — verify destination is authorized",
            })

    # ── 2. Explicit confidentiality markers ───────────────────────────────────
    if _CONFIDENTIAL_MARKERS.search(content):
        severity = "critical" if is_public_dest else "high"
        findings.append({
            "type": "confidential_marker_in_content",
            "destination": destination[:100] if destination else "—",
            "severity": severity,
            "detail": "Content contains explicit confidentiality marking",
        })

    # ── 3. Classification headers ─────────────────────────────────────────────
    if _CLASSIFICATION_HEADER.search(content):
        findings.append({
            "type": "classified_document_header",
            "severity": "critical" if is_public_dest else "high",
            "detail": "Content has formal classification header",
        })

    # ── 4. Proprietary rights markers ─────────────────────────────────────────
    if _PROPRIETARY_PATTERNS.search(content):
        findings.append({
            "type": "proprietary_content_detected",
            "severity": "high" if is_public_dest else "medium",
            "detail": "Content contains proprietary/copyright markers",
        })

    # ── 5. Internal document markers ─────────────────────────────────────────
    if _INTERNAL_DOCUMENT.search(content):
        severity = "critical" if is_public_dest else "high"
        findings.append({
            "type": "internal_document_detected",
            "severity": severity,
            "detail": "Content identified as internal-only document",
        })

    # ── 6. Threat intelligence (ClawdINT incident pattern) ───────────────────
    if _THREAT_INTEL_MARKERS.search(content) and is_public_dest:
        findings.append({
            "type": "threat_intel_leaking_to_public",
            "destination": destination[:100],
            "severity": "critical",
            "detail": "Threat intelligence content detected going to public destination — ClawdINT-type incident",
        })

    # ── 7. PII in outbound content ────────────────────────────────────────────
    if _PII_MARKERS.search(content):
        findings.append({
            "type": "pii_in_outbound_content",
            "severity": "critical" if is_public_dest else "high",
            "detail": "Personal/health/financial data detected in outbound content",
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
        "destination": destination[:100] if destination else "—",
        "destination_is_public": is_public_dest,
        "layer": "data_classifier",
        "scan_ms": elapsed_ms,
    }
