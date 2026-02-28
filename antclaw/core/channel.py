"""
antclaw.core.channel
~~~~~~~~~~~~~~~~~~~~~~
Channel trust scoring — OpenClaw connects to many messaging surfaces,
each with a different trust level. Messages from webhook endpoints are
untrusted by default; iMessage from a paired device is high trust.

Trust levels:
  high      — paired device, known contact, controlled surface
  medium    — allowlisted but open internet
  low       — open internet, unknown senders possible
  untrusted — external webhook, no sender verification
"""

from __future__ import annotations

CHANNEL_TRUST: dict[str, str] = {
    # High trust — paired / controlled surfaces
    "imessage":    "high",
    "bluebubbles": "high",
    "macos":       "high",
    "ios":         "high",
    "android":     "high",
    "webchat":     "high",   # local gateway webchat
    # Medium trust — allowlisted but open internet
    "slack":       "medium",
    "discord":     "medium",
    "msteams":     "medium",
    "googlechat":  "medium",
    # Low trust — open internet, unknown senders common
    "telegram":    "low",
    "whatsapp":    "low",
    "signal":      "low",
    "matrix":      "low",
    "zalo":        "low",
    # Untrusted — external triggers, no sender verification
    "webhook":     "untrusted",
    "gmail":       "untrusted",
    "unknown":     "untrusted",
}

TRUST_SEVERITY: dict[str, str] = {
    "high":      "none",
    "medium":    "none",
    "low":       "warning",
    "untrusted": "high",
}

TRUST_RANK: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "untrusted": 0,
}


def score(channel: str) -> dict:
    """
    Score the trust level of an incoming channel.

    Args:
        channel: OpenClaw channel name (e.g. "telegram", "webhook")

    Returns:
        Detection result with trust level and severity.
    """
    channel_norm = channel.strip().lower()
    trust = CHANNEL_TRUST.get(channel_norm, "untrusted")
    severity = TRUST_SEVERITY[trust]

    findings = []
    if trust in ("low", "untrusted"):
        findings.append({
            "type": "low_trust_channel",
            "channel": channel,
            "trust": trust,
            "severity": severity,
        })

    return {
        "detected": bool(findings),
        "channel": channel,
        "trust": trust,
        "findings": findings,
        "severity": severity,
        "layer": "channel_trust",
    }


def is_higher_trust(channel_a: str, channel_b: str) -> bool:
    """Return True if channel_a has higher trust than channel_b."""
    trust_a = CHANNEL_TRUST.get(channel_a.lower(), "untrusted")
    trust_b = CHANNEL_TRUST.get(channel_b.lower(), "untrusted")
    return TRUST_RANK[trust_a] > TRUST_RANK[trust_b]