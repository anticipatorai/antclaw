"""
anticlaw.core.acp
~~~~~~~~~~~~~~~~~~
ACP (Agent Communication Protocol) message inspector.

OpenClaw speaks JSON-RPC 2.0 over WebSocket. This layer scans
the full ACP message structure — not just text content — for
injection attempts embedded in protocol fields, dangerous method
calls, and malformed messages that could exploit parsing.

ACP methods monitored:
  session/prompt   — user → agent (highest risk)
  tool/call        — agent → tool (execution risk)
  tool/result      — tool → agent (injection via tool output)
  canvas/push      — agent → canvas (XSS / content injection)
  session/new      — session creation (parameter tampering)
  initialize       — protocol init (version/capability spoofing)
"""

from __future__ import annotations

import re
import time

# Methods that carry user-controlled content — highest scrutiny
HIGH_RISK_METHODS: frozenset[str] = frozenset({
    "session/prompt",
    "tool/result",
    "canvas/push",
})

# Methods that trigger execution — flag unexpected callers
EXECUTION_METHODS: frozenset[str] = frozenset({
    "tool/call",
    "session/spawn",
    "node/invoke",
})

# Methods that should only come from trusted sources
PRIVILEGED_METHODS: frozenset[str] = frozenset({
    "initialize",
    "session/patch",
    "gateway/config",
    "elevated",
})

# Suspicious parameter keys that shouldn't appear in normal ACP traffic
SUSPICIOUS_PARAM_KEYS: list[str] = [
    "system_prompt",
    "override",
    "bypass",
    "elevated",
    "admin",
    "debug",
    "unsafe",
    "unrestricted",
    "jailbreak",
    "injection",
]

# Content block types — only these are valid in session/prompt
VALID_CONTENT_TYPES: frozenset[str] = frozenset({
    "text", "image", "document", "tool_use", "tool_result"
})

# Regex for detecting injected instructions inside content blocks
_SYSTEM_IN_CONTENT = re.compile(
    r'(system\s*:|<\s*system\s*>|\[system\]|<!--\s*system)',
    re.IGNORECASE
)

_ROLE_OVERRIDE = re.compile(
    r'(you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on)',
    re.IGNORECASE
)


def _scan_content_blocks(blocks: list, method: str) -> list[dict]:
    """Scan ACP content blocks for embedded injection."""
    findings = []
    if not isinstance(blocks, list):
        return findings

    for i, block in enumerate(blocks):
        if not isinstance(block, dict):
            continue

        block_type = block.get("type", "")

        # Unknown content block type
        if block_type not in VALID_CONTENT_TYPES:
            findings.append({
                "type": "unknown_content_block_type",
                "block_index": i,
                "block_type": block_type,
                "severity": "high",
            })

        # Scan text content for injection patterns
        text = block.get("text", "")
        if text:
            if _SYSTEM_IN_CONTENT.search(text):
                findings.append({
                    "type": "system_instruction_in_content_block",
                    "block_index": i,
                    "preview": text[:100],
                    "severity": "critical",
                })
            if _ROLE_OVERRIDE.search(text):
                findings.append({
                    "type": "role_override_in_content_block",
                    "block_index": i,
                    "preview": text[:100],
                    "severity": "critical",
                })

    return findings


def _scan_params(params: dict) -> list[dict]:
    """Scan ACP params dict for suspicious keys."""
    findings = []
    if not isinstance(params, dict):
        return findings

    params_lower = {k.lower(): v for k, v in params.items()}

    for key in SUSPICIOUS_PARAM_KEYS:
        if key in params_lower:
            findings.append({
                "type": "suspicious_param_key",
                "key": key,
                "severity": "high",
            })

    # sessionId should always be a string — tampering often uses non-string
    session_id = params.get("sessionId")
    if session_id is not None and not isinstance(session_id, str):
        findings.append({
            "type": "malformed_session_id",
            "value_type": type(session_id).__name__,
            "severity": "high",
        })

    return findings


def scan_acp_message(message: dict) -> dict:
    """
    Scan a full ACP JSON-RPC message for security issues.

    Args:
        message: Parsed ACP message dict with jsonrpc, method, params fields.

    Returns:
        Detection result consistent with anticipator layer format.
    """
    start = time.perf_counter()
    findings: list[dict] = []

    if not isinstance(message, dict):
        return {
            "detected": True,
            "severity": "high",
            "findings": [{"type": "invalid_message_format", "severity": "high"}],
            "layer": "acp_inspector",
        }

    method = message.get("method", "")
    params = message.get("params", {}) or {}
    msg_id = message.get("id")

    # ── 1. Privileged method called from unexpected direction ────────────────
    if method in PRIVILEGED_METHODS and msg_id is None:
        # Privileged methods should always be request/response (have id)
        findings.append({
            "type": "privileged_method_as_notification",
            "method": method,
            "severity": "high",
        })

    # ── 2. Scan params for suspicious keys ──────────────────────────────────
    findings.extend(_scan_params(params))

    # ── 3. Scan content blocks in session/prompt ─────────────────────────────
    if method == "session/prompt":
        prompt_blocks = params.get("prompt", [])
        findings.extend(_scan_content_blocks(prompt_blocks, method))

    # ── 4. Scan tool/result for injection via tool output ────────────────────
    if method == "tool/result":
        content = params.get("content", [])
        if isinstance(content, list):
            findings.extend(_scan_content_blocks(content, method))
        # Also check raw result string
        result_str = params.get("result", "")
        if isinstance(result_str, str) and _SYSTEM_IN_CONTENT.search(result_str):
            findings.append({
                "type": "system_instruction_in_tool_result",
                "preview": result_str[:100],
                "severity": "critical",
            })

    # ── 5. canvas/push — scan for script injection ───────────────────────────
    if method == "canvas/push":
        payload = str(params.get("content", ""))
        if re.search(r'<script', payload, re.IGNORECASE):
            findings.append({
                "type": "script_tag_in_canvas_push",
                "severity": "critical",
            })
        if re.search(r'javascript:', payload, re.IGNORECASE):
            findings.append({
                "type": "javascript_uri_in_canvas_push",
                "severity": "critical",
            })

    # ── 6. Protocol version spoofing ─────────────────────────────────────────
    if method == "initialize":
        proto_version = params.get("protocolVersion")
        if proto_version is not None and not isinstance(proto_version, int):
            findings.append({
                "type": "malformed_protocol_version",
                "value": str(proto_version)[:50],
                "severity": "medium",
            })

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    # Severity rollup
    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif any(f["severity"] == "medium" for f in findings):
        severity = "medium"
    elif findings:
        severity = "warning"
    else:
        severity = "none"

    return {
        "detected": bool(findings),
        "method": method,
        "findings": findings,
        "severity": severity,
        "layer": "acp_inspector",
        "scan_ms": elapsed_ms,
    }