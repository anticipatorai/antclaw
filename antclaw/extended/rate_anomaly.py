import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field

# ── Thresholds ────────────────────────────────────────────────────────────────
MAX_MESSAGES_PER_MINUTE = 30
MAX_MESSAGES_PER_10S = 8
MAX_INPUT_TOKENS_ESTIMATE = 50_000   # ~200KB text
COST_BOMB_REPEAT_THRESHOLD = 50     # same pattern repeated 50+ times
MIN_SPAWN_FLOOD_COUNT = 5           # 5+ spawns in a single session = flood

# ── Cost bomb patterns ────────────────────────────────────────────────────────
_REPEAT_PATTERN = re.compile(r'(.{10,}?)\1{10,}')   # same chunk repeated 10+ times

_EXPANSION_PATTERN = re.compile(
    r'(repeat\s+the\s+(above|following|previous|this)\s+\d+\s+times?|'
    r'write\s+\d{3,}\s+(words?|sentences?|paragraphs?)|'
    r'generate\s+\d{3,}\s+(items?|examples?|variations?)|'
    r'list\s+\d{3,}|'
    r'explain\s+in\s+\d{3,}\s+words?)',
    re.IGNORECASE,
)

_NESTED_STRUCTURE = re.compile(
    r'(\[.*\[.*\[.*\[.*\[|'     # deeply nested arrays
    r'\{.*\{.*\{.*\{.*\{)',      # deeply nested dicts
)

# Unicode that expands significantly during tokenization
_UNICODE_EXPANSION = re.compile(
    r'[\u4e00-\u9fff\u3400-\u4dbf]{100,}|'    # CJK block (high token ratio)
    r'[\U00010000-\U0001f9ff]{50,}',            # Emoji/symbols block
)

# ── Per-session state ─────────────────────────────────────────────────────────

@dataclass
class _SessionMetrics:
    message_times: deque = field(default_factory=lambda: deque(maxlen=200))
    spawn_count: int = 0
    total_messages: int = 0
    total_estimated_tokens: int = 0
    first_seen: float = field(default_factory=time.time)


_sessions: dict[str, _SessionMetrics] = {}
_lock = threading.Lock()


def _get_or_create(session_id: str) -> _SessionMetrics:
    with _lock:
        if session_id not in _sessions:
            _sessions[session_id] = _SessionMetrics()
        return _sessions[session_id]


def record_message(session_id: str, text: str = "") -> None:
    """Call this on every incoming message for a session."""
    metrics = _get_or_create(session_id)
    now = time.time()
    with _lock:
        metrics.message_times.append(now)
        metrics.total_messages += 1
        metrics.total_estimated_tokens += max(1, len(text) // 4)


def record_spawn(session_id: str) -> None:
    """Call this when the session spawns a sub-agent."""
    metrics = _get_or_create(session_id)
    with _lock:
        metrics.spawn_count += 1


def clear_session(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token for English, less for CJK."""
    cjk = len(re.findall(r'[\u4e00-\u9fff]', text))
    latin = len(text) - cjk
    return (latin // 4) + (cjk * 2)


def detect(session_id: str, current_text: str = "") -> dict:
    """
    Detect rate anomalies and cost bombing for a session.

    Args:
        session_id:   Session to check.
        current_text: The current message text (for content analysis).

    Returns:
        Detection result dict.
    """
    start = time.perf_counter()
    findings = []
    now = time.time()

    # Record this message
    if current_text:
        record_message(session_id, current_text)

    metrics = _get_or_create(session_id)

    with _lock:
        times = list(metrics.message_times)
        spawn_count = metrics.spawn_count
        total_msgs = metrics.total_messages
        total_tokens = metrics.total_estimated_tokens

    # ── 1. Message flood — last 10 seconds ────────────────────────────────────
    recent_10s = sum(1 for t in times if now - t <= 10)
    if recent_10s > MAX_MESSAGES_PER_10S:
        findings.append({
            "type": "message_flood_10s",
            "messages_in_10s": recent_10s,
            "threshold": MAX_MESSAGES_PER_10S,
            "severity": "critical",
            "detail": f"{recent_10s} messages in last 10 seconds",
        })

    # ── 2. Message flood — last 60 seconds ────────────────────────────────────
    recent_60s = sum(1 for t in times if now - t <= 60)
    if recent_60s > MAX_MESSAGES_PER_MINUTE:
        findings.append({
            "type": "message_flood_60s",
            "messages_in_60s": recent_60s,
            "threshold": MAX_MESSAGES_PER_MINUTE,
            "severity": "high",
            "detail": f"{recent_60s} messages in last minute",
        })

    # ── 3. Agent spawn flood ──────────────────────────────────────────────────
    if spawn_count >= MIN_SPAWN_FLOOD_COUNT:
        findings.append({
            "type": "agent_spawn_flood",
            "spawn_count": spawn_count,
            "threshold": MIN_SPAWN_FLOOD_COUNT,
            "severity": "critical",
            "detail": f"Session spawned {spawn_count} sub-agents — possible recursive loop",
        })

    # ── Content-level cost bomb detection ─────────────────────────────────────
    if current_text:
        text_tokens = _estimate_tokens(current_text)

        # 4. Single message token overload
        if text_tokens > MAX_INPUT_TOKENS_ESTIMATE:
            findings.append({
                "type": "input_token_overload",
                "estimated_tokens": text_tokens,
                "threshold": MAX_INPUT_TOKENS_ESTIMATE,
                "severity": "high",
                "detail": f"Input ~{text_tokens:,} tokens — possible token stuffing",
            })

        # 5. Repeated pattern (token stuffing)
        if _REPEAT_PATTERN.search(current_text):
            findings.append({
                "type": "repeated_pattern_token_stuffing",
                "severity": "high",
                "detail": "Input contains highly repeated text patterns",
            })

        # 6. Explicit expansion request (cost bombing)
        if _EXPANSION_PATTERN.search(current_text):
            findings.append({
                "type": "explicit_expansion_request",
                "severity": "medium",
                "detail": "Input requests generation of very large output",
                "preview": current_text[:120],
            })

        # 7. Deeply nested structure
        if _NESTED_STRUCTURE.search(current_text):
            findings.append({
                "type": "deeply_nested_structure",
                "severity": "medium",
                "detail": "Input contains deeply nested brackets — possible parser overload",
            })

        # 8. Unicode expansion attack
        if _UNICODE_EXPANSION.search(current_text):
            findings.append({
                "type": "unicode_expansion_attack",
                "severity": "high",
                "detail": "Input contains high-token-ratio Unicode blocks",
            })

    # ── 9. Cumulative token budget overrun ────────────────────────────────────
    if total_tokens > MAX_INPUT_TOKENS_ESTIMATE * 10:
        findings.append({
            "type": "session_token_budget_exceeded",
            "total_estimated_tokens": total_tokens,
            "total_messages": total_msgs,
            "severity": "high",
            "detail": f"Session total ~{total_tokens:,} tokens across {total_msgs} messages",
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
        "session_id": session_id,
        "session_stats": {
            "total_messages": total_msgs,
            "total_estimated_tokens": total_tokens,
            "spawn_count": spawn_count,
            "messages_last_10s": recent_10s if 'recent_10s' in dir() else 0,
            "messages_last_60s": recent_60s if 'recent_60s' in dir() else 0,
        },
        "layer": "rate_anomaly",
        "scan_ms": elapsed_ms,
    }
