"""anticlaw.extended.tool_sequence — Tool call sequence anomaly detection."""
from __future__ import annotations
import threading
import time
from collections import deque

SUSPICIOUS_SEQUENCES = [
    (["bash", "http_request"],             "execute_then_exfiltrate",  "critical"),
    (["read_file", "http_request"],        "read_then_exfiltrate",     "critical"),
    (["bash", "write_file", "bash"],       "write_then_execute",       "critical"),
    (["read_file", "sessions_send"],       "read_then_relay",          "high"),
    (["bash", "sessions_send"],            "execute_then_relay",       "critical"),
    (["write_file", "http_request"],       "write_then_upload",        "high"),
    (["memory_search", "http_request"],    "memory_dump_exfiltrate",   "critical"),
    (["sessions_history", "http_request"], "history_exfiltrate",       "critical"),
    (["sessions_spawn","sessions_spawn","sessions_spawn"], "agent_flood", "high"),
    (["canvas_push", "http_request"],      "canvas_exfiltrate",        "high"),
]

_SESSION_HISTORY: dict = {}
_WINDOW_SIZE = 10
_lock = threading.Lock()


def record_tool_call(session_id: str, tool_name: str) -> None:
    with _lock:
        if session_id not in _SESSION_HISTORY:
            _SESSION_HISTORY[session_id] = deque(maxlen=_WINDOW_SIZE)
        _SESSION_HISTORY[session_id].append(tool_name.strip().lower())


def clear_session(session_id: str) -> None:
    with _lock:
        _SESSION_HISTORY.pop(session_id, None)


def _contains_sequence(history: list, sequence: list) -> bool:
    n = len(sequence)
    for i in range(len(history) - n + 1):
        if history[i:i + n] == sequence:
            return True
    return False


def detect(session_id: str) -> dict:
    start = time.perf_counter()
    findings = []

    with _lock:
        buf = _SESSION_HISTORY.get(session_id)
        history = list(buf) if buf else []

    if not history:
        return {"detected": False, "findings": [], "severity": "none",
                "layer": "tool_sequence", "scan_ms": 0.0,
                "note": "no tool history — call record_tool_call() on each tool/call event"}

    for sequence, label, sev in SUSPICIOUS_SEQUENCES:
        if _contains_sequence(history, sequence):
            findings.append({"type": "suspicious_tool_sequence",
                             "sequence": sequence, "pattern": label,
                             "severity": sev, "history_window": history})

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
    severity = "none"
    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"

    return {"detected": bool(findings), "session_id": session_id,
            "findings": findings, "severity": severity,
            "layer": "tool_sequence", "scan_ms": elapsed_ms}