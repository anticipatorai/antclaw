import copy
import threading
import time

IMMUTABLE_SESSION_KEYS = ["sessionId", "agentId", "workspace"]
SENSITIVE_SESSION_KEYS = ["elevated", "model", "sendPolicy", "thinkingLevel", "verboseLevel", "groupActivation"]
INJECTION_RISK_KEYS = frozenset({"elevated", "bypass", "unsafe", "override", "admin", "debug", "permissions"})

_baselines: dict = {}
_lock = threading.Lock()


def set_baseline(session_id: str, state: dict) -> None:
    with _lock:
        _baselines[session_id] = copy.deepcopy(state)


def clear_baseline(session_id: str) -> None:
    with _lock:
        _baselines.pop(session_id, None)


def detect(session_id: str, current_state: dict) -> dict:
    start = time.perf_counter()
    findings = []

    with _lock:
        baseline = _baselines.get(session_id)

    if baseline is None:
        return {
            "detected": False, "findings": [], "severity": "none",
            "layer": "session_drift",
            "note": f"no baseline for session {session_id!r} — call set_baseline() at session start",
            "scan_ms": 0.0,
        }

    for key in IMMUTABLE_SESSION_KEYS:
        b_val = baseline.get(key)
        c_val = current_state.get(key)
        if b_val is not None and c_val is not None and b_val != c_val:
            findings.append({"type": "immutable_session_key_changed", "key": key,
                             "baseline": str(b_val), "current": str(c_val), "severity": "critical"})

    for key in SENSITIVE_SESSION_KEYS:
        b_val = baseline.get(key)
        c_val = current_state.get(key)
        if b_val is not None and c_val is not None and b_val != c_val:
            findings.append({"type": "sensitive_session_key_changed", "key": key,
                             "baseline": str(b_val), "current": str(c_val), "severity": "high"})

    for key in set(current_state) - set(baseline):
        severity = "critical" if key in INJECTION_RISK_KEYS else "medium"
        findings.append({"type": "new_session_key_injected", "key": key,
                         "value": str(current_state[key])[:100], "severity": severity})

    for key in set(baseline) - set(current_state):
        severity = "critical" if key in IMMUTABLE_SESSION_KEYS else "high"
        findings.append({"type": "session_key_removed", "key": key,
                         "baseline_value": str(baseline[key])[:100], "severity": severity})

    if not baseline.get("elevated") and current_state.get("elevated"):
        findings.append({"type": "elevated_flag_activated", "severity": "critical",
                         "detail": "elevated changed to True mid-session"})

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "none"

    return {"detected": bool(findings), "session_id": session_id,
            "findings": findings, "severity": severity,
            "layer": "session_drift", "scan_ms": elapsed_ms}