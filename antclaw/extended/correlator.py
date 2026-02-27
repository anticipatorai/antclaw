"""
anticlaw.extended.correlator — Cross-channel attack correlation.

If the same injection pattern arrives from multiple channels within
a short time window, that is a coordinated attack — not coincidence.
This layer tracks detections across channels and fires when the same
pattern hits more than one channel within the correlation window.

Phase 2 feature — requires detections from other layers to be fed in.

Usage:
    from anticlaw.extended.correlator import record_detection, detect_coordinated

    # Feed in each detection as it happens
    record_detection(channel="telegram", pattern="ignore_instructions", severity="critical")
    record_detection(channel="whatsapp", pattern="ignore_instructions", severity="critical")

    result = detect_coordinated()
"""
from __future__ import annotations
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

CORRELATION_WINDOW_SECONDS = 60
MIN_CHANNELS_FOR_COORDINATED = 2

@dataclass
class _Detection:
    channel: str
    pattern: str
    severity: str
    timestamp: float = field(default_factory=time.time)


_detections: list[_Detection] = []
_lock = threading.Lock()


def record_detection(channel: str, pattern: str, severity: str) -> None:
    with _lock:
        _detections.append(_Detection(channel=channel, pattern=pattern, severity=severity))
        # prune old detections outside window
        cutoff = time.time() - CORRELATION_WINDOW_SECONDS
        _detections[:] = [d for d in _detections if d.timestamp >= cutoff]


def clear() -> None:
    with _lock:
        _detections.clear()


def detect_coordinated() -> dict:
    start = time.perf_counter()
    findings = []
    now = time.time()
    cutoff = now - CORRELATION_WINDOW_SECONDS

    with _lock:
        recent = [d for d in _detections if d.timestamp >= cutoff]

    # Group by pattern
    by_pattern: dict[str, list[_Detection]] = defaultdict(list)
    for d in recent:
        by_pattern[d.pattern].append(d)

    for pattern, hits in by_pattern.items():
        channels = set(h.channel for h in hits)
        if len(channels) >= MIN_CHANNELS_FOR_COORDINATED:
            findings.append({
                "type": "coordinated_cross_channel_attack",
                "pattern": pattern,
                "channels": sorted(channels),
                "hit_count": len(hits),
                "window_seconds": CORRELATION_WINDOW_SECONDS,
                "severity": "critical",
            })

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    return {
        "detected": bool(findings),
        "findings": findings,
        "severity": "critical" if findings else "none",
        "layer": "cross_channel_correlator",
        "scan_ms": elapsed_ms,
        "detections_in_window": len(recent),
    }