import re
import time

_SCRIPT_TAG    = re.compile(r'<\s*script', re.IGNORECASE)
_JS_URI        = re.compile(r'javascript\s*:', re.IGNORECASE)
_EVENT_HANDLER = re.compile(r'\bon\w+\s*=', re.IGNORECASE)
_IFRAME        = re.compile(r'<\s*iframe', re.IGNORECASE)
_DATA_URI      = re.compile(r'data\s*:\s*text/html', re.IGNORECASE)
_EVAL_CALL     = re.compile(r'\beval\s*\(', re.IGNORECASE)
_FETCH_CALL    = re.compile(r'\bfetch\s*\(', re.IGNORECASE)
_EXFIL_PATTERN = re.compile(r'(XMLHttpRequest|fetch|axios|sendBeacon)', re.IGNORECASE)

INJECTION_MARKERS = [
    "{{", "}}", "{%", "%}",
    "__proto__", "constructor[",
    "document.cookie", "document.write",
    "window.location", "localStorage",
]


def detect(payload: str) -> dict:
    start = time.perf_counter()
    findings = []

    if _SCRIPT_TAG.search(payload):
        findings.append({"type": "script_tag", "severity": "critical"})
    if _JS_URI.search(payload):
        findings.append({"type": "javascript_uri", "severity": "critical"})
    if _EVENT_HANDLER.search(payload):
        findings.append({"type": "event_handler_attribute", "severity": "high"})
    if _IFRAME.search(payload):
        findings.append({"type": "iframe_injection", "severity": "high"})
    if _DATA_URI.search(payload):
        findings.append({"type": "data_uri_html", "severity": "critical"})
    if _EVAL_CALL.search(payload):
        findings.append({"type": "eval_call", "severity": "critical"})
    if _EXFIL_PATTERN.search(payload):
        findings.append({"type": "network_call_in_canvas", "severity": "high"})

    for marker in INJECTION_MARKERS:
        if marker in payload:
            findings.append({"type": "template_injection_marker",
                             "marker": marker, "severity": "high"})
            break

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    if any(f["severity"] == "critical" for f in findings):
        severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        severity = "high"
    elif findings:
        severity = "medium"
    else:
        severity = "none"

    return {"detected": bool(findings), "findings": findings,
            "severity": severity, "layer": "canvas_inspector",
            "scan_ms": elapsed_ms}