"""anticlaw.scanner — main entry point."""
from __future__ import annotations
import asyncio
import time
import logging

logger = logging.getLogger("anticlaw.scanner")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "warning": 1, "none": 0}

def _highest(severities):
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0), default="none")


def _load_anticipator_scan():
    """
    Try every known import path for anticipator scan.

    Real Anticipator structure (from GitHub):
      anticipator/
        anticipator/
          detection/
            scanner.py   ← scan() lives here
            __init__.py
          __init__.py    ← may or may not re-export scan
    """
    # Path 1 — detection/scanner.py (actual location in repo)
    try:
        from anticipator.detection.scanner import scan as _scan
        logger.debug("anticipator loaded via anticipator.detection.scanner")
        return _scan
    except ImportError:
        pass

    # Path 2 — top-level __init__.py re-export
    try:
        from anticipator import scan as _scan
        logger.debug("anticipator loaded via anticipator.__init__")
        return _scan
    except ImportError:
        pass

    


_anticipator_scan = _load_anticipator_scan()


def _base_scan(text, agent_id, source_agent_id, pipeline_position,
               requested_tool, current_config):
    if _anticipator_scan is None:
        return {
            "detected": False, "severity": "none", "layers": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "warning": 0, "total": 0},
            "total_scan_ms": 0.0,
            "note": "anticipator not installed — run: pip install anticipator",
        }

    # Build kwargs — only pass args the installed version actually accepts
    import inspect
    try:
        sig = inspect.signature(_anticipator_scan)
        accepted = set(sig.parameters.keys())
    except Exception:
        accepted = set()

    kwargs = {"text": text, "agent_id": agent_id}
    if "source_agent_id" in accepted:
        kwargs["source_agent_id"] = source_agent_id
    if "pipeline_position" in accepted:
        kwargs["pipeline_position"] = pipeline_position
    if "agent_type" in accepted:
        kwargs["agent_type"] = "openclaw"
    if "requested_tool" in accepted:
        kwargs["requested_tool"] = requested_tool
    if "current_config" in accepted:
        kwargs["current_config"] = current_config

    try:
        return _anticipator_scan(**kwargs)
    except Exception as e:
        logger.error("anticipator scan failed: %s", e)
        return {
            "detected": False, "severity": "none", "layers": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "warning": 0, "total": 0},
            "total_scan_ms": 0.0, "error": str(e),
        }


def scan(text, agent_id="unknown", source_agent_id=None, pipeline_position=0,
         channel="unknown", acp_message=None, session_id=None, session_state=None,
         requested_tool=None, current_config=None, enable_correlator=False):

    start_total = time.perf_counter()
    openclaw_layers = {}

    base_result = _base_scan(text, agent_id, source_agent_id, pipeline_position,
                             requested_tool, current_config)

    from antclaw.core.channel import score as channel_score
    openclaw_layers["channel_trust"] = channel_score(channel)

    if acp_message:
        from antclaw.core.acp import scan_acp_message
        openclaw_layers["acp"] = scan_acp_message(acp_message)

    if session_id and session_state:
        from antclaw.core.session import detect as session_detect
        openclaw_layers["session_drift"] = session_detect(session_id, session_state)

    if session_id:
        from antclaw.extended.tool_sequence import detect as seq_detect
        openclaw_layers["tool_sequence"] = seq_detect(session_id)

    from antclaw.extended.pairing_bypass import detect as pairing_detect
    openclaw_layers["pairing_bypass"] = pairing_detect(text)

    if acp_message and acp_message.get("method") == "canvas/push":
        from antclaw.extended.canvas import detect as canvas_detect
        payload = str(acp_message.get("params", {}).get("content", ""))
        openclaw_layers["canvas"] = canvas_detect(payload)

    if enable_correlator:
        from antclaw.extended.correlator import detect_coordinated
        openclaw_layers["correlator"] = detect_coordinated()

    base_severity = base_result.get("severity", "none")
    openclaw_severities = [r.get("severity", "none") for r in openclaw_layers.values()]
    final_severity = _highest([base_severity] + openclaw_severities)
    detected = base_result.get("detected", False) or any(
        r.get("detected", False) for r in openclaw_layers.values()
    )

    summary = dict(base_result.get(
        "summary", {"critical": 0, "high": 0, "medium": 0, "warning": 0, "total": 0}
    ))
    for r in openclaw_layers.values():
        if r.get("detected"):
            sev = r.get("severity", "none")
            if sev in summary:
                summary[sev] += 1
            summary["total"] += 1

    total_ms = round((time.perf_counter() - start_total) * 1000, 3)

    return {
        "detected": detected,
        "severity": final_severity,
        "agent_id": agent_id,
        "source_agent_id": source_agent_id,
        "channel": channel,
        "session_id": session_id,
        "pipeline_position": pipeline_position,
        "input_preview": text[:100],
        "base": base_result,
        "openclaw_layers": openclaw_layers,
        "summary": summary,
        "total_scan_ms": total_ms,
    }


async def scan_async(text, timeout=0.05, **kwargs):
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: scan(text, **kwargs)),
            timeout=timeout,
        )
        return result
    except asyncio.TimeoutError:
        logger.warning("anticlaw scan timed out after %.0fms", timeout * 1000)
        return {
            "detected": True, "severity": "warning", "error": "scan_timeout",
            "agent_id": kwargs.get("agent_id", "unknown"),
            "total_scan_ms": timeout * 1000,
        }


async def scan_pipeline(messages, concurrency=10, **kwargs):
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(msg):
        async with semaphore:
            return await scan_async(
                text=msg.get("text", ""),
                agent_id=msg.get("agent_id", "unknown"),
                source_agent_id=msg.get("source_agent_id"),
                pipeline_position=msg.get("pipeline_position", 0),
                channel=msg.get("channel", "unknown"),
                acp_message=msg.get("acp_message"),
                session_id=msg.get("session_id"),
                **kwargs,
            )

    return await asyncio.gather(*[_bounded(m) for m in messages])