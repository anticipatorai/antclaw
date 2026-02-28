import asyncio
import time
import logging

logger = logging.getLogger("antclaw.scanner")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "warning": 1, "none": 0}

def _highest(severities):
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0), default="none")


def _load_anticipator_scan():
    try:
        from anticipator.detection.scanner import scan as _scan
        logger.debug("anticipator loaded via anticipator.detection.scanner")
        return _scan
    except ImportError:
        pass
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


def scan(
    text,
    agent_id="unknown",
    source_agent_id=None,
    pipeline_position=0,
    channel="unknown",
    acp_message=None,
    session_id=None,
    session_state=None,
    requested_tool=None,
    current_config=None,
    enable_correlator=False,
    # ── New detector args ──────────────────────────────────────────
    memory_content=None,          # str  — content being written to / read from memory
    memory_operation="write",     # "write" | "read"
    memory_path="",               # file path of memory entry
    indirect_content=None,        # str  — external content agent is reading
    indirect_source_type="unknown",  # "email"|"web_page"|"pdf"|"tool_result"|etc.
    indirect_source_url="",       # URL/path of external content
    outbound_content=None,        # str  — content agent is about to output/send
    outbound_destination="",      # where it's going (URL, channel, email)
    outbound_operation="output",  # "output"|"publish"|"email"|"api_send"
    enable_rate_anomaly=False,    # set True to track per-session rate metrics
):
    start_total = time.perf_counter()
    openclaw_layers = {}

    # ── Base scan (anticipator) ────────────────────────────────────────────────
    base_result = _base_scan(text, agent_id, source_agent_id, pipeline_position,
                             requested_tool, current_config)

    # ── Original layers ────────────────────────────────────────────────────────
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

    # ── NEW: Memory Poisoning ──────────────────────────────────────────────────
    if memory_content is not None:
        from antclaw.extended.memory_poison import detect as memory_detect
        openclaw_layers["memory_poison"] = memory_detect(
            content=memory_content,
            operation=memory_operation,
            memory_path=memory_path,
        )

    # ── NEW: Indirect Prompt Injection ────────────────────────────────────────
    if indirect_content is not None:
        from antclaw.extended.indirect_injection import detect as indirect_detect
        openclaw_layers["indirect_injection"] = indirect_detect(
            content=indirect_content,
            source_type=indirect_source_type,
            source_url=indirect_source_url,
        )

    # ── NEW: Destructive Action ───────────────────────────────────────────────
    # Always scan the main text for destructive commands
    from antclaw.extended.destructive_action import detect as destructive_detect
    destructive_result = destructive_detect(
        command_or_text=text,
        session_id=session_id or "",
    )
    if destructive_result["detected"]:
        openclaw_layers["destructive_action"] = destructive_result

    # ── NEW: Credential Leak ──────────────────────────────────────────────────
    # Scan outbound content if provided, otherwise scan main text
    _content_to_check_creds = outbound_content if outbound_content is not None else text
    from antclaw.extended.credential_leak import detect as cred_detect
    cred_result = cred_detect(
        content=_content_to_check_creds,
        operation=outbound_operation,
        destination=outbound_destination,
    )
    if cred_result["detected"]:
        openclaw_layers["credential_leak"] = cred_result

    # ── NEW: Rate Anomaly ─────────────────────────────────────────────────────
    if enable_rate_anomaly and session_id:
        from antclaw.extended.rate_anomaly import detect as rate_detect
        openclaw_layers["rate_anomaly"] = rate_detect(
            session_id=session_id,
            current_text=text,
        )

    # ── NEW: Data Classifier ──────────────────────────────────────────────────
    # Scan outbound content for confidential data leaks
    if outbound_content is not None:
        from antclaw.extended.data_classifier import detect as data_detect
        data_result = data_detect(
            content=outbound_content,
            destination=outbound_destination,
            operation=outbound_operation,
        )
        if data_result["detected"]:
            openclaw_layers["data_classifier"] = data_result
    elif outbound_destination:
        # Even without explicit outbound_content, scan main text if a destination is set
        from antclaw.extended.data_classifier import detect as data_detect
        data_result = data_detect(
            content=text,
            destination=outbound_destination,
            operation=outbound_operation,
        )
        if data_result["detected"]:
            openclaw_layers["data_classifier"] = data_result

    # ── Severity rollup ───────────────────────────────────────────────────────
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
        logger.warning("antclaw scan timed out after %.0fms", timeout * 1000)
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

