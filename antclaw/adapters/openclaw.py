"""
antclaw.adapters.openclaw
~~~~~~~~~~~~~~~~~~~~~~~~~~
Drop-in hooks for OpenClawAdapter (SuperClaw).

Wraps send_prompt and _handle_message to run antclaw scans
automatically on every inter-agent message. Zero changes needed
to your existing OpenClawAdapter code — just wrap it.

Usage:
    from antclaw.adapters.openclaw import wrap_adapter

    adapter = OpenClawAdapter(config={...})
    adapter = wrap_adapter(adapter, channel="telegram")

    # Now every send_prompt and tool/call/canvas notification is scanned
    output = await adapter.send_prompt("your prompt")
    print(output.session_metadata.get("antclaw"))

on_detection callback:
    Works with BOTH sync and async callbacks:

        # async
        async def on_threat(result):
            await alert_system(result)

        # sync
        def on_threat(result):
            print(result["severity"])

        adapter = wrap_adapter(adapter, on_detection=on_threat)
"""
from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("antclaw.adapter")

# Methods whose notifications carry injection risk
_RISKY_METHODS = frozenset({"tool/call", "tool/result", "canvas/push"})

# Extract plain text from a tool/result or canvas/push params dict
def _extract_params_text(params: Any) -> str:
    """Pull readable text out of ACP params for the scanner."""
    if not isinstance(params, dict):
        return str(params)[:500]

    parts = []

    # tool/result content blocks
    for block in params.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))

    # canvas/push content
    content = params.get("content", "")
    if isinstance(content, str):
        parts.append(content)

    # tool/call arguments
    args = params.get("arguments", {})
    if args:
        parts.append(json.dumps(args)[:300])

    # raw result string
    result = params.get("result", "")
    if isinstance(result, str):
        parts.append(result)

    return " ".join(p for p in parts if p).strip() or json.dumps(params)[:500]


async def _fire_callback(callback: Callable | None, result: dict) -> None:
    """
    Call on_detection safely — works with both sync and async callbacks.
    Never raises — a bad callback must not crash the relay.
    """
    if callback is None:
        return
    try:
        ret = callback(result)
        if inspect.isawaitable(ret):
            await ret
    except Exception as e:
        logger.warning("[ANTCLAW] on_detection callback raised: %s", e)


def wrap_adapter(
    adapter: Any,
    channel: str = "unknown",
    on_detection: Callable | None = None,
) -> Any:
    """
    Wrap an OpenClawAdapter instance with antclaw scanning.

    Args:
        adapter:      OpenClawAdapter instance from SuperClaw.
                      Must have: send_prompt(), _handle_message(), _session_id
        channel:      OpenClaw channel name — sets trust level in the scanner.
                      Use values from antclaw.core.channel:
                        "imessage" | "slack" | "telegram" | "webhook" | "unknown"
        on_detection: Optional callback(result: dict) called on every detection.
                      Works with both sync and async functions.

    Returns:
        The same adapter instance with patched methods.
        All original behaviour is preserved — antclaw never blocks traffic.

    Raises:
        AttributeError: if adapter is missing send_prompt or _handle_message.
    """
    # Validate adapter has the methods we need
    for attr in ("send_prompt", "_handle_message"):
        if not hasattr(adapter, attr):
            raise AttributeError(
                f"wrap_adapter: adapter is missing '{attr}'. "
                f"Are you passing an OpenClawAdapter instance from SuperClaw?"
            )

    # Import once at wrap time, not on every call
    try:
        from antclaw.scanner import scan as _scan
    except ImportError as e:
        raise ImportError(
            "antclaw is not installed. Run: pip install antclaw"
        ) from e

    original_send_prompt    = adapter.send_prompt
    original_handle_message = adapter._handle_message

    # ── Patched send_prompt ───────────────────────────────────────────────────

    async def patched_send_prompt(
        prompt: str,
        context: dict[str, Any] | None = None,
    ):
        session_id = getattr(adapter, "_session_id", None) or "unknown"

        # 1. Scan OUTBOUND prompt before sending
        prompt_result = _scan(
            text=prompt,
            channel=channel,
            agent_id=session_id,
        )

        if prompt_result["detected"]:
            logger.warning(
                "[ANTCLAW] Outbound prompt | severity=%s | session=%s | layers=%s",
                prompt_result["severity"],
                session_id,
                list(prompt_result.get("openclaw_layers", {}).keys()),
            )
            await _fire_callback(on_detection, prompt_result)

        # 2. Call the real send_prompt
        output = await original_send_prompt(prompt, context)

        if output is None:
            # Adapter returned nothing — nothing to scan
            return output

        # 3. Scan INBOUND response text
        resp_result = {"detected": False, "severity": "none"}
        if output.response_text:
            resp_result = _scan(
                text=output.response_text,
                channel=channel,
                agent_id=session_id,
                source_agent_id="openclaw_agent",
            )
            if resp_result["detected"]:
                logger.warning(
                    "[ANTCLAW] Inbound response | severity=%s | session=%s | layers=%s",
                    resp_result["severity"],
                    session_id,
                    list(resp_result.get("openclaw_layers", {}).keys()),
                )
                await _fire_callback(on_detection, resp_result)

        # 4. Scan any tool_results collected during the exchange
        #    (the real adapter stores these in output.tool_results)
        tool_results_findings = []
        for tr in getattr(output, "tool_results", []) or []:
            tr_text = _extract_params_text(tr)
            tr_result = _scan(
                text=tr_text,
                channel=channel,
                agent_id=session_id,
                acp_message={"method": "tool/result", "params": tr},
            )
            if tr_result["detected"]:
                logger.warning(
                    "[ANTCLAW] Tool result | severity=%s | session=%s",
                    tr_result["severity"], session_id,
                )
                tool_results_findings.append(tr_result)
                await _fire_callback(on_detection, tr_result)

        # 5. Attach all antclaw results to session_metadata
        #    session_metadata is a dict on AgentOutput — safe to write
        if not isinstance(output.session_metadata, dict):
            # Shouldn't happen but guard anyway
            object.__setattr__(output, "session_metadata", {})

        output.session_metadata["antclaw"] = {
            "prompt_scan":       prompt_result,
            "response_scan":     resp_result,
            "tool_result_scans": tool_results_findings,
            "session_id":        session_id,
            "channel":           channel,
        }

        return output

    # ── Patched _handle_message ───────────────────────────────────────────────

    async def patched_handle_message(raw: str) -> None:
        # 1. Let the real adapter process the message first
        #    (so tool_calls / tool_results lists are updated before we scan)
        await original_handle_message(raw)

        # 2. Parse and scan risky notification methods
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return

        method = data.get("method", "")
        if method not in _RISKY_METHODS:
            return

        params      = data.get("params", {})
        params_text = _extract_params_text(params)
        session_id  = getattr(adapter, "_session_id", None) or "unknown"

        result = _scan(
            text=params_text,
            channel=channel,
            agent_id=session_id,
            acp_message=data,          # full ACP message — enables ACP layer
        )

        if result["detected"]:
            logger.warning(
                "[ANTCLAW] Notification | method=%s | severity=%s | session=%s | layers=%s",
                method,
                result["severity"],
                session_id,
                list(result.get("openclaw_layers", {}).keys()),
            )
            await _fire_callback(on_detection, result)


    adapter.send_prompt    = patched_send_prompt
    adapter._handle_message = patched_handle_message

    logger.info(
        "[ANTCLAW] Adapter wrapped | channel=%s | callback=%s",
        channel,
        "yes" if on_detection else "no",
    )

    return adapter