"""
anticlaw.adapters.openclaw
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Drop-in hooks for OpenClawAdapter (SuperClaw).

Wraps send_prompt and _handle_message to run Anticlaw scans
automatically on every inter-agent message. Zero changes needed
to your existing OpenClawAdapter code — just wrap it.

Usage:
    from anticlaw.adapters.openclaw import wrap_adapter
    adapter = OpenClawAdapter(config={...})
    adapter = wrap_adapter(adapter)

    # Now every send_prompt and tool/call notification is scanned automatically
    output = await adapter.send_prompt("your prompt")
    print(output.session_metadata.get("anticlaw"))
"""
from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger("anticlaw.adapter")


def wrap_adapter(adapter: Any, channel: str = "unknown",
                 on_detection=None) -> Any:
    """
    Wrap an OpenClawAdapter instance with Anticlaw scanning.

    Args:
        adapter:      OpenClawAdapter instance from SuperClaw.
        channel:      OpenClaw channel name (e.g. "telegram", "slack").
        on_detection: Optional async callback(result) called on every detection.

    Returns:
        The same adapter instance with patched methods.
    """
    from anticlaw.scanner import scan as anticlaw_scan

    original_send_prompt = adapter.send_prompt
    original_handle_message = adapter._handle_message

    async def patched_send_prompt(prompt: str, context: dict = None):
        # Scan outbound prompt before sending
        scan_result = anticlaw_scan(
            text=prompt,
            channel=channel,
            agent_id=adapter._session_id or "unknown",
        )
        if scan_result["detected"]:
            logger.warning(
                "[ANTICLAW] Outbound prompt injection detected | severity=%s | session=%s",
                scan_result["severity"], adapter._session_id
            )
            if on_detection:
                await on_detection(scan_result)

        output = await original_send_prompt(prompt, context)

        # Scan inbound response
        if output and output.response_text:
            resp_result = anticlaw_scan(
                text=output.response_text,
                channel=channel,
                agent_id=adapter._session_id or "unknown",
                source_agent_id="openclaw_agent",
            )
            if resp_result["detected"]:
                logger.warning(
                    "[ANTICLAW] Response injection detected | severity=%s",
                    resp_result["severity"]
                )
                if on_detection:
                    await on_detection(resp_result)

            # Attach anticlaw results to session_metadata
            output.session_metadata["anticlaw"] = {
                "prompt_scan": scan_result,
                "response_scan": resp_result,
            }

        return output

    async def patched_handle_message(raw: str):
        await original_handle_message(raw)

        # Also scan tool/call and tool/result notifications
        import json
        try:
            data = json.loads(raw)
        except Exception:
            return

        method = data.get("method", "")
        if method in ("tool/call", "tool/result"):
            params_text = str(data.get("params", ""))
            result = anticlaw_scan(
                text=params_text,
                channel=channel,
                agent_id=adapter._session_id or "unknown",
                acp_message=data,
            )
            if result["detected"]:
                logger.warning(
                    "[ANTICLAW] %s notification injection | severity=%s",
                    method, result["severity"]
                )
                if on_detection:
                    await on_detection(result)

    adapter.send_prompt = patched_send_prompt
    adapter._handle_message = patched_handle_message
    return adapter