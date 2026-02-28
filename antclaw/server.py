import argparse
import asyncio
import json
import logging
import os
import pathlib
import signal
import sys
import time
from typing import Any

logger = logging.getLogger("antclaw.server")

DEFAULT_PORT     = 8765
DEFAULT_BIND     = "127.0.0.1"
DEFAULT_UPSTREAM = "ws://127.0.0.1:18789"

# WebSocket handshake magic bytes
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ──────────────────────────────────────────────────────────────────────────────
# .env loader (no external deps)
# ──────────────────────────────────────────────────────────────────────────────

def _load_dotenv(path: pathlib.Path | None = None) -> None:
    candidates = [path] if path else [
        pathlib.Path(".env"),
        pathlib.Path(__file__).parent.parent / ".env",
    ]
    for p in candidates:
        if p and p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
            logger.debug("Loaded .env from %s", p)
            break


# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

def resolve_config(
    port: int | str | None = None,
    bind: str | None = None,
    upstream: str | None = None,
    token: str | None = None,
    dotenv_path: pathlib.Path | None = None,
) -> dict:
    _load_dotenv(dotenv_path)

    resolved_port     = port     or os.environ.get("ANTCLAW_PORT")     or DEFAULT_PORT
    resolved_bind     = bind     or os.environ.get("ANTCLAW_BIND")     or DEFAULT_BIND
    resolved_upstream = upstream or os.environ.get("ANTCLAW_UPSTREAM") or DEFAULT_UPSTREAM
    resolved_token    = token    or os.environ.get("ANTCLAW_TOKEN")    or ""

    try:
        resolved_port = int(resolved_port)
    except (TypeError, ValueError):
        logger.warning("Invalid port %r — using default %d", resolved_port, DEFAULT_PORT)
        resolved_port = DEFAULT_PORT

    source = "explicit" if port else ("env" if os.environ.get("ANTCLAW_PORT") else "default")

    return {
        "port":     resolved_port,
        "bind":     resolved_bind,
        "upstream": resolved_upstream,
        "token":    resolved_token,
        "source":   source,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Scanner helper — safe import, never crashes the relay
# ──────────────────────────────────────────────────────────────────────────────

def _safe_scan(text: str, channel: str = "unknown",
               agent_id: str = "relay", acp_message: dict | None = None) -> dict:
    try:
        from antclaw.scanner import scan
        return scan(
            text=text,
            channel=channel,
            agent_id=agent_id,
            acp_message=acp_message,
        )
    except Exception as e:
        logger.debug("scan() error: %s", e)
        return {"detected": False, "severity": "none", "error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket relay — one instance per client connection
# ──────────────────────────────────────────────────────────────────────────────

class _RelaySession:
    """
    Handles one OpenClaw client ↔ antclaw relay ↔ real gateway connection.

    Flow:
      client  →  [antclaw scans]  →  upstream (real OpenClaw gateway)
      upstream →  [antclaw scans]  →  client

    Detection is logged but never blocks — pass-through always succeeds.
    Scan results are injected into server-bound responses as an
    extra "antclaw" field so developers can inspect them.
    """

    def __init__(self, client_ws, upstream_url: str, token: str,
                 server: "AntclawServer", channel: str = "unknown"):
        self._client   = client_ws        # websockets connection from OpenClaw
        self._upstream_url = upstream_url
        self._token    = token
        self._server   = server
        self._channel  = channel
        self._session_id = ""
        self._upstream = None             # websockets connection to real gateway

    # ── Direction: client → upstream ─────────────────────────────────────────

    async def _forward_to_upstream(self) -> None:
        """Read from OpenClaw client, scan, forward to real gateway."""
        try:
            async for raw in self._client:
                self._server._relay_messages += 1

                # Parse ACP message
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    # Not JSON — forward as-is, no scan
                    await self._upstream.send(raw)
                    continue

                # Extract session ID if this is session/new response or session/prompt
                method = msg.get("method", "")
                params = msg.get("params", {}) or {}
                if not self._session_id:
                    self._session_id = params.get("sessionId", "")

                # Scan the message
                text = self._extract_text(msg)
                result = _safe_scan(
                    text=text,
                    channel=self._channel,
                    agent_id=self._session_id or "relay-client",
                    acp_message=msg,
                )

                self._server._scan_count += 1
                if result.get("detected"):
                    self._server._detection_count += 1
                    logger.warning(
                        "[ANTCLAW] CLIENT→UPSTREAM | method=%s | severity=%s | session=%s",
                        method, result["severity"], self._session_id or "?",
                    )
                    self._log_findings(result, direction="client→upstream", method=method)
                    self._server._record_detection(
                        result=result, direction="client→upstream",
                        method=method, session_id=self._session_id,
                    )

                # Always forward — antclaw is detection-only, never blocks
                await self._upstream.send(raw)

        except Exception as e:
            logger.debug("client→upstream loop ended: %s", e)

    # ── Direction: upstream → client ─────────────────────────────────────────

    async def _forward_to_client(self) -> None:
        """Read from real gateway, scan, forward to OpenClaw client."""
        try:
            async for raw in self._upstream:
                self._server._relay_messages += 1

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await self._client.send(raw)
                    continue

                method = msg.get("method", "")

                # Capture session ID from session/new result
                result_data = msg.get("result", {}) or {}
                if not self._session_id and "sessionId" in result_data:
                    self._session_id = result_data["sessionId"]
                    logger.info("[ANTCLAW] Session established: %s", self._session_id)

                # Scan upstream content — tool results are the main injection vector
                text = self._extract_text(msg)
                result = _safe_scan(
                    text=text,
                    channel=self._channel,
                    agent_id=self._session_id or "relay-upstream",
                    acp_message=msg,
                )

                self._server._scan_count += 1
                if result.get("detected"):
                    self._server._detection_count += 1
                    logger.warning(
                        "[ANTCLAW] UPSTREAM→CLIENT | method=%s | severity=%s | session=%s",
                        method, result["severity"], self._session_id or "?",
                    )
                    self._log_findings(result, direction="upstream→client", method=method)
                    self._server._record_detection(
                        result=result, direction="upstream→client",
                        method=method, session_id=self._session_id,
                    )

                    # Inject antclaw scan result into the message for developers
                    # This adds an "antclaw" key to the JSON — OpenClaw ignores unknown keys
                    msg["antclaw"] = {
                        "detected":  result.get("detected"),
                        "severity":  result.get("severity"),
                        "session_id": self._session_id,
                        "layers":    list(result.get("openclaw_layers", {}).keys()),
                    }
                    raw = json.dumps(msg)

                await self._client.send(raw)

        except Exception as e:
            logger.debug("upstream→client loop ended: %s", e)

    # ── Session lifecycle ─────────────────────────────────────────────────────

    async def run(self) -> None:
        """Connect to upstream and start bidirectional relay."""
        try:
            import websockets

            headers = {}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            logger.info("[ANTCLAW] New relay session → %s", self._upstream_url)

            async with websockets.connect(
                self._upstream_url,
                additional_headers=headers or None,
                open_timeout=10.0,
            ) as upstream_ws:
                self._upstream = upstream_ws

                # Run both directions concurrently until either side closes
                done, pending = await asyncio.wait(
                    [
                        asyncio.create_task(self._forward_to_upstream()),
                        asyncio.create_task(self._forward_to_client()),
                    ],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()

        except Exception as e:
            logger.warning("[ANTCLAW] Relay session error: %s", e)
        finally:
            logger.info("[ANTCLAW] Relay session closed: %s", self._session_id or "?")
            self._server._active_sessions = max(0, self._server._active_sessions - 1)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_text(msg: dict) -> str:
        """Pull plain text out of an ACP message for the scanner."""
        parts = []
        params = msg.get("params", {}) or {}
        result = msg.get("result", {}) or {}

        # session/prompt content blocks
        for block in params.get("prompt", []):
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))

        # tool/result content blocks
        for block in params.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))

        # raw result string
        if isinstance(result, dict):
            parts.append(result.get("text", ""))

        # fallback — stringify whole params
        if not any(parts):
            parts.append(json.dumps(params)[:500])

        return " ".join(p for p in parts if p)

    @staticmethod
    def _source_type_for_method(method: str) -> str:
        return {
            "tool/result":   "tool_result",
            "canvas/push":   "web_page",
            "session/prompt":"user_message",
        }.get(method, "unknown")

    @staticmethod
    def _log_findings(result: dict, direction: str, method: str) -> None:
        for layer, layer_result in result.get("openclaw_layers", {}).items():
            for finding in layer_result.get("findings", []):
                logger.warning(
                    "  ↳ [%s] %s | layer=%s | type=%s",
                    direction, method,
                    layer, finding.get("type", "?"),
                )


# ──────────────────────────────────────────────────────────────────────────────
# Main server — HTTP + WebSocket relay in one asyncio process
# ──────────────────────────────────────────────────────────────────────────────

class AntclawServer:
    """
    Antclaw server — HTTP endpoints + WebSocket relay.

    HTTP endpoints (same port):
      GET  /health    — liveness
      GET  /ready     — readiness
      GET  /metrics   — counters
      POST /scan      — one-off scan API

    WebSocket relay (same port, path /):
      OpenClaw → antclaw → real OpenClaw gateway
      Every ACP message scanned in both directions.
    """

    def __init__(
        self,
        port: int | str | None = None,
        bind: str | None = None,
        upstream: str | None = None,
        token: str | None = None,
        dotenv_path: pathlib.Path | None = None,
    ):
        cfg = resolve_config(port, bind, upstream, token, dotenv_path)
        self.port:     int = cfg["port"]
        self.bind:     str = cfg["bind"]
        self.upstream: str = cfg["upstream"]
        self.token:    str = cfg["token"]

        self._config_source    = cfg["source"]
        self._start_time       = 0.0
        self._ready            = False
        self._scan_count       = 0
        self._detection_count  = 0
        self._relay_messages   = 0
        self._active_sessions  = 0

        # ── Auto-report state ─────────────────────────────────────────────────
        # Last scan result — updated on every detection, used for report writing
        self._last_result:         dict = {}
        # Ring buffer of recent detections for the live feed (max 200)
        self._recent_detections:   list = []
        # Where to write auto-reports (set by start() from CLI args)
        self._report_json:         pathlib.Path = pathlib.Path("reports/scan_report.json")
        self._report_html:         pathlib.Path = pathlib.Path("reports/scan_report.html")
        # Throttle: don't write more than once per second under heavy load
        self._last_report_write:   float = 0.0

        logger.info(
            "AntclawServer configured: bind=%s port=%d upstream=%s (source: %s)",
            self.bind, self.port, self.upstream, self._config_source,
        )

    # ── Auto-report ───────────────────────────────────────────────────────────

    def _record_detection(
        self,
        result: dict,
        direction: str = "unknown",
        method: str = "unknown",
        session_id: str = "",
    ) -> None:
        """
        Called on every detection. Updates the live feed and triggers
        an async report write (throttled to max once per second).
        """
        import datetime

        # Add to live feed ring buffer
        entry = {
            "timestamp": datetime.datetime.utcnow().strftime("%H:%M:%S"),
            "severity":  result.get("severity", "none"),
            "direction": direction,
            "method":    method,
            "session_id": session_id or "—",
            "layers":    list(result.get("openclaw_layers", {}).keys()),
        }
        self._recent_detections.append(entry)
        if len(self._recent_detections) > 200:
            self._recent_detections = self._recent_detections[-200:]

        # Save last result for report building
        self._last_result = result

        # Throttle writes — max once per second
        now = time.time()
        if now - self._last_report_write >= 1.0:
            self._last_report_write = now
            # Schedule the write as a background task (non-blocking)
            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(
                    lambda: asyncio.ensure_future(self._write_report_async())
                )
            except Exception:
                pass  # never crash the relay over a report write

    async def _write_report_async(self) -> None:
        """Write JSON + HTML report in a thread so it never blocks the relay."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self._write_report_sync
            )
        except Exception as e:
            logger.debug("Auto-report write failed: %s", e)

    def _write_report_sync(self) -> None:
        """Synchronous report write — runs in thread pool."""
        import datetime
        try:
            from scripts.generate_reports import write_report
        except ImportError:
            try:
                from scripts.generate_reports import write_report
            except ImportError:
                return   # generate_reports not available — skip silently

        meta = {
            "stage":           "live",
            "port":            str(self.port),
            "bind":            self.bind,
            "upstream":        self.upstream,
            "environment":     "production",
            "version":         self._get_version(),
            "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
            "relay_messages":  self._relay_messages,
            "active_sessions": self._active_sessions,
        }

        result = self._last_result or {
            "detected": False, "severity": "none",
            "openclaw_layers": {}, "summary": {},
            "total_scan_ms": 0, "agent_id": "relay", "channel": "openclaw_relay",
        }

        write_report(
            result=result,
            meta=meta,
            json_path=self._report_json,
            html_path=self._report_html,
            autorefresh=True,
            recent_detections=self._recent_detections.copy(),
        )
        logger.debug("Auto-report written → %s", self._report_html)

    @staticmethod
    def _get_version() -> str:
        try:
            from antclaw import __version__
            return __version__
        except Exception:
            return "0.0.0"

    # ── Connection router — HTTP or WebSocket? ────────────────────────────────

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Peek at the first line of the request.
        WebSocket upgrades → relay handler.
        Everything else    → HTTP handler.
        """
        try:
            raw = await asyncio.wait_for(reader.read(8192), timeout=5)
        except asyncio.TimeoutError:
            writer.close()
            return

        request = raw.decode("utf-8", errors="replace")
        first_line = request.split("\r\n")[0] if request else ""

        if "Upgrade: websocket" in request or "upgrade: websocket" in request:
            await self._handle_ws_upgrade(raw, reader, writer, request)
        else:
            await self._handle_http(raw, reader, writer, request, first_line)

    # ── WebSocket upgrade + relay ─────────────────────────────────────────────

    async def _handle_ws_upgrade(
        self,
        raw: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: str,
    ) -> None:
        """
        Complete the WebSocket handshake, then hand off to _RelaySession.
        Uses the `websockets` library's server-side helpers.
        """
        try:
            import websockets
            import websockets.server

            # Let websockets handle the handshake and give us a ServerConnection
            ws_server = await websockets.server.ServerConnection.open(
                reader, writer,
                extra_headers={},
            )

            self._active_sessions += 1
            logger.info(
                "[ANTCLAW] WebSocket client connected | active=%d",
                self._active_sessions,
            )

            session = _RelaySession(
                client_ws=ws_server,
                upstream_url=self.upstream,
                token=self.token,
                server=self,
                channel="openclaw_relay",
            )
            await session.run()

        except Exception as e:
            logger.debug("WS upgrade error: %s", e)
            # Fallback: complete handshake manually using base64 + hashlib
            await self._manual_ws_handshake_and_relay(raw, reader, writer, request)

    async def _manual_ws_handshake_and_relay(
        self,
        raw: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: str,
    ) -> None:
        """
        Manual WebSocket handshake (RFC 6455) — no websockets library needed
        for the server side. We still use websockets for the upstream connection.
        """
        import base64
        import hashlib

        # Extract Sec-WebSocket-Key
        ws_key = ""
        for line in request.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                ws_key = line.split(":", 1)[1].strip()
                break

        if not ws_key:
            writer.close()
            return

        # Build accept key
        accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID).encode()).digest()
        ).decode()

        # Send 101 Switching Protocols
        handshake = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        writer.write(handshake.encode())
        await writer.drain()

        self._active_sessions += 1
        logger.info(
            "[ANTCLAW] WebSocket (manual) client connected | active=%d",
            self._active_sessions,
        )

        # Now relay raw WebSocket frames between client and upstream
        await self._raw_frame_relay(reader, writer)

    async def _raw_frame_relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """
        Raw WebSocket frame relay using websockets for the upstream connection.
        Decodes frames from client, scans text frames, forwards everything.
        """
        try:
            import websockets

            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            async with websockets.connect(
                self.upstream,
                additional_headers=headers or None,
                open_timeout=10.0,
            ) as upstream_ws:

                async def client_to_upstream():
                    while True:
                        frame = await self._read_ws_frame(client_reader)
                        if frame is None:
                            break
                        opcode, payload = frame
                        if opcode == 0x8:  # close
                            break
                        if opcode == 0x1:  # text
                            text = payload.decode("utf-8", errors="replace")
                            self._scan_and_log(text, direction="client→upstream")
                        await upstream_ws.send(
                            payload.decode("utf-8", errors="replace")
                            if opcode == 0x1 else payload
                        )

                async def upstream_to_client():
                    async for message in upstream_ws:
                        self._relay_messages += 1
                        if isinstance(message, str):
                            result = self._scan_and_log(message, direction="upstream→client")
                            # Inject antclaw field if detection found
                            if result and result.get("detected"):
                                try:
                                    msg = json.loads(message)
                                    msg["antclaw"] = {
                                        "detected": result["detected"],
                                        "severity": result["severity"],
                                    }
                                    message = json.dumps(msg)
                                except Exception:
                                    pass
                        frame = self._build_ws_frame(
                            message.encode() if isinstance(message, str) else message,
                            opcode=0x1 if isinstance(message, str) else 0x2,
                        )
                        client_writer.write(frame)
                        await client_writer.drain()

                done, pending = await asyncio.wait(
                    [
                        asyncio.create_task(client_to_upstream()),
                        asyncio.create_task(upstream_to_client()),
                    ],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()

        except Exception as e:
            logger.debug("Raw frame relay error: %s", e)
        finally:
            self._active_sessions = max(0, self._active_sessions - 1)
            client_writer.close()

    def _scan_and_log(self, text: str, direction: str) -> dict | None:
        """Scan a raw text message, log if detected, trigger auto-report."""
        self._relay_messages += 1
        try:
            msg = json.loads(text)
        except Exception:
            return None

        method = msg.get("method", "?")
        result = _safe_scan(text=text[:500], acp_message=msg, channel="openclaw_relay")
        self._scan_count += 1
        if result.get("detected"):
            self._detection_count += 1
            logger.warning(
                "[ANTCLAW] %s | method=%s | severity=%s",
                direction, method, result["severity"],
            )
            # Auto-report: update live feed + write HTML
            self._record_detection(
                result=result,
                direction=direction,
                method=method,
            )
        return result

    @staticmethod
    async def _read_ws_frame(
        reader: asyncio.StreamReader,
    ) -> tuple[int, bytes] | None:
        """Read one WebSocket frame from raw stream. Returns (opcode, payload)."""
        try:
            header = await reader.readexactly(2)
            fin_opcode = header[0]
            mask_len   = header[1]
            opcode     = fin_opcode & 0x0F
            masked     = bool(mask_len & 0x80)
            length     = mask_len & 0x7F

            if length == 126:
                ext = await reader.readexactly(2)
                length = int.from_bytes(ext, "big")
            elif length == 127:
                ext = await reader.readexactly(8)
                length = int.from_bytes(ext, "big")

            mask_key = await reader.readexactly(4) if masked else b""
            data     = await reader.readexactly(length)

            if masked:
                data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

            return opcode, data
        except Exception:
            return None

    @staticmethod
    def _build_ws_frame(payload: bytes, opcode: int = 0x1) -> bytes:
        """Build an unmasked WebSocket frame (server → client)."""
        length = len(payload)
        header = bytearray()
        header.append(0x80 | opcode)  # FIN + opcode
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.append(126)
            header += length.to_bytes(2, "big")
        else:
            header.append(127)
            header += length.to_bytes(8, "big")
        return bytes(header) + payload

    # ── HTTP handlers ─────────────────────────────────────────────────────────

    async def _handle_http(
        self,
        raw: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: str,
        first_line: str,
    ) -> None:
        try:
            method, path, *_ = (first_line.split() + ["", ""])[:3]

            body = b""
            if "\r\n\r\n" in request:
                body = request.split("\r\n\r\n", 1)[1].encode()

            if path == "/health":
                resp = self._health_response()
            elif path == "/ready":
                resp = self._ready_response()
            elif path == "/metrics":
                resp = self._metrics_response()
            elif path == "/scan" and method == "POST":
                resp = await self._scan_response(body)
            else:
                resp = self._json_response(404, {"error": "not found", "path": path})

            writer.write(resp.encode())
            await writer.drain()
        except Exception as e:
            logger.debug("HTTP handler error: %s", e)
        finally:
            writer.close()

    def _json_response(self, status: int, data: Any) -> str:
        body = json.dumps(data, indent=2, default=str)
        status_text = {
            200: "OK", 400: "Bad Request",
            404: "Not Found", 503: "Service Unavailable",
        }.get(status, "")
        return (
            f"HTTP/1.1 {status} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )

    def _health_response(self) -> str:
        return self._json_response(200, {
            "status":           "healthy",
            "uptime_s":         round(time.time() - self._start_time, 1),
            "bind":             self.bind,
            "port":             self.port,
            "upstream":         self.upstream,
            "active_sessions":  self._active_sessions,
        })

    def _ready_response(self) -> str:
        if not self._ready:
            return self._json_response(503, {"status": "not_ready"})
        return self._json_response(200, {"status": "ready"})

    def _metrics_response(self) -> str:
        return self._json_response(200, {
            "scans_total":       self._scan_count,
            "detections_total":  self._detection_count,
            "relay_messages":    self._relay_messages,
            "active_sessions":   self._active_sessions,
            "uptime_s":          round(time.time() - self._start_time, 1),
        })

    async def _scan_response(self, body: bytes) -> str:
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return self._json_response(400, {"error": "invalid JSON body"})

        text     = payload.get("text", "")
        agent_id = payload.get("agent_id", "api-client")
        channel  = payload.get("channel", "unknown")

        result = _safe_scan(text=text, channel=channel, agent_id=agent_id)
        self._scan_count += 1
        if result.get("detected"):
            self._detection_count += 1

        return self._json_response(200, result)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(
        self,
        report_html: pathlib.Path | None = None,
        report_json: pathlib.Path | None = None,
    ) -> None:
        self._start_time = time.time()

        # Set report output paths
        if report_html:
            self._report_html = report_html
        if report_json:
            self._report_json = report_json

        # Ensure report dirs exist
        self._report_html.parent.mkdir(parents=True, exist_ok=True)
        self._report_json.parent.mkdir(parents=True, exist_ok=True)

        server = await asyncio.start_server(
            self._handle_connection, self.bind, self.port
        )

        self._ready = True
        logger.info("✅ Antclaw relay running on ws://%s:%d", self.bind, self.port)
        logger.info("   Upstream    : %s", self.upstream)
        logger.info("   HTTP        : /health  /ready  /metrics  /scan")
        logger.info("   Report HTML : %s  (auto-refreshes every 10s)", self._report_html)
        logger.info("   Report JSON : %s", self._report_json)
        logger.info("")
        logger.info("   ── How to connect OpenClaw ──────────────────────────")
        logger.info("   Change OpenClaw gateway URL to: ws://%s:%d", self.bind, self.port)
        logger.info("   ────────────────────────────────────────────────────")
        logger.info("   Open the report once — it updates automatically:")
        logger.info("   file://%s", self._report_html.resolve())
        logger.info("   ────────────────────────────────────────────────────")

        loop = asyncio.get_event_loop()
        stop_event = asyncio.Event()

        def _handle_signal():
            logger.info("Shutdown signal received")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handle_signal)
            except NotImplementedError:
                pass  # Windows

        async with server:
            await stop_event.wait()

        self._ready = False
        logger.info("Antclaw relay stopped.")

    def run(
        self,
        report_html: pathlib.Path | None = None,
        report_json: pathlib.Path | None = None,
    ) -> None:
        asyncio.run(self.start(report_html=report_html, report_json=report_json))


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antclaw-server",
        description=(
            "Antclaw — WebSocket relay + scan server for OpenClaw.\n\n"
            "Sits between OpenClaw and its gateway, scanning every ACP\n"
            "message for injection, credential leaks, destructive actions,\n"
            "and more — without ever blocking traffic (detection-only).\n\n"
            "Normal user setup:\n"
            "  1. antclaw-server --upstream ws://127.0.0.1:18789\n"
            "  2. Set OpenClaw gateway URL to ws://127.0.0.1:8765\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--port", "-p",
        type=int, default=None, metavar="PORT",
        help="Relay listen port (default 8765 / ANTCLAW_PORT env).",
    )
    parser.add_argument(
        "--bind", "-b",
        type=str, default=None, metavar="ADDRESS",
        help="Bind address (default 127.0.0.1 / ANTCLAW_BIND env).",
    )
    parser.add_argument(
        "--upstream", "-u",
        type=str, default=None, metavar="WS_URL",
        help=(
            "Real OpenClaw gateway WebSocket URL "
            "(default ws://127.0.0.1:18789 / ANTCLAW_UPSTREAM env)."
        ),
    )
    parser.add_argument(
        "--token", "-t",
        type=str, default=None, metavar="TOKEN",
        help="Bearer token for upstream connection (ANTCLAW_TOKEN env).",
    )
    parser.add_argument(
        "--env-file",
        type=pathlib.Path, default=None, metavar="PATH",
        help="Path to .env file (default: .env in project root).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Print resolved config and exit.",
    )
    parser.add_argument(
        "--report-html",
        type=pathlib.Path,
        default=pathlib.Path("reports/scan_report.html"),
        metavar="PATH",
        help=(
            "Where to write the live HTML report. "
            "Open once in browser — auto-refreshes every 10s. "
            "(default: reports/scan_report.html)"
        ),
    )
    parser.add_argument(
        "--report-json",
        type=pathlib.Path,
        default=pathlib.Path("reports/scan_report.json"),
        metavar="PATH",
        help="Where to write the live JSON report. (default: reports/scan_report.json)",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    cfg = resolve_config(args.port, args.bind, args.upstream, args.token, args.env_file)

    if args.show_config:
        print(json.dumps({k: v for k, v in cfg.items() if k != "token"}, indent=2))
        sys.exit(0)

    print(f"\n  antclaw relay  →  {cfg['bind']}:{cfg['port']}  →  {cfg['upstream']}")
    print(f"  config source  :  {cfg['source']}\n")

    server = AntclawServer(
        port=cfg["port"],
        bind=cfg["bind"],
        upstream=cfg["upstream"],
        token=cfg["token"],
    )

    print(f"  report HTML    :  {args.report_html}  (auto-refreshes every 10s)")
    print("  report JSON    :  " + str(args.report_json))
    print("  Open the report once and leave it open — it updates automatically.")
    print()

    server.run(
        report_html=args.report_html,
        report_json=args.report_json,
    )


if __name__ == "__main__":
    main()