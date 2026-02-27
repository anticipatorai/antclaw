"""
anticlaw/server.py
───────────────────
Anticlaw WebSocket / HTTP health server.

Supports custom port and bind address via:
  1. CLI args:       python -m anticlaw.server --port 9000 --bind 0.0.0.0
  2. Environment:    ANTICLAW_PORT=9000 ANTICLAW_BIND=0.0.0.0
  3. .env file:      loaded automatically from project root
  4. Code:           from anticlaw.server import AntclawServer; AntclawServer(port=9000, bind="0.0.0.0")

Priority: CLI > env var > .env file > default (127.0.0.1:8765)
"""

from __future__ import annotations

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

logger = logging.getLogger("anticlaw.server")

DEFAULT_PORT = 8765
DEFAULT_BIND = "127.0.0.1"


# ──────────────────────────────────────────────────────────────────────────────
# .env loader (no external deps)
# ──────────────────────────────────────────────────────────────────────────────

def _load_dotenv(path: pathlib.Path | None = None) -> None:
    """Load key=value pairs from a .env file into os.environ (won't overwrite)."""
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
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                os.environ.setdefault(key, val)  # setdefault = don't overwrite
            logger.debug("Loaded .env from %s", p)
            break


# ──────────────────────────────────────────────────────────────────────────────
# Config resolution
# ──────────────────────────────────────────────────────────────────────────────

def resolve_config(
    port: int | str | None = None,
    bind: str | None = None,
    dotenv_path: pathlib.Path | None = None,
) -> dict:
    """
    Resolve final port + bind with priority:
      explicit args > env vars > .env > defaults

    Args:
        port:        Explicit port (int or str). None = use env/default.
        bind:        Explicit bind address. None = use env/default.
        dotenv_path: Optional explicit path to .env file.

    Returns:
        dict with keys: port (int), bind (str), source (str)
    """
    _load_dotenv(dotenv_path)

    resolved_port = port or os.environ.get("ANTICLAW_PORT") or DEFAULT_PORT
    resolved_bind = bind or os.environ.get("ANTICLAW_BIND") or DEFAULT_BIND

    try:
        resolved_port = int(resolved_port)
    except (TypeError, ValueError):
        logger.warning("Invalid port %r — falling back to %d", resolved_port, DEFAULT_PORT)
        resolved_port = DEFAULT_PORT

    if not isinstance(resolved_bind, str) or not resolved_bind.strip():
        resolved_bind = DEFAULT_BIND

    source = "default"
    if port:
        source = "explicit"
    elif os.environ.get("ANTICLAW_PORT"):
        source = "env"

    return {"port": resolved_port, "bind": resolved_bind, "source": source}


# ──────────────────────────────────────────────────────────────────────────────
# Server
# ──────────────────────────────────────────────────────────────────────────────

class AntclawServer:
    """
    Lightweight anticlaw scan server.

    Exposes:
      GET  /health          — liveness check
      GET  /ready           — readiness check (returns 503 until warm)
      POST /scan            — run anticlaw scan, returns JSON result
      GET  /metrics         — basic counters in JSON

    WebSocket /ws           — stream scan results
    """

    def __init__(
        self,
        port: int | str | None = None,
        bind: str | None = None,
        dotenv_path: pathlib.Path | None = None,
    ):
        cfg = resolve_config(port, bind, dotenv_path)
        self.port: int = cfg["port"]
        self.bind: str = cfg["bind"]
        self._config_source: str = cfg["source"]
        self._start_time: float = 0.0
        self._ready: bool = False
        self._scan_count: int = 0
        self._detection_count: int = 0
        logger.info(
            "AntclawServer configured: bind=%s port=%d (source: %s)",
            self.bind, self.port, self._config_source,
        )

    # ── HTTP handlers ─────────────────────────────────────────────────────────

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5)
            request = raw.decode("utf-8", errors="replace")
            first_line = request.split("\r\n")[0] if request else ""
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
        status_text = {200: "OK", 503: "Service Unavailable", 404: "Not Found", 400: "Bad Request"}.get(status, "")
        return (
            f"HTTP/1.1 {status} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )

    def _health_response(self) -> str:
        return self._json_response(200, {
            "status": "healthy",
            "uptime_s": round(time.time() - self._start_time, 1),
            "bind": self.bind,
            "port": self.port,
        })

    def _ready_response(self) -> str:
        if not self._ready:
            return self._json_response(503, {"status": "not_ready"})
        return self._json_response(200, {"status": "ready"})

    def _metrics_response(self) -> str:
        return self._json_response(200, {
            "scans_total": self._scan_count,
            "detections_total": self._detection_count,
            "uptime_s": round(time.time() - self._start_time, 1),
        })

    async def _scan_response(self, body: bytes) -> str:
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return self._json_response(400, {"error": "invalid JSON body"})

        text = payload.get("text", "")
        agent_id = payload.get("agent_id", "api-client")
        channel = payload.get("channel", "unknown")

        try:
            from antclaw.scanner import scan
            result = scan(text=text, agent_id=agent_id, channel=channel)
        except Exception as e:
            result = {"error": str(e), "detected": False, "severity": "none"}

        self._scan_count += 1
        if result.get("detected"):
            self._detection_count += 1

        return self._json_response(200, result)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        self._start_time = time.time()
        server = await asyncio.start_server(
            self._handle_http, self.bind, self.port
        )
        self._ready = True
        logger.info("✅ Anticlaw server running on http://%s:%d", self.bind, self.port)
        logger.info("   Endpoints: /health  /ready  /metrics  /scan (POST)")

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
        logger.info("Anticlaw server stopped.")

    def run(self):
        """Convenience: run the server synchronously."""
        asyncio.run(self.start())


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anticlaw-server",
        description="Anticlaw scan server — custom port and bind address",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        metavar="PORT",
        help=(
            "Port to listen on. "
            "Falls back to ANTICLAW_PORT env var, then .env, then default 8765."
        ),
    )
    parser.add_argument(
        "--bind", "-b",
        type=str,
        default=None,
        metavar="ADDRESS",
        help=(
            "Bind address, e.g. 0.0.0.0 or 127.0.0.1. "
            "Falls back to ANTICLAW_BIND env var, then .env, then default 127.0.0.1. "
            "Use 0.0.0.0 to accept connections from all interfaces."
        ),
    )
    parser.add_argument(
        "--env-file",
        type=pathlib.Path,
        default=None,
        metavar="PATH",
        help="Path to a custom .env file (default: .env in project root).",
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
        help="Print resolved configuration and exit.",
    )
    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    cfg = resolve_config(args.port, args.bind, args.env_file)

    if args.show_config:
        print(json.dumps(cfg, indent=2))
        sys.exit(0)

    print(f"Starting anticlaw server on {cfg['bind']}:{cfg['port']} (config source: {cfg['source']})")
    server = AntclawServer(port=cfg["port"], bind=cfg["bind"])
    server.run()


if __name__ == "__main__":
    main()