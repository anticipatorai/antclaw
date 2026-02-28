#!/usr/bin/env python3
"""
antclaw/setup_wizard.py
────────────────────────
Interactive setup wizard — run once, protected forever.

Usage:
    antclaw-setup

What it does automatically:
    1. Checks antclaw is installed correctly
    2. Finds OpenClaw's gateway URL (scans config files)
    3. Finds a free port
    4. Writes a .env config so you never type flags again
    5. Starts the relay
    6. Opens the live report in your browser

Users never need to know about ports, URLs, or config files.
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

# ── Terminal colours (work on Windows 10+ and all Unix) ──────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
DIM    = "\033[2m"


def _supports_color() -> bool:
    if platform.system() == "Windows":
        # Enable VT100 on Windows 10+
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = _supports_color()


def _c(text: str, *codes: str) -> str:
    if not _COLOR:
        return text
    return "".join(codes) + text + RESET


def ok(msg: str)   -> None: print(f"  {_c('✅', GREEN)}  {msg}")
def warn(msg: str) -> None: print(f"  {_c('⚠️ ', YELLOW)} {msg}")
def err(msg: str)  -> None: print(f"  {_c('❌', RED)}  {msg}")
def info(msg: str) -> None: print(f"  {_c('ℹ️ ', CYAN)}  {msg}")
def step(n: int, total: int, msg: str) -> None:
    print(f"\n{_c(f'[{n}/{total}]', BOLD + CYAN)} {_c(msg, BOLD)}")


def _banner() -> None:
    print()
    print(_c("  ╔══════════════════════════════════════╗", CYAN))
    print(_c("  ║    ", CYAN) + _c("ant", BOLD + CYAN) + _c("claw", BOLD) + _c(" — Setup Wizard              ║", CYAN))
    print(_c("  ║  Runtime protection for OpenClaw     ║", CYAN))
    print(_c("  ╚══════════════════════════════════════╝", CYAN))
    print()


def _divider() -> None:
    print(_c("  " + "─" * 42, DIM))


# ── Step 1: Check installation ────────────────────────────────────────────────

def check_installation() -> bool:
    step(1, 6, "Checking installation")
    all_ok = True

    # Python version
    major, minor = sys.version_info[:2]
    if major >= 3 and minor >= 10:
        ok(f"Python {major}.{minor} ✓")
    else:
        err(f"Python {major}.{minor} — need 3.10+")
        info("Download from https://python.org")
        all_ok = False

    # antclaw itself
    try:
        import antclaw
        version = getattr(antclaw, "__version__", "unknown")
        ok(f"antclaw {version} installed ✓")
    except ImportError:
        err("antclaw not found")
        info("Run:  pip install antclaw")
        all_ok = False

    # websockets (needed for relay)
    try:
        import websockets
        ok(f"websockets installed ✓")
    except ImportError:
        warn("websockets not installed — installing now...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "websockets", "-q"],
                timeout=60,
            )
            ok("websockets installed ✓")
        except Exception as e:
            err(f"Could not install websockets: {e}")
            info("Run manually:  pip install websockets")
            all_ok = False

    return all_ok


# ── Step 2: Find OpenClaw gateway URL ─────────────────────────────────────────

# Known locations where OpenClaw stores its config on each OS
_OPENCLAW_CONFIG_PATHS = {
    "Windows": [
        pathlib.Path(os.environ.get("APPDATA", ""), "OpenClaw", "config.json"),
        pathlib.Path(os.environ.get("LOCALAPPDATA", ""), "OpenClaw", "config.json"),
        pathlib.Path(os.environ.get("USERPROFILE", ""), ".openclaw", "config.json"),
        pathlib.Path(os.environ.get("USERPROFILE", ""), "AppData", "Roaming", "OpenClaw", "config.json"),
        pathlib.Path(os.environ.get("USERPROFILE", ""), "AppData", "Local", "OpenClaw", "config.json"),
    ],
    "Darwin": [  # macOS
        pathlib.Path.home() / "Library" / "Application Support" / "OpenClaw" / "config.json",
        pathlib.Path.home() / ".openclaw" / "config.json",
        pathlib.Path.home() / ".config" / "openclaw" / "config.json",
    ],
    "Linux": [
        pathlib.Path.home() / ".config" / "openclaw" / "config.json",
        pathlib.Path.home() / ".openclaw" / "config.json",
        pathlib.Path("/etc") / "openclaw" / "config.json",
    ],
}

_DEFAULT_GATEWAY = "ws://127.0.0.1:18789"

# Keys OpenClaw might use for its gateway URL in config.json
_GATEWAY_KEYS = [
    "gateway", "gatewayUrl", "gateway_url", "wsUrl", "ws_url",
    "target", "serverUrl", "server_url", "host", "endpoint",
]


def _parse_gateway_from_config(path: pathlib.Path) -> str | None:
    """Try to extract the OpenClaw gateway URL from a config file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in _GATEWAY_KEYS:
            val = data.get(key, "")
            if isinstance(val, str) and val.startswith("ws"):
                return val
        # Nested: data.server.url, data.openclaw.gateway, etc.
        for section in data.values():
            if isinstance(section, dict):
                for key in _GATEWAY_KEYS:
                    val = section.get(key, "")
                    if isinstance(val, str) and val.startswith("ws"):
                        return val
    except Exception:
        pass
    return None


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_common_ports() -> str | None:
    """Try common OpenClaw gateway ports."""
    common = [18789, 18790, 18791, 8789, 9000, 9001]
    for port in common:
        if _port_open("127.0.0.1", port):
            return f"ws://127.0.0.1:{port}"
    return None


def find_openclaw_gateway() -> str:
    step(2, 6, "Finding OpenClaw gateway")

    system = platform.system()
    config_paths = _OPENCLAW_CONFIG_PATHS.get(system, _OPENCLAW_CONFIG_PATHS["Linux"])

    # 1. Try reading config files
    for path in config_paths:
        if path.exists():
            gateway = _parse_gateway_from_config(path)
            if gateway:
                ok(f"Found in config: {path.name}")
                ok(f"Gateway URL: {_c(gateway, CYAN)}")
                return gateway
            else:
                info(f"Config found at {path} but no gateway URL — using default")

    # 2. Try probing common ports
    probed = _probe_common_ports()
    if probed:
        ok(f"OpenClaw detected on {_c(probed, CYAN)}")
        return probed

    # 3. Fall back to default
    warn(f"Could not auto-detect OpenClaw gateway")
    info(f"Using default: {_c(_DEFAULT_GATEWAY, CYAN)}")
    info("If this is wrong, edit the .env file after setup")
    return _DEFAULT_GATEWAY


# ── Step 3: Find a free port ──────────────────────────────────────────────────

def find_free_port(preferred: int = 8765) -> int:
    step(3, 6, "Choosing relay port")

    # Try preferred first
    if not _port_open("127.0.0.1", preferred):
        ok(f"Port {preferred} is free ✓")
        return preferred

    warn(f"Port {preferred} is in use — finding another...")
    for port in range(8766, 8800):
        if not _port_open("127.0.0.1", port):
            ok(f"Using port {port}")
            return port

    # Last resort: let OS pick
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ok(f"Using port {port}")
    return port


# ── Step 4: Write .env config ─────────────────────────────────────────────────

_ENV_PATH = pathlib.Path(".env")
_REPORT_HTML = pathlib.Path("reports") / "scan_report.html"
_REPORT_JSON = pathlib.Path("reports") / "scan_report.json"


def write_env_config(gateway: str, port: int) -> None:
    step(4, 6, "Saving config")

    env_content = f"""# antclaw configuration
# Generated by antclaw-setup — edit as needed

ANTCLAW_PORT={port}
ANTCLAW_BIND=127.0.0.1
ANTCLAW_UPSTREAM={gateway}

# Uncomment and set if your OpenClaw requires a bearer token:
# ANTCLAW_TOKEN=your-token-here
"""
    _ENV_PATH.write_text(env_content, encoding="utf-8")
    ok(f"Config saved to {_c(str(_ENV_PATH.resolve()), CYAN)}")
    info("Edit this file anytime to change settings — no need to re-run setup")


# ── Step 5: Start the relay ───────────────────────────────────────────────────

def start_relay(port: int, gateway: str) -> subprocess.Popen | None:
    step(5, 6, "Starting antclaw relay")

    report_dir = _REPORT_HTML.parent
    report_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "antclaw.server",
        "--port",        str(port),
        "--upstream",    gateway,
        "--report-html", str(_REPORT_HTML),
        "--report-json", str(_REPORT_JSON),
        "--log-level",   "WARNING",   # quiet in wizard mode
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP
                           if platform.system() == "Windows" else 0),
        )

        # Give it 2 seconds to start
        time.sleep(2)

        if proc.poll() is not None:
            # Process already exited — something went wrong
            stderr = proc.stderr.read().decode("utf-8", errors="replace")
            err("Relay failed to start")
            if stderr:
                info(f"Error: {stderr[:200]}")
            return None

        # Verify it's actually listening
        if _port_open("127.0.0.1", port):
            ok(f"Relay running on {_c(f'ws://127.0.0.1:{port}', CYAN)} ✓")
            ok(f"Forwarding to {_c(gateway, CYAN)}")
            return proc
        else:
            warn("Relay started but not responding yet — may need a moment")
            return proc

    except FileNotFoundError:
        err("Could not start relay — is antclaw installed?")
        info("Run:  pip install antclaw")
        return None
    except Exception as e:
        err(f"Unexpected error starting relay: {e}")
        return None


# ── Step 6: Open report in browser ───────────────────────────────────────────

def open_report() -> None:
    step(6, 6, "Opening live report")

    # Write an initial empty report so the browser has something to show
    try:
        from scripts.generate_reports import write_report
    except ImportError:
        try:
            from scripts.generate_reports import write_report
        except ImportError:
            write_report = None

    if write_report:
        import datetime
        write_report(
            result={
                "detected": False, "severity": "none",
                "openclaw_layers": {}, "summary": {},
                "total_scan_ms": 0, "agent_id": "relay",
                "channel": "openclaw_relay", "base": {},
            },
            meta={
                "stage": "live",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "environment": "production",
                "version": _get_version(),
            },
            json_path=_REPORT_JSON,
            html_path=_REPORT_HTML,
            autorefresh=True,
            recent_detections=[],
        )

    report_url = _REPORT_HTML.resolve().as_uri()
    try:
        webbrowser.open(report_url)
        ok(f"Report opened in browser ✓")
        info(f"URL: {_c(report_url, CYAN)}")
        info("The report auto-refreshes every 10 seconds — leave it open")
    except Exception:
        warn("Could not auto-open browser")
        info(f"Open manually: {_c(report_url, CYAN)}")


def _get_version() -> str:
    try:
        from antclaw import __version__
        return __version__
    except Exception:
        return "0.0.0"


# ── Final instructions ────────────────────────────────────────────────────────

def print_final_instructions(port: int, gateway: str) -> None:
    _divider()
    print()
    print(_c("  🎉  antclaw is running!", BOLD + GREEN))
    print()
    print(_c("  One thing left to do:", BOLD))
    print()
    print(f"  In OpenClaw settings, change the gateway URL to:")
    print()
    print(f"    {_c(f'ws://127.0.0.1:{port}', BOLD + CYAN)}")
    print()
    print(f"  (was: {_c(gateway, DIM)})")
    print()
    _divider()
    print()
    print(_c("  How it works:", BOLD))
    print(f"  OpenClaw → antclaw relay → real OpenClaw gateway")
    print(f"  Every message scanned automatically. Nothing blocked.")
    print()
    print(_c("  To stop antclaw:", BOLD))
    print(f"  Press Ctrl+C in this window")
    print()
    print(_c("  To start again later:", BOLD))
    print(f"  antclaw-server   (reads .env automatically)")
    print()
    _divider()
    print()


# ── Installer scripts ─────────────────────────────────────────────────────────

def write_installer_scripts(port: int, gateway: str) -> None:
    """Write platform installer scripts so users can double-click next time."""

    # Windows .bat
    bat = pathlib.Path("start_antclaw.bat")
    bat.write_text(
        f"@echo off\n"
        f"title antclaw — OpenClaw Protection\n"
        f"echo Starting antclaw relay...\n"
        f"pip install antclaw -q\n"
        f"antclaw-server\n"
        f"pause\n",
        encoding="utf-8",
    )

    # Mac/Linux .sh
    sh = pathlib.Path("start_antclaw.sh")
    sh.write_text(
        f"#!/bin/bash\n"
        f"echo 'Starting antclaw relay...'\n"
        f"pip install antclaw -q\n"
        f"antclaw-server\n",
        encoding="utf-8",
    )
    try:
        sh.chmod(0o755)
    except Exception:
        pass

    info(f"Windows users: double-click {_c('start_antclaw.bat', CYAN)} next time")
    info(f"Mac/Linux:     run {_c('./start_antclaw.sh', CYAN)} next time")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    _banner()

    print(_c("  This wizard will set up antclaw in about 10 seconds.", DIM))
    print(_c("  No technical knowledge required.", DIM))
    print()

    # Step 1 — check installation
    if not check_installation():
        print()
        err("Setup cannot continue — fix the errors above first.")
        sys.exit(1)

    # Step 2 — find OpenClaw
    gateway = find_openclaw_gateway()

    # Step 3 — find free port
    port = find_free_port()

    # Step 4 — write .env
    write_env_config(gateway, port)

    # Step 5 — start relay
    proc = start_relay(port, gateway)
    if proc is None:
        print()
        err("Setup failed at relay start — check errors above.")
        sys.exit(1)

    # Step 6 — open browser
    open_report()

    # Write installer scripts for next time
    write_installer_scripts(port, gateway)

    # Show final instructions
    print_final_instructions(port, gateway)

    # Keep wizard alive so relay process stays running
    try:
        print(_c("  antclaw is running. Press Ctrl+C to stop.\n", DIM))
        proc.wait()
    except KeyboardInterrupt:
        print()
        ok("antclaw stopped.")
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()