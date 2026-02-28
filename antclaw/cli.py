"""
antclaw/cli.py
───────────────
Antclaw CLI — terminal entry point with pixel art logo.

Usage:
  antclaw-cli scan "some text"
  antclaw-cli scan "text" --channel webhook --agent myagent
  antclaw-cli server --port 8765 --bind 127.0.0.1
  antclaw-cli setup
  antclaw-cli report --output-html reports/scan.html
  antclaw-cli version
"""
from __future__ import annotations
import argparse
import json
import os
import sys

# ──────────────────────────────────────────────────────────────────────────────
# PIXEL ART LOGO
# ──────────────────────────────────────────────────────────────────────────────

# Pixel grid of the antclaw logo (circle with split diamond eye)
# 1 = white pixel, 0 = black/empty
_LOGO_PIXELS = [
    "000001111001111000000",
    "000111110001011111000",
    "001111100001001111100",
    "011111000001000111110",
    "011110000001000011110",
    "111100000001000001111",
    "111000000001000000111",
    "111000000001000000011",
    "111000000001000000011",
    "111000000001000000011",
    "111000000001000000111",
    "111100000001000001111",
    "011110000001000011110",
    "011111000001000111110",
    "001111100001001111100",
    "000111110001011111000",
    "000001111001111000000",
]

# ANSI colour codes
_RESET  = "\033[0m"
_WHITE  = "\033[97m"
_GRAY   = "\033[90m"
_CYAN   = "\033[96m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"


def _supports_ansi() -> bool:
    """Return True if the terminal supports ANSI colour codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        # Windows Terminal and modern cmd support ANSI; legacy cmd does not
        return os.environ.get("WT_SESSION") is not None or "ANSICON" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _render_logo(color: bool = True) -> str:
    """Render the pixel art logo as a string."""
    lines = []
    for row in _LOGO_PIXELS:
        line = ""
        for px in row:
            if px == "1":
                line += ("█" if color else "#") + ("█" if color else "#")
            else:
                line += "  "
        lines.append(line)
    return "\n".join(lines)


def _print_banner(color: bool = True):
    """Print the full antclaw banner with logo + tagline."""
    logo = _render_logo(color)

    if color and _supports_ansi():
        # Coloured version
        print()
        for line in logo.split("\n"):
            print(f"  {_WHITE}{line}{_RESET}")
        print()
        print(f"  {_BOLD}{_WHITE}ant{_RESET}{_BOLD}{_CYAN}claw{_RESET}  "
              f"{_DIM}runtime security for OpenClaw agents{_RESET}")
        print(f"  {_GRAY}────────────────────────────────────────{_RESET}")
        print(f"  {_DIM}detection-only · open source · zero config{_RESET}")
        print()
    else:
        # Plain version for Windows cmd / no-color
        print()
        print(logo)
        print()
        print("  antclaw — runtime security for OpenClaw agents")
        print("  detection-only · open source · zero config")
        print()


# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY COLOURS
# ──────────────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "critical": _RED,
    "high":     _YELLOW,
    "medium":   "\033[33m",
    "warning":  "\033[34m",
    "none":     _GREEN,
}

def _sev(severity: str, color: bool = True) -> str:
    if not color or not _supports_ansi():
        return severity.upper()
    c = _SEV_COLOR.get(severity, "")
    return f"{_BOLD}{c}{severity.upper()}{_RESET}"


# ──────────────────────────────────────────────────────────────────────────────
# COMMANDS
# ──────────────────────────────────────────────────────────────────────────────

def cmd_scan(args, color: bool):
    """Run a single scan and print results."""
    try:
        from antclaw.scanner import scan
    except ImportError:
        print("❌  antclaw not installed. Run: pip install antclaw")
        sys.exit(1)

    text = " ".join(args.text)
    result = scan(
        text=text,
        agent_id=args.agent or "cli",
        channel=args.channel or "unknown",
        session_id=args.session or None,
    )

    sev = result.get("severity", "none")
    detected = result.get("detected", False)
    ms = result.get("total_scan_ms", 0)
    layers = result.get("openclaw_layers", {})
    summary = result.get("summary", {})

    if color and _supports_ansi():
        icon = "🔴" if detected else "🟢"
        print(f"\n  {icon}  Severity : {_sev(sev, color)}")
        print(f"      Detected : {'Yes' if detected else 'No'}")
        print(f"      Scan ms  : {ms}")
        print(f"      Critical : {_RED}{summary.get('critical', 0)}{_RESET}  "
              f"High : {_YELLOW}{summary.get('high', 0)}{_RESET}  "
              f"Medium : {summary.get('medium', 0)}  "
              f"Warning : {summary.get('warning', 0)}")
    else:
        print(f"\n  Severity : {sev.upper()}")
        print(f"  Detected : {'Yes' if detected else 'No'}")
        print(f"  Scan ms  : {ms}")

    # Layer breakdown
    if layers:
        print()
        if color and _supports_ansi():
            print(f"  {_GRAY}Layers:{_RESET}")
        else:
            print("  Layers:")
        for name, r in layers.items():
            if r.get("detected"):
                layer_sev = r.get("severity", "none")
                findings = r.get("findings", [])
                types = ", ".join(f.get("type","?") for f in findings[:2])
                print(f"    {'⚠' if color else '!'} {name:25} {_sev(layer_sev, color)}  {types}")

    print()

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    sys.exit(1 if sev in ("critical", "high") and args.fail_on_detection else 0)


def cmd_server(args, color: bool):
    """Start the antclaw relay server."""
    try:
        from antclaw.server import main as server_main
    except ImportError:
        print("❌  antclaw not installed.")
        sys.exit(1)

    # Inject args into sys.argv for server's own argparse
    new_argv = ["antclaw-server"]
    if args.port:
        new_argv += ["--port", str(args.port)]
    if args.bind:
        new_argv += ["--bind", args.bind]
    if args.upstream:
        new_argv += ["--upstream", args.upstream]
    sys.argv = new_argv
    server_main()


def cmd_setup(args, color: bool):
    """Run the setup wizard."""
    try:
        from antclaw.setup_wizard import main as wizard_main
    except ImportError:
        print("❌  Setup wizard not found. Run: pip install antclaw")
        sys.exit(1)
    wizard_main()


def cmd_report(args, color: bool):
    """Generate HTML + JSON scan reports."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "generate_reports", "scripts/generate_reports.py"
        )
        if spec:
            mod = importlib.util.load_from_spec(spec) if hasattr(importlib.util, 'load_from_spec') else None

        # Inject args and call directly
        sys.argv = [
            "generate_reports.py",
            "--output-html", args.output_html or "reports/scan_report.html",
            "--output-json", args.output_json or "reports/scan_report.json",
            "--stage", args.stage or "cli",
        ]
        from scripts.generate_reports import main as report_main
        report_main()
    except ImportError:
        # Fallback: try running as subprocess
        import subprocess
        subprocess.run([
            sys.executable, "scripts/generate_reports.py",
            "--output-html", args.output_html or "reports/scan_report.html",
            "--output-json", args.output_json or "reports/scan_report.json",
        ])


def cmd_version(args, color: bool):
    """Print version info."""
    try:
        from antclaw import __version__
        ver = __version__
    except ImportError:
        ver = "unknown"

    layers = [
        "channel_trust", "acp", "session_drift", "tool_sequence",
        "pairing_bypass", "canvas", "correlator",
        "memory_poison", "indirect_injection", "destructive_action",
        "credential_leak", "rate_anomaly", "data_classifier",
    ]

    if color and _supports_ansi():
        print(f"\n  {_BOLD}antclaw{_RESET}  v{_CYAN}{ver}{_RESET}")
        print(f"  {_GRAY}Detection layers : {len(layers)}{_RESET}")
        for l in layers:
            print(f"    {_GREEN}✓{_RESET}  {l}")
    else:
        print(f"\n  antclaw v{ver}")
        print(f"  Detection layers: {len(layers)}")
        for l in layers:
            print(f"    + {l}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    color = _supports_ansi() and "--no-color" not in sys.argv

    # Show banner unless --no-banner or piped output
    show_banner = "--no-banner" not in sys.argv and "--json" not in sys.argv
    if show_banner:
        _print_banner(color)

    parser = argparse.ArgumentParser(
        prog="antclaw",
        description="antclaw — runtime security detection for OpenClaw agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument("--no-color",  action="store_true", help="Disable colour output")
    parser.add_argument("--no-banner", action="store_true", help="Suppress logo banner")

    sub = parser.add_subparsers(dest="command", title="commands")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a text string")
    p_scan.add_argument("text", nargs="+", help="Text to scan")
    p_scan.add_argument("--channel",  default="unknown", help="Channel name (webhook, telegram, slack...)")
    p_scan.add_argument("--agent",    default="cli",     help="Agent ID")
    p_scan.add_argument("--session",  default=None,      help="Session ID")
    p_scan.add_argument("--json",     action="store_true", help="Also print raw JSON result")
    p_scan.add_argument("--fail-on-detection", action="store_true",
                        help="Exit code 1 if severity is high or critical")

    # server
    p_srv = sub.add_parser("server", help="Start the relay server")
    p_srv.add_argument("--port",     type=int, default=None, help="Port (default: 8765)")
    p_srv.add_argument("--bind",     default=None, help="Bind address (default: 127.0.0.1)")
    p_srv.add_argument("--upstream", default=None, help="OpenClaw gateway URL")

    # setup
    sub.add_parser("setup", help="Run the setup wizard")

    # report
    p_rep = sub.add_parser("report", help="Generate HTML + JSON scan report")
    p_rep.add_argument("--output-html", default="reports/scan_report.html")
    p_rep.add_argument("--output-json", default="reports/scan_report.json")
    p_rep.add_argument("--stage", default="cli")

    # version
    sub.add_parser("version", help="Show version and loaded layers")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args, color)
    elif args.command == "server":
        cmd_server(args, color)
    elif args.command == "setup":
        cmd_setup(args, color)
    elif args.command == "report":
        cmd_report(args, color)
    elif args.command == "version":
        cmd_version(args, color)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()