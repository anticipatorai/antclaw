from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# ANSI colour codes
_RESET  = "\033[0m"
_GRAY   = "\033[90m"
_CYAN   = "\033[96m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_BOLD   = "\033[1m"


BANNER = """
 █████  ███    ██ ████████  ██████ ██       █████  ██     ██ 
██   ██ ████   ██    ██    ██      ██      ██   ██ ██     ██ 
███████ ██ ██  ██    ██    ██      ██      ███████ ██  █  ██ 
██   ██ ██  ██ ██    ██    ██      ██      ██   ██ ██ ███ ██ 
██   ██ ██   ████    ██     ██████ ███████ ██   ██  ███ ███  
"""

def _supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        return os.environ.get("WT_SESSION") is not None or "ANSICON" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


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


def cmd_scan(args, color: bool):
    try:
        from antclaw.scanner import scan
    except ImportError:
        print("antclaw not installed. Run: pip install antclaw")
        sys.exit(1)

    text   = " ".join(args.text)
    result = scan(
        text=text,
        agent_id=args.agent or "cli",
        channel=args.channel or "unknown",
        session_id=args.session or None,
    )

    sev      = result.get("severity", "none")
    detected = result.get("detected", False)
    ms       = result.get("total_scan_ms", 0)
    layers   = result.get("openclaw_layers", {})
    summary  = result.get("summary", {})

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

    if layers:
        print()
        print(f"  {_GRAY}Layers:{_RESET}" if color and _supports_ansi() else "  Layers:")
        for name, r in layers.items():
            if r.get("detected"):
                layer_sev = r.get("severity", "none")
                findings  = r.get("findings", [])
                types     = ", ".join(f.get("type", "?") for f in findings[:2])
                print(f"    {'⚠' if color else '!'} {name:25} {_sev(layer_sev, color)}  {types}")

    print()

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    sys.exit(1 if sev in ("critical", "high") and args.fail_on_detection else 0)


def cmd_server(args, color: bool):
    try:
        from antclaw.server import main as server_main
    except ImportError:
        print("antclaw not installed.")
        sys.exit(1)

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
    try:
        from antclaw.setup_wizard import main as wizard_main
    except ImportError:
        print("Setup wizard not found. Run: pip install antclaw")
        sys.exit(1)
    wizard_main()


def cmd_report(args, color: bool):
    subprocess.run([
        sys.executable, "scripts/generate_reports.py",
        "--output-html", args.output_html or "reports/scan_report.html",
        "--output-json", args.output_json or "reports/scan_report.json",
        "--stage",       args.stage or "cli",
    ])


def cmd_version(args, color: bool):
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
        for layer_name in layers:
            print(f"    {_GREEN}✓{_RESET}  {layer_name}")
    else:
        print(f"\n  antclaw v{ver}")
        print(f"  Detection layers: {len(layers)}")
        for layer_name in layers:
            print(f"    + {layer_name}")
    print()


def main():
    color = _supports_ansi() and "--no-color" not in sys.argv

    if "--no-banner" not in sys.argv:
        if color and _supports_ansi():
            print(f"{_CYAN}{BANNER}{_RESET}")
        else:
            print(BANNER)

    parser = argparse.ArgumentParser(
        prog="antclaw",
        description="antclaw — runtime security detection for OpenClaw agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-color",  action="store_true", help="Disable colour output")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    sub = parser.add_subparsers(dest="command", title="commands")

    p_scan = sub.add_parser("scan", help="Scan a text string")
    p_scan.add_argument("text", nargs="+")
    p_scan.add_argument("--channel", default="unknown")
    p_scan.add_argument("--agent",   default="cli")
    p_scan.add_argument("--session", default=None)
    p_scan.add_argument("--json",    action="store_true")
    p_scan.add_argument("--fail-on-detection", action="store_true")

    p_srv = sub.add_parser("server", help="Start the relay server")
    p_srv.add_argument("--port",     type=int, default=None)
    p_srv.add_argument("--bind",     default=None)
    p_srv.add_argument("--upstream", default=None)

    sub.add_parser("setup",   help="Run the setup wizard")

    p_rep = sub.add_parser("report", help="Generate HTML + JSON scan report")
    p_rep.add_argument("--output-html", default="reports/scan_report.html")
    p_rep.add_argument("--output-json", default="reports/scan_report.json")
    p_rep.add_argument("--stage",       default="cli")

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