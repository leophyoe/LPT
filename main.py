#!/usr/bin/env python3
"""CyberSecuritySuite - Master Application Entrypoint.

Supports:
1. Desktop GUI: Launches PySide6 Dark Cyber Workstation (default).
2. Headless VNC Mode: Runs desktop interface on VNC server (port 5900) when running headless (--vnc).
3. CLI Interactive Shell: Command-line pentest execution and tool runner (--cli or when no display is present).
4. Automated Tool Diagnostics: Inspects and verifies all 24 integrated tools (--tools).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Automatically ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Prepend project bin/ and .venv/bin/ to PATH so all tools and virtual environment tools are accessible
BIN_DIR = PROJECT_ROOT / "bin"
VENV_DIR = PROJECT_ROOT / ".venv"
VENV_BIN = VENV_DIR / "bin"
VENV_PYTHON = VENV_BIN / "python"

current_path = os.environ.get("PATH", "")
os.environ["PATH"] = f"{BIN_DIR}:{VENV_BIN}:{current_path}"

# Re-exec under virtual environment python if invoked with system python
if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)


def run_cli_interactive():
    """Lightweight interactive CLI console for terminal-only environments."""
    from core.registry import ToolRegistry
    from storage.db import Database
    from terminal.runner import ProcessRunner

    db_path = PROJECT_ROOT / "storage" / "data" / "cybersecuritysuite.db"
    db = Database(db_path)
    reg = ToolRegistry()
    runner = ProcessRunner()

    print("=" * 70)
    print("  🛡️  CyberSecuritySuite — Security Testing & CPENT Platform [CLI Mode]")
    print("=" * 70)
    print(f"Working Directory : {os.getcwd()}")
    print(f"Database Path     : {db_path}")
    print(f"Discovered Tools  : {len(reg.list_installed_tools())} ready / {len(reg.list_tools())} total")
    print("Commands:")
    print("  tools               - List security tools and installation status")
    print("  test <tool_name>    - Run safe diagnostic test on tool (e.g. test nmap, test sqlmap)")
    print("  projects            - List active assessment projects")
    print("  run <cmd...>        - Execute a security tool or shell command with live streaming")
    print("  gui                 - Launch PySide6 Desktop GUI")
    print("  exit / quit         - Exit console\n")

    while True:
        try:
            line = input("CyberSecuritySuite $ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting CyberSecuritySuite CLI.")
            break

        if not line:
            continue
        if line in ("exit", "quit", "q"):
            break

        if line == "tools":
            print(f"\n{'Tool':<15} {'Status':<12} {'Version / Info':<40}")
            print("-" * 70)
            for t in reg.list_tools():
                status = "Installed" if t.is_installed else "Missing"
                ver = (t.version or t.error_message or "Not found")[:40]
                print(f"{t.name:<15} {status:<12} {ver:<40}")
            print()
        elif line.startswith("test "):
            tool_name = line.split(maxsplit=1)[1].strip()
            print(f"[*] Testing tool '{tool_name}'...")
            ok, out, code = reg.test_tool(tool_name)
            if ok:
                print(f"[+] SUCCESS (Exit Code {code}):\n{out}\n")
            else:
                print(f"[-] FAILED (Exit Code {code}):\n{out}\n")
        elif line == "projects":
            projects = db.list_projects()
            if not projects:
                print("[!] No projects found. Create one in the GUI or database.")
            else:
                for p in projects:
                    print(f"  [{p.id}] {p.name} (Client: {p.client_name or 'N/A'}, Created: {p.created_at})")
            print()
        elif line.startswith("run "):
            cmd = line[4:].strip()
            print(f"[*] Executing: {cmd}")
            import shlex
            try:
                args = shlex.split(cmd)
                res = runner.run(args, on_output=lambda c, s: sys.stdout.write(c))
                print(f"\n[+] Execution finished with exit code: {res.exit_code}\n")
            except Exception as e:
                print(f"[-] Error: {e}\n")
        elif line == "gui":
            run_gui()
            break
        else:
            # Fallback: execute as shell command
            import shlex
            try:
                args = shlex.split(line)
                res = runner.run(args, on_output=lambda c, s: sys.stdout.write(c))
                if res.exit_code != 0:
                    print(f"[-] Process exited with code {res.exit_code}")
            except Exception as e:
                print(f"[-] Unknown command or execution error: {e}")


def run_gui():
    """Launches the PySide6 desktop interface."""
    from desktop.app import main as app_main
    app_main()


def main():
    parser = argparse.ArgumentParser(
        description="CyberSecuritySuite - AI-Assisted Cybersecurity & CPENT Learning Platform"
    )
    parser.add_argument("--cli", action="store_true", help="Launch interactive terminal CLI mode")
    parser.add_argument("--tools", action="store_true", help="Inspect and list all tools and exit")
    parser.add_argument("--vnc", action="store_true", help="Launch GUI on internal VNC platform (port 5900)")
    parser.add_argument("--offscreen", action="store_true", help="Launch GUI in headless offscreen mode")
    args, unknown = parser.parse_known_args()

    if args.tools:
        from core.registry import ToolRegistry
        reg = ToolRegistry()
        print(f"\n{'Tool':<15} {'Status':<12} {'Path / Version':<50}")
        print("-" * 80)
        for t in reg.list_tools():
            status = "Installed" if t.is_installed else "Missing"
            detail = t.binary_path or t.error_message or "Missing"
            print(f"{t.name:<15} {status:<12} {detail:<50}")
        print()
        sys.exit(0)

    if args.cli:
        run_cli_interactive()
        return

    # Check display environment
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

    if args.vnc or (not has_display and not os.environ.get("QT_QPA_PLATFORM") and sys.platform.startswith("linux")):
        if args.vnc:
            os.environ["QT_QPA_PLATFORM"] = "vnc"
            print("[*] Starting CyberSecuritySuite on VNC display server at 127.0.0.1:5900...")
            run_gui()
            return
        elif not has_display:
            # No X11/Wayland display detected
            print("\n[!] No active graphical display ($DISPLAY or $WAYLAND_DISPLAY) detected.")
            print("    Options to run:")
            print("    1. Interactive CLI Shell : python3 main.py --cli")
            print("    2. VNC Desktop Server    : python3 main.py --vnc  (Connect via VNC client to 127.0.0.1:5900)")
            print("    3. Connect X11 display   : export DISPLAY=:0 && python3 main.py\n")
            print("[*] Automatically launching Interactive CLI Shell now...\n")
            run_cli_interactive()
            return

    if args.offscreen:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    run_gui()


if __name__ == "__main__":
    main()

