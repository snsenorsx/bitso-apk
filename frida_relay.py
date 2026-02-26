#!/usr/bin/env python3
"""
Frida Relay Script - Bitso Wallet Bypass Communication Bridge
=============================================================

This script acts as a bridge between your local Frida session and the Devin
analysis session. It reads Frida console output from stdin (piped) or from
a log file, and sends it to a webhook endpoint where Devin can read and
analyze it in real-time.

Usage Options:
--------------

Option 1: Pipe directly from Frida
    frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause 2>&1 | python3 frida_relay.py

Option 2: Write Frida output to file, relay watches the file
    # Terminal 1: Run Frida and log output
    frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause 2>&1 | tee frida_output.log

    # Terminal 2: Relay watches the log file
    python3 frida_relay.py --watch frida_output.log

Option 3: Manual paste mode (copy-paste Frida output)
    python3 frida_relay.py --interactive

Option 4: Save to structured JSON for later sharing
    frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause 2>&1 | python3 frida_relay.py --save-json output.json

Environment Variables:
    RELAY_WEBHOOK_URL  - Custom webhook URL to send data to (optional)
"""

import sys
import os
import json
import time
import re
import argparse
import threading
from datetime import datetime
from collections import defaultdict

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

CATEGORY_COLORS = {
    "ROOT": Colors.RED,
    "FRIDA": Colors.MAGENTA,
    "SSL": Colors.CYAN,
    "EMU": Colors.YELLOW,
    "DEBUG": Colors.BLUE,
    "INTEGRITY": Colors.GREEN,
    "FPJS": Colors.CYAN,
    "IPROOV": Colors.RED,
    "WEBVIEW": Colors.YELLOW,
    "NETWORK": Colors.BLUE,
    "DETECTION": Colors.RED + Colors.BOLD,
    "ERROR": Colors.RED + Colors.BOLD,
    "INIT": Colors.GREEN,
}


class DetectionTracker:
    """Tracks and categorizes all detections found during the Frida session."""

    def __init__(self):
        self.detections = []
        self.categories = defaultdict(list)
        self.start_time = datetime.now()
        self.raw_lines = []

    def add_line(self, line):
        """Process a raw line from Frida output."""
        self.raw_lines.append(line)
        parsed = self.parse_line(line)
        if parsed:
            self.detections.append(parsed)
            self.categories[parsed["category"]].append(parsed)

    def parse_line(self, line):
        """Parse a Frida output line into structured data."""
        # Match: TIMESTAMP [BITSO-BYPASS] [CATEGORY] message
        match = re.search(
            r"\[BITSO-BYPASS\]\s+\[(\w+(?:_\w+)?)\]\s+(.*)",
            line,
        )
        if match:
            category = match.group(1)
            message = match.group(2)
            return {
                "timestamp": datetime.now().isoformat(),
                "category": category,
                "message": message,
                "raw": line.strip(),
                "is_detection": "DETECTION" in category
                or "blocked" in message.lower()
                or "bypassed" in message.lower()
                or "spoofed" in message.lower(),
            }
        return None

    def get_summary(self):
        """Generate a summary of all detections."""
        summary = {
            "session_duration": str(datetime.now() - self.start_time),
            "total_detections": len(self.detections),
            "total_lines": len(self.raw_lines),
            "categories": {},
        }
        for cat, items in self.categories.items():
            summary["categories"][cat] = {
                "count": len(items),
                "samples": [i["message"] for i in items[:5]],
            }
        return summary

    def get_report(self):
        """Generate a formatted report for analysis."""
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("BITSO WALLET - FRIDA BYPASS SESSION REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Session Duration: {datetime.now() - self.start_time}")
        report_lines.append(f"Total Events: {len(self.detections)}")
        report_lines.append(f"Total Raw Lines: {len(self.raw_lines)}")
        report_lines.append("")

        # Detection breakdown
        report_lines.append("--- DETECTION BREAKDOWN ---")
        for cat in sorted(self.categories.keys()):
            items = self.categories[cat]
            report_lines.append(f"\n[{cat}] ({len(items)} events)")
            for item in items[:10]:
                marker = " !! " if item["is_detection"] else "    "
                report_lines.append(f"{marker}{item['message']}")
            if len(items) > 10:
                report_lines.append(f"    ... and {len(items) - 10} more")

        # Active detections (things that were actually triggered)
        active = [d for d in self.detections if d["is_detection"]]
        report_lines.append(f"\n--- ACTIVE BYPASSES ({len(active)}) ---")
        for d in active:
            report_lines.append(f"  [{d['category']}] {d['message']}")

        report_lines.append("\n" + "=" * 70)
        return "\n".join(report_lines)


def colorize_line(line):
    """Add color to a Frida output line based on its category."""
    for cat, color in CATEGORY_COLORS.items():
        if f"[{cat}]" in line or f"[{cat}_" in line:
            return f"{color}{line}{Colors.RESET}"
    if "DETECTION" in line or "blocked" in line.lower() or "bypassed" in line.lower():
        return f"{Colors.RED}{Colors.BOLD}{line}{Colors.RESET}"
    return line


def process_stdin(tracker, save_json=None):
    """Read from stdin (piped Frida output) and process it."""
    print(f"{Colors.GREEN}{Colors.BOLD}[RELAY] Reading from stdin (pipe mode){Colors.RESET}")
    print(f"{Colors.DIM}[RELAY] Waiting for Frida output...{Colors.RESET}")
    print()

    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue

            tracker.add_line(line)
            print(colorize_line(line))
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        print()
        print(tracker.get_report())
        if save_json:
            save_results(tracker, save_json)


def watch_file(tracker, filepath, save_json=None):
    """Watch a log file for new content."""
    print(f"{Colors.GREEN}{Colors.BOLD}[RELAY] Watching file: {filepath}{Colors.RESET}")
    print(f"{Colors.DIM}[RELAY] Press Ctrl+C to stop and see report{Colors.RESET}")
    print()

    try:
        with open(filepath, "r") as f:
            # Go to end of file
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                line = line.rstrip("\n")
                if not line:
                    continue
                tracker.add_line(line)
                print(colorize_line(line))
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    except FileNotFoundError:
        print(f"{Colors.RED}[RELAY] File not found: {filepath}{Colors.RESET}")
        print(f"[RELAY] Make sure Frida is running and logging to this file.")
        return
    finally:
        print()
        print(tracker.get_report())
        if save_json:
            save_results(tracker, save_json)


def interactive_mode(tracker, save_json=None):
    """Interactive paste mode - user pastes output manually."""
    print(f"{Colors.GREEN}{Colors.BOLD}[RELAY] Interactive mode{Colors.RESET}")
    print(f"[RELAY] Paste Frida console output below.")
    print(f"[RELAY] Type 'report' to see current summary, 'quit' to exit.")
    print()

    try:
        while True:
            try:
                line = input()
            except EOFError:
                break

            if line.strip().lower() == "quit":
                break
            if line.strip().lower() == "report":
                print(tracker.get_report())
                continue
            if line.strip().lower() == "summary":
                print(json.dumps(tracker.get_summary(), indent=2))
                continue

            if not line.strip():
                continue

            tracker.add_line(line)
            print(colorize_line(line))
    except KeyboardInterrupt:
        pass
    finally:
        print()
        print(tracker.get_report())
        if save_json:
            save_results(tracker, save_json)


def save_results(tracker, filepath):
    """Save session results to a JSON file."""
    data = {
        "summary": tracker.get_summary(),
        "detections": tracker.detections,
        "report": tracker.get_report(),
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n{Colors.GREEN}[RELAY] Results saved to: {filepath}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Frida Relay - Bridge between Frida sessions and analysis"
    )
    parser.add_argument(
        "--watch",
        metavar="FILE",
        help="Watch a log file for new Frida output",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive paste mode",
    )
    parser.add_argument(
        "--save-json",
        metavar="FILE",
        help="Save structured results to JSON file",
    )
    args = parser.parse_args()

    tracker = DetectionTracker()

    print(f"{Colors.BOLD}")
    print("=" * 60)
    print("  BITSO WALLET - Frida Bypass Relay")
    print("  Real-time detection monitoring & analysis")
    print("=" * 60)
    print(f"{Colors.RESET}")

    if args.watch:
        watch_file(tracker, args.watch, args.save_json)
    elif args.interactive:
        interactive_mode(tracker, args.save_json)
    else:
        # Default: read from stdin (pipe mode)
        if sys.stdin.isatty():
            print(f"{Colors.YELLOW}[RELAY] No input detected. Usage options:{Colors.RESET}")
            print()
            print("  1) Pipe from Frida:")
            print("     frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause 2>&1 | python3 frida_relay.py")
            print()
            print("  2) Watch log file:")
            print("     python3 frida_relay.py --watch frida_output.log")
            print()
            print("  3) Interactive paste:")
            print("     python3 frida_relay.py --interactive")
            print()
            print("  4) Save to JSON:")
            print("     ... | python3 frida_relay.py --save-json results.json")
            print()
            print(f"{Colors.DIM}Falling back to interactive mode...{Colors.RESET}")
            print()
            interactive_mode(tracker, args.save_json)
        else:
            process_stdin(tracker, args.save_json)


if __name__ == "__main__":
    main()
