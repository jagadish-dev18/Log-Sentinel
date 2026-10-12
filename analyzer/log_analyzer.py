#!/usr/bin/env python3
"""Log Sentinel CLI: parse a small set of authentication logs and export IP statistics.

Supported formats are documented in README.md. This is a learning tool; a flagged
source is a review signal, not proof of a brute-force attack.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

KEY_VALUE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z)?)\s+"
    r"(?P<event>FAILED_LOGIN|LOGIN_FAILED|AUTH_FAILURE|SUCCESS_LOGIN|LOGIN_SUCCESS|AUTH_SUCCESS|INFO|WARNING|ERROR|OTHER)\b(?P<rest>.*)$",
    re.IGNORECASE,
)
SSH_FAILED_RE = re.compile(r"Failed password for (?:(?:invalid|illegal) user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?", re.I)
SSH_SUCCESS_RE = re.compile(r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?", re.I)
SSH_TIME_RE = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
GENERIC_FAILED_RE = re.compile(r"failed password|login failed|authentication failure|invalid password|access denied", re.I)
GENERIC_SUCCESS_RE = re.compile(r"accepted password|login successful|authentication success|user authenticated", re.I)


@dataclass
class Event:
    line_number: int
    timestamp: str
    event_type: str
    username: str
    source_ip: str
    detail: str
    format: str
    raw_line: str


def normalize_type(value: object) -> str:
    text = re.sub(r"[\s-]+", "_", str(value or "").lower())
    if re.search(r"fail|denied|invalid_password|authentication_failure", text):
        return "failed"
    if re.search(r"success|accepted|authenticated|login_ok", text):
        return "success"
    return "other"


def parse_line(line: str, line_number: int) -> Optional[Event]:
    """Return an Event for a supported line, or None if no parser recognizes it."""
    stripped = line.strip()
    if not stripped:
        return None

    # JSON event, e.g. {"timestamp":"...", "event":"failed_login", "ip":"..."}
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
            raw_event = record.get("event", record.get("event_type", record.get("action", record.get("status", ""))))
            if not re.search(r"login|auth|password|accepted|failed|denied", str(raw_event), re.I):
                return None
            return Event(
                line_number=line_number,
                timestamp=str(record.get("timestamp", record.get("time", record.get("datetime", record.get("ts", ""))))),
                event_type=normalize_type(raw_event),
                username=str(record.get("username", record.get("user", record.get("account", "—")))),
                source_ip=str(record.get("ip", record.get("source_ip", record.get("src_ip", record.get("remote_addr", "Unknown"))))),
                detail=str(raw_event or "Authentication event"),
                format="JSON",
                raw_line=stripped,
            )
        except (ValueError, TypeError):
            pass

    # Common OpenSSH authentication messages.
    ssh_timestamp = SSH_TIME_RE.match(stripped)
    if ssh_timestamp:
        failed = SSH_FAILED_RE.search(stripped)
        succeeded = SSH_SUCCESS_RE.search(stripped)
        if failed:
            detail = "SSH failed password" + (f" on port {failed.group('port')}" if failed.group("port") else "")
            return Event(line_number, ssh_timestamp.group("timestamp"), "failed", failed.group("user"), failed.group("ip"), detail, "OpenSSH", stripped)
        if succeeded:
            detail = "SSH accepted authentication" + (f" on port {succeeded.group('port')}" if succeeded.group("port") else "")
            return Event(line_number, ssh_timestamp.group("timestamp"), "success", succeeded.group("user"), succeeded.group("ip"), detail, "OpenSSH", stripped)

    # Friendly teaching format: TIMESTAMP FAILED_LOGIN user=admin ip=192.0.2.10
    match = KEY_VALUE_RE.match(stripped)
    if match:
        rest = match.group("rest") or ""
        def field(names: str) -> str:
            found = re.search(rf"\b(?:{names})=([^\s,]+)", rest, re.I)
            return found.group(1) if found else ""
        raw_event = match.group("event")
        return Event(
            line_number=line_number,
            timestamp=match.group("timestamp"),
            event_type=normalize_type(raw_event),
            username=field("user|username|account") or "—",
            source_ip=field("ip|source_ip|src_ip|remote_ip") or "Unknown",
            detail=rest.strip() or raw_event.replace("_", " ").lower(),
            format="key-value",
            raw_line=stripped,
        )

    # A few generic lines that mention a known authentication phrase.
    failed = GENERIC_FAILED_RE.search(stripped)
    succeeded = GENERIC_SUCCESS_RE.search(stripped)
    if failed or succeeded:
        ip_match = re.search(r"(?:from|ip[=: ]|src[=: ]|rhost=)([0-9a-fA-F:.]{3,})", stripped, re.I)
        user_match = re.search(r"(?:for|user[=: ]|username[=: ])\s*(?:invalid user\s+)?([A-Za-z0-9_.@-]+)", stripped, re.I)
        timestamp_match = re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", stripped)
        return Event(
            line_number, timestamp_match.group(0) if timestamp_match else "",
            "failed" if failed else "success", user_match.group(1) if user_match else "—",
            ip_match.group(1) if ip_match else "Unknown",
            "Login failure pattern" if failed else "Successful authentication pattern",
            "generic", stripped,
        )

    return None


def analyze_lines(lines: list[str], threshold: int = 5) -> tuple[list[Event], list[tuple[int, str]], dict[str, dict[str, object]]]:
    events: list[Event] = []
    unparsed: list[tuple[int, str]] = []
    stats: dict[str, dict[str, object]] = defaultdict(lambda: {"failed": 0, "success": 0, "other": 0, "last_seen": "", "users": set()})
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        event = parse_line(line, number)
        if event is None:
            unparsed.append((number, line.strip()))
            continue
        events.append(event)
        if event.source_ip == "Unknown":
            continue
        item = stats[event.source_ip]
        item[event.event_type] = int(item[event.event_type]) + 1
        if event.timestamp >= str(item["last_seen"]):
            item["last_seen"] = event.timestamp
        if event.username != "—":
            item["users"].add(event.username)
    for item in stats.values():
        item["flagged"] = int(item["failed"]) >= threshold
        item["users"] = sorted(item["users"])
    return events, unparsed, dict(stats)


def safe_csv_text(value: object) -> str:
    """Neutralize spreadsheet formula prefixes in untrusted text fields."""
    text = str(value if value is not None else "")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def export_csv(path: Path, stats: dict[str, dict[str, object]], threshold: int) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Source IP", "Failed logins", "Successful logins", "Other events", "Last seen", "Review status", "Threshold", "Observed users"])
        for ip, item in sorted(stats.items(), key=lambda pair: (-int(pair[1]["failed"]), pair[0])):
            writer.writerow([safe_csv_text(ip), item["failed"], item["success"], item["other"], safe_csv_text(item["last_seen"]), "Review" if item["flagged"] else "Below threshold", threshold, safe_csv_text("; ".join(item["users"]))])


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze local authentication logs and flag repeated failed logins.")
    parser.add_argument("input", type=Path, help="Path to a .log or .txt input file")
    parser.add_argument("--threshold", type=int, default=5, help="Flag an IP at or above this failed-login count (2-20, default: 5)")
    parser.add_argument("--csv", type=Path, default=Path("ip_summary.csv"), help="Output CSV path (default: ip_summary.csv)")
    args = parser.parse_args()
    if not 2 <= args.threshold <= 20:
        parser.error("--threshold must be between 2 and 20")
    try:
        lines = args.input.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        print(f"Error reading {args.input}: {error}", file=sys.stderr)
        return 2
    events, unparsed, stats = analyze_lines(lines, args.threshold)
    failed_count = sum(event.event_type == "failed" for event in events)
    success_count = sum(event.event_type == "success" for event in events)
    flagged = [ip for ip, item in stats.items() if item["flagged"]]
    try:
        export_csv(args.csv, stats, args.threshold)
    except OSError as error:
        print(f"Error writing CSV {args.csv}: {error}", file=sys.stderr)
        return 2
    print("\nLOG SENTINEL — ANALYSIS SUMMARY")
    print("-" * 34)
    print(f"Input lines:           {sum(bool(line.strip()) for line in lines)}")
    print(f"Recognized events:     {len(events)}")
    print(f"Failed logins:         {failed_count}")
    print(f"Successful logins:     {success_count}")
    print(f"Unique source IPs:     {len(stats)}")
    print(f"IPs flagged for review:{len(flagged):>5}")
    print(f"Unparsed lines:        {len(unparsed)}")
    print(f"Threshold:             {args.threshold}")
    print(f"CSV report:            {args.csv.resolve()}")
    if flagged:
        print("\nSources to review:")
        for ip in flagged:
            print(f"  {ip}: {stats[ip]['failed']} failed attempts")
    if unparsed:
        print("\nSome lines were not recognized (first 5):")
        for line_number, line in unparsed[:5]:
            print(f"  Line {line_number}: {line[:140]}")
    print("\nNote: a flagged source is an investigation signal, not proof of an attack.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
