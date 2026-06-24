"""
PATENT NOTICE
Module: connector/sources/local_file
Part of: Core Patent Claim 2 — Edge Processing Architecture

Reads from a local log file.
Supports CSV, JSON, and syslog formats.
Fallback source for environments where
cloud APIs are not available.

What this source NEVER sends:
  Raw log lines, source IPs, user identities.
  Only matched tool name + call count.
"""

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timezone

from connector.sources.vpc_flow import VPCFlowSource


class LocalFileSource:
    """Local log file source for the Tier 3 connector."""

    def __init__(self, config: dict):
        """Initialize with source config.

        Args:
            config: sources.local_file dict from connector.yaml
        """
        self.config = config
        self.file_path = config.get("file_path", "/var/log/network/flows.log")
        self.format = config.get("format", "csv")

    def scan(self, since: datetime, until: datetime) -> list[dict]:
        """Read log file and match destination fields against AI signatures.

        Supports formats: csv, json, syslog.
        Returns signal dicts.
        """
        if not os.path.exists(self.file_path):
            return []

        if self.format == "csv":
            records = self._read_csv()
        elif self.format == "json":
            records = self._read_json()
        elif self.format == "syslog":
            records = self._read_syslog()
        else:
            return []

        matches: dict[str, dict] = defaultdict(
            lambda: {
                "count": 0,
                "hostname_pattern": "",
                "first_seen": None,
                "last_seen": None,
            }
        )

        for record in records:
            dest = (
                record.get("destination", "")
                or record.get("dstAddr", "")
                or record.get("hostname", "")
                or record.get("dst", "")
                or ""
            )
            timestamp = self._parse_timestamp(record.get("timestamp"))

            if timestamp and (timestamp < since or timestamp > until):
                continue

            for tool_name, patterns in VPCFlowSource.AI_HOSTNAME_SIGNATURES.items():
                for pattern in patterns:
                    if pattern in dest or dest in pattern:
                        entry = matches[tool_name]
                        entry["count"] += 1
                        entry["hostname_pattern"] = pattern
                        if entry["first_seen"] is None or (
                            timestamp and timestamp < entry["first_seen"]
                        ):
                            entry["first_seen"] = timestamp
                        if entry["last_seen"] is None or (
                            timestamp and timestamp > entry["last_seen"]
                        ):
                            entry["last_seen"] = timestamp
                        break

        signals: list[dict] = []
        now = datetime.now(timezone.utc)
        for tool_name, data in matches.items():
            first_seen = data["first_seen"] or now
            last_seen = data["last_seen"] or now
            signals.append({
                "signal_type": "local_file_match",
                "matched_tool": tool_name,
                "hostname_pattern": data["hostname_pattern"],
                "call_count_24h": data["count"],
                "source_system_label": f"local_file:{os.path.basename(self.file_path)}",
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            })

        return signals

    def _read_csv(self) -> list[dict]:
        """Read CSV format log file."""
        records: list[dict] = []
        try:
            with open(self.file_path, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
        except (OSError, csv.Error):
            pass
        return records

    def _read_json(self) -> list[dict]:
        """Read JSON format log file (one JSON object per line)."""
        records: list[dict] = []
        try:
            with open(self.file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except (json.JSONDecodeError, TypeError):
                        continue
        except OSError:
            pass
        return records

    def _read_syslog(self) -> list[dict]:
        """Read syslog format log file (basic parsing)."""
        records: list[dict] = []
        try:
            with open(self.file_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    record = {
                        "timestamp": parts[0] + " " + parts[1] if len(parts) > 1 else "",
                        "hostname": parts[2] if len(parts) > 2 else "",
                        "destination": parts[4] if len(parts) > 4 else "",
                    }
                    records.append(record)
        except OSError:
            pass
        return records

    def _parse_timestamp(self, ts) -> datetime | None:
        """Parse a timestamp string from the log file."""
        if not ts:
            return None
        if isinstance(ts, datetime):
            return ts
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(str(ts), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
