"""
PATENT NOTICE
Module: connector/sources/gcp_audit
Part of: Core Patent Claim 2 — Edge Processing Architecture

Reads GCP Cloud Audit Logs for API calls to
Google AI services.
Uses Google Cloud Logging SDK.

What this source NEVER sends:
  User emails, project metadata,
  request details.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


class GCPAuditSource:
    """GCP Cloud Audit Logs source for the Tier 3 connector."""

    AI_SERVICE_NAMES = [
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com",
        "ml.googleapis.com",
        "automl.googleapis.com",
    ]

    def __init__(self, config: dict, gcp_credentials=None):
        """Initialize with source config.

        Args:
            config: sources.gcp_audit dict from connector.yaml
            gcp_credentials: Google Cloud credentials object
        """
        self.config = config
        self.credentials = gcp_credentials
        self.project_id = config.get("project_id", "")
        self.log_name = config.get(
            "log_name", "cloudaudit.googleapis.com/activity"
        )

    def scan(self, since: datetime, until: datetime) -> list[dict]:
        """Query GCP Cloud Logging for audit entries matching AI service names.

        Returns signal dicts.
        NEVER includes: user emails, project metadata, request details.
        """
        entries = self._fetch_entries(since, until)

        matches: dict[str, dict] = defaultdict(
            lambda: {
                "count": 0,
                "first_seen": None,
                "last_seen": None,
            }
        )

        for entry in entries:
            service_name = entry.get("serviceName", "") or entry.get(
                "resource", {}
            ).get("labels", {}).get("service", "")
            timestamp = self._parse_timestamp(entry.get("timestamp"))

            for ai_service in self.AI_SERVICE_NAMES:
                if ai_service in service_name or service_name in ai_service:
                    entry_data = matches[ai_service]
                    entry_data["count"] += 1
                    if entry_data["first_seen"] is None or (
                        timestamp and timestamp < entry_data["first_seen"]
                    ):
                        entry_data["first_seen"] = timestamp
                    if entry_data["last_seen"] is None or (
                        timestamp and timestamp > entry_data["last_seen"]
                    ):
                        entry_data["last_seen"] = timestamp
                    break

        signals: list[dict] = []
        now = datetime.now(timezone.utc)
        source_label = f"gcp:{self.project_id[:8]}" if self.project_id else "gcp_audit"
        for service_name, data in matches.items():
            first_seen = data["first_seen"] or now
            last_seen = data["last_seen"] or now
            signals.append({
                "signal_type": "gcp_audit_match",
                "matched_tool": service_name,
                "hostname_pattern": service_name,
                "call_count_24h": data["count"],
                "source_system_label": source_label,
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            })

        return signals

    def _fetch_entries(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch GCP audit log entries using Google Cloud Logging SDK."""
        if not self.project_id or self.credentials is None:
            return []

        try:
            from google.cloud import logging as gcp_logging

            client = gcp_logging.Client(credentials=self.credentials)
            filter_str = (
                f'logName = "projects/{self.project_id}/logs/{self.log_name}" '
                f'AND timestamp >= "{since.isoformat()}" '
                f'AND timestamp <= "{until.isoformat()}"'
            )
            entries: list[dict] = []
            for entry in client.list_entries(filter_=filter_str, max_results=10000):
                entry_dict = entry.to_dict()
                entries.append(entry_dict)
            return entries
        except Exception:
            return []

    def _parse_timestamp(self, timestamp) -> datetime | None:
        """Parse GCP timestamp string."""
        if not timestamp:
            return None
        if isinstance(timestamp, datetime):
            return timestamp
        try:
            return datetime.fromisoformat(
                str(timestamp).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return None
