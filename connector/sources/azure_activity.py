"""
PATENT NOTICE
Module: connector/sources/azure_activity
Part of: Core Patent Claim 2 — Edge Processing Architecture

Reads Azure Activity Logs for API calls to
Azure AI services.
Uses Azure Monitor Query SDK.

What this source NEVER sends:
  User identities, resource IDs,
  subscription details beyond resource type.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


class AzureActivitySource:
    """Azure Activity Log source for the Tier 3 connector."""

    AI_RESOURCE_TYPES = [
        "Microsoft.CognitiveServices",
        "Microsoft.MachineLearningServices",
        "Microsoft.BotService",
    ]

    def __init__(self, config: dict, azure_credential=None):
        """Initialize with source config.

        Args:
            config: sources.azure_activity dict from connector.yaml
            azure_credential: Azure credential object for authentication
        """
        self.config = config
        self.credential = azure_credential
        self.subscription_id = config.get("subscription_id", "")

    def scan(self, since: datetime, until: datetime) -> list[dict]:
        """Query Azure Monitor for activity log entries matching AI resource types.

        Returns signal dicts.
        NEVER includes: user identities, resource IDs,
        subscription details beyond resource type.
        """
        events = self._fetch_events(since, until)

        matches: dict[str, dict] = defaultdict(
            lambda: {
                "count": 0,
                "first_seen": None,
                "last_seen": None,
            }
        )

        for event in events:
            resource_type = event.get("resourceType", "") or event.get(
                "resourceId", ""
            )
            event_time = self._parse_event_time(
                event.get("eventTimestamp") or event.get("time")
            )

            for ai_type in self.AI_RESOURCE_TYPES:
                if ai_type.lower() in resource_type.lower():
                    entry = matches[ai_type]
                    entry["count"] += 1
                    if entry["first_seen"] is None or (
                        event_time and event_time < entry["first_seen"]
                    ):
                        entry["first_seen"] = event_time
                    if entry["last_seen"] is None or (
                        event_time and event_time > entry["last_seen"]
                    ):
                        entry["last_seen"] = event_time
                    break

        signals: list[dict] = []
        now = datetime.now(timezone.utc)
        for resource_type, data in matches.items():
            first_seen = data["first_seen"] or now
            last_seen = data["last_seen"] or now
            signals.append({
                "signal_type": "azure_activity_match",
                "matched_tool": resource_type,
                "hostname_pattern": resource_type,
                "call_count_24h": data["count"],
                "source_system_label": f"azure:{self.subscription_id[:8]}" if self.subscription_id else "azure_activity",
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            })

        return signals

    def _fetch_events(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch Azure Activity Log events using Azure Monitor Query SDK."""
        if not self.subscription_id or self.credential is None:
            return []

        try:
            from azure.monitor.query import LogsQueryClient

            client = LogsQueryClient(self.credential)
            query = (
                "AzureActivity "
                f"| where TimeGenerated >= datetime({since.isoformat()}) "
                f"and TimeGenerated <= datetime({until.isoformat()}) "
                f"| where ResourceProvider in ('Microsoft.CognitiveServices', "
                f"'Microsoft.MachineLearningServices', 'Microsoft.BotService')"
            )
            response = client.query_workspace(
                workspace_id=self.subscription_id,
                query=query,
                timespan=(since, until),
            )
            events: list[dict] = []
            if response and response.tables:
                for table in response.tables:
                    for row in table.rows:
                        events.append(dict(zip(table.columns, row)))
            return events
        except Exception:
            return []

    def _parse_event_time(self, event_time) -> datetime | None:
        """Parse Azure event timestamp."""
        if not event_time:
            return None
        if isinstance(event_time, datetime):
            return event_time
        try:
            return datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
