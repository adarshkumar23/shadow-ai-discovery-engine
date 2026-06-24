"""
PATENT NOTICE
Module: connector/sources/cloudtrail
Part of: Core Patent Claim 2 — Edge Processing Architecture

Reads AWS CloudTrail logs for API calls to
known AI service endpoints.

Matches event.eventSource against known
AI service API domain patterns.

What this source NEVER sends:
  Raw event details, user ARNs,
  request parameters, response elements.
  Only: matched service name, call count,
  time window.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone


class CloudTrailSource:
    """AWS CloudTrail log source for the Tier 3 connector."""

    AI_EVENT_SOURCES = {
        "Amazon Bedrock": [
            "bedrock.amazonaws.com",
            "bedrock-runtime.amazonaws.com",
        ],
        "Amazon Rekognition": [
            "rekognition.amazonaws.com",
        ],
        "Amazon Comprehend": [
            "comprehend.amazonaws.com",
        ],
        "Amazon Transcribe": [
            "transcribe.amazonaws.com",
        ],
        "Amazon SageMaker": [
            "sagemaker.amazonaws.com",
        ],
    }

    def __init__(self, config: dict, aws_session=None):
        """Initialize with source config and optional boto3 Session.

        Args:
            config: sources.cloudtrail dict from connector.yaml
            aws_session: boto3 Session with credentials
        """
        self.config = config
        self.aws_session = aws_session
        self.region = config.get("aws_region", "ap-south-1")
        self.log_group = config.get("log_group", "")
        self.s3_bucket = config.get("s3_bucket", "")

    def scan(self, since: datetime, until: datetime) -> list[dict]:
        """Read CloudTrail events and match against AI service sources.

        Returns signal dicts.
        NEVER includes: raw event details, user ARNs,
        request parameters, response elements.
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
            event_source = event.get("eventSource", "")
            event_time = self._parse_event_time(event.get("eventTime"))

            for service_name, sources in self.AI_EVENT_SOURCES.items():
                for src in sources:
                    if src in event_source or event_source in src:
                        entry = matches[service_name]
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
        source_label = self.log_group or self.s3_bucket or "cloudtrail"
        for service_name, data in matches.items():
            first_seen = data["first_seen"] or now
            last_seen = data["last_seen"] or now
            signals.append({
                "signal_type": "cloudtrail_match",
                "matched_tool": service_name,
                "hostname_pattern": service_name,
                "call_count_24h": data["count"],
                "source_system_label": source_label,
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            })

        return signals

    def _fetch_events(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch CloudTrail events from CloudWatch Logs or S3."""
        if self.aws_session is None:
            return []

        try:
            if self.log_group:
                return self._fetch_from_cloudwatch(since, until)
            elif self.s3_bucket:
                return self._fetch_from_s3(since, until)
        except Exception:
            pass
        return []

    def _fetch_from_cloudwatch(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch CloudTrail events from CloudWatch Logs."""
        logs = self.aws_session.client("logs", region_name=self.region)
        response = logs.filter_log_events(
            logGroupName=self.log_group,
            startTime=int(since.timestamp() * 1000),
            endTime=int(until.timestamp() * 1000),
            limit=10000,
        )
        events: list[dict] = []
        for event in response.get("events", []):
            try:
                events.append(json.loads(event.get("message", "{}")))
            except (json.JSONDecodeError, TypeError):
                continue
        return events

    def _fetch_from_s3(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch CloudTrail events from S3 (simplified)."""
        return []

    def _parse_event_time(self, event_time) -> datetime | None:
        """Parse CloudTrail eventTime string."""
        if not event_time:
            return None
        if isinstance(event_time, datetime):
            return event_time
        try:
            return datetime.fromisoformat(
                event_time.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return None
