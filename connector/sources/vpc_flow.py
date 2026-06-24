"""
PATENT NOTICE
Module: connector/sources/vpc_flow
Part of: Core Patent Claim 2 — Edge Processing Architecture

Reads AWS VPC Flow Logs from CloudWatch Logs.
Matches destination hostname patterns against
AI service signatures.

What this source reads:
  destination host fields from VPC Flow Log
  record (if DNS hostnames are enabled) or
  destination IP ranges.

What this source NEVER sends:
  Raw log lines, source IPs, user identities,
  request/response contents.
  Only matched tool name + call count.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from collections import defaultdict


class VPCFlowSource:
    """AWS VPC Flow Logs source for the Tier 3 connector."""

    AI_HOSTNAME_SIGNATURES = {
        "OpenAI API": ["api.openai.com"],
        "Claude": ["api.anthropic.com"],
        "Cohere": ["api.cohere.ai", "api.cohere.com"],
        "Mistral AI": ["api.mistral.ai"],
        "Hugging Face": ["api-inference.huggingface.co"],
        "Stability AI": ["api.stability.ai"],
        "Groq": ["api.groq.com"],
        "Perplexity AI": ["api.perplexity.ai"],
        "Azure OpenAI": [".openai.azure.com"],
        "Amazon Bedrock": ["bedrock-runtime"],
        "Google Gemini": ["generativelanguage.googleapis.com"],
        "Vertex AI": ["aiplatform.googleapis.com"],
    }

    def __init__(self, config: dict, aws_session=None):
        """Initialize with source config and optional boto3 Session.

        Args:
            config: sources.vpc_flow dict from connector.yaml
            aws_session: boto3 Session with credentials
        """
        self.config = config
        self.aws_session = aws_session
        self.log_group = config.get("log_group", "/aws/vpc/flowlogs")
        self.region = config.get("aws_region", "ap-south-1")

    def scan(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch VPC Flow Log records from CloudWatch.

        Matches destination hostnames against AI_HOSTNAME_SIGNATURES.

        Returns list of signal dicts matching ConnectorSignalPayload schema.

        NEVER includes:
            Raw log lines, source IPs, destination IPs
            (only hostname patterns), user identities.
        """
        records = self._fetch_flow_logs(since, until)

        matches: dict[str, dict] = defaultdict(
            lambda: {
                "count": 0,
                "hostname_pattern": "",
                "first_seen": None,
                "last_seen": None,
            }
        )

        for record in records:
            dest = self._extract_destination(record)
            if not dest:
                continue
            timestamp = self._extract_timestamp(record)

            for tool_name, patterns in self.AI_HOSTNAME_SIGNATURES.items():
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
                "signal_type": "network_match",
                "matched_tool": tool_name,
                "hostname_pattern": data["hostname_pattern"],
                "call_count_24h": data["count"],
                "source_system_label": self.log_group,
                "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen),
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen),
            })

        return signals

    def _fetch_flow_logs(self, since: datetime, until: datetime) -> list[dict]:
        """Fetch VPC Flow Log records from CloudWatch Logs.

        Returns list of log record dicts. Returns empty list on error
        or when no AWS session is available.
        """
        if self.aws_session is None:
            return []

        try:
            logs = self.aws_session.client("logs", region_name=self.region)
            response = logs.filter_log_events(
                logGroupName=self.log_group,
                startTime=int(since.timestamp() * 1000),
                endTime=int(until.timestamp() * 1000),
                limit=10000,
            )
            records: list[dict] = []
            for event in response.get("events", []):
                try:
                    record = json.loads(event.get("message", "{}"))
                    record["_timestamp"] = datetime.fromtimestamp(
                        event.get("timestamp", 0) / 1000, tz=timezone.utc
                    )
                    records.append(record)
                except (json.JSONDecodeError, TypeError):
                    continue
            return records
        except Exception:
            return []

    def _extract_destination(self, record: dict) -> str:
        """Extract destination hostname from a flow log record."""
        return (
            record.get("dstAddr", "")
            or record.get("destination_hostname", "")
            or record.get("destination", "")
            or ""
        )

    def _extract_timestamp(self, record: dict) -> datetime | None:
        """Extract timestamp from a flow log record."""
        ts = record.get("_timestamp")
        if ts is not None:
            return ts
        start_field = record.get("start")
        if start_field:
            try:
                return datetime.fromtimestamp(int(start_field), tz=timezone.utc)
            except (ValueError, TypeError):
                pass
        return None
