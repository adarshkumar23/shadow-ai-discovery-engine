"""
Tests for the connector source modules.

All cloud SDK calls are mocked. Never makes real API calls.
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from connector.sources.vpc_flow import VPCFlowSource
from connector.sources.cloudtrail import CloudTrailSource
from connector.sources.local_file import LocalFileSource


def _make_mock_logs_session(events):
    """Create a mock boto3 session that returns the given log events."""
    mock_logs = MagicMock()
    mock_logs.filter_log_events.return_value = {"events": events}
    mock_session = MagicMock()
    mock_session.client.return_value = mock_logs
    return mock_session


# ═══════════════════════════════════════════════
# VPC FLOW SOURCE TESTS
# ═══════════════════════════════════════════════


def test_vpc_flow_scan_returns_signal_format():
    """VPCFlowSource.scan returns signals matching the expected schema."""
    now = datetime.now(timezone.utc)
    events = [
        {
            "timestamp": int(now.timestamp() * 1000),
            "message": json.dumps({
                "dstAddr": "api.openai.com",
                "start": str(int(now.timestamp())),
            }),
        },
    ]
    mock_session = _make_mock_logs_session(events)

    source = VPCFlowSource(
        {"aws_region": "us-east-1", "log_group": "test-flowlogs"},
        mock_session,
    )
    signals = source.scan(now - timedelta(hours=1), now)

    assert len(signals) == 1
    sig = signals[0]
    assert sig["signal_type"] == "network_match"
    assert sig["matched_tool"] == "OpenAI API"
    assert sig["hostname_pattern"] == "api.openai.com"
    assert sig["call_count_24h"] == 1
    assert "source_system_label" in sig
    assert "first_seen" in sig
    assert "last_seen" in sig


def test_vpc_flow_never_includes_source_ip():
    """VPC flow signals never include source IP or other forbidden fields."""
    now = datetime.now(timezone.utc)
    events = [
        {
            "timestamp": int(now.timestamp() * 1000),
            "message": json.dumps({
                "srcAddr": "10.0.0.1",
                "dstAddr": "api.openai.com",
            }),
        },
    ]
    mock_session = _make_mock_logs_session(events)

    source = VPCFlowSource(
        {"aws_region": "us-east-1", "log_group": "test"},
        mock_session,
    )
    signals = source.scan(now - timedelta(hours=1), now)

    assert len(signals) == 1
    forbidden = {
        "raw_log", "log_line", "ip_address", "internal_ip",
        "source_ip", "dest_ip", "user_id", "user_email",
        "payload_content", "request_body", "response_body",
        "packet_data", "full_url", "query_string", "http_headers",
    }
    for key in signals[0].keys():
        assert key not in forbidden, f"Forbidden field {key} found in signal"


def test_vpc_flow_no_session_returns_empty():
    """VPCFlowSource with no AWS session returns empty list."""
    source = VPCFlowSource({"log_group": "test"}, None)
    now = datetime.now(timezone.utc)
    signals = source.scan(now - timedelta(hours=1), now)
    assert signals == []


# ═══════════════════════════════════════════════
# CLOUDTRAIL SOURCE TESTS
# ═══════════════════════════════════════════════


def test_cloudtrail_matches_bedrock():
    """CloudTrailSource matches Amazon Bedrock eventSource."""
    now = datetime.now(timezone.utc)
    events = [
        {
            "message": json.dumps({
                "eventSource": "bedrock.amazonaws.com",
                "eventTime": now.isoformat(),
                "eventName": "InvokeModel",
            }),
        },
    ]
    mock_session = _make_mock_logs_session(events)

    source = CloudTrailSource(
        {"aws_region": "us-east-1", "log_group": "test-cloudtrail"},
        mock_session,
    )
    signals = source.scan(now - timedelta(hours=1), now)

    assert len(signals) == 1
    assert signals[0]["matched_tool"] == "Amazon Bedrock"
    assert signals[0]["signal_type"] == "cloudtrail_match"
    assert signals[0]["call_count_24h"] == 1


def test_cloudtrail_no_session_returns_empty():
    """CloudTrailSource with no AWS session returns empty list."""
    source = CloudTrailSource({"log_group": "test"}, None)
    now = datetime.now(timezone.utc)
    signals = source.scan(now - timedelta(hours=1), now)
    assert signals == []


# ═══════════════════════════════════════════════
# LOCAL FILE SOURCE TESTS
# ═══════════════════════════════════════════════


def test_local_file_reads_csv_format():
    """LocalFileSource reads CSV files and matches AI hostnames."""
    now = datetime.now(timezone.utc)
    csv_content = "destination,timestamp\n"
    csv_content += f"api.openai.com,{now.isoformat()}\n"
    csv_content += f"api.anthropic.com,{now.isoformat()}\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(csv_content)
        f.flush()
        file_path = f.name

    try:
        source = LocalFileSource({"file_path": file_path, "format": "csv"})
        signals = source.scan(now - timedelta(hours=2), now + timedelta(hours=1))

        tools = {s["matched_tool"] for s in signals}
        assert "OpenAI API" in tools
        assert "Claude" in tools
        for sig in signals:
            assert sig["signal_type"] == "local_file_match"
    finally:
        os.unlink(file_path)


def test_local_file_reads_json_format():
    """LocalFileSource reads JSON-lines files and matches AI hostnames."""
    now = datetime.now(timezone.utc)
    lines = [
        json.dumps({"destination": "api.openai.com", "timestamp": now.isoformat()}),
        json.dumps({"destination": "api.openai.com", "timestamp": now.isoformat()}),
        json.dumps({"destination": "api.groq.com", "timestamp": now.isoformat()}),
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        for line in lines:
            f.write(line + "\n")
        f.flush()
        file_path = f.name

    try:
        source = LocalFileSource({"file_path": file_path, "format": "json"})
        signals = source.scan(now - timedelta(hours=2), now + timedelta(hours=1))

        tool_counts = {s["matched_tool"]: s["call_count_24h"] for s in signals}
        assert "OpenAI API" in tool_counts
        assert tool_counts["OpenAI API"] == 2
        assert "Groq" in tool_counts
        assert tool_counts["Groq"] == 1
    finally:
        os.unlink(file_path)


def test_signal_count_correct_per_source():
    """Multiple records to the same destination produce correct call_count_24h."""
    now = datetime.now(timezone.utc)
    events = [
        {
            "timestamp": int(now.timestamp() * 1000),
            "message": json.dumps({"dstAddr": "api.openai.com"}),
        },
        {
            "timestamp": int(now.timestamp() * 1000),
            "message": json.dumps({"dstAddr": "api.openai.com"}),
        },
        {
            "timestamp": int(now.timestamp() * 1000),
            "message": json.dumps({"dstAddr": "api.openai.com"}),
        },
    ]
    mock_session = _make_mock_logs_session(events)

    source = VPCFlowSource(
        {"aws_region": "us-east-1", "log_group": "test"},
        mock_session,
    )
    signals = source.scan(now - timedelta(hours=1), now)

    assert len(signals) == 1
    assert signals[0]["call_count_24h"] == 3
