# CompliVibe Shadow AI Discovery Connector

> **PATENT NOTICE:** This connector is the open source edge component of
> Core Patent Claim 2 (Edge Processing Architecture) in the system
> described by provisional patent filing: *System and Method for Inferring
> Undeclared Artificial Intelligence Systems and Generating AI Governance
> Artifacts from Enterprise Telemetry.*
>
> **It runs inside your environment. It sends signals only. Raw telemetry
> never leaves your network.**

---

## What This Connector Does

The CompliVibe Shadow AI Discovery Connector reads log and audit sources
inside your cloud environment (AWS VPC Flow Logs, AWS CloudTrail, Azure
Activity Logs, GCP Cloud Audit Logs, or local log files), matches
destination hostnames and API endpoints against known AI service
signatures, and sends **pre-processed signals** to the CompliVibe ingest
API.

Each signal contains only:

- Matched tool name (e.g. "OpenAI API")
- Hostname pattern matched (e.g. "api.openai.com")
- Call count in the scan window
- Source system label (customer-assigned)
- First-seen and last-seen timestamps
- Connector version

The CompliVibe service uses these signals to detect undeclared AI systems
in your environment and generate governance artifacts.

## What This Connector NEVER Sends

This is a **patent design invariant**. The connector is open source so
you can audit every line. The following fields are **never** collected,
processed, or transmitted:

| Forbidden Field | Why |
|---|---|
| `raw_log` | Raw log lines never leave your environment |
| `log_line` | Individual log entries are not transmitted |
| `ip_address` | Internal IP addresses are never sent |
| `internal_ip` | Internal network topology is not exposed |
| `source_ip` | Source IPs are not collected |
| `dest_ip` | Only hostname patterns are sent, not IPs |
| `user_id` | User identities are never transmitted |
| `user_email` | Employee PII is never collected |
| `payload_content` | Request/response bodies are never read |
| `request_body` | API request contents are not captured |
| `response_body` | API response contents are not captured |
| `packet_data` | Network packet captures are not performed |
| `full_url` | Full URLs with paths/queries are not sent |
| `query_string` | URL query parameters are never transmitted |
| `http_headers` | HTTP headers are never collected |

The CompliVibe ingest API enforces this at the HTTP layer — any payload
containing these fields is rejected with HTTP 400 before any database
write occurs.

## Deployment Options

### Cron (simplest)

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and edit config
cp connector.yaml.example connector.yaml
# Edit connector.yaml with your org_id and connector_token

# Run every 60 minutes
*/60 * * * * cd /opt/complivibe-connector && python connector.py --config connector.yaml --once
```

### Docker

```bash
docker run -d \
  --name complivibe-connector \
  -v /path/to/connector.yaml:/app/connector.yaml \
  -v /var/lib/complivibe:/var/lib/complivibe \
  complivibe/connector:latest
```

### AWS Lambda

Package the connector with its dependencies as a Lambda layer. Configure
as a scheduled Lambda function with a 60-minute rate:

```python
# lambda_handler.py
from connector.connector import load_config, run_scan
from connector.queue_manager import QueueManager

def handler(event, context):
    config = load_config("connector.yaml")
    queue = QueueManager("/tmp/queue.db")
    run_scan(config, queue)
    queue.close()
```

## Zero-Day Detection

The connector can send signals for **all** observed hostnames that meet the
minimum call count, not just known AI services. The CompliVibe server runs a
server-side behavioral classifier on these signals to determine if an unknown
hostname exhibits AI service patterns.

This enables detection of AI services that are not yet in the signature
registry — zero-day AI tools in use in your environment. The classifier
analyzes only network envelope metadata:

- Hostname pattern structure
- Call count and frequency
- First-seen and last-seen timestamps

It **never** inspects payload contents, request bodies, or response bodies.

Zero-day detection is optional and enabled by default. Configure it under the
`zero_day` section in `connector.yaml`:

```yaml
zero_day:
  enabled: true
  threshold: 0.55
  min_calls_24h: 5
```

Detected zero-day candidates appear in the CompliVibe UI for human review. A
reviewer can add the hostname to the registry, dismiss it, or set it to
monitoring.

## Federated Intelligence Network

The connector can opt in to the **Federated Registry Intelligence Network**
(Dependent Patent Claim 8). When enabled, the connector submits unknown AI
service hostnames to a central, privacy-preserving aggregation service.

### What it is

A network effect: every participating organization makes the registry better
for all customers. When 3+ independent organizations observe the same unknown
hostname, it is automatically promoted to a candidate signature for human
review.

### What is submitted

Only these three fields are sent:

- `hostname` — the unknown AI service hostname
- `behavioral_score` — the local confidence that the hostname is AI-related
- `connector_version` — the connector version string

### What is NEVER submitted

- Organization identity (the server derives org_id from the token and strips it)
- IP addresses
- User data
- Raw logs or telemetry

### How to enable it

Add the `federated` section to `connector.yaml`:

```yaml
federated:
  enabled: true
  min_behavioral_score: 0.55
  submit_interval_hours: 24
```

Then call `submit_federated_signals(config, unknown_hostnames)` after a scan.

### Privacy guarantee

Organization identity is stripped before any aggregation storage. The
aggregation table has no `organization_id` column and cannot reveal which
organizations contributed to any observation count. This is provably
privacy-preserving by design.

## Configuration Reference

All configuration is in `connector.yaml`:

| Key | Required | Default | Description |
|---|---|---|---|
| `complivibe.api_url` | Yes | — | CompliVibe API base URL |
| `complivibe.org_id` | Yes | — | Your organization UUID |
| `complivibe.connector_token` | Yes | — | Connector API token (from CompliVibe admin) |
| `connector.version` | No | `1.0.0` | Connector version (semver) |
| `connector.scan_interval_minutes` | No | `60` | How often to scan |
| `connector.heartbeat_interval_minutes` | No | `30` | Heartbeat frequency |
| `connector.queue_file` | No | `/var/lib/complivibe/queue.db` | SQLite queue path |
| `connector.queue_max_size` | No | `10000` | Max buffered signals |
| `sources.vpc_flow.enabled` | No | `false` | Enable AWS VPC Flow Logs |
| `sources.vpc_flow.aws_region` | No | `ap-south-1` | AWS region |
| `sources.vpc_flow.log_group` | No | `/aws/vpc/flowlogs` | CloudWatch log group |
| `sources.cloudtrail.enabled` | No | `false` | Enable AWS CloudTrail |
| `sources.cloudtrail.aws_region` | No | `ap-south-1` | AWS region |
| `sources.cloudtrail.s3_bucket` | No | — | S3 bucket for CloudTrail |
| `sources.cloudtrail.log_group` | No | — | CloudWatch log group |
| `sources.azure_activity.enabled` | No | `false` | Enable Azure Activity Logs |
| `sources.azure_activity.subscription_id` | No | — | Azure subscription ID |
| `sources.gcp_audit.enabled` | No | `false` | Enable GCP Audit Logs |
| `sources.gcp_audit.project_id` | No | — | GCP project ID |
| `sources.gcp_audit.log_name` | No | `cloudaudit.googleapis.com/activity` | GCP log name |
| `sources.local_file.enabled` | No | `false` | Enable local file source |
| `sources.local_file.file_path` | No | `/var/log/network/flows.log` | Log file path |
| `sources.local_file.format` | No | `csv` | Format: `csv`, `json`, or `syslog` |

## Security: Generating a Token

1. Log in to CompliVibe as an administrator.
2. Navigate to Shadow AI Discovery → Connector.
3. Click "Generate Connector Token".
4. Enter a label (e.g. "aws-prod-connector").
5. Copy the token immediately — **it is shown only once**.
6. Store it securely (e.g. in AWS Secrets Manager, Azure Key Vault).
7. The token expires after 365 days. Generate a new one before expiry.

The token is stored as a SHA256 hash in CompliVibe. The raw token value
is never persisted. If you lose it, you must generate a new one.

## Verification: Confirming It's Working

1. **Check the connector status dashboard** in CompliVibe:
   `GET /api/v1/shadow-ai/connector/status`
   — your connector should show as "online".

2. **Check heartbeats**:
   `GET /api/v1/shadow-ai/connector/heartbeats`
   — a recent heartbeat confirms the connector is running.

3. **Check signals received**:
   `GET /api/v1/shadow-ai/connector/tokens`
   — `signals_total` should increment on each scan.

4. **Check detections**:
   `GET /api/v1/shadow-ai/detections`
   — matched AI tools should appear as detections.

5. **Check the queue** (if API is unreachable):
   The SQLite queue file at `connector.queue_file` will grow. It flushes
   automatically when the API becomes reachable again.

## Signal Schema

This is the exact JSON schema the connector sends to the ingest API:

```json
{
  "org_id": "11111111-1111-1111-1111-111111111111",
  "signal_type": "network_match",
  "matched_tool": "OpenAI API",
  "hostname_pattern": "api.openai.com",
  "call_count_24h": 42,
  "source_system_label": "/aws/vpc/flowlogs",
  "first_seen": "2026-06-24T10:00:00+00:00",
  "last_seen": "2026-06-24T11:00:00+00:00",
  "connector_version": "1.0.0"
}
```

The full schema is available at:
`GET /api/v1/shadow-ai/connector/schema` (no authentication required).

## Trust Statement

This connector is **open source**. You can audit every line of code to
verify that:

1. No raw telemetry leaves your environment.
2. No user identities are collected.
3. No request/response contents are read.
4. No internal IP addresses are transmitted.
5. The connector only sends pre-processed signals to CompliVibe.
6. CompliVibe never initiates connections into your environment —
   the connector is always the initiator.

The CompliVibe ingest API enforces these invariants at the HTTP layer.
Any attempt to send forbidden fields is rejected with HTTP 400 before
any database write occurs. This is a patent design invariant.

## Offline Queue

When the CompliVibe API is unreachable, signals are buffered locally in
SQLite (`connector.queue_file`). The queue has a maximum of 10,000
signals. When full, the oldest signals are dropped (not newest — newer
signals are more valuable for recency). The queue is flushed on every
successful API call.
