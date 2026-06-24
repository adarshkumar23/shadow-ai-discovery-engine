"""
PATENT NOTICE
This connector is the open source edge
component of Core Patent Claim 2.

It runs inside the customer's environment.
It reads local log sources.
It sends pre-processed signals only.
Raw telemetry never leaves this machine.

Deploy options:
  cron:   */60 * * * * python connector.py
  docker: docker run complivibe/connector
  lambda: configure as scheduled Lambda

Configuration: connector.yaml
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow running as: python connector/connector.py
# by adding the project root to sys.path so the connector package resolves.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import httpx
import yaml

from connector.queue_manager import QueueManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("complivibe-connector")


def load_config(path: str = "connector.yaml") -> dict:
    """Load connector configuration from YAML file.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed configuration dict.
    """
    config_file = Path(path)
    if not config_file.exists():
        logger.error("Config file not found: %s", path)
        sys.exit(1)

    with open(config_file, "r") as f:
        config = yaml.safe_load(f)

    if not config:
        logger.error("Empty or invalid config file: %s", path)
        sys.exit(1)

    return config


def get_active_sources(config: dict) -> list:
    """Return list of enabled source objects.

    Reads the 'sources' section of the config and instantiates
    each enabled source. Sources that require cloud SDKs are
    only instantiated if the SDK is available.
    """
    sources_config = config.get("sources", {})
    active_sources: list = []

    vpc_cfg = sources_config.get("vpc_flow", {})
    if vpc_cfg.get("enabled", False):
        try:
            from connector.sources.vpc_flow import VPCFlowSource

            aws_session = None
            try:
                import boto3

                aws_session = boto3.Session()
            except Exception:
                logger.warning("boto3 not available — VPC Flow source will be inactive")
            active_sources.append(VPCFlowSource(vpc_cfg, aws_session))
        except ImportError:
            logger.warning("VPCFlowSource import failed")

    ct_cfg = sources_config.get("cloudtrail", {})
    if ct_cfg.get("enabled", False):
        try:
            from connector.sources.cloudtrail import CloudTrailSource

            aws_session = None
            try:
                import boto3

                aws_session = boto3.Session()
            except Exception:
                pass
            active_sources.append(CloudTrailSource(ct_cfg, aws_session))
        except ImportError:
            logger.warning("CloudTrailSource import failed")

    azure_cfg = sources_config.get("azure_activity", {})
    if azure_cfg.get("enabled", False):
        try:
            from connector.sources.azure_activity import AzureActivitySource

            active_sources.append(AzureActivitySource(azure_cfg))
        except ImportError:
            logger.warning("AzureActivitySource import failed")

    gcp_cfg = sources_config.get("gcp_audit", {})
    if gcp_cfg.get("enabled", False):
        try:
            from connector.sources.gcp_audit import GCPAuditSource

            active_sources.append(GCPAuditSource(gcp_cfg))
        except ImportError:
            logger.warning("GCPAuditSource import failed")

    lf_cfg = sources_config.get("local_file", {})
    if lf_cfg.get("enabled", False):
        try:
            from connector.sources.local_file import LocalFileSource

            active_sources.append(LocalFileSource(lf_cfg))
        except ImportError:
            logger.warning("LocalFileSource import failed")

    return active_sources


def send_signal(
    payload: dict,
    config: dict,
    queue: QueueManager,
) -> bool:
    """Send a signal to CompliVibe ingest API.

    On success: returns True.
    On failure: enqueues signal, returns False.
    Never raises.
    """
    api_cfg = config.get("complivibe", {})
    api_url = api_cfg.get("api_url", "").rstrip("/")
    org_id = api_cfg.get("org_id", "")
    token = api_cfg.get("connector_token", "")
    connector_version = config.get("connector", {}).get("version", "1.0.0")

    full_payload = dict(payload)
    full_payload["org_id"] = org_id
    full_payload["connector_version"] = connector_version

    ingest_url = f"{api_url}/api/v1/shadow-ai/connector/ingest"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                ingest_url,
                json=full_payload,
                headers={"X-Connector-Token": token},
            )
        if response.status_code == 200:
            logger.debug("Signal accepted: %s", full_payload.get("matched_tool"))
            return True
        elif response.status_code == 429:
            logger.warning("Rate limited — queuing signal for later")
            queue.enqueue(full_payload)
            return False
        else:
            logger.warning(
                "Signal rejected: HTTP %d — %s",
                response.status_code,
                response.text[:200],
            )
            if response.status_code != 400:
                queue.enqueue(full_payload)
            return False
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("API unreachable — queuing signal: %s", exc)
        queue.enqueue(full_payload)
        return False


def send_heartbeat(config: dict, signals_sent: int) -> None:
    """Post heartbeat to /connector/heartbeat.

    Never raises — heartbeat failures are logged only.
    """
    api_cfg = config.get("complivibe", {})
    api_url = api_cfg.get("api_url", "").rstrip("/")
    token = api_cfg.get("connector_token", "")
    connector_version = config.get("connector", {}).get("version", "1.0.0")

    heartbeat_url = f"{api_url}/api/v1/shadow-ai/connector/heartbeat"

    payload = {
        "connector_version": connector_version,
        "signals_last_hour": signals_sent,
        "sources_active": [
            name
            for name, cfg in config.get("sources", {}).items()
            if cfg.get("enabled", False)
        ],
        "status": "online",
    }

    try:
        with httpx.Client(timeout=15) as client:
            response = client.post(
                heartbeat_url,
                json=payload,
                headers={"X-Connector-Token": token},
            )
        if response.status_code == 200:
            logger.debug("Heartbeat sent successfully")
        else:
            logger.warning(
                "Heartbeat failed: HTTP %d", response.status_code
            )
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("Heartbeat failed: %s", exc)


def submit_federated_signals(
    config: dict,
    unknown_hostnames: list[dict],
):
    """
    Submits unknown hostname signals to the CompliVibe federated registry
    network.

    Only runs if federated.enabled = True in connector.yaml.
    Only submits hostnames with behavioral_score >=
    federated.min_behavioral_score.

    What is sent: hostname, behavioral_score, connector_version.
    What is NEVER sent: organization_id (server derives from token), IP
    addresses, user data, raw logs.

    Endpoint: POST /federated/submit
    Auth: X-Connector-Token header
    """
    federated_cfg = config.get("federated", {})
    if not federated_cfg.get("enabled", False):
        return

    api_cfg = config.get("complivibe", {})
    api_url = api_cfg.get("api_url", "").rstrip("/")
    token = api_cfg.get("connector_token", "")
    connector_version = config.get("connector", {}).get("version", "1.0.0")
    min_score = federated_cfg.get("min_behavioral_score", 0.55)

    submit_url = f"{api_url}/api/v1/shadow-ai/federated/submit"

    for item in unknown_hostnames:
        hostname = item.get("hostname", "")
        score = item.get("behavioral_score", 0.0)
        if not hostname:
            continue
        if score < min_score:
            continue

        payload = {
            "hostname": hostname,
            "behavioral_score": score,
            "connector_version": connector_version,
        }
        try:
            with httpx.Client(timeout=15) as client:
                response = client.post(
                    submit_url,
                    json=payload,
                    headers={"X-Connector-Token": token},
                )
            if response.status_code == 200:
                logger.debug("Federated signal accepted: %s", hostname)
            else:
                logger.warning(
                    "Federated signal rejected: HTTP %d — %s",
                    response.status_code,
                    response.text[:200],
                )
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Federated submission failed: %s", exc)


def run_scan(config: dict, queue: QueueManager) -> int:
    """Main scan loop.

    1. Flush queue (send buffered signals first)
    2. For each active source:
       signals = source.scan(since, until)
       For each signal: send_signal(signal, config, queue)
    3. Send heartbeat

    Returns count of signals sent successfully.
    """
    connector_cfg = config.get("connector", {})
    scan_interval = connector_cfg.get("scan_interval_minutes", 60)

    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=scan_interval)

    # 1. Flush queue first
    flush_result = queue.flush(
        lambda payload: send_signal(payload, config, QueueManager(":memory:"))
    )
    if flush_result["flushed"] > 0:
        logger.info(
            "Queue flushed: %d sent, %d failed, %d abandoned",
            flush_result["flushed"],
            flush_result["failed"],
            flush_result["abandoned"],
        )

    # 2. Scan active sources
    sources = get_active_sources(config)
    signals_sent = 0

    for source in sources:
        try:
            signals = source.scan(since, now)
            for signal in signals:
                if send_signal(signal, config, queue):
                    signals_sent += 1
        except Exception as exc:
            logger.error("Source scan failed: %s", exc)

    logger.info("Scan complete: %d signals sent", signals_sent)

    # 3. Send heartbeat
    send_heartbeat(config, signals_sent)

    return signals_sent


def main():
    """Entry point.

    Loads config. Runs scan loop on configured interval.
    Handles KeyboardInterrupt gracefully.
    """
    parser = argparse.ArgumentParser(
        description="CompliVibe Shadow AI Discovery Connector"
    )
    parser.add_argument(
        "--config",
        default="connector.yaml",
        help="Path to connector config file (default: connector.yaml)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (for cron/lambda)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override scan interval in minutes",
    )
    args = parser.parse_args()

    config = load_config(args.config)

    if args.interval is not None:
        config.setdefault("connector", {})["scan_interval_minutes"] = args.interval

    connector_cfg = config.get("connector", {})
    queue_file = connector_cfg.get("queue_file", "/var/lib/complivibe/queue.db")
    scan_interval = connector_cfg.get("scan_interval_minutes", 60)

    queue = QueueManager(queue_file)

    if args.once:
        run_scan(config, queue)
        queue.close()
        return

    logger.info(
        "CompliVibe connector started — scan interval: %d minutes",
        scan_interval,
    )

    try:
        while True:
            run_scan(config, queue)
            logger.info("Sleeping %d minutes...", scan_interval)
            time.sleep(scan_interval * 60)
    except KeyboardInterrupt:
        logger.info("Connector stopped by user")
        queue.close()


if __name__ == "__main__":
    main()
