"""
Tests for the Tier 1 Scanner.
"""

import json
from uuid import uuid4

from sqlalchemy import select

from app.models.telemetry import TelemetryEvent
from app.models.detection import ShadowAIDetection
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response

ORG_A = uuid4()
ORG_B = uuid4()


def test_scan_finds_chatgpt_in_text(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for drafting customer support responses.",
    )
    summary = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary["new_signals"] > 0

    events = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.organization_id == org_id)
    ).scalars().all()
    assert len(events) > 0

    found_chatgpt = False
    for e in events:
        raw = json.loads(e.raw_signal_json)
        if "chatgpt" in raw.get("matched_keyword", "").lower():
            found_chatgpt = True
            break
    assert found_chatgpt


def test_scan_finds_multiple_tools_in_one_response(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT, Claude, and Gemini for various tasks across the team.",
    )
    summary = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary["new_signals"] >= 3


def test_scan_creates_telemetry_events(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "Our team relies on ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    events = seeded_db.execute(
        select(TelemetryEvent).where(
            TelemetryEvent.organization_id == org_id,
            TelemetryEvent.tier == 1,
        )
    ).scalars().all()
    assert len(events) >= 1
    for e in events:
        assert e.event_type == "text_mention"
        assert e.matched_signature_id is not None
        raw = json.loads(e.raw_signal_json)
        assert "matched_keyword" in raw
        assert "matched_text_excerpt" in raw
        assert "source_table" in raw


def test_duplicate_signal_not_stored(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for drafting responses.",
    )
    summary1 = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary1["new_signals"] > 0

    summary2 = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary2["new_signals"] == 0
    assert summary2["duplicates_skipped"] > 0


def test_scan_returns_scan_summary(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for drafting.",
    )
    summary = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    expected_keys = {
        "records_scanned", "new_signals", "duplicates_skipped",
        "detections_created", "detections_updated", "scan_duration_ms",
        "scan_type",
    }
    assert set(summary.keys()) == expected_keys
    assert summary["scan_type"] == "questionnaire"
    assert summary["records_scanned"] >= 1
    assert summary["scan_duration_ms"] >= 0


def test_scan_only_processes_org_responses(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT at org A.",
    )
    make_questionnaire_response(
        seeded_db, ORG_B,
        "We use Claude at org B.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    org_b_events = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.organization_id == ORG_B)
    ).scalars().all()
    assert len(org_b_events) == 0


def test_low_confidence_not_stored(seeded_db, org_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use a proprietary internal system for all our work. No external tools.",
    )
    summary = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary["detections_created"] == 0
    assert summary["new_signals"] == 0


def test_text_excerpt_max_150_chars(seeded_db, org_id):
    long_text = (
        "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
        "eiusmod tempor incididunt ut labore et dolore magna aliqua Ut "
        "enim ad minim veniam quis nostrud exercitation ullamco laboris "
        "nisi ut aliquip ex ea commodo consequat Duis aute irure dolor "
        "in reprehenderit in voluptate velit esse cillum dolore eu fugiat "
        "nulla pariatur We use ChatGPT here excepteur sint occaecat "
        "cupidatat non proident sunt in culpa qui officia deserunt mollit "
        "anim id est laborum"
    )
    make_questionnaire_response(seeded_db, org_id, long_text)
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    events = seeded_db.execute(
        select(TelemetryEvent).where(TelemetryEvent.organization_id == org_id)
    ).scalars().all()
    for e in events:
        raw = json.loads(e.raw_signal_json)
        excerpt = raw.get("matched_text_excerpt", "")
        assert len(excerpt) <= 150


def test_scan_single_response_realtime_hook(seeded_db, org_id):
    resp = make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for content generation.",
    )
    count = Tier1Scanner.scan_single_response(
        response_id=resp.id,
        answer_text=resp.answer_text,
        organization_id=org_id,
        db=seeded_db,
    )
    assert count > 0


def test_empty_response_text_skipped(seeded_db, org_id):
    make_questionnaire_response(seeded_db, org_id, "")
    summary = Tier1Scanner.scan_organization(org_id, None, seeded_db)
    assert summary["records_scanned"] == 0
    assert summary["new_signals"] == 0
