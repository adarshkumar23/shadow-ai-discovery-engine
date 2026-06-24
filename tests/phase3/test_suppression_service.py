"""
Tests for the Suppression Service.

Verifies patent invariants 9 and 10:
- Dismissed detections are never hard deleted
- Suppression prevents re-detection via the same method
- Suppression is org-scoped
- Duplicate suppressions are not created
"""

import json
from uuid import uuid4

from sqlalchemy import select

from app.models.detection import ShadowAIDetection
from app.models.suppression import SuppressedDetection
from app.models.telemetry import TelemetryEvent
from app.services.detection_service import DetectionService
from app.services.suppression_service import SuppressionService
from app.services.tier1_scanner import Tier1Scanner
from tests.conftest import make_questionnaire_response

ORG_A = uuid4()
ORG_B = uuid4()


def test_suppression_created_on_dismiss(seeded_db, org_id, user_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work and customer support.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
        )
    ).scalars().first()
    assert detection is not None

    DetectionService.dismiss_detection(
        detection_id=detection.id,
        organization_id=org_id,
        dismissed_by=user_id,
        reason="This is a false positive detection.",
        notes=None,
        db=seeded_db,
    )

    suppressions = SuppressionService.list_suppressions(org_id, seeded_db)
    assert len(suppressions) >= 1

    assert detection.deleted_at is None
    assert detection.dismissed_at is not None
    assert detection.status == "dismissed"


def test_suppressed_tool_skipped_on_next_scan(seeded_db, org_id, user_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.provider_name == "ChatGPT",
        )
    ).scalars().first()
    assert detection is not None

    events_before = seeded_db.execute(
        select(TelemetryEvent).where(
            TelemetryEvent.organization_id == org_id,
        )
    ).scalars().all()
    count_before = len(events_before)

    DetectionService.dismiss_detection(
        detection_id=detection.id,
        organization_id=org_id,
        dismissed_by=user_id,
        reason="This is a false positive detection.",
        notes=None,
        db=seeded_db,
    )

    make_questionnaire_response(
        seeded_db, org_id,
        "We also use ChatGPT for additional tasks.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    events_after = seeded_db.execute(
        select(TelemetryEvent).where(
            TelemetryEvent.organization_id == org_id,
        )
    ).scalars().all()
    count_after = len(events_after)

    assert count_after == count_before


def test_lift_suppression_enables_detection(seeded_db, org_id, user_id):
    make_questionnaire_response(
        seeded_db, org_id,
        "We use ChatGPT for daily work.",
    )
    Tier1Scanner.scan_organization(org_id, None, seeded_db)

    detection = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.provider_name == "ChatGPT",
        )
    ).scalars().first()
    assert detection is not None

    signature = seeded_db.execute(
        select(ShadowAIDetection).where(
            ShadowAIDetection.id == detection.id,
        )
    ).scalar_one()

    from app.models.signature import AISignatureRegistry
    sig = seeded_db.execute(
        select(AISignatureRegistry).where(
            AISignatureRegistry.id == detection.signature_id
        )
    ).scalar_one()

    DetectionService.dismiss_detection(
        detection_id=detection.id,
        organization_id=org_id,
        dismissed_by=user_id,
        reason="This is a false positive detection.",
        notes=None,
        db=seeded_db,
    )

    assert SuppressionService.is_suppressed(org_id, sig.slug, "questionnaire", seeded_db)

    lifted = SuppressionService.lift_suppression(
        organization_id=org_id,
        tool_slug=sig.slug,
        detection_method="questionnaire",
        lifted_by=user_id,
        db=seeded_db,
    )
    seeded_db.commit()
    assert lifted is True
    assert not SuppressionService.is_suppressed(org_id, sig.slug, "questionnaire", seeded_db)

    signatures = seeded_db.execute(
        select(AISignatureRegistry).where(AISignatureRegistry.is_active.is_(True))
    ).scalars().all()

    new_resp = make_questionnaire_response(
        seeded_db, org_id,
        "We have started using ChatGPT for new projects.",
    )

    new_signals, _ = Tier1Scanner._process_response_text(
        response_id=new_resp.id,
        answer_text=new_resp.answer_text,
        organization_id=org_id,
        signatures=signatures,
        db=seeded_db,
    )
    assert new_signals > 0


def test_suppression_is_org_scoped(seeded_db, org_id, user_id):
    from uuid import uuid4

    SuppressionService.create_suppression(
        organization_id=ORG_A,
        tool_slug="test-tool",
        detection_method="questionnaire",
        suppressed_by=user_id,
        reason="False positive in org A",
        source_detection_id=uuid4(),
        db=seeded_db,
    )
    seeded_db.commit()

    assert SuppressionService.is_suppressed(ORG_A, "test-tool", "questionnaire", seeded_db)
    assert not SuppressionService.is_suppressed(ORG_B, "test-tool", "questionnaire", seeded_db)


def test_duplicate_suppression_not_created(seeded_db, org_id, user_id):
    from uuid import uuid4

    det_id = uuid4()
    SuppressionService.create_suppression(
        organization_id=org_id,
        tool_slug="test-tool",
        detection_method="questionnaire",
        suppressed_by=user_id,
        reason="False positive detection",
        source_detection_id=det_id,
        db=seeded_db,
    )
    seeded_db.commit()

    SuppressionService.create_suppression(
        organization_id=org_id,
        tool_slug="test-tool",
        detection_method="questionnaire",
        suppressed_by=user_id,
        reason="Another false positive detection",
        source_detection_id=uuid4(),
        db=seeded_db,
    )
    seeded_db.commit()

    all_suppressions = seeded_db.execute(
        select(SuppressedDetection).where(
            SuppressedDetection.organization_id == org_id,
            SuppressedDetection.tool_slug == "test-tool",
        )
    ).scalars().all()
    active = [s for s in all_suppressions if s.lifted_at is None]
    assert len(active) == 1
