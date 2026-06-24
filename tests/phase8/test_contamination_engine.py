"""Tests for the vendor contamination engine."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from app.models.contamination import VendorAIContamination, VendorDPARecord
from app.models.detection import ShadowAIDetection
from app.models.questionnaire_response import QuestionnaireResponse
from app.models.signature import AISignatureRegistry
from app.models.telemetry import TelemetryEvent
from app.models.vendor import Vendor
from app.services.contamination_engine import (
    ASSESSMENT_VERSION,
    WEIGHT_CONTRACTUAL,
    WEIGHT_EXTERNAL,
    WEIGHT_INTERNAL,
    ContaminationEngine,
)
from tests.conftest import org_id


def _make_vendor(db, organization_id, name="Test Vendor"):
    vendor = Vendor(
        id=uuid4(),
        organization_id=organization_id,
        name=name,
        vendor_type="software",
        risk_tier="medium",
        status="active",
        processes_personal_data=True,
    )
    db.add(vendor)
    db.commit()
    return vendor


def _make_dpa(db, organization_id, vendor_id, vendor_name, exists, covers):
    record = VendorDPARecord(
        id=uuid4(),
        organization_id=organization_id,
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        dpa_exists=exists,
        covers_ai_processing=covers,
        created_by=uuid4(),
    )
    db.add(record)
    db.commit()
    return record


def _make_response(db, organization_id, vendor_name, answer_text):
    """Create a questionnaire response and a telemetry event for it."""
    response = QuestionnaireResponse(
        id=uuid4(),
        organization_id=organization_id,
        vendor_name=vendor_name,
        question_text="Does this vendor use AI?",
        answer_text=answer_text,
    )
    db.add(response)
    db.commit()

    # Manually create a tier-1 telemetry event linked to this response
    signatures = db.execute(select(AISignatureRegistry)).scalars().all()
    matched_sig = None
    for sig in signatures:
        keywords = [k.lower() for k in sig.keyword_patterns]
        if any(kw in answer_text.lower() for kw in keywords):
            matched_sig = sig
            break

    if matched_sig is None:
        return response

    event = TelemetryEvent(
        id=uuid4(),
        organization_id=organization_id,
        tier=1,
        event_type="text_mention",
        source_system_label=f"questionnaire_response:{response.id}",
        matched_signature_id=matched_sig.id,
        raw_signal_json='{"matched_keyword": "ai"}',
        signal_hash=str(response.id).replace("-", ""),
        observed_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    return response


def test_no_dpa_gives_max_contractual_score(test_db, org_id):
    vendor = _make_vendor(test_db, org_id)
    score, dpa_exists, covers = ContaminationEngine.compute_contractual_score(
        vendor.id, org_id, test_db
    )
    assert score == 1.0
    assert dpa_exists is False
    assert covers is False


def test_dpa_with_ai_coverage_gives_zero(test_db, org_id):
    vendor = _make_vendor(test_db, org_id)
    _make_dpa(test_db, org_id, vendor.id, vendor.name, True, True)
    score, dpa_exists, covers = ContaminationEngine.compute_contractual_score(
        vendor.id, org_id, test_db
    )
    assert score == 0.0
    assert dpa_exists is True
    assert covers is True


def test_partial_dpa_gives_half_score(test_db, org_id):
    vendor = _make_vendor(test_db, org_id)
    _make_dpa(test_db, org_id, vendor.id, vendor.name, True, False)
    score, dpa_exists, covers = ContaminationEngine.compute_contractual_score(
        vendor.id, org_id, test_db
    )
    assert score == 0.5
    assert dpa_exists is True
    assert covers is False


def test_contamination_formula_correct(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id)
    _make_dpa(seeded_db, org_id, vendor.id, vendor.name, True, False)  # 0.5
    record = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    expected = round(
        WEIGHT_INTERNAL * 0.0  # no internal signals
        + WEIGHT_EXTERNAL * 0.5  # disabled
        + WEIGHT_CONTRACTUAL * 0.5,
        4,
    )
    assert float(record.contamination_score) == expected


def test_weights_sum_to_one():
    assert WEIGHT_INTERNAL + WEIGHT_EXTERNAL + WEIGHT_CONTRACTUAL == pytest.approx(1.0)


def test_score_in_valid_range(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id)
    record = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    assert 0.0 <= float(record.contamination_score) <= 1.0


def test_score_precision_4_decimal_places(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id)
    record = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    score_str = str(record.contamination_score)
    # NUMERIC(5,4) so max decimal places is 4
    assert "." not in score_str or len(score_str.split(".")[1]) <= 4


def test_high_internal_score_with_no_dpa(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id, name="AIHeavy")
    _make_response(seeded_db, org_id, "AIHeavy", "We use ChatGPT, Claude, and GitHub Copilot.")
    _make_response(seeded_db, org_id, "AIHeavy", "We also use Gemini and AWS Bedrock for processing.")
    record = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    assert record.contamination_band in {"critical", "high"}


def test_contamination_band_correct(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id)
    _make_dpa(seeded_db, org_id, vendor.id, vendor.name, True, True)
    record = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    assert record.contamination_band == "low"


def test_audit_log_created_on_assessment(seeded_db, org_id):
    from app.models.detection import AuditLog

    vendor = _make_vendor(seeded_db, org_id)
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    audit = seeded_db.execute(
        select(AuditLog).where(
            AuditLog.organization_id == org_id,
            AuditLog.action == "shadow_ai.vendor.contamination_assessed",
        )
    ).scalars().first()
    assert audit is not None


def test_upsert_updates_existing_record(seeded_db, org_id):
    vendor = _make_vendor(seeded_db, org_id)
    r1 = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    r2 = ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    assert r1.id == r2.id
    count = seeded_db.execute(
        select(func.count()).select_from(VendorAIContamination).where(
            VendorAIContamination.organization_id == org_id,
            VendorAIContamination.vendor_id == vendor.id,
        )
    ).scalar()
    assert count == 1


def test_org_isolation(seeded_db, org_id, globex_org_id):
    vendor = _make_vendor(seeded_db, org_id, name="AcmeVendor")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=seeded_db,
    )
    other_vendor = seeded_db.execute(
        select(VendorAIContamination).where(
            VendorAIContamination.organization_id == globex_org_id,
            VendorAIContamination.vendor_id == vendor.id,
        )
    ).scalar_one_or_none()
    assert other_vendor is None
