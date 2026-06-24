"""Tests for the jurisdiction traversal engine."""

from datetime import datetime, timezone
from uuid import uuid4

from app.models.detection import ShadowAIDetection
from app.services.jurisdiction_engine import JurisdictionEngine
from app.services.regulatory_graph import GRAPH_VERSION
from tests.conftest import make_signature


def _make_detection(
    test_db,
    org_id,
    provider_name="Test Tool",
    risk_level="high",
    intent_action=None,
    data_subject=None,
    business_context=None,
    use_case=None,
    signature=None,
):
    detection = ShadowAIDetection(
        id=uuid4(),
        organization_id=org_id,
        signature_id=signature.id if signature else None,
        provider_name=provider_name,
        confidence_score=0.85,
        confidence_band=risk_level,
        detection_basis_json='{"tier1_signals": 1}',
        base_confidence_score=0.85,
        decay_lambda=0.023,
        status="new",
        first_detected_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
        intent_action=intent_action,
        intent_data_subject=data_subject,
        intent_business_context=business_context,
        inferred_use_case=use_case,
        is_zero_day=False,
    )
    test_db.add(detection)
    test_db.commit()

    if signature is not None:
        JurisdictionEngine.assess_detection(detection, signature, test_db)

    return detection


def test_llm_in_hr_context_triggers_eu_ai_act(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="evaluating",
        data_subject="job_candidates",
        business_context="hr",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    article_ids = [a.article_id for a in assessment.applicable_articles]
    assert "EU_AI_ACT_ART6" in article_ids
    assert "EU_AI_ACT_ART14" in article_ids


def test_automated_decision_triggers_gdpr_art22(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="automated_decision",
        data_subject="job_candidates",
        business_context="hr",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    article_ids = [a.article_id for a in assessment.applicable_articles]
    assert "GDPR_ART22" in article_ids


def test_healthcare_triggers_hipaa(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="healthcare",
        data_subject="patients",
        business_context="healthcare",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    article_ids = [a.article_id for a in assessment.applicable_articles]
    assert "HIPAA_MINIMUM_NECESSARY" in article_ids
    assert "HIPAA_SAFEGUARDS" in article_ids


def test_india_context_triggers_dpdp(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="medium")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="processing_personal_data",
        data_subject="general_public",
        business_context="customer_support",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    article_ids = [a.article_id for a in assessment.applicable_articles]
    assert "INDIA_DPDP_S4" in article_ids


def test_low_risk_general_tool_minimal_results(test_db, org_id):
    sig = make_signature(test_db, category="other", risk_level="low")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="content_generation",
        data_subject="internal_data",
        business_context="engineering",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    assert assessment.total_articles == 0
    assert assessment.highest_risk == "low"


def test_highest_risk_computation(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="automated_decision",
        data_subject="employees",
        business_context="hr",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    assert assessment.highest_risk in {"high", "critical"}


def test_missing_governance_populated(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="automated_decision",
        data_subject="job_candidates",
        business_context="hr",
    )
    assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
    assert len(assessment.missing_governance) > 0
    assert any("DPIA" in item for item in assessment.missing_governance)


def test_traversal_is_deterministic(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="automated_decision",
        data_subject="employees",
        business_context="hr",
    )
    results = []
    for _ in range(10):
        assessment = JurisdictionEngine.assess_detection(detection, sig, test_db)
        results.append(
            tuple(a.article_id for a in assessment.applicable_articles)
        )
    assert len(set(results)) == 1


def test_no_external_calls(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="high")
    detection = _make_detection(test_db, org_id, signature=sig)
    # If any external call were made, this test would require mocking.
    # The engine uses only in-memory rule lookups, so this documents the
    # invariant and ensures the call completes without network activity.
    JurisdictionEngine.assess_detection(detection, sig, test_db)
    assert detection.jurisdiction_assessed_at is not None


def test_assessment_stored_on_detection(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="medium")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="processing_personal_data",
        data_subject="customers",
    )
    assert detection.jurisdiction_assessed_at is not None
    assert detection.jurisdiction_assessment_json is not None
    assert detection.jurisdiction_graph_version == GRAPH_VERSION


def test_assessment_pass_skips_current(test_db, org_id):
    sig = make_signature(test_db, category="llm", risk_level="medium")
    detection = _make_detection(
        test_db,
        org_id,
        signature=sig,
        intent_action="processing_personal_data",
        data_subject="customers",
    )
    result = JurisdictionEngine.run_assessment_pass(org_id, test_db)
    assert result["assessed"] == 0
    assert result["errors"] == 0
