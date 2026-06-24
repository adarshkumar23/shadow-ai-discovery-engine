"""
Tests for the Intent Classification Engine — Dependent Patent Claim 7.

Verifies deterministic rule-based intent classification from linguistic
context, regulatory risk mapping, and patent invariants:
- No external calls
- Fully deterministic
- Rule-based only (no probabilistic models)
"""

import json
from unittest.mock import patch, MagicMock

from app.services.intent_engine import IntentEngine, CLASSIFIER_VERSION


def test_hr_evaluation_triggers_eu_ai_act():
    text = "We use ChatGPT for evaluating candidates in our recruiting process"
    result = IntentEngine.classify(text=text, tool_name="ChatGPT")
    assert result is not None
    assert result["intent_tuple"]["action"] == "evaluating"
    assert result["intent_tuple"]["data_subject"] == "job_candidates"
    reg_codes = [r["code"] for r in result["applicable_regulations"]]
    assert "EU_AI_ACT_ART6" in reg_codes
    assert "GDPR_ART22" in reg_codes


def test_patient_data_triggers_hipaa():
    text = "Claude is used for processing patient medical records in our clinic"
    result = IntentEngine.classify(text=text, tool_name="Claude")
    assert result is not None
    assert result["risk_level"] == "critical"
    reg_codes = [r["code"] for r in result["applicable_regulations"]]
    assert "HIPAA_MINIMUM_NECESSARY" in reg_codes


def test_content_generation_is_low_risk():
    text = "We use ChatGPT to draft marketing copy for internal campaigns"
    result = IntentEngine.classify(text=text, tool_name="ChatGPT")
    assert result is not None
    assert result["risk_level"] == "low"
    assert len(result["applicable_regulations"]) == 0


def test_financial_decision_triggers_gdpr():
    text = "Our system uses AI for credit scoring and loan decisions"
    result = IntentEngine.classify(text=text, tool_name="AI System")
    assert result is not None
    reg_codes = [r["code"] for r in result["applicable_regulations"]]
    assert "GDPR_ART22" in reg_codes


def test_insufficient_context_returns_none():
    text = "We use chatgpt"
    result = IntentEngine.classify(text=text, tool_name="ChatGPT")
    assert result is None


def test_classifier_is_deterministic():
    text = "We use ChatGPT for evaluating candidates in our recruiting process"
    results = []
    for _ in range(100):
        r = IntentEngine.classify(text=text, tool_name="ChatGPT")
        results.append(r)

    first = results[0]
    for r in results[1:]:
        r_copy = dict(r)
        r_copy.pop("classified_at", None)
        first_copy = dict(first)
        first_copy.pop("classified_at", None)
        assert r_copy == first_copy


def test_classification_confidence_levels():
    text_three = "We use ChatGPT for evaluating candidates in our recruiting process"
    result_three = IntentEngine.classify(text=text_three, tool_name="ChatGPT")
    assert result_three is not None
    assert result_three["classification_confidence"] == "high"

    text_two = "We use AI to process personal information about customers"
    result_two = IntentEngine.classify(text=text_two, tool_name="AI")
    assert result_two is not None
    assert result_two["classification_confidence"] == "medium"

    text_one = "We use AI for drafting"
    result_one = IntentEngine.classify(text=text_one, tool_name="AI")
    assert result_one is not None
    assert result_one["classification_confidence"] == "low"


def test_no_external_calls():
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        text = "We use ChatGPT for evaluating candidates in our recruiting process"
        IntentEngine.classify(text=text, tool_name="ChatGPT")
        mock_get.assert_not_called()
        mock_post.assert_not_called()


def test_classifier_version_in_output():
    text = "We use ChatGPT for evaluating candidates in our recruiting process"
    result = IntentEngine.classify(text=text, tool_name="ChatGPT")
    assert result is not None
    assert result["classifier_version"] == CLASSIFIER_VERSION
    assert result["classifier_version"] == "1.0.0"


def test_classified_at_is_present():
    text = "We use ChatGPT for evaluating candidates in our recruiting process"
    result = IntentEngine.classify(text=text, tool_name="ChatGPT")
    assert result is not None
    assert "classified_at" in result
    assert result["classified_at"]
    assert isinstance(result["classified_at"], str)
