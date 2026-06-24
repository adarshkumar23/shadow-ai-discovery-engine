"""Tests for the regulatory graph definitions."""

import json

import pytest

from app.services.regulatory_graph import (
    ARTICLE_DEFINITIONS,
    GRAPH_VERSION,
    REGULATION_DEFINITIONS,
)


REQUIRED_REG_FIELDS = {
    "id",
    "short_name",
    "full_name",
    "jurisdiction",
    "effective_date",
    "regulation_type",
    "risk_categories",
    "base_url",
}
REQUIRED_ARTICLE_FIELDS = {
    "id",
    "regulation_id",
    "article_number",
    "article_title",
    "obligation_type",
    "applies_to_risk",
    "trigger_conditions",
    "plain_english",
}
VALID_REGULATION_TYPES = {"ai_specific", "data_protection", "sector_specific", "voluntary_framework"}
VALID_OBLIGATION_TYPES = {
    "prohibition",
    "requirement",
    "documentation",
    "notification",
    "assessment",
    "transparency",
}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


def test_all_regulations_have_required_fields():
    for reg in REGULATION_DEFINITIONS:
        missing = REQUIRED_REG_FIELDS - set(reg.keys())
        assert not missing, f"Regulation {reg.get('id')} missing fields: {missing}"
        assert reg["regulation_type"] in VALID_REGULATION_TYPES
        assert isinstance(reg["risk_categories"], list)
        assert len(reg["risk_categories"]) > 0


def test_all_articles_have_required_fields():
    for art in ARTICLE_DEFINITIONS:
        missing = REQUIRED_ARTICLE_FIELDS - set(art.keys())
        assert not missing, f"Article {art.get('id')} missing fields: {missing}"
        assert art["obligation_type"] in VALID_OBLIGATION_TYPES
        assert isinstance(art["applies_to_risk"], list)
        assert isinstance(art["trigger_conditions"], dict)
        assert art["plain_english"]


def test_all_articles_reference_valid_regulation():
    reg_ids = {reg["id"] for reg in REGULATION_DEFINITIONS}
    for art in ARTICLE_DEFINITIONS:
        assert art["regulation_id"] in reg_ids, (
            f"Article {art['id']} references unknown regulation {art['regulation_id']}"
        )


def test_trigger_conditions_are_valid_json():
    for art in ARTICLE_DEFINITIONS:
        cond = art["trigger_conditions"]
        assert isinstance(cond, dict)
        valid_keys = {"categories", "use_cases", "data_subjects", "contexts"}
        assert set(cond.keys()).issubset(valid_keys)
        for key, values in cond.items():
            assert isinstance(values, list)
            for value in values:
                assert isinstance(value, str)


def test_graph_version_constant_exists():
    assert GRAPH_VERSION == "1.0.0"


def test_regulation_count_matches_expected():
    assert len(REGULATION_DEFINITIONS) == 7


def test_article_count_matches_expected():
    assert len(ARTICLE_DEFINITIONS) == 16
