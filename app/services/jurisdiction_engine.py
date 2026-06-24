"""
PATENT NOTICE
Module: services/jurisdiction_engine
Implements Dependent Patent Claim 9:
Regulatory Jurisdiction Graph Traversal.

This engine traverses the regulatory DAG from a detection's inferred
attributes to all applicable regulatory obligations.

Algorithm (patent-specified):
  Input: DetectionAttributeSet containing:
    - tool category (from signature registry)
    - risk level (from signature or detection)
    - intent_action (from intent engine)
    - intent_data_subject (from intent engine)
    - intent_business_context (from intent engine)
    - is_zero_day (boolean)

  For each ArticleNode in the graph:
    Evaluate trigger_conditions against input.
    If ANY condition matches: include article.

  A condition matches when:
    ANY item in the condition list matches ANY corresponding attribute
    in the input. (OR logic within each condition type)
    (AND logic between condition types when multiple condition types are
    specified)

  The article's applies_to_risk array is used as an amplifier, not a
  sole trigger: if specified and the detection's risk_level is not in
  the array, the article is excluded regardless of other matches.

  This is O(articles) — linear scan. No graph traversal library needed.
  No recursion.

  Output: JurisdictionAssessment

CRITICAL:
  This function never calls any external API.
  This function never uses any LLM.
  This function is fully deterministic.
  Same input always produces same output.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import cast
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.models.regulation import RegulationArticle, RegulationNode
from app.models.signature import AISignatureRegistry
from app.schemas.jurisdiction import ApplicableArticle, JurisdictionAssessment
from app.services.audit_service import AuditService
from app.services.regulatory_graph import (
    ARTICLE_DEFINITIONS,
    GRAPH_VERSION,
    MISSING_GOVERNANCE_RULES,
    REGULATION_DEFINITIONS,
)

logger = get_logger(__name__)

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_gte(a: str | None, b: str | None) -> bool:
    """Return True if risk level a >= b in risk ordering."""
    if a is None:
        return False
    if b is None:
        return True
    return _RISK_ORDER.get(a, -1) >= _RISK_ORDER.get(b, -1)


class JurisdictionEngine:
    """Deterministic regulatory jurisdiction graph traversal engine."""

    @staticmethod
    def assess_detection(
        detection: ShadowAIDetection,
        signature: AISignatureRegistry | None,
        db: Session,
    ) -> JurisdictionAssessment:
        """Run full graph traversal for a single detection.

        Builds the DetectionAttributeSet from the detection record and
        its associated signature, runs traversal, computes missing
        governance actions, persists the result on the detection record,
        and writes an audit log entry.
        """
        category = signature.category if signature else "other"
        risk_level = signature.risk_level if signature else detection.confidence_band

        attributes = {
            "category": category,
            "risk_level": risk_level,
            "intent_action": detection.intent_action,
            "data_subject": detection.intent_data_subject,
            "business_context": detection.intent_business_context,
            "use_case": detection.inferred_use_case,
            "is_zero_day": detection.is_zero_day,
        }

        matched = JurisdictionEngine._traverse_graph(attributes)
        missing_governance = JurisdictionEngine._compute_missing_governance(
            matched, attributes
        )
        highest_risk = JurisdictionEngine._compute_highest_risk(
            matched, cast(str | None, risk_level)
        )

        regulation_ids = sorted({article["regulation_id"] for article in matched})
        regulation_name_map = {
            reg["id"]: reg["short_name"] for reg in REGULATION_DEFINITIONS
        }

        applicable_articles = [
            ApplicableArticle(
                article_id=article["id"],
                regulation_id=article["regulation_id"],
                regulation_name=regulation_name_map.get(
                    article["regulation_id"], article["regulation_id"]
                ),
                article_number=article["article_number"],
                article_title=article["article_title"],
                obligation_type=article["obligation_type"],
                plain_english=article["plain_english"],
                triggered_by=article["triggered_by"],
            )
            for article in matched
        ]

        now = datetime.now(timezone.utc)
        assessment = JurisdictionAssessment(
            detection_id=detection.id,
            assessed_at=now,
            graph_version=GRAPH_VERSION,
            applicable_regulations=regulation_ids,
            applicable_articles=applicable_articles,
            highest_risk=highest_risk,
            total_articles=len(applicable_articles),
            missing_governance=missing_governance,
            assessment_basis={
                "category": category,
                "risk_level": risk_level,
                "intent_action": detection.intent_action,
                "data_subject": detection.intent_data_subject,
                "business_context": detection.intent_business_context,
                "use_case": detection.inferred_use_case,
                "is_zero_day": detection.is_zero_day,
            },
        )

        detection.jurisdiction_assessment_json = json.dumps(
            assessment.model_dump(mode="json")
        )
        detection.applicable_regulations_count = len(regulation_ids)
        detection.jurisdiction_assessed_at = now
        detection.highest_regulatory_risk = highest_risk
        detection.jurisdiction_graph_version = GRAPH_VERSION

        try:
            AuditService.log(
                db=db,
                organization_id=detection.organization_id,
                user_id=None,
                action="shadow_ai.detection.jurisdiction_assessed",
                entity_type="shadow_ai_detection",
                entity_id=detection.id,
                context_json={
                    "regulations_count": len(regulation_ids),
                    "articles_count": len(applicable_articles),
                    "highest_risk": highest_risk,
                    "graph_version": GRAPH_VERSION,
                },
            )
        except Exception:
            logger.error(
                "Audit logging failed for jurisdiction assessment",
                extra={"detection_id": str(detection.id)},
            )

        return assessment

    @staticmethod
    def _traverse_graph(attributes: dict) -> list[dict]:
        """Core graph traversal.

        Evaluates every article's trigger_conditions against the supplied
        structured detection attributes. Returns matched articles with
        triggered_by metadata explaining which attribute(s) caused the
        match.

        An article's applies_to_risk array acts as an amplifier: if
        present and the detection's risk_level is not included, the
        article is excluded even if other conditions match.
        """
        detection_risk = attributes.get("risk_level")
        matched: list[dict] = []

        for article in ARTICLE_DEFINITIONS:
            conditions = article.get("trigger_conditions", {})
            applies_to_risk = article.get("applies_to_risk", [])

            if applies_to_risk and detection_risk not in applies_to_risk:
                continue

            triggered_by: dict[str, list[str] | str] = {}
            matched_any_condition = False

            if "categories" in conditions:
                category = attributes.get("category")
                if category in conditions["categories"]:
                    triggered_by["category"] = category
                    matched_any_condition = True

            if "use_cases" in conditions:
                intent_action = attributes.get("intent_action")
                if intent_action in conditions["use_cases"]:
                    triggered_by["intent_action"] = intent_action
                    matched_any_condition = True

            if "data_subjects" in conditions:
                data_subject = attributes.get("data_subject")
                if data_subject in conditions["data_subjects"]:
                    triggered_by["data_subject"] = data_subject
                    matched_any_condition = True

            if "contexts" in conditions:
                business_context = attributes.get("business_context")
                if business_context in conditions["contexts"]:
                    triggered_by["business_context"] = business_context
                    matched_any_condition = True

            if matched_any_condition:
                article_copy = dict(article)
                article_copy["triggered_by"] = triggered_by
                matched.append(article_copy)

        return matched

    @staticmethod
    def _compute_missing_governance(
        matched_articles: list[dict],
        attributes: dict,
    ) -> list[str]:
        """Compute required governance actions not yet evidenced.

        Evaluates MISSING_GOVERNANCE_RULES against the set of matched
        regulation IDs, the detection's risk level, its data subject,
        and its inferred use case.
        """
        matched_regulation_ids = {article["regulation_id"] for article in matched_articles}
        detection_risk = attributes.get("risk_level")
        data_subject = attributes.get("data_subject")
        use_case = attributes.get("intent_action")
        missing: list[str] = []

        for rule in MISSING_GOVERNANCE_RULES:
            condition = rule["condition"]
            triggered = False

            if "regulation_ids" in condition:
                if any(
                    rid in matched_regulation_ids for rid in condition["regulation_ids"]
                ):
                    triggered = True
                else:
                    continue

            if "risk_levels" in condition:
                if detection_risk in condition["risk_levels"]:
                    triggered = True
                else:
                    continue

            if "data_subjects" in condition:
                if data_subject in condition["data_subjects"]:
                    triggered = True
                else:
                    continue

            if "use_cases" in condition:
                if use_case in condition["use_cases"]:
                    triggered = True
                else:
                    continue

            if triggered and rule["missing"] not in missing:
                missing.append(rule["missing"])

        return missing

    @staticmethod
    def _compute_highest_risk(
        matched_articles: list[dict],
        base_risk: str | None,
    ) -> str:
        """Return the highest risk level across matched articles.

        Risk ordering: critical > high > medium > low.
        Starts with the detection's base risk level and raises it
        whenever a matched article applies to a higher risk level.
        """
        highest = base_risk

        for article in matched_articles:
            applies_to_risk = article.get("applies_to_risk", [])
            for risk in applies_to_risk:
                if _risk_gte(risk, highest):
                    highest = risk

        return highest or "low"

    @staticmethod
    def run_assessment_pass(
        organization_id: UUID,
        db: Session,
    ) -> dict:
        """Re-assess all active detections that need jurisdiction evaluation.

        Targets detections where assessment is missing, or where the
        stored graph version differs from the current GRAPH_VERSION.
        """
        from sqlalchemy import select

        query = (
            select(ShadowAIDetection)
            .where(
                ShadowAIDetection.organization_id == organization_id,
                ShadowAIDetection.deleted_at.is_(None),
                ShadowAIDetection.status.notin_(["dismissed", "registered"]),
            )
            .where(
                (ShadowAIDetection.jurisdiction_assessed_at.is_(None))
                | (ShadowAIDetection.jurisdiction_graph_version != GRAPH_VERSION)
            )
        )
        detections = db.execute(query).scalars().all()

        assessed = 0
        skipped_already_current = 0
        errors = 0

        for detection in detections:
            try:
                signature = None
                if detection.signature_id is not None:
                    signature = db.execute(
                        select(AISignatureRegistry).where(
                            AISignatureRegistry.id == detection.signature_id
                        )
                    ).scalar_one_or_none()
                JurisdictionEngine.assess_detection(detection, signature, db)
                assessed += 1
            except Exception:
                logger.error(
                    "Jurisdiction assessment failed for detection",
                    extra={"detection_id": str(detection.id)},
                )
                errors += 1

        skipped_already_current = 0  # Query already excludes current ones.
        db.commit()

        return {
            "assessed": assessed,
            "skipped_already_current": skipped_already_current,
            "errors": errors,
        }

    @staticmethod
    def seed_regulation_data(db: Session) -> dict:
        """Seed regulation_nodes and regulation_articles tables.

        Idempotent upsert pattern: existing rows are updated in place
        so the database always matches the in-code graph definitions.
        """
        from sqlalchemy import select

        regulations_seeded = 0
        articles_seeded = 0

        for reg in REGULATION_DEFINITIONS:
            existing = db.execute(
                select(RegulationNode).where(RegulationNode.id == reg["id"])
            ).scalar_one_or_none()

            effective_date_value = reg.get("effective_date")
            if isinstance(effective_date_value, str):
                effective_date_value = date.fromisoformat(effective_date_value)

            if existing is None:
                node = RegulationNode(
                    id=reg["id"],
                    short_name=reg["short_name"],
                    full_name=reg["full_name"],
                    jurisdiction=reg["jurisdiction"],
                    effective_date=effective_date_value,
                    regulation_type=reg["regulation_type"],
                    risk_categories=json.dumps(reg["risk_categories"]),
                    base_url=reg.get("base_url"),
                    is_active=True,
                )
                db.add(node)
                regulations_seeded += 1
            else:
                existing.short_name = reg["short_name"]
                existing.full_name = reg["full_name"]
                existing.jurisdiction = reg["jurisdiction"]
                existing.effective_date = effective_date_value
                existing.regulation_type = reg["regulation_type"]
                existing.risk_categories = json.dumps(reg["risk_categories"])
                existing.base_url = reg.get("base_url")

        db.flush()

        for art in ARTICLE_DEFINITIONS:
            existing = db.execute(
                select(RegulationArticle).where(RegulationArticle.id == art["id"])
            ).scalar_one_or_none()

            if existing is None:
                article = RegulationArticle(
                    id=art["id"],
                    regulation_id=art["regulation_id"],
                    article_number=art["article_number"],
                    article_title=art["article_title"],
                    obligation_type=art["obligation_type"],
                    applies_to_risk=json.dumps(art["applies_to_risk"]),
                    trigger_conditions=json.dumps(art["trigger_conditions"]),
                    plain_english=art["plain_english"],
                )
                db.add(article)
                articles_seeded += 1
            else:
                existing.regulation_id = art["regulation_id"]
                existing.article_number = art["article_number"]
                existing.article_title = art["article_title"]
                existing.obligation_type = art["obligation_type"]
                existing.applies_to_risk = json.dumps(art["applies_to_risk"])
                existing.trigger_conditions = json.dumps(art["trigger_conditions"])
                existing.plain_english = art["plain_english"]

        db.commit()

        return {
            "regulations_seeded": regulations_seeded,
            "articles_seeded": articles_seeded,
        }
