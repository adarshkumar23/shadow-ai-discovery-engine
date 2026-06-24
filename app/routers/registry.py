"""
PATENT NOTICE
Module: routers/registry
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Public registry endpoints. No auth required.
This is the public Trust Document endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.regulation import RegulationArticle, RegulationNode
from app.models.signature import AISignatureRegistry
from app.schemas.jurisdiction import RegulationNodeRead
from app.registry.signature_registry import (
    REGISTRY_LAST_UPDATED,
    REGISTRY_VERSION,
    TOTAL_SIGNATURES,
    get_registry_stats,
)
from app.schemas.signature import AISignatureRead

router = APIRouter()


@router.get(
    "/registry/tools",
    summary="List AI Signature Registry",
    description=(
        "Returns all active AI tool signatures in the detection registry. "
        "Public endpoint for transparency — no auth required. "
        "Includes registry version."
    ),
)
def list_registry_tools(db: Session = Depends(get_db)):
    signatures = db.execute(
        select(AISignatureRegistry).where(
            AISignatureRegistry.is_active.is_(True)
        ).order_by(AISignatureRegistry.category, AISignatureRegistry.provider_name)
    ).scalars().all()

    return {
        "version": REGISTRY_VERSION,
        "last_updated": REGISTRY_LAST_UPDATED,
        "total": len(signatures),
        "tools": [AISignatureRead.model_validate(sig) for sig in signatures],
    }


@router.get(
    "/registry/stats",
    summary="Registry Coverage Statistics",
    description=(
        "Returns registry coverage breakdown by category and risk level."
    ),
)
def registry_stats():
    return get_registry_stats()


@router.get(
    "/registry/regulations",
    summary="List Regulation Nodes",
    description=(
        "Returns all regulations in the regulatory jurisdiction graph. "
        "No authentication required — this is a transparency endpoint."
    ),
    response_model=list[RegulationNodeRead],
)
def list_regulations(db: Session = Depends(get_db)):
    regulations = db.execute(
        select(RegulationNode).where(
            RegulationNode.is_active.is_(True)
        ).order_by(RegulationNode.jurisdiction, RegulationNode.short_name)
    ).scalars().all()
    return [RegulationNodeRead.model_validate(reg) for reg in regulations]


@router.get(
    "/registry/regulations/{regulation_id}/articles",
    summary="List Regulation Articles",
    description=(
        "Returns all articles for a specific regulation with their trigger conditions."
    ),
)
def list_regulation_articles(
    regulation_id: str,
    db: Session = Depends(get_db),
):
    articles = db.execute(
        select(RegulationArticle).where(
            RegulationArticle.regulation_id == regulation_id
        ).order_by(RegulationArticle.article_number)
    ).scalars().all()
    return [
        {
            "id": article.id,
            "regulation_id": article.regulation_id,
            "article_number": article.article_number,
            "article_title": article.article_title,
            "obligation_type": article.obligation_type,
            "applies_to_risk": article.applies_to_risk,
            "trigger_conditions": article.trigger_conditions,
            "plain_english": article.plain_english,
        }
        for article in articles
    ]
