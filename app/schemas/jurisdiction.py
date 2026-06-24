"""
Pydantic schemas for regulatory jurisdiction graph traversal.

Schemas define the structured output of Dependent Patent Claim 9:
Regulatory Jurisdiction Graph Traversal.
"""

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RegulationNodeRead(BaseModel):
    id: str
    short_name: str
    full_name: str
    jurisdiction: str
    effective_date: date | None = None
    regulation_type: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class ApplicableArticle(BaseModel):
    article_id: str
    regulation_id: str
    regulation_name: str
    article_number: str
    article_title: str
    obligation_type: str
    plain_english: str
    triggered_by: dict


class JurisdictionAssessment(BaseModel):
    detection_id: UUID
    assessed_at: datetime
    graph_version: str
    applicable_regulations: list[str]
    applicable_articles: list[ApplicableArticle]
    highest_risk: str
    total_articles: int
    missing_governance: list[str]
    assessment_basis: dict


class JurisdictionAssessmentResponse(BaseModel):
    detection_id: UUID
    provider_name: str
    assessment: JurisdictionAssessment
    assessed_at: datetime
