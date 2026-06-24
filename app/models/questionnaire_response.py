"""
PATENT NOTICE
Module: models/questionnaire_response
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from uuid import uuid4

from sqlalchemy import Column, DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class QuestionnaireResponse(Base):
    __tablename__ = "questionnaire_responses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    submitted_by = Column(UUID(as_uuid=True), nullable=True)
    vendor_name = Column(String(255), nullable=True)
    question_text = Column(Text, nullable=True)
    answer_text = Column(Text, nullable=False)
    submitted_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<QuestionnaireResponse(id={self.id}, org={self.organization_id}, "
            f"vendor={self.vendor_name}, submitted_at={self.submitted_at})>"
        )
