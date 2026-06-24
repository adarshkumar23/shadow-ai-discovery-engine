"""
PATENT NOTICE
Module: models/regulation
Implements Dependent Patent Claim 9:
Regulatory Jurisdiction Graph Traversal.

Graph node models for the regulatory jurisdiction DAG.
Each RegulationNode represents a regulation law.
Each RegulationArticle represents a specific article or section
within a regulation and carries predicate conditions that trigger
applicability for a given detection attribute set.

CRITICAL INVARIANTS:
1. These models store human-authored rules only.
2. No LLM inference, no external API calls, no randomness.
3. The graph schema is patent-claimed: node types, edge types,
   and predicate function signatures are fixed by design.
"""

from sqlalchemy import Boolean, Column, Date, DateTime, String, Text, text

from app.core.database import Base


class RegulationNode(Base):
    __tablename__ = "regulation_nodes"

    id = Column(String(50), primary_key=True)
    short_name = Column(String(100), nullable=False)
    full_name = Column(String(500), nullable=False)
    jurisdiction = Column(String(100), nullable=False)
    effective_date = Column(Date, nullable=True)
    regulation_type = Column(String(50), nullable=False)
    risk_categories = Column(Text, nullable=False)
    base_url = Column(String(500), nullable=True)
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<RegulationNode(id={self.id}, short_name={self.short_name}, "
            f"jurisdiction={self.jurisdiction}, type={self.regulation_type})>"
        )


class RegulationArticle(Base):
    __tablename__ = "regulation_articles"

    id = Column(String(100), primary_key=True)
    regulation_id = Column(
        String(50),
        nullable=False,
    )
    article_number = Column(String(50), nullable=False)
    article_title = Column(String(500), nullable=False)
    obligation_type = Column(String(50), nullable=False)
    applies_to_risk = Column(Text, nullable=False)
    trigger_conditions = Column(Text, nullable=False)
    plain_english = Column(Text, nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<RegulationArticle(id={self.id}, regulation={self.regulation_id}, "
            f"article_number={self.article_number})>"
        )
