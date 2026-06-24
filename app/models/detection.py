"""
PATENT NOTICE
Module: models/detection
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class ShadowAIDetection(Base):
    __tablename__ = "shadow_ai_detections"
    __table_args__ = (
        Index(
            "uq_detection_org_sig_active",
            "organization_id",
            "signature_id",
            unique=True,
            postgresql_where=text(
                "status NOT IN ('dismissed', 'registered') "
                "AND deleted_at IS NULL"
            ),
        ),
        Index(
            "ix_detection_stale",
            "is_stale",
            postgresql_where=text("is_stale = TRUE"),
        ),
        Index(
            "ix_detection_decayed",
            "decayed_at",
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    signature_id = Column(
        UUID(as_uuid=True),
        ForeignKey("ai_signature_registry.id", ondelete="SET NULL"),
        nullable=True,
    )
    provider_name = Column(String(255), nullable=False)
    confidence_score = Column(Numeric(5, 4), nullable=False)
    confidence_band = Column(String(10), nullable=False)
    detection_basis_json = Column(Text, nullable=False)
    attributed_owner_id = Column(UUID(as_uuid=True), nullable=True)
    attribution_confidence = Column(Numeric(4, 3), nullable=True)
    status = Column(String(20), nullable=False, default="new")
    first_detected_at = Column(DateTime(timezone=True), nullable=False)
    last_observed_at = Column(DateTime(timezone=True), nullable=False)
    reviewed_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    dismissed_at = Column(DateTime(timezone=True), nullable=True)
    dismissed_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    dismissal_reason = Column(Text, nullable=True)
    escalated_at = Column(DateTime(timezone=True), nullable=True)
    escalated_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    escalation_notes = Column(Text, nullable=True)
    registered_ai_system_id = Column(UUID(as_uuid=True), nullable=True)
    suppressed = Column(Boolean, nullable=False, default=False)
    base_confidence_score = Column(Numeric(5, 4), nullable=True)
    decay_lambda = Column(Numeric(6, 5), nullable=True)
    decayed_at = Column(DateTime(timezone=True), nullable=True)
    is_stale = Column(Boolean, nullable=False, default=False, server_default=text("false"))
    intent_action = Column(String(100), nullable=True)
    intent_data_subject = Column(String(100), nullable=True)
    intent_business_context = Column(String(100), nullable=True)
    inferred_use_case = Column(String(255), nullable=True)
    use_case_risk_json = Column(Text, nullable=True)
    intent_classified_at = Column(DateTime(timezone=True), nullable=True)

    # Zero-day behavioral classification fields
    # (Dependent Patent Claim 4)
    is_zero_day = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    zero_day_hostname = Column(String(500), nullable=True)
    behavioral_features_json = Column(Text, nullable=True)
    classifier_version = Column(String(20), nullable=True)

    # Regulatory jurisdiction graph traversal fields
    # (Dependent Patent Claim 9)
    jurisdiction_assessment_json = Column(Text, nullable=True)
    applicable_regulations_count = Column(Integer, nullable=True)
    jurisdiction_assessed_at = Column(DateTime(timezone=True), nullable=True)
    highest_regulatory_risk = Column(String(20), nullable=True)
    jurisdiction_graph_version = Column(String(20), nullable=True)

    # Dark AI side channel classification fields
    # (Dependent Patent Claim 10)
    detection_method = Column(String(50), nullable=True)
    is_dark_ai = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    dark_ai_features_json = Column(Text, nullable=True)
    dark_ai_score = Column(Numeric(5, 4), nullable=True)
    dark_ai_proxy_detected = Column(Boolean, nullable=True)

    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ShadowAIDetection(id={self.id}, org={self.organization_id}, "
            f"provider={self.provider_name}, score={self.confidence_score}, "
            f"band={self.confidence_band}, status={self.status})>"
        )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    user_id = Column(UUID(as_uuid=True), nullable=True)
    action = Column(String(255), nullable=False)
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(UUID(as_uuid=True), nullable=False)
    context_json = Column(Text, nullable=False, default="{}")
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id={self.id}, org={self.organization_id}, "
            f"action={self.action}, entity_type={self.entity_type}, "
            f"entity_id={self.entity_id})>"
        )


class ConnectorToken(Base):
    __tablename__ = "connector_tokens"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "token_hash", name="uq_connector_org_token_hash"
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    token_hash = Column(String(64), nullable=False)
    label = Column(String(255), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
    )
    connector_version = Column(String(20), nullable=True)
    last_ingest_at = Column(DateTime(timezone=True), nullable=True)
    signals_total = Column(Integer, nullable=False, default=0, server_default=text("0"))
    is_active = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    requests_this_hour = Column(Integer, nullable=False, default=0, server_default=text("0"))
    hour_window_start = Column(DateTime(timezone=True), nullable=True)

    # Federated Registry Intelligence Network opt-in columns.
    # PATENT INVARIANT 34: Federated submission is OPT-IN only.
    # Defaults to False; organizations must explicitly enable per token.
    federated_submissions_enabled = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    federated_submissions_count = Column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    def __repr__(self) -> str:
        return (
            f"<ConnectorToken(id={self.id}, org={self.organization_id}, "
            f"label={self.label}, revoked={self.revoked_at is not None})>"
        )


class ConnectorHeartbeat(Base):
    __tablename__ = "connector_heartbeats"
    __table_args__ = (
        Index("ix_heartbeat_org", "organization_id"),
        Index("ix_heartbeat_token", "token_id"),
        Index("ix_heartbeat_reported", "reported_at"),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    token_id = Column(
        UUID(as_uuid=True),
        ForeignKey("connector_tokens.id", ondelete="CASCADE"),
        nullable=False,
    )
    connector_version = Column(String(20), nullable=False)
    signals_last_hour = Column(Integer, nullable=False, default=0, server_default=text("0"))
    sources_active = Column(Text, nullable=True)
    status = Column(String(20), nullable=False)
    reported_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    def __repr__(self) -> str:
        return (
            f"<ConnectorHeartbeat(id={self.id}, token={self.token_id}, "
            f"status={self.status}, reported_at={self.reported_at})>"
        )
