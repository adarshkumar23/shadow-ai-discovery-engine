"""
PATENT NOTICE
Module: models/idp
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class IdpConnection(Base):
    __tablename__ = "idp_connections"
    __table_args__ = (
        Index(
            "uq_idp_org_provider_active",
            "organization_id",
            "idp_provider",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    idp_provider = Column(String(30), nullable=False)
    access_token_enc = Column(Text, nullable=False)
    refresh_token_enc = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    idp_domain = Column(String(255), nullable=True)
    scopes_granted = Column(Text, nullable=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    sync_status = Column(String(20), nullable=False, default="pending")
    sync_error = Column(Text, nullable=True)
    connected_by_user_id = Column(UUID(as_uuid=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    sync_window_hours = Column(Integer, nullable=False, default=24, server_default=text("24"))
    total_syncs = Column(Integer, nullable=False, default=0, server_default=text("0"))
    total_signals = Column(Integer, nullable=False, default=0, server_default=text("0"))

    def __repr__(self) -> str:
        return (
            f"<IdpConnection(id={self.id}, org={self.organization_id}, "
            f"provider={self.idp_provider}, status={self.sync_status}, "
            f"domain={self.idp_domain})>"
        )


class IdpSyncLog(Base):
    """Audit trail of every IdP sync operation."""

    __tablename__ = "idp_sync_logs"
    __table_args__ = (
        Index("ix_idp_sync_org", "organization_id"),
        Index("ix_idp_sync_connection", "connection_id"),
        Index("ix_idp_sync_started", "started_at"),
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id = Column(UUID(as_uuid=True), nullable=False)
    connection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("idp_connections.id", ondelete="CASCADE"),
        nullable=False,
    )
    idp_provider = Column(String(30), nullable=False)
    events_fetched = Column(Integer, nullable=False, default=0, server_default=text("0"))
    events_matched = Column(Integer, nullable=False, default=0, server_default=text("0"))
    signals_created = Column(Integer, nullable=False, default=0, server_default=text("0"))
    signals_duplicate = Column(Integer, nullable=False, default=0, server_default=text("0"))
    detections_created = Column(Integer, nullable=False, default=0, server_default=text("0"))
    detections_updated = Column(Integer, nullable=False, default=0, server_default=text("0"))
    sync_from = Column(DateTime(timezone=True), nullable=True)
    sync_to = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), nullable=False, default="running", server_default=text("'running'"))
    error_message = Column(Text, nullable=True)
    triggered_by = Column(UUID(as_uuid=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<IdpSyncLog(id={self.id}, org={self.organization_id}, "
            f"connection={self.connection_id}, provider={self.idp_provider}, "
            f"status={self.status}, events_fetched={self.events_fetched})>"
        )
