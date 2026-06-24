"""
Pydantic schemas for the Federated Registry Intelligence Network.

Dependent Patent Claim 8: Federated Registry Intelligence Network.

Schemas here support:
  * Anonymized hostname signal submission from connectors
  * Candidate review by administrators
  * Aggregate, non-identifying network statistics

What these schemas NEVER include:
  - Organization identity in submission responses
  - Lists of which organizations contributed to an observation count
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FederatedSignalSubmission(BaseModel):
    """
    Connector-submitted signal for the federated registry network.

    Only hostnames and behavioral scores are accepted. Full URLs are
    normalized to hostnames before processing because URL paths may
    contain identifiers.
    """

    hostname: str = Field(..., max_length=500)
    behavioral_score: float = Field(..., ge=0.0, le=1.0)
    connector_version: str

    @field_validator("hostname")
    @classmethod
    def hostname_must_not_contain_path(cls, v: str) -> str:
        """
        Federated submissions accept hostnames only — not full URLs.
        Paths, query strings, fragments, and standard ports are stripped.
        This is a privacy protection measure: paths may contain identifiers.
        """
        v = v.lower().strip()

        # Strip scheme if present (https://api.example.com)
        if "://" in v:
            v = v.split("://", 1)[1]

        # Strip path, query, fragment (everything after first "/" or "?" or "#")
        for sep in ("/", "?", "#"):
            if sep in v:
                v = v.split(sep, 1)[0]

        # Strip standard port numbers (:443, :80)
        if v.endswith(":443") or v.endswith(":80"):
            v = v.rsplit(":", 1)[0]

        return v


class FederatedSubmissionResponse(BaseModel):
    """
    Response to a federated signal submission.

    Returns the hostname_hash (not the hostname) so the connector can
    verify submission without the server echoing the hostname back.
    current_observation_count is only returned if the submission was not
    a duplicate; it never reveals which organizations contributed.
    """

    accepted: bool
    was_duplicate: bool
    hostname_hash: str
    current_observation_count: int | None = None
    message: str


class FederatedCandidateRead(BaseModel):
    """
    Read model for a federated hostname candidate.

    This is global data shared across the network. It is intentionally
    not filtered by organization_id.
    """

    id: UUID
    hostname: str
    observation_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    behavioral_score: Decimal | None
    status: str
    promoted_at: datetime | None
    reviewed_by_admin: bool
    signature_id: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class FederatedNetworkStats(BaseModel):
    """
    Aggregate statistics for the federated intelligence network.

    Contains only counts. No organization-identifying data is returned.
    """

    total_hostnames_observed: int
    candidates_pending_review: int
    promoted_to_registry: int
    observation_threshold: int
    network_size_orgs: int


class FederatedPromoteRequest(BaseModel):
    """Admin request body to promote a federated candidate to the registry."""

    provider_name: str = Field(..., min_length=1, max_length=255)
    category: str = Field(..., min_length=1, max_length=50)


class FederatedEnableResponse(BaseModel):
    """Simple response confirming a connector token federated flag change."""

    id: UUID
    federated_submissions_enabled: bool
    federated_submissions_count: int
