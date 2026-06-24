"""
PATENT NOTICE
Module: services/idp_connectors/base
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Abstract base class for all Identity Provider connectors.

PATENT INVARIANT 12: IdP API calls MUST request only the
minimum OAuth scopes documented in each subclass. The system
must NEVER request write scopes, directory read scopes, or
any scope beyond audit log read access.

PATENT INVARIANT 13: The IdP sync MUST extract only these
fields from IdP API responses:
  app_name, app_id, oauth_scopes, event_time, event_type.
  All other fields from IdP responses MUST be discarded
  immediately. Never log or store raw IdP API responses.

PATENT INVARIANT 14: Attribution is advisory only. The
  attributed_owner_id field on a detection is a suggestion —
  it never automatically grants access or creates permissions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.core.logging_config import get_logger
from app.core.security import decrypt_value
from app.models.idp import IdpConnection

logger = get_logger(__name__)


@dataclass
class OAuthEvent:
    """
    Normalized OAuth event extracted from any IdP API response.

    PATENT INVARIANT 13: Only these fields are ever extracted
    from IdP responses. All other fields are discarded
    immediately on receipt of the API response. Never log raw
    IdP API responses.

    actor_id is a SHA256 hash (never raw PII) when the connector
    provides it. It is used only in memory for attribution
    computation and stored in telemetry_events.raw_signal_json.
    """

    app_name: str
    app_id: str
    oauth_scopes: list[str] = field(default_factory=list)
    event_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = "grant"
    actor_id: str | None = None
    idp_provider: str = ""


class BaseIdpConnector(ABC):
    """
    Abstract base for all IdP connectors.

    Minimum OAuth scopes are defined per provider in each
    subclass. These must never be expanded beyond what is listed.

    All subclasses must:
    1. Discard all fields not in OAuthEvent
    2. Never log raw API responses
    3. Never store raw API responses
    4. Return normalized OAuthEvent objects only
    5. Handle token refresh before API calls
    6. Raise ConnectionError on auth failure
       (never silently swallow auth errors)
    """

    MINIMUM_SCOPES: list[str] = []

    def __init__(
        self,
        connection: IdpConnection,
        settings: Settings,
    ):
        self.connection = connection
        self.settings = settings

    @abstractmethod
    def get_authorization_url(
        self,
        state: str,
        redirect_uri: str,
    ) -> str:
        """Returns the OAuth consent URL."""

    @abstractmethod
    def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
    ) -> dict:
        """
        Exchanges authorization code for tokens.
        Returns: {
            "access_token": str,
            "refresh_token": str | None,
            "expires_in": int,
            "scope": str
        }
        Raises ConnectionError on failure.
        """

    @abstractmethod
    def refresh_access_token(self) -> str:
        """
        Refreshes the access token using the stored refresh token.
        Updates connection.access_token_enc with the new encrypted
        token. Returns new access token (decrypted, in memory only —
        never logged). Raises ConnectionError if refresh fails.
        """

    @abstractmethod
    def fetch_oauth_events(
        self,
        since: datetime,
        until: datetime,
    ) -> list[OAuthEvent]:
        """
        Fetches OAuth authorization events from the IdP for the
        given time window.

        Returns normalized OAuthEvent objects. Raw API responses
        are NEVER returned. All fields beyond OAuthEvent are
        discarded before this method returns.

        Raises ConnectionError on API failure.
        Raises PermissionError if token lacks required scopes.
        """

    def _get_access_token(self) -> str:
        """
        Returns decrypted access token.
        Refreshes if expired (within 5-minute window).
        Never logs the token value.

        PATENT INVARIANT 11: decrypt_value() from
        app/core/security.py is the only decryption path.
        """
        if self.connection.token_expires_at is not None:
            expires = self.connection.token_expires_at
            if expires.tzinfo is not None:
                expires = expires.replace(tzinfo=None)
            if expires <= datetime.utcnow() + timedelta(minutes=5):
                return self.refresh_access_token()
        return decrypt_value(self.connection.access_token_enc)

    def test_connection(self) -> bool:
        """
        Tests if the connection is valid by fetching a minimal
        time window. Returns True if successful. Returns False
        if auth fails. Raises ConnectionError on network error.
        """
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            until = datetime.now(timezone.utc)
            self.fetch_oauth_events(since, until)
            return True
        except PermissionError:
            return False
