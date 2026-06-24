"""
PATENT NOTICE
Module: services/idp_connectors/google_ws
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Google Workspace connector.

MINIMUM_SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly"
]

These are the ONLY scopes requested from Google Workspace. The
system never requests write access, directory access, or any
scope beyond audit log reading. This is a patent invariant (12).

PATENT INVARIANT 13: Only OAuthEvent fields are extracted
from Google Workspace API responses. All other fields are
discarded immediately. Raw API responses are never logged or
stored.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from app.core.config import Settings
from app.core.logging_config import get_logger
from app.core.security import decrypt_value, encrypt_value
from app.models.idp import IdpConnection
from app.services.idp_connectors.base import BaseIdpConnector, OAuthEvent

logger = get_logger(__name__)


class GoogleWSConnector(BaseIdpConnector):
    """
    Google Workspace connector using the Reports API token activity.

    MINIMUM_SCOPES = [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
    ]
    These are the ONLY scopes requested from Google Workspace.
    The system never requests write access, directory access,
    or any scope beyond audit log reading. This is a patent invariant.
    """

    MINIMUM_SCOPES = [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly"
    ]

    AUTHORIZATION_URL = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        "?client_id={client_id}"
        "&scope={scope_encoded}"
        "&response_type=code"
        "&redirect_uri={redirect_uri}"
        "&access_type=offline"
        "&prompt=consent"
        "&state={state}"
    )

    TOKEN_URL = "https://oauth2.googleapis.com/token"

    REPORTS_API_URL = (
        "https://admin.googleapis.com/admin/"
        "reports/v1/activity/users/all/"
        "applications/token"
        "?startTime={since_iso}"
        "&endTime={until_iso}"
        "&maxResults=1000"
    )

    MAX_PAGES = 10

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Returns the Google Workspace OAuth consent URL."""
        scope_encoded = quote(
            "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            safe="",
        )
        return self.AUTHORIZATION_URL.format(
            client_id=self.settings.google_client_id,
            scope_encoded=scope_encoded,
            redirect_uri=quote(redirect_uri, safe=""),
            state=state,
        )

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> dict:
        """Exchanges authorization code for Google Workspace tokens.

        Raises ConnectionError on HTTP failure. Never includes
        the response body in the error.
        """
        try:
            resp = httpx.post(
                self.TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.settings.google_client_id,
                    "client_secret": self.settings.google_client_secret,
                },
                timeout=30,
            )
        except Exception as exc:
            raise ConnectionError(
                f"Google token exchange network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            raise ConnectionError(
                f"Google token exchange failed: HTTP {resp.status_code}"
            )
        return resp.json()

    def refresh_access_token(self) -> str:
        """Refreshes the Google Workspace access token.

        Updates connection.access_token_enc in memory. Raises
        ConnectionError if refresh fails. Sets sync_status='expired'.
        """
        if not self.connection.refresh_token_enc:
            self.connection.sync_status = "expired"
            raise ConnectionError("No refresh token stored for Google connection")

        try:
            resp = httpx.post(
                self.TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": decrypt_value(
                        self.connection.refresh_token_enc
                    ),
                    "client_id": self.settings.google_client_id,
                    "client_secret": self.settings.google_client_secret,
                },
                timeout=30,
            )
        except Exception as exc:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Google token refresh network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Google token refresh failed: HTTP {resp.status_code}"
            )

        data = resp.json()
        new_token = data["access_token"]
        self.connection.access_token_enc = encrypt_value(new_token)
        if "refresh_token" in data:
            self.connection.refresh_token_enc = encrypt_value(
                data["refresh_token"]
            )
        if "expires_in" in data:
            self.connection.token_expires_at = datetime.now(
                timezone.utc
            ) + timedelta(seconds=data["expires_in"])
        return new_token

    def fetch_oauth_events(
        self,
        since: datetime,
        until: datetime,
    ) -> list[OAuthEvent]:
        """Fetches token activity events from Google Workspace Reports API.

        PATENT INVARIANT 13: Only OAuthEvent fields are extracted.
        All other fields are discarded immediately. Raw API
        responses are never logged or stored.

        actor_id is SHA256-hashed from actor email — raw emails
        are NEVER stored in OAuthEvent. This protects employee privacy.

        Follows nextPageToken pagination (max 10 pages).
        """
        access_token = self._get_access_token()
        results: list[OAuthEvent] = []

        url = self.REPORTS_API_URL.format(
            since_iso=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            until_iso=until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        for _page in range(self.MAX_PAGES):
            try:
                resp = httpx.get(url, headers=headers, timeout=60)
            except Exception as exc:
                raise ConnectionError(
                    f"Google Reports API network error: {type(exc).__name__}"
                )
            if resp.status_code == 401 or resp.status_code == 403:
                raise PermissionError(
                    f"Google API returned {resp.status_code} — token may lack required scopes"
                )
            if resp.status_code != 200:
                raise ConnectionError(
                    f"Google Reports API failed: HTTP {resp.status_code}"
                )

            data = resp.json()
            items = data.get("items", [])

            for item in items:
                events = self._parse_google_item(item)
                results.extend(events)

            next_token = data.get("nextPageToken")
            if next_token is None:
                break
            url = (
                self.REPORTS_API_URL.format(
                    since_iso=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    until_iso=until.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
                + f"&pageToken={next_token}"
            )

        return results

    @staticmethod
    def _parse_google_item(item: dict) -> list[OAuthEvent]:
        """Extract ONLY OAuthEvent fields from a Google Workspace activity item.

        PATENT INVARIANT 13: All other fields are discarded immediately.
        The raw item dict is never stored or logged.

        actor_id is SHA256-hashed from actor email — raw emails
        are NEVER stored in OAuthEvent.
        """
        results: list[OAuthEvent] = []
        try:
            event_time = datetime.now(timezone.utc)
            item_id = item.get("id", {})
            time_str = item_id.get("time")
            if time_str:
                event_time = datetime.fromisoformat(
                    time_str.replace("Z", "+00:00")
                )

            actor = item.get("actor", {})
            actor_email = actor.get("email", "")
            actor_id = None
            if actor_email:
                actor_id = hashlib.sha256(actor_email.encode()).hexdigest()

            for event in item.get("events", []):
                params = event.get("parameters", [])

                app_name = next(
                    (p["value"] for p in params if p.get("name") == "app_name"),
                    "",
                )
                app_id = next(
                    (p["value"] for p in params if p.get("name") == "client_id"),
                    "",
                )
                oauth_scopes = next(
                    (
                        p["multiValue"]
                        for p in params
                        if p.get("name") == "scope"
                    ),
                    [],
                )
                if not isinstance(oauth_scopes, list):
                    oauth_scopes = []

                event_name = event.get("name", "")
                event_type = "grant" if event_name == "authorize" else "access"

                results.append(
                    OAuthEvent(
                        app_name=str(app_name) if app_name else "",
                        app_id=str(app_id) if app_id else "",
                        oauth_scopes=oauth_scopes,
                        event_time=event_time,
                        event_type=event_type,
                        actor_id=actor_id,
                        idp_provider="google_ws",
                    )
                )
        except Exception:
            logger.debug(
                "Failed to parse Google Workspace event — skipping",
                exc_info=True,
            )
        return results
