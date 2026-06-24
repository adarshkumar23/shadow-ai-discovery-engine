"""
PATENT NOTICE
Module: services/idp_connectors/okta
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Okta Identity Provider connector.

MINIMUM_SCOPES = ["okta.logs.read"]

These are the ONLY scopes requested from Okta. The system
never requests write access, directory access, or any scope
beyond audit log reading. This is a patent invariant (12).

PATENT INVARIANT 13: Only OAuthEvent fields are extracted
from Okta API responses. All other fields are discarded
immediately. Raw API responses are never logged or stored.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from app.core.config import Settings
from app.core.logging_config import get_logger
from app.core.security import decrypt_value, encrypt_value
from app.models.idp import IdpConnection
from app.services.idp_connectors.base import BaseIdpConnector, OAuthEvent

logger = get_logger(__name__)


class OktaConnector(BaseIdpConnector):
    """
    Okta IdP connector using the System Log API.

    MINIMUM_SCOPES = ["okta.logs.read"]
    These are the ONLY scopes requested from Okta. The system
    never requests write access, directory access, or any scope
    beyond audit log reading. This is a patent invariant.
    """

    MINIMUM_SCOPES = ["okta.logs.read"]

    AUTHORIZATION_URL_TEMPLATE = (
        "https://{domain}/oauth2/v1/authorize"
        "?client_id={client_id}"
        "&scope=openid%20okta.logs.read"
        "&response_type=code"
        "&redirect_uri={redirect_uri}"
        "&state={state}"
    )

    TOKEN_URL_TEMPLATE = "https://{domain}/oauth2/v1/token"

    LOG_API_URL_TEMPLATE = (
        "https://{domain}/api/v1/logs"
        "?filter=eventType+eq+%22app.oauth2.token.grant%22"
        "&limit=1000"
        "&since={since_iso}"
        "&until={until_iso}"
    )

    MAX_PAGES = 10

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Returns the Okta OAuth consent URL."""
        return self.AUTHORIZATION_URL_TEMPLATE.format(
            domain=self.connection.idp_domain,
            client_id=self.settings.okta_client_id,
            redirect_uri=quote(redirect_uri, safe=""),
            state=state,
        )

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> dict:
        """Exchanges authorization code for Okta tokens.

        Raises ConnectionError on HTTP failure. Never includes
        the response body in the error (may contain sensitive data).
        """
        token_url = self.TOKEN_URL_TEMPLATE.format(
            domain=self.connection.idp_domain
        )
        try:
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.settings.okta_client_id,
                    "client_secret": self.settings.okta_client_secret,
                },
                timeout=30,
            )
        except Exception as exc:
            raise ConnectionError(
                f"Okta token exchange network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            raise ConnectionError(
                f"Okta token exchange failed: HTTP {resp.status_code}"
            )
        return resp.json()

    def refresh_access_token(self) -> str:
        """Refreshes the Okta access token using the stored refresh token.

        Updates connection.access_token_enc in memory. Raises
        ConnectionError if refresh fails. Sets sync_status='expired'
        on failure.
        """
        if not self.connection.refresh_token_enc:
            self.connection.sync_status = "expired"
            raise ConnectionError("No refresh token stored for Okta connection")

        token_url = self.TOKEN_URL_TEMPLATE.format(
            domain=self.connection.idp_domain
        )
        try:
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": decrypt_value(
                        self.connection.refresh_token_enc
                    ),
                    "client_id": self.settings.okta_client_id,
                    "client_secret": self.settings.okta_client_secret,
                },
                timeout=30,
            )
        except Exception as exc:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Okta token refresh network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Okta token refresh failed: HTTP {resp.status_code}"
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
        """Fetches OAuth token grant events from the Okta System Log API.

        PATENT INVARIANT 13: Only OAuthEvent fields are extracted.
        All other fields are discarded immediately. Raw API
        responses are never logged or stored.

        Follows Link header pagination (max 10 pages).
        Raises ConnectionError on API failure.
        """
        access_token = self._get_access_token()
        results: list[OAuthEvent] = []

        url = self.LOG_API_URL_TEMPLATE.format(
            domain=self.connection.idp_domain,
            since_iso=since.isoformat(),
            until_iso=until.isoformat(),
        )

        headers = {
            "Authorization": f"SSWS {access_token}",
            "Accept": "application/json",
        }

        for _page in range(self.MAX_PAGES):
            try:
                resp = httpx.get(url, headers=headers, timeout=60)
            except Exception as exc:
                raise ConnectionError(
                    f"Okta log API network error: {type(exc).__name__}"
                )
            if resp.status_code == 401 or resp.status_code == 403:
                raise PermissionError(
                    f"Okta API returned {resp.status_code} — token may lack required scopes"
                )
            if resp.status_code != 200:
                raise ConnectionError(
                    f"Okta log API failed: HTTP {resp.status_code}"
                )

            items = resp.json()
            if not isinstance(items, list):
                break

            for item in items:
                event = self._parse_okta_event(item)
                if event is not None:
                    results.append(event)

            next_url = self._extract_next_link(resp)
            if next_url is None:
                break
            url = next_url

        return results

    @staticmethod
    def _parse_okta_event(item: dict) -> OAuthEvent | None:
        """Extract ONLY OAuthEvent fields from a single Okta log entry.

        PATENT INVARIANT 13: All other fields are discarded
        immediately. The raw item dict is never stored or logged.
        """
        try:
            target = item.get("target", [])
            app_name = ""
            app_id = ""
            if target and isinstance(target, list) and len(target) > 0:
                app_name = target[0].get("displayName", "")
                app_id = target[0].get("id", "")

            debug_data = item.get("debugContext", {}).get("debugData", {})
            oauth_scopes = debug_data.get("requestedScopes", [])
            if not isinstance(oauth_scopes, list):
                oauth_scopes = []

            published = item.get("published")
            event_time = (
                datetime.fromisoformat(published.replace("Z", "+00:00"))
                if published
                else datetime.now(timezone.utc)
            )

            actor_id = None
            actor = item.get("actor")
            if actor and isinstance(actor, dict):
                actor_id = actor.get("id")

            return OAuthEvent(
                app_name=app_name,
                app_id=str(app_id) if app_id else "",
                oauth_scopes=oauth_scopes,
                event_time=event_time,
                event_type="grant",
                actor_id=actor_id,
                idp_provider="okta",
            )
        except Exception:
            logger.debug("Failed to parse Okta event — skipping", exc_info=True)
            return None

    @staticmethod
    def _extract_next_link(resp: httpx.Response) -> str | None:
        """Extract the next page URL from the Okta Link header."""
        link_header = resp.headers.get("Link", "")
        if not link_header:
            return None
        for part in link_header.split(","):
            if 'rel="next"' in part:
                start = part.find("<")
                end = part.find(">")
                if start != -1 and end != -1:
                    return part[start + 1 : end]
        return None
