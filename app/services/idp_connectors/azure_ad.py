"""
PATENT NOTICE
Module: services/idp_connectors/azure_ad
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation

Azure Active Directory (Microsoft Entra ID) connector.

MINIMUM_SCOPES = ["AuditLog.Read.All", "offline_access"]

These are the ONLY scopes requested from Azure AD. The system
never requests write access, directory access, or any scope
beyond audit log reading. offline_access is required for
token refresh. This is a patent invariant (12).

PATENT INVARIANT 13: Only OAuthEvent fields are extracted
from Azure AD API responses. All other fields are discarded
immediately. Raw API responses are never logged or stored.

Note on tenant_id: Azure AD connections require a tenant_id.
It is stored in idp_connections.idp_domain (same column,
different semantic meaning from Okta's domain usage).
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


class AzureADConnector(BaseIdpConnector):
    """
    Azure AD connector using the Microsoft Graph sign-in logs API.

    MINIMUM_SCOPES = ["AuditLog.Read.All", "offline_access"]
    These are the ONLY scopes requested from Azure AD. The system
    never requests write access, directory access, or any scope
    beyond audit log reading. offline_access is required for
    token refresh. This is a patent invariant.

    tenant_id is stored in connection.idp_domain.
    """

    MINIMUM_SCOPES = ["AuditLog.Read.All", "offline_access"]

    AUTHORIZATION_URL_TEMPLATE = (
        "https://login.microsoftonline.com/"
        "{tenant_id}/oauth2/v2.0/authorize"
        "?client_id={client_id}"
        "&scope=AuditLog.Read.All+offline_access"
        "&response_type=code"
        "&redirect_uri={redirect_uri}"
        "&state={state}"
    )

    TOKEN_URL_TEMPLATE = (
        "https://login.microsoftonline.com/"
        "{tenant_id}/oauth2/v2.0/token"
    )

    SIGNIN_LOG_URL = (
        "https://graph.microsoft.com/v1.0/"
        "auditLogs/signIns"
        "?$filter=appDisplayName ne '' and "
        "createdDateTime ge {since_iso} and "
        "createdDateTime le {until_iso}"
        "&$top=1000"
        "&$select=appDisplayName,appId,"
        "resourceDisplayName,createdDateTime,"
        "status,userPrincipalName"
    )

    MAX_PAGES = 10

    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Returns the Azure AD OAuth consent URL."""
        return self.AUTHORIZATION_URL_TEMPLATE.format(
            tenant_id=self.connection.idp_domain,
            client_id=self.settings.azure_ad_client_id,
            redirect_uri=quote(redirect_uri, safe=""),
            state=state,
        )

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> dict:
        """Exchanges authorization code for Azure AD tokens.

        Raises ConnectionError on HTTP failure. Never includes
        the response body in the error.
        """
        token_url = self.TOKEN_URL_TEMPLATE.format(
            tenant_id=self.connection.idp_domain
        )
        try:
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.settings.azure_ad_client_id,
                    "client_secret": self.settings.azure_ad_client_secret,
                    "scope": "AuditLog.Read.All offline_access",
                },
                timeout=30,
            )
        except Exception as exc:
            raise ConnectionError(
                f"Azure AD token exchange network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            raise ConnectionError(
                f"Azure AD token exchange failed: HTTP {resp.status_code}"
            )
        return resp.json()

    def refresh_access_token(self) -> str:
        """Refreshes the Azure AD access token.

        Updates connection.access_token_enc in memory. Raises
        ConnectionError if refresh fails. Sets sync_status='expired'.
        """
        if not self.connection.refresh_token_enc:
            self.connection.sync_status = "expired"
            raise ConnectionError("No refresh token stored for Azure AD connection")

        token_url = self.TOKEN_URL_TEMPLATE.format(
            tenant_id=self.connection.idp_domain
        )
        try:
            resp = httpx.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": decrypt_value(
                        self.connection.refresh_token_enc
                    ),
                    "client_id": self.settings.azure_ad_client_id,
                    "client_secret": self.settings.azure_ad_client_secret,
                    "scope": "AuditLog.Read.All offline_access",
                },
                timeout=30,
            )
        except Exception as exc:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Azure AD token refresh network error: {type(exc).__name__}"
            )
        if resp.status_code != 200:
            self.connection.sync_status = "expired"
            raise ConnectionError(
                f"Azure AD token refresh failed: HTTP {resp.status_code}"
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
        """Fetches sign-in log events from Microsoft Graph.

        PATENT INVARIANT 13: Only OAuthEvent fields are extracted.
        All other fields are discarded immediately. Raw API
        responses are never logged or stored.

        Only successful sign-ins (status.errorCode == 0) are included.
        actor_id is SHA256-hashed from userPrincipalName — raw emails
        are NEVER stored. This protects employee privacy.

        Follows @odata.nextLink pagination (max 10 pages).
        """
        access_token = self._get_access_token()
        results: list[OAuthEvent] = []

        url = self.SIGNIN_LOG_URL.format(
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
                    f"Azure AD Graph API network error: {type(exc).__name__}"
                )
            if resp.status_code == 401 or resp.status_code == 403:
                raise PermissionError(
                    f"Azure AD API returned {resp.status_code} — token may lack required scopes"
                )
            if resp.status_code != 200:
                raise ConnectionError(
                    f"Azure AD Graph API failed: HTTP {resp.status_code}"
                )

            data = resp.json()
            items = data.get("value", [])

            for item in items:
                event = self._parse_azure_event(item)
                if event is not None:
                    results.append(event)

            next_url = data.get("@odata.nextLink")
            if next_url is None:
                break
            url = next_url

        return results

    @staticmethod
    def _parse_azure_event(item: dict) -> OAuthEvent | None:
        """Extract ONLY OAuthEvent fields from a single Azure sign-in log.

        PATENT INVARIANT 13: All other fields are discarded immediately.

        Only successful sign-ins (status.errorCode == 0) are included.
        actor_id is SHA256-hashed from userPrincipalName — raw emails
        are NEVER stored in OAuthEvent. This protects employee privacy.
        The signIn endpoint does not return OAuth scopes, so
        oauth_scopes is always an empty list.
        """
        try:
            status = item.get("status", {})
            error_code = status.get("errorCode", -1)
            if error_code != 0:
                return None

            app_name = item.get("appDisplayName", "")
            app_id = item.get("appId", "")

            created = item.get("createdDateTime")
            event_time = (
                datetime.fromisoformat(created.replace("Z", "+00:00"))
                if created
                else datetime.now(timezone.utc)
            )

            upn = item.get("userPrincipalName")
            actor_id = None
            if upn:
                actor_id = hashlib.sha256(upn.encode()).hexdigest()

            return OAuthEvent(
                app_name=app_name,
                app_id=str(app_id) if app_id else "",
                oauth_scopes=[],
                event_time=event_time,
                event_type="access",
                actor_id=actor_id,
                idp_provider="azure_ad",
            )
        except Exception:
            logger.debug("Failed to parse Azure AD event — skipping", exc_info=True)
            return None
