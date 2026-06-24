"""
Health endpoint tests.
"""

from app.core.config import settings
from app.schemas.common import HealthResponse


def test_liveness_returns_200(client):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_returns_200_when_db_available(client):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["fernet_key"] == "ok"
    assert data["checks"]["capability_flag"] == "ok"


def test_readiness_returns_503_when_fernet_key_missing(client, monkeypatch):
    monkeypatch.setattr(settings, "shadow_ai_fernet_key", "")
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "degraded"
    assert "failed" in data["checks"]["fernet_key"]


def test_readiness_response_matches_schema(client):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    HealthResponse(**response.json())


def test_request_id_in_response_headers(client):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert response.headers["x-request-id"]


def test_unknown_route_returns_404_not_500(client):
    response = client.get("/api/v1/nonexistent")
    assert response.status_code == 404


def test_cors_headers_present_in_development(client):
    response = client.get(
        "/api/v1/health/live",
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
