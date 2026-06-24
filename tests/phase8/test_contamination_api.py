"""Tests for vendor contamination API endpoints."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.contamination import VendorAIContamination, VendorDPARecord
from app.models.vendor import Vendor
from app.services.contamination_engine import ContaminationEngine
from tests.conftest import GLOBEX_ORG_ID


def _make_vendor(db, organization_id, name="Test Vendor"):
    vendor = Vendor(
        id=uuid4(),
        organization_id=organization_id,
        name=name,
        vendor_type="software",
        risk_tier="medium",
        status="active",
    )
    db.add(vendor)
    db.commit()
    return vendor


def test_assess_all_vendors_returns_summary(client, test_db, org_id):
    _make_vendor(test_db, org_id, name="Vendor A")
    response = client.post(
        "/api/v1/shadow-ai/vendors/assess",
        json={"enable_external_scan": False},
    )
    assert response.status_code == 200
    data = response.json()
    assert "assessed" in data
    assert "summary" in data
    assert data["assessed"] >= 1


def test_list_contamination_paginated(client, test_db, org_id):
    vendor = _make_vendor(test_db, org_id, name="Vendor B")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.get("/api/v1/shadow-ai/vendors/contamination?page=1&page_size=10")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] >= 1


def test_get_vendor_contamination_detail(client, test_db, org_id):
    vendor = _make_vendor(test_db, org_id, name="Vendor C")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.get(f"/api/v1/shadow-ai/vendors/{vendor.id}/contamination")
    assert response.status_code == 200
    data = response.json()
    assert data["vendor_id"] == str(vendor.id)
    assert "contamination_score" in data


def test_update_dpa_recalculates_score(client, test_db, org_id):
    vendor = _make_vendor(test_db, org_id, name="Vendor D")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.post(
        f"/api/v1/shadow-ai/vendors/{vendor.id}/dpa",
        json={
            "vendor_id": str(vendor.id),
            "vendor_name": vendor.name,
            "dpa_exists": True,
            "covers_ai_processing": True,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["dpa_exists"] is True
    assert data["dpa_covers_ai"] is True
    assert data["contamination_band"] == "low"


def test_contamination_summary_correct_counts(client, test_db, org_id):
    vendor = _make_vendor(test_db, org_id, name="Vendor E")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.get("/api/v1/shadow-ai/vendors/contamination/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_vendors_assessed" in data
    assert "vendors_without_dpa" in data


def test_metrics_includes_contamination(client, test_db, org_id):
    vendor = _make_vendor(test_db, org_id, name="Vendor F")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        org_id,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.get("/api/v1/shadow-ai/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "vendor_contamination_critical" in data
    assert "vendor_contamination_high" in data
    assert "vendors_without_dpa" in data


def test_wrong_org_returns_404(client, test_db, org_id, globex_org_id):
    vendor = _make_vendor(test_db, GLOBEX_ORG_ID, name="Globex Vendor")
    ContaminationEngine.compute_contamination_score(
        vendor.id,
        vendor.name,
        GLOBEX_ORG_ID,
        enable_external_scan=False,
        db=test_db,
    )
    response = client.get(f"/api/v1/shadow-ai/vendors/{vendor.id}/contamination")
    assert response.status_code == 404
