"""
Test configuration and fixtures.
"""

import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base, get_db
from app.main import app
from app.models.questionnaire_response import QuestionnaireResponse
from app.models.signature import AISignatureRegistry
from app.services.registry_service import RegistryService


@compiles(PgUUID, "sqlite")
def _compile_uuid_as_text(element, compiler, **kw):
    return "TEXT"


ACME_ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
GLOBEX_ORG_ID = UUID("22222222-2222-2222-2222-222222222222")
ACME_ADMIN_ID = UUID("11111111-1111-1111-1111-111111111101")


def _sqlite_now():
    """SQLite custom function to emulate PostgreSQL now()."""
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def test_db():
    """In-memory SQLite session with all tables created from models."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _register_custom_functions(dbapi_conn, _):
        dbapi_conn.create_function("now", 0, _sqlite_now)

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def seeded_db(test_db):
    """test_db with all 50+ signatures seeded."""
    RegistryService.seed_signatures(test_db)
    return test_db


@pytest.fixture
def org_id() -> UUID:
    """Fixed UUID matching seed org 1 (Acme Corp)."""
    return ACME_ORG_ID


@pytest.fixture
def globex_org_id() -> UUID:
    """Fixed UUID matching seed org 2 (Globex Ltd)."""
    return GLOBEX_ORG_ID


@pytest.fixture
def user_id() -> UUID:
    """Fixed UUID matching seed user 1 (Acme admin)."""
    return ACME_ADMIN_ID


@pytest.fixture
def client(test_db, org_id, user_id):
    """TestClient with required headers pre-set and DB overridden."""
    original_fernet_key = settings.shadow_ai_fernet_key
    settings.shadow_ai_fernet_key = Fernet.generate_key().decode()

    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        c.headers.update(
            {
                "X-Organization-ID": str(org_id),
                "X-User-ID": str(user_id),
            }
        )
        yield c

    app.dependency_overrides.clear()
    settings.shadow_ai_fernet_key = original_fernet_key


def make_signature(
    db,
    slug="test-tool",
    provider_name="Test Tool",
    category="llm",
    keyword_patterns=None,
    confidence_weights=None,
    risk_level="medium",
):
    """Helper: create and persist an AISignatureRegistry record."""
    if keyword_patterns is None:
        keyword_patterns = ["test tool", "testtool", "test-tool", "test tool ai"]
    if confidence_weights is None:
        confidence_weights = {
            "endpoint_match": 0.25,
            "identity_match": 0.25,
            "volume_match": 0.20,
            "keyword_match": 0.30,
        }

    sig = AISignatureRegistry(
        id=uuid4(),
        slug=slug,
        provider_name=provider_name,
        category=category,
        endpoint_patterns=json.dumps(["api.test.com"]),
        keyword_patterns=json.dumps(keyword_patterns),
        oauth_app_patterns=json.dumps([]),
        data_egress_indicators=json.dumps(
            {"min_bytes": 1000, "max_bytes": 100000, "typical_latency_ms": 500}
        ),
        confidence_weights=json.dumps(confidence_weights),
        risk_level=risk_level,
        is_active=True,
    )
    db.add(sig)
    db.commit()
    return sig


def make_questionnaire_response(
    db,
    organization_id,
    answer_text,
    response_id=None,
    submitted_by=None,
):
    """Helper: create and persist a QuestionnaireResponse record."""
    resp = QuestionnaireResponse(
        id=response_id or uuid4(),
        organization_id=organization_id,
        submitted_by=submitted_by,
        answer_text=answer_text,
    )
    db.add(resp)
    db.commit()
    return resp
