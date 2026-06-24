"""
Seed script for Shadow AI Discovery Engine.

Creates seed data for standalone development:
  - 50+ AI tool signatures in the registry
  - 2 organizations (fixed UUIDs)
  - 3 users per organization (6 total)
  - 15 questionnaire response records with AI tool mentions
  - Demo Tier 1 scan producing real detections

Idempotent — running it twice produces the same state.

The organizations, users, and questionnaire_responses tables are
standalone development tables. At integration time, these are
replaced by CompliVibe's main database tables.
"""

import json
import sys
from uuid import UUID

from sqlalchemy import Boolean, Column, DateTime, String, Table, Text, func, select, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID

from app.core.database import Base, SessionLocal, engine
from app.core.logging_config import get_logger
from app.models.detection import ShadowAIDetection
from app.models.contamination import VendorAIContamination, VendorDPARecord
from app.models.questionnaire_response import QuestionnaireResponse
from app.models.regulation import RegulationArticle, RegulationNode
from app.models.signature import AISignatureRegistry
from app.models.vendor import Vendor
from app.services.contamination_engine import ContaminationEngine
from app.services.jurisdiction_engine import JurisdictionEngine
from app.services.registry_service import RegistryService

logger = get_logger(__name__)

# ── Fixed UUIDs for repeatability ───────────

ACME_ORG_ID = UUID("11111111-1111-1111-1111-111111111111")
GLOBEX_ORG_ID = UUID("22222222-2222-2222-2222-222222222222")

ACME_ADMIN = UUID("11111111-1111-1111-1111-111111111101")
ACME_MEMBER = UUID("11111111-1111-1111-1111-111111111102")
ACME_AUDITOR = UUID("11111111-1111-1111-1111-111111111103")

GLOBEX_ADMIN = UUID("22222222-2222-2222-2222-222222222201")
GLOBEX_MEMBER = UUID("22222222-2222-2222-2222-222222222202")
GLOBEX_AUDITOR = UUID("22222222-2222-2222-2222-222222222203")

# Phase 8 vendor contamination demo vendors
ACME_TECHCORP = UUID("33333333-3333-3333-3333-333333333301")
ACME_SAFEVENDOR = UUID("33333333-3333-3333-3333-333333333302")
ACME_PARTIALCORP = UUID("33333333-3333-3333-3333-333333333303")
GLOBEX_TECHCORP = UUID("44444444-4444-4444-4444-444444444401")
GLOBEX_SAFEVENDOR = UUID("44444444-4444-4444-4444-444444444402")
GLOBEX_PARTIALCORP = UUID("44444444-4444-4444-4444-444444444403")

# ── Seed-specific table definitions ─────────
# These are standalone dev tables, not part of the migration set.
# At integration time, replaced by CompliVibe's tables.
# questionnaire_responses is now managed by Alembic migration i005.

organizations_table = Table(
    "organizations",
    Base.metadata,
    Column("id", PgUUID(as_uuid=True), primary_key=True),
    Column("name", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=text("now()")),
    extend_existing=True,
)

users_table = Table(
    "users",
    Base.metadata,
    Column("id", PgUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PgUUID(as_uuid=True), nullable=False),
    Column("name", String(255), nullable=False),
    Column("role", String(50), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=text("now()")),
    extend_existing=True,
)

# ── Seed data ───────────────────────────────

ORGANIZATIONS = [
    {"id": ACME_ORG_ID, "name": "Acme Corp"},
    {"id": GLOBEX_ORG_ID, "name": "Globex Ltd"},
]

USERS = [
    {"id": ACME_ADMIN, "organization_id": ACME_ORG_ID, "name": "Alice Anderson", "role": "admin"},
    {"id": ACME_MEMBER, "organization_id": ACME_ORG_ID, "name": "Bob Brown", "role": "member"},
    {"id": ACME_AUDITOR, "organization_id": ACME_ORG_ID, "name": "Carol Clark", "role": "auditor"},
    {"id": GLOBEX_ADMIN, "organization_id": GLOBEX_ORG_ID, "name": "Dave Davis", "role": "admin"},
    {"id": GLOBEX_MEMBER, "organization_id": GLOBEX_ORG_ID, "name": "Eve Evans", "role": "member"},
    {"id": GLOBEX_AUDITOR, "organization_id": GLOBEX_ORG_ID, "name": "Frank Foster", "role": "auditor"},
]

VENDORS = [
    {"id": ACME_TECHCORP, "organization_id": ACME_ORG_ID, "name": "TechCorp AI", "vendor_type": "software", "risk_tier": "high"},
    {"id": ACME_SAFEVENDOR, "organization_id": ACME_ORG_ID, "name": "SafeVendor", "vendor_type": "software", "risk_tier": "low"},
    {"id": ACME_PARTIALCORP, "organization_id": ACME_ORG_ID, "name": "PartialCorp", "vendor_type": "software", "risk_tier": "medium"},
    {"id": GLOBEX_TECHCORP, "organization_id": GLOBEX_ORG_ID, "name": "TechCorp AI", "vendor_type": "software", "risk_tier": "high"},
    {"id": GLOBEX_SAFEVENDOR, "organization_id": GLOBEX_ORG_ID, "name": "SafeVendor", "vendor_type": "software", "risk_tier": "low"},
    {"id": GLOBEX_PARTIALCORP, "organization_id": GLOBEX_ORG_ID, "name": "PartialCorp", "vendor_type": "software", "risk_tier": "medium"},
]

DPA_RECORDS = [
    {"organization_id": ACME_ORG_ID, "vendor_id": ACME_SAFEVENDOR, "vendor_name": "SafeVendor", "dpa_exists": True, "covers_ai_processing": True},
    {"organization_id": ACME_ORG_ID, "vendor_id": ACME_PARTIALCORP, "vendor_name": "PartialCorp", "dpa_exists": True, "covers_ai_processing": False},
    {"organization_id": GLOBEX_ORG_ID, "vendor_id": GLOBEX_SAFEVENDOR, "vendor_name": "SafeVendor", "dpa_exists": True, "covers_ai_processing": True},
    {"organization_id": GLOBEX_ORG_ID, "vendor_id": GLOBEX_PARTIALCORP, "vendor_name": "PartialCorp", "dpa_exists": True, "covers_ai_processing": False},
]

QUESTIONNAIRE_RESPONSES = [
    {
        "id": UUID("aaaaaaaa-0001-0000-0000-000000000001"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We use ChatGPT for drafting customer support responses and "
            "recently began evaluating GitHub Copilot for our engineering team."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0002-0000-0000-000000000002"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "Our data science team uses Hugging Face models deployed via "
            "AWS SageMaker. We do not use any OpenAI products."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0003-0000-0000-000000000003"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": "TechVendor Inc",
        "question_text": "Does your vendor use AI in data processing?",
        "answer_text": (
            "The vendor confirmed they do not use any AI tools in their "
            "data processing pipeline."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0004-0000-0000-000000000004"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We have integrated Claude into our internal knowledge base "
            "for document summarization."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0005-0000-0000-000000000005"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "Midjourney is used by our marketing team for creating "
            "promotional imagery and social media content."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0006-0000-0000-000000000006"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We recently adopted Gemini for email drafting and are "
            "exploring Perplexity for research queries."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0007-0000-0000-000000000007"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_AUDITOR,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "Our engineering team uses GitHub Copilot Enterprise across "
            "all repositories with code review workflows."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0008-0000-0000-000000000008"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We deployed Azure OpenAI Service for internal chatbot "
            "development and are evaluating AWS Bedrock for additional "
            "model hosting."
        ),
    },
    {
        "id": UUID("aaaaaaaa-0009-0000-0000-000000000009"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "No AI tools are currently in use. We are evaluating options "
            "for Q4 procurement cycle."
        ),
    },
    {
        "id": UUID("aaaaaaaa-000a-0000-0000-000000000010"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "Cohere's embedding models power our internal search "
            "functionality across the document repository."
        ),
    },
    {
        "id": UUID("bbbbbbbb-0001-0000-0000-000000000011"),
        "organization_id": GLOBEX_ORG_ID,
        "submitted_by": GLOBEX_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We use ChatGPT Enterprise for content generation and "
            "AWS Bedrock for deploying custom model endpoints."
        ),
    },
    {
        "id": UUID("bbbbbbbb-0002-0000-0000-000000000012"),
        "organization_id": GLOBEX_ORG_ID,
        "submitted_by": GLOBEX_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "Our team has adopted GitHub Copilot and reports a 30% "
            "productivity increase in boilerplate code generation."
        ),
    },
    {
        "id": UUID("bbbbbbbb-0003-0000-0000-000000000013"),
        "organization_id": GLOBEX_ORG_ID,
        "submitted_by": GLOBEX_ADMIN,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We are piloting Claude for code review automation and "
            "considering Perplexity for competitive intelligence."
        ),
    },
    {
        "id": UUID("bbbbbbbb-0004-0000-0000-000000000014"),
        "organization_id": GLOBEX_ORG_ID,
        "submitted_by": GLOBEX_AUDITOR,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "The organization has no formal AI tools policy. Individual "
            "teams use various tools including Perplexity and Gemini "
            "without centralized oversight."
        ),
    },
    {
        "id": UUID("bbbbbbbb-0005-0000-0000-000000000015"),
        "organization_id": GLOBEX_ORG_ID,
        "submitted_by": GLOBEX_MEMBER,
        "vendor_name": None,
        "question_text": "What AI tools does your team currently use?",
        "answer_text": (
            "We use Hugging Face transformers for sentiment analysis on "
            "customer feedback and have experimented with Midjourney for "
            "design prototypes."
        ),
    },
    # Phase 8 vendor assessment responses
    {
        "id": UUID("cccccccc-0001-0000-0000-000000000001"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": "TechCorp AI",
        "question_text": "Does this vendor use AI to process your data?",
        "answer_text": (
            "TechCorp AI uses ChatGPT Enterprise and Claude for customer "
            "support automation and content generation across our shared data."
        ),
    },
    {
        "id": UUID("cccccccc-0002-0000-0000-000000000002"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": "SafeVendor",
        "question_text": "Does this vendor use AI to process your data?",
        "answer_text": (
            "SafeVendor has a fully manual process and does not use any AI "
            "tools for data processing or analysis."
        ),
    },
    {
        "id": UUID("cccccccc-0003-0000-0000-000000000003"),
        "organization_id": ACME_ORG_ID,
        "submitted_by": ACME_ADMIN,
        "vendor_name": "PartialCorp",
        "question_text": "Does this vendor use AI to process your data?",
        "answer_text": (
            "PartialCorp uses OpenAI API and GitHub Copilot in their "
            "engineering workflow. They may process some of our data through "
            "these tools."
        ),
    },
]


vendors_table = Table(
    "vendors",
    Base.metadata,
    Column("id", PgUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PgUUID(as_uuid=True), nullable=False),
    Column("name", String(255), nullable=False),
    Column("vendor_type", String(50), nullable=True),
    Column("risk_tier", String(20), nullable=True),
    Column("status", String(20), nullable=True),
    Column("owner_user_id", PgUUID(as_uuid=True), nullable=True),
    Column("data_access", String(255), nullable=True),
    Column("processes_personal_data", Boolean, nullable=False, server_default=text("false")),
    Column("sub_processor", Boolean, nullable=False, server_default=text("false")),
    Column("created_at", DateTime(timezone=True), server_default=text("now()")),
    extend_existing=True,
)

vendor_assessments_table = Table(
    "vendor_assessments",
    Base.metadata,
    Column("id", PgUUID(as_uuid=True), primary_key=True),
    Column("organization_id", PgUUID(as_uuid=True), nullable=False),
    Column("vendor_id", PgUUID(as_uuid=True), nullable=False),
    Column("status", String(50), nullable=True),
    Column("created_at", DateTime(timezone=True), server_default=text("now()")),
    extend_existing=True,
)


def create_seed_tables() -> None:
    """Create seed-specific tables if they do not exist."""
    organizations_table.create(bind=engine, checkfirst=True)
    users_table.create(bind=engine, checkfirst=True)
    vendors_table.create(bind=engine, checkfirst=True)
    vendor_assessments_table.create(bind=engine, checkfirst=True)


def seed_signatures(db) -> int:
    """Seed all AI tool signatures into the registry. Returns count."""
    return RegistryService.seed_signatures(db)


def seed_organizations(db) -> int:
    """Insert organizations if not present. Returns count inserted."""
    count = 0
    for org in ORGANIZATIONS:
        existing = db.execute(
            organizations_table.select().where(organizations_table.c.id == org["id"])
        ).first()
        if not existing:
            db.execute(organizations_table.insert().values(**org))
            count += 1
    db.commit()
    return count


def seed_users(db) -> int:
    """Insert users if not present. Returns count inserted."""
    count = 0
    for user in USERS:
        existing = db.execute(
            users_table.select().where(users_table.c.id == user["id"])
        ).first()
        if not existing:
            db.execute(users_table.insert().values(**user))
            count += 1
    db.commit()
    return count


def seed_questionnaire_responses(db) -> int:
    """Insert questionnaire responses if not present. Returns count inserted."""
    count = 0
    for resp in QUESTIONNAIRE_RESPONSES:
        existing = db.execute(
            select(QuestionnaireResponse).where(QuestionnaireResponse.id == resp["id"])
        ).scalar_one_or_none()
        if not existing:
            record = QuestionnaireResponse(
                id=resp["id"],
                organization_id=resp["organization_id"],
                submitted_by=resp["submitted_by"],
                vendor_name=resp.get("vendor_name"),
                question_text=resp.get("question_text"),
                answer_text=resp["answer_text"],
            )
            db.add(record)
            count += 1
    db.commit()
    return count


def seed_vendors(db) -> int:
    """Insert seed vendors if not present. Returns count inserted."""
    count = 0
    for vendor in VENDORS:
        existing = db.execute(
            select(Vendor).where(Vendor.id == vendor["id"])
        ).scalar_one_or_none()
        if not existing:
            record = Vendor(
                id=vendor["id"],
                organization_id=vendor["organization_id"],
                name=vendor["name"],
                vendor_type=vendor.get("vendor_type"),
                risk_tier=vendor.get("risk_tier"),
                status="active",
            )
            db.add(record)
            count += 1
    db.commit()
    return count


def seed_dpa_records(db) -> int:
    """Insert seed DPA records if not present. Returns count inserted."""
    count = 0
    for dpa in DPA_RECORDS:
        existing = db.execute(
            select(VendorDPARecord).where(
                VendorDPARecord.organization_id == dpa["organization_id"],
                VendorDPARecord.vendor_id == dpa["vendor_id"],
                VendorDPARecord.deleted_at.is_(None),
            )
        ).scalar_one_or_none()
        if not existing:
            record = VendorDPARecord(
                organization_id=dpa["organization_id"],
                vendor_id=dpa["vendor_id"],
                vendor_name=dpa["vendor_name"],
                dpa_exists=dpa["dpa_exists"],
                covers_ai_processing=dpa["covers_ai_processing"],
                created_by=ACME_ADMIN,
            )
            db.add(record)
            count += 1
    db.commit()
    return count


def run_demo_scan(db, org_id) -> dict:
    """Run a Tier 1 scan on the first org and print results.

    This is the patent demo function: shows the system detecting
    real AI tool mentions from realistic questionnaire text.
    """
    from app.services.tier1_scanner import Tier1Scanner

    summary = Tier1Scanner.scan_organization(
        organization_id=org_id,
        triggered_by=None,
        db=db,
    )

    detections = db.execute(
        select(ShadowAIDetection)
        .where(
            ShadowAIDetection.organization_id == org_id,
            ShadowAIDetection.deleted_at.is_(None),
        )
        .order_by(ShadowAIDetection.confidence_score.desc())
    ).scalars().all()

    lines = []
    lines.append(f"Scan complete: {len(detections)} detections found")
    lines.append("")
    lines.append("Detections:")
    for d in detections:
        lines.append(
            f"  [{d.provider_name} — {d.confidence_band} confidence "
            f"({float(d.confidence_score):.4f})]"
        )
        if d.jurisdiction_assessment_json:
            try:
                assessment = json.loads(d.jurisdiction_assessment_json)
                lines.append(
                    f"    Regulatory assessment for {d.provider_name}:"
                )
                lines.append(
                    f"      Applicable regulations: {assessment.get('applicable_regulations', [])}"
                )
                lines.append(
                    f"      Missing governance: {assessment.get('missing_governance', [])}"
                )
            except (json.JSONDecodeError, TypeError):
                pass

    output = "\n".join(lines)
    sys.stdout.write(output + "\n")

    sys.stdout.write("\nRunning vendor contamination assessment...\n")
    contamination_result = ContaminationEngine.run_assessment_pass(
        organization_id=org_id,
        enable_external_scan=False,
        db=db,
    )
    db.commit()

    contamination_records = db.execute(
        select(VendorAIContamination)
        .where(VendorAIContamination.organization_id == org_id)
        .order_by(VendorAIContamination.contamination_score.desc())
    ).scalars().all()

    sys.stdout.write("\nVendor Contamination Assessment:\n")
    for record in contamination_records:
        sys.stdout.write(
            f"  {record.vendor_name}: {record.contamination_band} "
            f"({float(record.contamination_score):.4f})\n"
        )

    return summary


def run_seed() -> None:
    """Run the full seed process."""
    logger.info("Starting seed process")
    create_seed_tables()

    db = SessionLocal()
    try:
        sig_count = seed_signatures(db)
        reg_seed = JurisdictionEngine.seed_regulation_data(db)
        org_count = seed_organizations(db)
        user_count = seed_users(db)
        resp_count = seed_questionnaire_responses(db)
        vendor_count = seed_vendors(db)
        dpa_count = seed_dpa_records(db)

        total_sigs = db.execute(
            select(func.count()).select_from(AISignatureRegistry)
        ).scalar()
        total_regs = db.execute(
            select(func.count()).select_from(RegulationNode)
        ).scalar()
        total_arts = db.execute(
            select(func.count()).select_from(RegulationArticle)
        ).scalar()
        total_orgs = db.execute(select(func.count()).select_from(organizations_table)).scalar()
        total_users = db.execute(select(func.count()).select_from(users_table)).scalar()
        total_resps = db.execute(
            select(func.count()).select_from(QuestionnaireResponse)
        ).scalar()
        total_vendors = db.execute(select(func.count()).select_from(Vendor)).scalar()
        total_dpas = db.execute(
            select(func.count()).select_from(VendorDPARecord).where(
                VendorDPARecord.deleted_at.is_(None)
            )
        ).scalar()

        summary_lines = [
            "Seed complete:",
            f"  Signatures: {total_sigs} tools in registry",
            f"  Regulations: {total_regs} regulations, {total_arts} articles",
            f"  Organizations: {total_orgs}",
            f"  Users: {total_users}",
            f"  Questionnaire responses: {total_resps}",
            f"  Vendors: {total_vendors} vendors seeded",
            f"  DPA records: {total_dpas} seeded",
            "",
            "Running demo Tier 1 scan...",
        ]

        sys.stdout.write("\n".join(summary_lines) + "\n")

        demo_summary = run_demo_scan(db, ACME_ORG_ID)

        logger.info(
            "Seed complete",
            extra={
                "signatures": total_sigs,
                "organizations": total_orgs,
                "users": total_users,
                "questionnaire_responses": total_resps,
                "demo_detections_created": demo_summary.get("detections_created", 0),
            },
        )

        sys.stdout.write("\nReady for Phase 3 API layer\n")
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
