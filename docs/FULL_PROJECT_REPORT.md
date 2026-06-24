# Shadow AI Discovery Engine — Full Project Report

**Date:** 2026-06-24  
**Overall Status:** COMPLETE — Phases 1 through 8 finished, all 292 tests passing.  
**Alembic Migration Head:** `i014`  
**Zero Regressions:** Yes

---

## Executive Summary

The Shadow AI Discovery Engine is a compliance platform that discovers, scores, and governs unsanctioned or unrecognized AI tools inside an organization. The system is built around a three-tier behavioral inference engine (questionnaire text, Identity Provider OAuth logs, and network-edge signals), a deterministic intent classifier, a regulatory jurisdiction graph, and a vendor contamination index.

As of 2026-06-24 the project has completed all eight planned phases. The database migration chain is at `i014` head, and the test suite reports **292 tests passing with zero failures and zero regressions** across all phases. Phases 2–8 are documented in detail in `docs/DEVELOPMENT_LOG.md`; Phase 1 is represented by the foundational health endpoint and base infrastructure extended by later phases.

---

## Cumulative Test Results

| Phase | Tests Passed | Running Total | Key Deliverable |
|-------|-------------:|--------------:|-----------------|
| Phase 1 | 7 | 7 | Health / foundation baseline |
| Phase 2 | 50 | 57 | Signature registry, confidence scoring, Tier 1 scan |
| Phase 3 | 49 | 106 | Governance workflow, intent classification, API layer |
| Phase 4 | 44 | 150 | Tier 2 IdP OAuth discovery, owner attribution |
| Phase 5 | 47 | 197 | Edge processing architecture, Tier 3 ingest, connector package |
| Phase 6 | 44 | 241 | Zero-day AI detection via behavioral classification |
| Phase 7 | 25 | 266 | Regulatory jurisdiction graph traversal |
| Phase 8 | 26 | 292 | Vendor AI Contamination Index |

**Final result:** `292 passed, 3 warnings in 26.10s`.

---

## Phase Summaries

### Phase 1 — Foundation Baseline

**Status:** COMPLETE  
**Tests:** 7/7 passed

Phase 1 established the project foundation that later phases extend: base FastAPI application, health endpoint, initial SQLAlchemy models, and the migration baseline up to `i005`. The only file explicitly referenced in the development log is the relocated health test file.

**Key files:**
- `tests/phase1/test_health.py` — 7 health endpoint tests (moved from `tests/test_health.py`)

**Patent claims:** Foundation only; no standalone patent claims implemented.

**Notable output:** Baseline health endpoint verification.

---

### Phase 2 — AI Signature Registry & Confidence Scoring

**Status:** COMPLETE  
**Patent Claims Implemented:** Core Claim 1, Dependent Claim 6  
**Tests:** 57/57 passed (7 Phase 1 + 50 Phase 2)

**Implemented:**
- 50 AI tool signatures across 8 categories (llm=30, image_gen=8, data_ai=4, voice_ai=3, embedding=2, agent=2, code_assistant=1)
- Weighted confidence scoring algorithm `Σ(w×s)/Σ(w)`
- Temporal confidence decay with category-calibrated λ
- Tier 1 questionnaire response scanner with word-boundary matching, deduplication, and real-time hook
- Detection service with rolling averages and audit logging
- APScheduler nightly jobs at 2 AM UTC (Tier 1 scan) and 3 AM UTC (decay pass)

**Key files created:**
- `migrations/versions/i006_add_decay_fields.py`
- `app/registry/signature_registry.py`
- `app/services/registry_service.py`
- `app/services/confidence_engine.py`
- `app/services/decay_engine.py`
- `app/services/detection_service.py`
- `app/services/tier1_scanner.py`
- `tests/phase2/test_registry.py` (9 tests)
- `tests/phase2/test_confidence_engine.py` (12 tests)
- `tests/phase2/test_decay_engine.py` (11 tests)
- `tests/phase2/test_tier1_scanner.py` (10 tests)
- `tests/phase2/test_detection_service.py` (8 tests)

**Demo output:** Seed data produced 11 distinct AI tool detections from 15 questionnaire responses across 2 organizations, all high confidence (1.0000).

---

### Phase 3 — Governance Artifacts, Intent Classification & API Layer

**Status:** COMPLETE  
**Patent Claims Implemented:** Core Claim 3, Dependent Claim 7  
**Tests:** 106/106 passed (7 Phase 1 + 50 Phase 2 + 49 Phase 3)

**Implemented:**
- Latent AI System entity promotion workflow through explicit human escalation
- Deterministic rule-based intent classifier (8 actions, 7 data subjects, 8 business contexts, 7 regulatory risk rules)
- Detection suppression service with permanent audit retention
- Bulk operations, CSV/JSON export, manual report endpoint
- 25 API endpoints across 4 routers under `/api/v1/shadow-ai`
- Public registry and data trust endpoints

**Key files created:**
- `migrations/versions/i007_create_ai_systems_stub.py`
- `migrations/versions/i008_create_suppressed_detections.py`
- `migrations/versions/i009_add_intent_fields.py`
- `app/models/ai_system.py`
- `app/models/suppression.py`
- `app/services/intent_engine.py`
- `app/services/suppression_service.py`
- `app/routers/detections.py`, `app/routers/scans.py`, `app/routers/registry.py`, `app/routers/metrics.py`
- `tests/phase3/test_intent_engine.py` (10 tests)
- `tests/phase3/test_suppression_service.py` (5 tests)
- `tests/phase3/test_detections_api.py` (20 tests)
- `tests/phase3/test_scans_api.py` (4 tests)
- `tests/phase3/test_metrics_api.py` (5 tests)
- `tests/phase3/test_export.py` (5 tests)

**Notable demo:** 8-step end-to-end lifecycle from scan through escalation to AI System creation, metrics, trust document, registry listing, and CSV export.

---

### Phase 4 — Tier 2 Connected Discovery via IdP OAuth Log Analysis

**Status:** COMPLETE  
**Patent Claims Implemented:** Core Claim 1 (Tier 2 complete), Owner Attribution Algorithm  
**Tests:** 150/150 passed (all prior + 44 Phase 4)

**Implemented:**
- Tier 2 behavioral inference via IdP OAuth log analysis
- Three IdP connectors: Okta, Azure AD, Google Workspace (read-only audit scopes)
- Encrypted token storage and refresh
- Owner attribution engine with 60% concentration threshold and 30-day lookback
- 10 IdP management endpoints
- `idp_sync_logs` audit table
- Third APScheduler job at 1 AM UTC (Tier 2 sync)

**Key files created:**
- `migrations/versions/i010_add_idp_sync_log.py`
- `app/services/idp_connectors/base.py`, `okta.py`, `azure_ad.py`, `google_ws.py`
- `app/services/attribution_engine.py`
- `app/services/tier2_scanner.py`
- `app/routers/idp.py`
- `tests/phase4/test_okta_connector.py` (7 tests)
- `tests/phase4/test_azure_connector.py` (6 tests)
- `tests/phase4/test_google_connector.py` (6 tests)
- `tests/phase4/test_tier2_scanner.py` (8 tests)
- `tests/phase4/test_attribution_engine.py` (7 tests)
- `tests/phase4/test_idp_api.py` (10 tests)

---

### Phase 5 — Edge Processing Architecture

**Status:** COMPLETE  
**Patent Claims Implemented:** Core Claim 2, Core Claim 1 (Tier 3 complete), Claim 10  
**Tests:** 197/197 passed (all prior + 47 Phase 5)

**Implemented:**
- Core Claim 2 edge processing architecture
- `Tier3Ingestor` central reception layer for pre-processed network signals
- Connector token management (SHA256-hashed, 365-day expiry)
- Rate limiting: 1000 signals/hour per token
- 15-field `FORBIDDEN_FIELDS` enforcement at HTTP 400 before any DB write
- Open source `connector/` package with SQLite offline queue (10,000 max, oldest-drop)
- 5 cloud/log source adapters: AWS VPC Flow, CloudTrail, Azure Activity, GCP Audit, local file
- Connector heartbeat monitoring (online/stale/offline)
- `PATENT_BRIEF.md` documenting all 10 claims
- Trust document incremented to version 1.1.0

**Key files created:**
- `migrations/versions/i011_add_token_expiry.py`
- `app/services/tier3_ingestor.py`
- `app/routers/connector.py`
- `connector/connector.py`, `connector/queue_manager.py`
- `connector/sources/vpc_flow.py`, `cloudtrail.py`, `azure_activity.py`, `gcp_audit.py`, `local_file.py`
- `connector/README.md`, `connector/requirements.txt`, `connector/connector.yaml.example`
- `PATENT_BRIEF.md`
- `tests/phase5/test_tier3_ingestor.py` (12 tests)
- `tests/phase5/test_connector_tokens.py` (7 tests)
- `tests/phase5/test_connector_api.py` (12 tests)
- `tests/phase5/test_connector_queue.py` (8 tests)
- `tests/phase5/test_connector_sources.py` (8 tests)

---

### Phase 6 — Zero-Day AI Detection via Behavioral Classification

**Status:** COMPLETE  
**Patent Claims Implemented:** Dependent Claim 4  
**Tests:** 241/241 passed (all prior + 44 Phase 6)  
**Migration:** `i012` applied cleanly (head)

**Implemented:**
- Behavioral feature extractor from network signal envelope data (no payload inspection)
- Zero-day classifier with `AI_PROBABILITY_THRESHOLD = 0.55`
- `ZeroDayCandidate` model and review endpoints
- Integration into Tier 3 ingestor

**Key files created:**
- `app/services/behavioral_feature_extractor.py`
- `app/services/zero_day_classifier.py`
- `app/models/zero_day.py`
- `app/schemas/zero_day.py`
- `migrations/versions/i012_add_zero_day_fields.py`
- `tests/phase6/test_behavioral_feature_extractor.py`
- `tests/phase6/test_zero_day_classifier.py`
- `tests/phase6/test_zero_day_integration.py`

**Key invariants:** `AI_PROBABILITY_THRESHOLD = 0.55`, `CLASSIFIER_VERSION = "1.0.0"`, feature weights sum to 1.0, fully deterministic, no payload inspection, no external calls.

---

### Phase 7 — Regulatory Jurisdiction Graph Traversal

**Status:** COMPLETE  
**Patent Claims Implemented:** Dependent Claim 9  
**Tests:** 266/266 passed (all prior + 25 Phase 7)  
**Migration:** `i013` applied cleanly (head)

**Implemented:**
- Deterministic regulatory jurisdiction graph with 7 regulations and 16 articles
- Graph traversal engine that maps structured detection attributes to specific regulatory obligations
- `RegulationNode` and `RegulationArticle` models
- API endpoints for jurisdiction assessment and public regulation listing
- Automatic assessment on detection creation/update and nightly re-assessment at 4 AM UTC
- Escalation workflow updated to populate `AISystem.regulatory_flags`

**Key files created:**
- `app/services/regulatory_graph.py`
- `app/services/jurisdiction_engine.py`
- `app/models/regulation.py`
- `app/schemas/jurisdiction.py`
- `migrations/versions/i013_add_jurisdiction_fields.py`
- `tests/phase7/test_regulatory_graph.py` (7 tests)
- `tests/phase7/test_jurisdiction_engine.py` (11 tests)
- `tests/phase7/test_jurisdiction_api.py` (7 tests)

**Graph stats:** 7 regulations, 16 articles, 7 missing-governance rules, `GRAPH_VERSION = "1.0.0"`.

**Notable demo:** ChatGPT in an HR context triggers EU AI Act Articles 6, 9, 13, 14; GDPR Articles 5, 22, 35; India DPDP Sections 4, 8; HIPAA Safeguards; ISO 42001 Clauses 4, 8; and NIST AI RMF GOVERN/MAP functions.

---

### Phase 8 — Vendor AI Contamination Index

**Status:** COMPLETE  
**Patent Claims Implemented:** Dependent Claim 5  
**Tests:** 292/292 passed (all prior + 26 Phase 8)  
**Migration:** `i014` applied cleanly (head)

**Implemented:**
- Vendor AI Contamination Index combining three orthogonal signals:
  - Internal contamination from detected vendor-linked AI tools
  - Optional external public signal scanning
  - Contractual gap based on DPA existence and AI coverage
- Weighted composite score: `0.30 × internal + 0.30 × external + 0.40 × contractual`
- Risk bands: low (<0.4000), medium (0.4000–0.5999), high (0.6000–0.7999), critical (≥0.8000)
- External signal scanner disabled by default, 24-hour rate limit, graceful failure handling
- `vendor_ai_contamination` and `vendor_dpa_records` tables
- REST endpoints and dashboard metrics integration

**Key files created:**
- `migrations/versions/i014_vendor_contamination.py`
- `app/models/vendor.py` (standalone dev/test models)
- `app/models/contamination.py`
- `app/schemas/contamination.py`
- `app/services/external_signal_scanner.py`
- `app/services/contamination_engine.py`
- `app/routers/contamination.py`
- `tests/phase8/test_contamination_engine.py` (14 tests)
- `tests/phase8/test_external_signal_scanner.py` (8 tests)
- `tests/phase8/test_contamination_api.py` (9 tests)

**Demo output:**
- TechCorp AI: high (0.7300)
- PartialCorp: medium (0.5300)
- SafeVendor: low (0.1500)

---

## Architecture Overview

The system is organized into models, services, routers/scanners, seed data, and tests.

### Models (Data Layer)

Core entities reside in `app/models/` and are evolved by Alembic migrations `i006` through `i014`:

- `ShadowAIDetection` — central detection record; stores confidence, decay, intent, jurisdiction, zero-day, and attribution fields
- `TelemetryEvent` — per-source signal events for Tiers 1, 2, and 3
- `AISystem` — promoted governance artifact with `source_detection_id` foreign key
- `SuppressedDetection` — prevents re-detection of dismissed tools
- `IdpConnection`, `IdpSyncLog` — IdP OAuth connections and sync audit trail
- `ConnectorToken`, `ConnectorHeartbeat` — Tier 3 edge connector tokens and health
- `ZeroDayCandidate` — unregistered AI behavior candidates
- `RegulationNode`, `RegulationArticle` — jurisdiction graph nodes
- `VendorAIContamination`, `VendorDPARecord` — vendor risk index persistence

### Services (Business Logic)

- **Inference & Scoring:** `confidence_engine.py`, `decay_engine.py`, `attribution_engine.py`, `behavioral_feature_extractor.py`, `zero_day_classifier.py`
- **Scanners/Ingestors:** `tier1_scanner.py`, `tier2_scanner.py`, `tier3_ingestor.py`, `idp_connectors/*`
- **Classification & Compliance:** `intent_engine.py`, `regulatory_graph.py`, `jurisdiction_engine.py`
- **Governance & Risk:** `detection_service.py`, `suppression_service.py`, `registry_service.py`, `contamination_engine.py`, `external_signal_scanner.py`

### Routers (API Layer)

All protected routers sit under `/api/v1/shadow-ai` and require `X-Organization-ID`, `X-User-ID`, and the capability flag unless noted public:

- `detections.py` — detection review, dismiss, escalate, bulk actions, export, jurisdiction
- `scans.py` — Tier 1 trigger, suppression management
- `registry.py` — public tool list/stats (no auth), public regulations/articles (Phase 7)
- `metrics.py` — dashboard metrics and public trust document
- `idp.py` — IdP connection lifecycle and required-scopes transparency endpoint
- `connector.py` — token management (user auth), ingest/heartbeat (token auth), public schema endpoint
- `contamination.py` — vendor contamination assessment and DPA management

### External Connector

The `connector/` package is a standalone open-source component deployed inside the customer environment. It reads AWS, Azure, GCP, and local log sources, extracts only pre-processed signals, queues them locally in SQLite if the API is unreachable, and transmits them to the central ingest endpoint.

### Seed & Scheduling

- `seed/seed.py` — seeds signatures, regulations, organizations, users, questionnaire responses, vendors, and demo assessments
- `app/main.py` — registers all routers and runs four APScheduler jobs: Tier 2 sync (1 AM), Tier 1 scan (2 AM), decay pass (3 AM), jurisdiction pass (4 AM UTC)

### Tests

Tests are grouped by phase under `tests/phase1/` through `tests/phase8/` and run with `pytest tests/`. The combined suite reports 292 passing tests.

---

## File Inventory of Important Modules

| Module | Responsibility |
|--------|----------------|
| `app/registry/signature_registry.py` | 50 AI tool signatures |
| `app/services/confidence_engine.py` | Weighted confidence scoring, signal hash, bands |
| `app/services/decay_engine.py` | Temporal decay with category λ |
| `app/services/detection_service.py` | Detection CRUD, review, escalate, export, bulk actions |
| `app/services/tier1_scanner.py` | Questionnaire text inference |
| `app/services/intent_engine.py` | Deterministic intent classification |
| `app/services/suppression_service.py` | Dismissal suppression |
| `app/services/idp_connectors/*` | Okta, Azure AD, Google Workspace connectors |
| `app/services/attribution_engine.py` | Owner attribution algorithm |
| `app/services/tier2_scanner.py` | IdP OAuth sync orchestration |
| `app/services/tier3_ingestor.py` | Edge signal reception |
| `connector/connector.py` + `connector/sources/*` | Open source edge connector |
| `app/services/behavioral_feature_extractor.py` | Zero-day behavioral features |
| `app/services/zero_day_classifier.py` | Zero-day classification |
| `app/services/regulatory_graph.py` | Regulation/article DAG |
| `app/services/jurisdiction_engine.py` | Graph traversal and assessment persistence |
| `app/services/contamination_engine.py` | Vendor contamination scoring |
| `app/services/external_signal_scanner.py` | Optional external public signal |
| `app/routers/detections.py` | Detection lifecycle endpoints |
| `app/routers/idp.py` | IdP endpoints |
| `app/routers/connector.py` | Connector token and ingest endpoints |
| `app/routers/contamination.py` | Contamination assessment endpoints |
| `app/routers/metrics.py` | Dashboard metrics and trust document |
| `seed/seed.py` | Full environment seed and demo |
| `PATENT_BRIEF.md` | Patent disclosure document |

---

## Demonstrated Patent Claims Across All Phases

| Claim | Name | Implementation | Phase |
|-------|------|----------------|-------|
| Core Claim 1 | Three-tier behavioral inference engine | `confidence_engine.py`, `tier1_scanner.py`, `tier2_scanner.py`, `tier3_ingestor.py` | 2, 4, 5 |
| Core Claim 2 | Edge processing architecture | `tier3_ingestor.py`, `connector/` package | 5 |
| Core Claim 3 | Governance artifact generation | `detection_service.py` (`escalate_to_inventory`) | 3 |
| Dependent Claim 4 | Zero-day AI detection via behavioral classification | `behavioral_feature_extractor.py`, `zero_day_classifier.py` | 6 |
| Dependent Claim 5 | Vendor AI Contamination Index | `contamination_engine.py`, `external_signal_scanner.py` | 8 |
| Dependent Claim 6 | Confidence decay | `decay_engine.py` | 2 |
| Dependent Claim 7 | Intent classification from linguistic context | `intent_engine.py` | 3 |
| Dependent Claim 8 / Patent Invariants 9–10 | Detection suppression | `suppression_service.py` | 3 |
| Dependent Claim 9 | Regulatory jurisdiction graph traversal | `regulatory_graph.py`, `jurisdiction_engine.py` | 7 |
| Claim 10 / Privacy Invariants | Privacy-preserving data handling | `telemetry.py` schemas, `connector/`, forbidden-field enforcement | 1, 3, 5 |

In addition, the Owner Attribution Algorithm (60% threshold, 30-day lookback) and the AI Signature Registry are implemented and tested.

---

## Next Steps / Ready for Next Phase

All eight planned phases are complete. The system is ready for:

1. **Integration with CompliVibe core modules** — wire the standalone `ai_systems`, vendor, and regulation tables to their production counterparts.
2. **PostgreSQL migration verification** — run `alembic upgrade head` in a PostgreSQL environment to validate migrations `i006`–`i014`.
3. **Production IdP OAuth registration** — configure real Okta, Azure AD, and Google Workspace OAuth apps and redirect URIs.
4. **Connector packaging and distribution** — publish `connector/` as `complivibe-connector-shadow-ai`, build Docker image, and publish deployment guides.
5. **Enhanced external signal sources** — extend `ExternalSignalScanner` beyond GitHub public search while keeping the scanner disabled by default.
6. **Operational dashboards and alerting** — build visualizations around `/metrics`, jurisdiction assessments, contamination leaderboards, and stale detection thresholds.
7. **Patent filing support** — finalize `PATENT_BRIEF.md`, collect claim-to-code evidence, and prepare filing materials.

**READY FOR NEXT PHASE: YES**
