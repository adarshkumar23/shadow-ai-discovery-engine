# Shadow AI Discovery Engine

> **PATENT STATUS:** Provisional filing in preparation — **All 10 Patent Claims Implemented**
>
> **Title:** System and Method for Inferring Undeclared Artificial
> Intelligence Systems and Generating AI Governance Artifacts from
> Enterprise Telemetry
>
> All 10 patent claims are implemented with working, tested code.
> See `PATENT_BRIEF.md` for the full technical disclosure.

---

## What This System Is

The Shadow AI Discovery Engine detects artificial intelligence systems
in use across an organization that have not been formally declared or
registered in the AI governance inventory. It accomplishes this by
analyzing three categories of telemetry — questionnaire responses,
identity provider OAuth logs, and network traffic signals — and
computing confidence-scored detections that governance teams can
review, dismiss, or escalate into the formal AI System inventory.

The system is built around three independent patent claims: a
three-tier weighted inference engine that aggregates heterogeneous
signals into unified confidence scores; an edge processing architecture
where an open source connector runs inside the customer's environment
and sends only pre-processed signals (raw telemetry never leaves the
customer network); and a governance artifact generation method that
converts inferred detections into formal inventory records through
explicit human authorization.

## The Three-Tier Architecture

```
Tier 1 — Platform Discovery     Questionnaire text analysis (keyword inference)
Tier 2 — Connected Discovery    IdP OAuth log analysis (Okta, Azure AD, Google)
Tier 3 — Deep Discovery         Network signal analysis (edge connector)
```

All three tiers feed into a unified confidence engine:
`ConfidenceScore = Σ(weight × score) / Σ(weight)`

## Quick Start

```bash
docker-compose up -d db                          # Start PostgreSQL
alembic upgrade head                             # Run all migrations
python seed/seed.py                              # Seed 50+ AI signatures
POST /api/v1/shadow-ai/scans/tier1               # Trigger a Tier 1 scan
GET  /api/v1/shadow-ai/detections                # View detections
```

Environment setup:
```bash
cp .env.example .env
# Fill in SHADOW_AI_FERNET_KEY:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## API Endpoints

### Health
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health/live` | Liveness probe |
| GET | `/api/v1/health/ready` | Readiness probe (DB + Fernet key) |
| GET | `/api/v1/shadow-ai/status` | Shadow AI system status and patent claim summary |

### Scans
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/shadow-ai/scans/tier1` | Trigger Tier 1 questionnaire scan |
| GET | `/api/v1/shadow-ai/scans/suppressions` | List active suppressions |
| DELETE | `/api/v1/shadow-ai/scans/suppressions/{id}` | Lift a suppression |

### Detections
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/shadow-ai/detections` | List detections (paginated, filterable) |
| GET | `/api/v1/shadow-ai/detections/export` | Export detections as CSV or JSON |
| GET | `/api/v1/shadow-ai/detections/summary` | Detection summary metrics |
| POST | `/api/v1/shadow-ai/detections/bulk-dismiss` | Bulk dismiss detections |
| POST | `/api/v1/shadow-ai/detections/bulk-review` | Bulk mark as reviewed |
| POST | `/api/v1/shadow-ai/detections/manual` | Submit a manual detection report |
| GET | `/api/v1/shadow-ai/detections/{id}` | Get detection detail |
| PATCH | `/api/v1/shadow-ai/detections/{id}/review` | Mark detection under review |
| POST | `/api/v1/shadow-ai/detections/{id}/dismiss` | Dismiss a detection |
| POST | `/api/v1/shadow-ai/detections/{id}/escalate` | Escalate to AI System inventory |

### Registry
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/shadow-ai/registry/tools` | List all AI signatures |
| GET | `/api/v1/shadow-ai/registry/stats` | Registry coverage statistics |

### IdP Integration (Tier 2)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/shadow-ai/idp/connect` | Initiate IdP OAuth connection |
| GET | `/api/v1/shadow-ai/idp/callback` | OAuth callback handler |
| GET | `/api/v1/shadow-ai/idp/connections` | List IdP connections |
| GET | `/api/v1/shadow-ai/idp/connections/{id}` | Get connection detail |
| DELETE | `/api/v1/shadow-ai/idp/connections/{id}` | Disconnect IdP |
| POST | `/api/v1/shadow-ai/idp/connections/{id}/sync` | Trigger IdP sync |
| POST | `/api/v1/shadow-ai/idp/connections/{id}/test` | Test IdP connection |
| GET | `/api/v1/shadow-ai/idp/connections/{id}/sync-logs` | List sync logs |
| GET | `/api/v1/shadow-ai/idp/required-scopes` | Required OAuth scopes (no auth) |

### Connector (Tier 3)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/shadow-ai/connector/tokens` | Generate connector token (admin) |
| GET | `/api/v1/shadow-ai/connector/tokens` | List connector tokens (read) |
| DELETE | `/api/v1/shadow-ai/connector/tokens/{id}` | Revoke connector token (admin) |
| GET | `/api/v1/shadow-ai/connector/status` | Connector status dashboard (read) |
| GET | `/api/v1/shadow-ai/connector/heartbeats` | List connector heartbeats (read) |
| POST | `/api/v1/shadow-ai/connector/ingest` | Ingest network signal (token auth) |
| POST | `/api/v1/shadow-ai/connector/heartbeat` | Post connector heartbeat (token auth) |
| GET | `/api/v1/shadow-ai/connector/schema` | Signal schema (no auth) |

### Metrics & Trust
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/shadow-ai/metrics` | Dashboard metrics |
| GET | `/api/v1/shadow-ai/trust` | Data trust document (no auth) |

## Phase Build Status

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Infrastructure (scaffold, DB, config, logging, auth, health, Docker, seed) | ✅ Complete |
| Phase 2 | Tier 1 scanning (questionnaire text analysis, confidence engine) | ✅ Complete |
| Phase 3 | Tier 2 IdP integration (Okta, Azure AD, Google), suppression | ✅ Complete |
| Phase 4 | Detection engine, decay, intent, attribution, escalation, audit | ✅ Complete |
| Phase 5 | Tier 3 connector (edge processing, open source connector, token management) | ✅ Complete |
| Phase 6 | Zero-day behavioral classifier for unknown AI services | ✅ Complete |
| Phase 7 | Regulatory jurisdiction graph traversal | ✅ Complete |
| Phase 8 | Vendor AI contamination index and DPA tracking | ✅ Complete |
| Phase 9 | Federated registry intelligence network | ✅ Complete |
| Phase 10 | Dark AI side channel detection and production hardening | ✅ Complete |

## Patent Claims Implemented

| # | Claim | Status | Phase |
|---|---|---|---|
| Core 1 | Three-tier inference engine | ✅ | 2, 3, 5 |
| Core 2 | Edge processing architecture | ✅ | 5 |
| Core 3 | Governance artifact generation | ✅ | 4 |
| Dependent 4 | Zero-day AI behavioral classifier | ✅ | 6 |
| Dependent 5 | Vendor AI contamination index | ✅ | 8 |
| Dependent 6 | Temporal confidence decay | ✅ | 4 |
| Dependent 7 | Intent classification | ✅ | 4 |
| Dependent 8 | Federated registry intelligence network | ✅ | 9 |
| Dependent 9 | Regulatory jurisdiction graph traversal | ✅ | 7 |
| Dependent 10 | Dark AI detection via side channels | ✅ | 10 |

See `PATENT_BRIEF.md` for the full technical disclosure of all 10 claims.

## Integration Seams

| # | Seam | Current (Standalone) | Integration Change |
|---|---|---|---|
| 1 | DB session | Own engine + `Depends(get_db)` | Swap to CompliVibe's `get_db` |
| 2 | Org ID | `X-Organization-ID` header | `Depends(get_current_org)` |
| 3 | Audit logging | Own `audit_logs` table | Import `AuditService` from CompliVibe |
| 4 | Capability flag | `SHADOW_AI_ENABLED` env var | DB query: `innovation_capabilities` |
| 5 | AI escalation | Stub function | Direct service call |
| 6 | Permissions | `require_permission()` always passes | `require_permission()` from CompliVibe |
| 7 | Router | Own `main.py` | One `include_router()` in CompliVibe app |

## Data Trust Statement

This system collects metadata and governance-relevant signals only.
It never collects raw logs, IP addresses, user identities, or
request/response contents. See `GET /api/v1/shadow-ai/trust` for the
full machine-readable data trust document.

## Connector Deployment

The open source Tier 3 connector runs inside the customer's environment.
It reads log sources, matches against AI service signatures, and sends
pre-processed signals only. See `connector/README.md` for deployment
instructions (cron, Docker, Lambda), configuration reference, and the
full list of data it never sends.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `APP_ENV` | No | `development` \| `staging` \| `production` (default: `development`) |
| `APP_VERSION` | No | Application version string (default: `0.1.0`) |
| `APP_NAME` | No | Service name (default: `shadow-ai-discovery`) |
| `LOG_LEVEL` | No | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` (default: `INFO`) |
| `DATABASE_URL` | **Yes** | PostgreSQL connection URL |
| `SHADOW_AI_ENABLED` | No | Capability flag — `true` to enable all endpoints (default: `true`) |
| `SHADOW_AI_FERNET_KEY` | **Yes** | Fernet key for encrypting IdP OAuth tokens at rest |
| `OKTA_CLIENT_ID` | No | CompliVibe's Okta OAuth app client ID |
| `OKTA_CLIENT_SECRET` | No | CompliVibe's Okta OAuth app client secret |
| `AZURE_AD_CLIENT_ID` | No | Azure AD OAuth app client ID |
| `AZURE_AD_CLIENT_SECRET` | No | Azure AD OAuth app client secret |
| `AZURE_AD_REDIRECT_URI` | No | Azure AD OAuth redirect URI |
| `GOOGLE_CLIENT_ID` | No | Google Workspace OAuth app client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google Workspace OAuth app client secret |
| `GOOGLE_REDIRECT_URI` | No | Google Workspace OAuth redirect URI |
| `CONNECTOR_RATE_LIMIT_PER_HOUR` | No | Rate limit for connector ingest (default: `1000`) |
| `AWS_CONTROL_TEST_ACCESS_KEY_ID` | No | AWS access key for Tier 3 connector testing |
| `AWS_CONTROL_TEST_SECRET_ACCESS_KEY` | No | AWS secret key for Tier 3 connector testing |
| `AWS_CONTROL_TEST_REGION` | No | AWS region (default: `ap-south-1`) |

## Development

```bash
pip install -r requirements.txt
alembic upgrade head
pytest tests/ -v
uvicorn app.main:app --reload
```

## Patent Notice

This software is part of a system covered by a provisional patent
filing: **System and Method for Inferring Undeclared Artificial
Intelligence Systems and Generating AI Governance Artifacts from
Enterprise Telemetry**. Status: Provisional filing in preparation.
