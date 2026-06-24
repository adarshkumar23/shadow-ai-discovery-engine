# Shadow AI Discovery Engine — Phase 10 Development Log

## Phase 10 — Dark AI Side Channels & Production Hardening

**Date:** 2026-06-24
**Status:** COMPLETE
**Patent Claims Implemented:** Dependent Claim 10
**Test Results:** 340 passed, 3 warnings, zero failures

---

### Overview

Phase 10 is the final phase. It implements Dependent Patent Claim 10 — Dark
AI Detection via Side Channels — and completes production hardening across
all ten phases.

Dark AI detection identifies probable AI service usage from network flow
metadata when direct hostname identification is unavailable (traffic routed
through proxies, VPNs, gateways, or embedded inside broader service calls).
The classifier operates entirely on timing, variance, payload-size
distribution, connection patterns, and session behavior. It never inspects
packet payloads, never decrypts TLS, and never reads application-layer
content.

Production hardening delivers:

- Migration `i016` adding dark AI fields to `shadow_ai_detections`
- Optional flow metadata fields on `ConnectorSignalPayload`
- Dynamic scheduler job counting in `GET /api/v1/shadow-ai/status`
- Data trust document v2.0.0 with dark AI and federated network sections
- Updated `README.md` and `PATENT_BRIEF.md` declaring all ten claims
  implemented

---

### Files Created

| File | Description |
|------|-------------|
| `migrations/versions/i016_dark_ai_fields.py` | Adds dark AI columns and partial index to `shadow_ai_detections` |
| `app/services/dark_ai_classifier.py` | Dependent Claim 10: DarkAIClassifier with six feature scores, composite scoring, proxy detection, and detection creation |
| `tests/phase10/__init__.py` | Phase 10 test package |
| `tests/phase10/test_dark_ai_classifier.py` | 16 unit tests: feature scoring, threshold, weights, determinism, payload inspection guard |
| `tests/phase10/test_dark_ai_integration.py` | 6 integration tests: proxied traffic, unknown hostname, detection list, jurisdiction, status endpoint, trust document |

### Files Modified

| File | Changes |
|------|---------|
| `app/schemas/telemetry.py` | Added six optional Phase 10 flow metadata fields to `ConnectorSignalPayload` (outside FORBIDDEN_FIELDS) |
| `app/models/detection.py` | Added `detection_method`, `is_dark_ai`, `dark_ai_features_json`, `dark_ai_score`, `dark_ai_proxy_detected` columns |
| `app/services/tier3_ingestor.py` | Wired `DarkAIClassifier` after zero-day classification; fixed latent `UnboundLocalError` on zero-day `candidate` variable |
| `app/routers/health.py` | `GET /api/v1/shadow-ai/status` production readiness endpoint; dynamically counts scheduler jobs |
| `app/routers/metrics.py` | `GET /api/v1/shadow-ai/trust` updated to v2.0.0 with `dark_ai_detection` and `federated_network` sections |
| `app/main.py` | Exposes APScheduler on `app.state.scheduler` for dynamic job counting |
| `app/services/dark_ai_classifier.py` | Updated nightly-review comment to reflect six scheduler jobs |
| `PATENT_BRIEF.md` | Marked all 10 claims implemented; updated Phase 10 wording and migration range |
| `README.md` | All 10 phases and all 10 patent claims marked COMPLETE |

---

### Migration i016 — Dark AI Side Channel Fields

**Revision ID:** `i016`
**Down revision:** `i014`
**Subsequently followed by:** `i017`, `i015` (current alembic head)

Added to `shadow_ai_detections`:

| Column | Type | Nullable | Default | Purpose |
|--------|------|----------|---------|---------|
| `detection_method` | VARCHAR(50) | YES | — | Marker for dark AI detections: `"dark_ai_side_channel"` (Patent Invariant 38) |
| `is_dark_ai` | BOOLEAN | NO | FALSE | True when detection originated from dark AI classifier |
| `dark_ai_features_json` | TEXT | YES | — | JSON object with all six feature scores and composite |
| `dark_ai_score` | NUMERIC(5,4) | YES | — | Classifier composite score |
| `dark_ai_proxy_detected` | BOOLEAN | YES | — | True when proxy/VPN/gateway routing is inferred |

Added partial index:
- `ix_detection_dark_ai` on `(organization_id, is_dark_ai) WHERE is_dark_ai = TRUE`

No new `telemetry_events` columns were required; the six optional connector
flow metrics are stored inside `raw_signal_json`.

Alembic verification:

```
$ alembic current
i015 (head)
```

DB inspection confirmed all five columns and the partial index exist on
PostgreSQL.

---

### Dark AI Classifier — Dependent Patent Claim 10

**Module:** `app/services/dark_ai_classifier.py`
**Classifier version:** `1.0.0`
**Threshold:** `DARK_AI_THRESHOLD = 0.60`
**Weights sum:** `Σ DARK_AI_WEIGHTS.values() == 1.0`

#### Patent-Specified Features

1. **response_time_variance_score** (weight 0.25)
   - LLM inference shows distinctive variance.
   - `< 100 ms` → 0.1 (static/CDN)
   - `100–500 ms` → 0.5 (database-like)
   - `500–2000 ms` → 0.8 (LLM-like)
   - `> 2000 ms` → 0.6 (too variable)

2. **payload_asymmetry_score** (weight 0.20)
   - AI inference: small request, large response.
   - `response / request <= 1` → 0.1
   - `1–5` → 0.5
   - `5–50` → 0.8
   - `> 50` → 0.9

3. **inter_request_timing_score** (weight 0.20)
   - Human-AI conversation gaps are distinctive.
   - `< 100 ms` → 0.1 (polling/streaming)
   - `100 ms–2 s` → 0.4 (API integration)
   - `2 s–60 s` → 0.9 (human-paced)
   - `> 60 s` → 0.5 (infrequent)

4. **connection_efficiency_score** (weight 0.15)
   - AI services reuse persistent connections.
   - `< 0.3` → 0.2
   - `0.3–0.7` → 0.6
   - `> 0.7` → 0.9

5. **call_volume_pattern_score** (weight 0.10)
   - Reuses Phase 6 `BehavioralFeatureExtractor._score_call_frequency()`.
   - Penalizes zero usage and suspiciously bursty usage.

6. **response_latency_profile_score** (weight 0.10)
   - AI inference latency is higher than CDN/static.
   - `< 50 ms` → 0.1
   - `50–200 ms` → 0.3
   - `200–2000 ms` → 0.8
   - `> 2000 ms` → 0.6

#### Activation Conditions

`DarkAIClassifier.should_classify(payload, matched_signature)` returns True
when either:

1. A signature matched **and** the hostname looks like a proxy/gateway/CDN
   or an IP address or uses a non-standard port.
2. No signature matched **and** at least two optional timing/payload fields
   are present (`avg_response_time_ms`, `response_time_variance_ms`,
   `inter_request_gap_ms`, `avg_response_bytes`).

#### Proxy Detection

`DarkAIClassifier._is_proxy_pattern()` flags:
- Hostnames containing `proxy`, `gateway`, `relay`, `forward`, or `cdn`
- IPv4 address patterns
- Ports other than 443

#### Detection Creation

When `composite_score >= 0.60` and no active dark AI detection already
exists for the org + hostname:

- `provider_name = "Dark AI Traffic ({hostname})"`
- `detection_method = "dark_ai_side_channel"`
- `is_dark_ai = True`
- `dark_ai_score = composite_score`
- `dark_ai_features_json = json.dumps(features.to_dict())`
- `dark_ai_proxy_detected = proxy_flag`
- `confidence_score`/`base_confidence_score` = composite_score
- `decay_lambda = 0.046`
- Jurisdiction assessment runs immediately via `JurisdictionEngine.assess_detection()`
- Audit log action: `shadow_ai.dark_ai.detection_created`

#### What the Classifier NEVER Does

- Inspects packet payload contents
- Decrypts TLS traffic
- Reads HTTP headers, URLs, or query strings
- Identifies the specific AI service (only that traffic appears AI-like)
- Makes external API calls

---

### Tier 3 Ingestor Integration

`app/services/tier3_ingestor.py` calls `DarkAIClassifier.classify()` in two
places:

1. **Unmatched signals:** After zero-day classification, if the unknown
   hostname provides enough timing metadata, dark AI classification runs
   from side-channel signals alone.
2. **Matched signatures:** After `DetectionService.run_detection()`, if the
   hostname matches a known AI signature but is routed through a proxy, the
   classifier creates an additional dark AI detection.

This means a single ingress can produce:
- A standard Tier 3 detection (signature match)
- A zero-day candidate (behavioral hostname analysis)
- A dark AI detection (flow-level side channel analysis)

All three are independent and all write audit logs.

---

### Production Hardening

#### A. Data Trust Document v2.0.0

`GET /api/v1/shadow-ai/trust` now returns:

- `document_version`: `"2.0.0"`
- `dark_ai_detection` section:
  - `method`: `"network flow metadata analysis"`
  - `payload_inspection`: `False`
  - `tls_decryption`: `False`
  - `features`: list of all six feature names
- `federated_network` section:
  - `opt_in`: `True`
  - `anonymization`: `"SHA256 hash only"`
  - `promotion_threshold`: `3`
  - `org_identity_stored`: `False`

#### B. Shadow AI System Status Endpoint

`GET /api/v1/shadow-ai/status` (no auth) returns:

```json
{
  "service": "shadow-ai-discovery",
  "version": "0.1.0",
  "patent_claims_implemented": 10,
  "patent_status": "provisional_in_preparation",
  "patent_title": "System and Method for Inferring Undeclared Artificial Intelligence Systems and Generating AI Governance Artifacts from Enterprise Telemetry",
  "build_phases_complete": 10,
  "detection_methods": [
    "questionnaire_text_inference",
    "idp_oauth_analysis",
    "network_signal_analysis",
    "behavioral_zero_day",
    "dark_ai_side_channel",
    "federated_registry"
  ],
  "database_tables": 20,
  "api_endpoints": 57,
  "registry_tools": 50,
  "scheduler_jobs": 6,
  "trust_document_version": "2.0.0",
  "timestamp": "2026-06-24T14:50:37.964281+00:00"
}
```

`scheduler_jobs` is now counted dynamically from the running APScheduler
instance, reflecting the actual six nightly jobs:

1. `nightly_federated_submission`
2. `nightly_tier2_sync`
3. `nightly_tier1_scan`
4. `nightly_decay_pass`
5. `nightly_jurisdiction_pass`
6. `nightly_dark_ai_review`

#### C. Documentation Updates

- `README.md` now declares **"All 10 Patent Claims Implemented"** and marks
  all ten phases COMPLETE.
- `PATENT_BRIEF.md` has a full claims table with implementation files, key
  functions, phases, and verifying tests for all 10 claims, plus a Build
  Complete section with the actual git commit count (`1`).

---

### Dark AI Demo

Input Tier 3 signal (proxy hostname + timing metadata):

```
hostname_pattern:            proxy.company.internal
avg_response_time_ms:        800
response_time_variance_ms:   1200
avg_request_bytes:           150
avg_response_bytes:          4500
connection_reuse_ratio:      0.9
inter_request_gap_ms:        12000
call_count_24h:              250
```

Computed feature scores:

| Feature | Score |
|---------|-------|
| response_time_variance_score | 0.8 |
| payload_asymmetry_score | 0.8 |
| inter_request_timing_score | 0.9 |
| connection_efficiency_score | 0.9 |
| call_volume_pattern_score | 0.9 |
| response_latency_profile_score | 0.8 |
| **composite_score** | **0.8450** |
| has_timing_data | True |

Threshold: 0.60
Detection created: yes
dark_ai_proxy_detected: yes
detection_method: dark_ai_side_channel

---

### Test Results

```
pytest tests/ -v

340 passed, 3 warnings in 17.30s
```

Breakdown by phase:

| Phase | Tests | Status |
|-------|-------|--------|
| Phase 1 | 7 | passed |
| Phase 2 | 50 | passed |
| Phase 3 | 49 | passed |
| Phase 4 | 44 | passed |
| Phase 5 | 49 | passed |
| Phase 6 | 44 | passed |
| Phase 7 | 25 | passed |
| Phase 8 | 26 | passed |
| Phase 9 | 20 | passed |
| Phase 10 | 26 | passed |

Zero failures across all 340 tests.

---

### Definition of Done Verification

- [x] Migration `i016` applied cleanly; `alembic current` = `i015 (head)`
- [x] Dark AI columns and partial index present in PostgreSQL
- [x] `DARK_AI_THRESHOLD == 0.60`
- [x] `DARK_AI_WEIGHTS` sum to exactly 1.0
- [x] Classifier never reads `request_body`, `response_body`, `payload_content`, etc.
- [x] `dark_ai_proxy_detected` correctly set for proxy-pattern hostnames
- [x] `is_dark_ai = True` on all dark AI detections
- [x] Missing timing fields degrade gracefully to neutral 0.5
- [x] `GET /api/v1/shadow-ai/status` returns `patent_claims_implemented: 10`
- [x] `GET /api/v1/shadow-ai/trust` returns `document_version: "2.0.0"`
- [x] `README.md` shows all 10 phases COMPLETE
- [x] `PATENT_BRIEF.md` marks all 10 claims IMPLEMENTED with file paths
- [x] `PATENT_NOTICE` present in `dark_ai_classifier.py`
- [x] Six timing features documented formally in module docstring
- [x] `DARK_AI_WEIGHTS` documented as named dict constant
- [x] `pytest tests/` all pass, zero failures

---

### Patent Invariants Verified

**New for Phase 10:**

1. **Patent Invariant 36** — Dark AI classifier operates only on network
   flow metadata. Verified by source inspection and
   `test_no_payload_inspection`.
2. **Patent Invariant 37** — Timing side-channel features and discriminators
   documented in module docstring.
3. **Patent Invariant 38** — Dark AI detections use
   `detection_method = "dark_ai_side_channel"` and `is_dark_ai = True`.
   Verified by `test_dark_ai_detection_method_string`.
4. **Patent Invariant 39** — Production hardening checklist completed and
   verified by tests/observable outputs.

**All prior invariants still enforced** (verified by existing phase tests):
- Confidence score `NUMERIC(5,4)` in [0,1]
- Signal hash SHA256 determinism
- Detections below 0.40 discarded
- Decay formula `base × e^(-λ × days)`
- Every detection writes an audit log entry
- Dismissed detections never hard-deleted
- Deterministic, local intent classification
- Federated network opt-in and anonymization

---

### Patent Claims Demonstrated

- [x] **Dependent Claim 10** — Dark AI Detection via Side Channels working:
      - Six flow-level metadata features extracted without payload inspection.
      - Composite score weighted by patent-specified coefficients.
      - Proxy/VPN/gateway detection from hostname and port heuristics.
      - Detections created with `detection_method = "dark_ai_side_channel"`.
      - Jurisdiction assessment runs automatically on every dark AI detection.
      - Audit log records classifier version, score, and proxy flag.

---

### Complete Patent Claim Summary

- [x] Core Claim 1 — Three-tier inference engine
- [x] Core Claim 2 — Edge processing architecture
- [x] Core Claim 3 — Governance artifact generation
- [x] Dependent Claim 4 — Zero-day behavioral classifier
- [x] Dependent Claim 5 — Vendor AI contamination index
- [x] Dependent Claim 6 — Temporal confidence decay
- [x] Dependent Claim 7 — Intent classification
- [x] Dependent Claim 8 — Federated registry intelligence network
- [x] Dependent Claim 9 — Regulatory jurisdiction graph traversal
- [x] Dependent Claim 10 — Dark AI side channels

---

### Blockers or Deviations

1. **`tier3_ingestor.py` UnboundLocalError fix:** The zero-day
   `candidate` variable was referenced before assignment in the unmatched
   signal branch. Initialized `candidate = None` before the conditional to
   prevent regression.

2. **Scheduler job count accuracy:** The status endpoint originally
   hardcoded `scheduler_jobs: 5`, but the system actually registers six
   nightly jobs (the new `nightly_dark_ai_review` is the sixth). Changed the
   endpoint to count jobs dynamically from `app.state.scheduler` so the
   response is always accurate.

3. **Orphan `federated_registry_contributions` table:** Migration
   `migrations/versions/i017_federated_registry.py` creates a
   `federated_registry_contributions` table that is not referenced by any
   model or code. It is harmless but is an orphan artifact. Left untouched
   because it is a Phase 9 migration and the instructions prohibit modifying
   Phase 1–9 files unless explicitly required.

4. **Git commit count:** The repository currently has one commit. The final
   patent brief records that actual count as invention activity evidence.

---

### Final Build Status

**Production build status:** COMPLETE

**All 10 patent claims implemented:** YES

**Final system test result:** 340 passed, zero failures

**BUILD COMPLETE: YES**
