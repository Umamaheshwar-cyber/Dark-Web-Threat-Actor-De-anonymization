# SHADOWTRACE

**Threat Actor Intelligence & Identity Correlation Platform**  
*Defensive cybersecurity research prototype using synthetic intelligence artifacts and authorized threat feeds.*

---

## 1. Quick Start (Windows)

```powershell
# Navigate to the project directory
cd C:\Users\Abilash\Downloads\SHADOWTRACE_full_project\SHADOWTRACE

# Activate existing virtual environment (or create with: python -m venv .venv)
.venv\Scripts\Activate.ps1

# Install requirements (if not already installed)
pip install -r requirements.txt

# Start the FastAPI ASGI server
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open the dashboard in your browser:  
`http://127.0.0.1:8000`

---

## 2. Project Structure

```
SHADOWTRACE/
├── backend/
│   ├── main.py                 # FastAPI application shell & router mounting
│   ├── models.py               # Pydantic schemas (Cases, Actors, STIX, Feeds)
│   ├── data_store.py           # Multi-case registry & isolated storage layer
│   ├── correlation_engine.py   # Multi-signal ensemble correlation & OPSEC engine
│   ├── provenance.py           # SHA-256 canonical hashing & Admiralty metadata
│   ├── audit.py                # Append-only audit logger (data/audit_log.jsonl)
│   ├── stix_export.py          # Standard-compliant STIX 2.1 JSON bundle builder
│   ├── reporting.py            # Structured 9-section JSON & Markdown briefings
│   ├── authorized_adapter.py   # Read-only, SSL-verified MISP REST adapter
│   └── routers/
│       ├── cases.py            # Case catalog & metadata routes
│       ├── actors.py           # Actor profiles & comprehensive drill-down dossiers
│       ├── evidence.py         # Evidence catalog queries
│       ├── analytics.py        # Correlation, OPSEC evaluation & alias breakdown
│       ├── search.py           # Multi-entity synthetic artifact search
│       ├── reports.py          # STIX export, JSON/MD reports, provenance & audit
│       └── feeds.py            # MISP status, connection probe, preview & import
├── data/
│   ├── case.json               # Default primary case dataset
│   ├── audit_log.jsonl         # Append-only sanitized investigation audit events
│   └── cases/
│       ├── case_2026_09x.json  # Synthetic Case 1 (Candidate: ShadowX)
│       ├── case_2026_02b.json  # Synthetic Case 2 (Candidate: CipherPhantom)
│       ├── case_2026_03c.json  # Synthetic Case 3 (Candidate: GhostWeaver)
│       └── case_authorized_misp.json # Isolated Authorized MISP Feed Container
├── frontend/
│   ├── index.html              # Single-page command-center dashboard shell
│   ├── style.css               # Dark cyber-ops theme styling
│   └── app.js                  # Frontend controllers, graph rendering & export flows
└── tests/                      # 14 test suites covering Phases 1–6.4 (672 tests)
```

---

## 3. Major API Groups (Phases 1–6.4)

### Core Investigation & Multi-Case
* `GET /api/cases` — Catalog of all registered synthetic cases
* `GET /api/cases/{case_id}` — Metadata for a specific case
* `GET /api/case` — Active case overview (defaults to primary)
* `GET /api/actors` — Tracked actor clusters for a case
* `GET /api/actors/{actor_id}/drilldown` — Comprehensive investigation dossier (OPSEC, correlation, evidence, graph)
* `GET /api/evidence` — Cataloged evidence records for a case
* `GET /api/graph` — Interactive relationship graph nodes and edges
* `GET /api/timeline` — Chronological investigation milestone events
* `GET /api/metrics` — Case-level investigation summary metrics
* `GET /api/search?q={query}` — Unified artifact and candidate search
* `GET /api/health` — Platform status and defensive safety probe

### Correlation Engine & OPSEC Analytics
* `GET /api/analytics/alias-similarity?s1={a}&s2={b}` — Multi-algorithm similarity score (Levenshtein, Jaro-Winkler, 2-gram)
* `GET /api/analytics/correlation/{actor_id}` — 5-dimension ensemble correlation assessment
* `GET /api/analytics/opsec-evaluation/{actor_id}` — Itemized OPSEC hygiene exposure triggers and scores

### Reporting, Provenance & STIX 2.1 Intelligence Export
* `GET /api/cases/{case_id}/report` — Comprehensive 9-section structured JSON investigation report
* `GET /api/cases/{case_id}/report/markdown` — Intelligence-grade executive briefing formatted in Markdown
* `GET /api/cases/{case_id}/stix` — STIX 2.1 compliant JSON bundle (threat-actor, observed-data, indicator, report)
* `GET /api/evidence/{evidence_id}/provenance` — Canonical SHA-256 integrity digest and Admiralty B-2 provenance
* `GET /api/audit` — Append-only audit trail query endpoint with credential sanitization

### Authorized MISP Threat Feeds (Phase 6)
* `GET /api/feeds/misp/status` — Operational status and mode check (zero secret leakage)
* `POST /api/feeds/misp/test-connection` — Lightweight connectivity probe to authorized MISP instance
* `POST /api/feeds/misp/preview` — Read-only indicator search and normalization preview
* `POST /api/feeds/misp/import` — Controlled ingestion of authorized indicators into `CASE-AUTH-MISP`
* `GET /api/feeds/misp/evidence` — List authorized feed indicators currently persisted

---

## 4. Configuration & Environment Variables

When integrating with an authorized enterprise MISP instance, configure the following environment variables:

| Variable | Default | Description |
|---|---|---|
| `MISP_URL` | *None* | Base URL of the authorized MISP instance (e.g. `https://misp.your-org.internal`) |
| `MISP_API_KEY` | *None* | Automation Auth Key generated from your authorized MISP profile |
| `MISP_VERIFY_SSL` | `true` | Enforces strict TLS certificate validation. Set to `false` only for internal private CAs |
| `MISP_TIMEOUT` | `15` | Read-only REST request timeout in seconds |

> **Secret Protection**: `MISP_API_KEY` is strictly protected. It is never exposed in API responses, logs, frontend state, or exception messages.

---

## 5. Operating Modes: Offline Demo vs. Authorized Feed

* **Offline Demo Mode (Default)**:  
  Active whenever `MISP_URL` or `MISP_API_KEY` are not set. The platform runs completely offline using controlled synthetic test fixtures. All core functionality, exports, analytics, and reports are fully functional without external network access.
* **Authorized MISP Mode**:  
  Activated when valid MISP environment variables are provided. Enables read-only queries against an authorized MISP instance. Ingested indicators are stored strictly in the dedicated, isolated `CASE-AUTH-MISP` container.

> **Read-Only / Pull-Only Notice**: The MISP integration is strictly read-only and pull-only. It has no capabilities or endpoints to create, modify, or publish indicators back to external systems.
>
> **Live Server Status**: The platform has been validated using controlled mock threat data in an isolated offline sandbox. No live external MISP server is currently connected.

---

## 6. Verification & Test Suite

The platform includes 14 automated test suites covering all phases:

```powershell
# Run the complete test suite
.venv\Scripts\python.exe tests/test_analytics.py
.venv\Scripts\python.exe tests/test_phase3.py
.venv\Scripts\python.exe tests/test_phase4_step1.py
.venv\Scripts\python.exe tests/test_phase4_step2.py
.venv\Scripts\python.exe tests/test_phase4_step3.py
.venv\Scripts\python.exe tests/test_phase4_step4.py
.venv\Scripts\python.exe tests/test_phase4_step5_integration.py
.venv\Scripts\python.exe tests/test_phase5_integration.py
.venv\Scripts\python.exe tests/test_opsec_isolation.py
.venv\Scripts\python.exe tests/test_opsec_api_runtime.py
.venv\Scripts\python.exe tests/test_misp_adapter.py
.venv\Scripts\python.exe tests/test_phase6_2_integration.py
.venv\Scripts\python.exe tests/test_phase6_3_authorized.py
.venv\Scripts\python.exe tests/test_phase6_4_e2e_feed.py
```

**Validation Status**: **672 tests passed, 0 failed (100% passing)**.

---

## 7. Defensive Research & Safety Notice

* **Synthetic Data Only**: All baseline threat actors (`ShadowX`, `CipherPhantom`, `GhostWeaver`) and evidence items are synthetic demo artifacts.
* **Non-Attributive**: Correlation scores, stylometry analysis, and OPSEC hygiene signals represent analytical indicators for defensive training and research. They do **not** constitute definitive legal identity attribution or real-world individual tracking.
* **No Illicit Connections**: Zero Tor, dark-web, illicit forum/marketplace, or unauthorized private network access is implemented.
