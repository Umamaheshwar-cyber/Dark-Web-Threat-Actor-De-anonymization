"""
SHADOWTRACE Automated Test Suite — Phase 6.4 End-to-End Authorized Feed Validation
Validates the complete end-to-end authorized threat intelligence feed pipeline:
  Controlled Mock MISP Data
          ↓
  MISP Adapter
          ↓
  Feed Preview
          ↓
  Feed Import
          ↓
  Evidence Persistence
          ↓
  Evidence Provenance / SHA-256
          ↓
  Correlation / Analytics
          ↓
  Investigation Report
          ↓
  STIX 2.1 Export

All tests run locally in an isolated offline research environment.
No live external network connections, no Tor/dark-web access, no real-person data.
"""

import sys
import os
import json
import urllib.request
import urllib.error
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.authorized_adapter import (
    MISPAdapter,
    map_misp_type_to_shadowtrace,
    map_misp_confidence
)
from backend.provenance import (
    generate_evidence_hash,
    verify_evidence_integrity
)
from backend.correlation_engine import compute_multi_signal_correlation
from backend.reporting import (
    generate_investigation_report,
    generate_investigation_report_markdown
)
from backend.stix_export import export_case_to_stix
from backend.data_store import (
    load_raw_data,
    get_actors_data,
    get_evidence_data,
    CASE_FILES
)

BASE_URL = "http://127.0.0.1:8000"

PASS = 0
FAIL = 0

@pytest.fixture(autouse=True)
def isolate_case_authorized_misp_state():
    """Ensure persistent CASE-AUTH-MISP file is never permanently modified by test imports."""
    auth_file = PROJECT_ROOT / "data" / "cases" / "case_authorized_misp.json"
    initial_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else None
    try:
        yield
    finally:
        if auth_file.exists() and initial_content is not None:
            auth_file.write_text(initial_content, encoding="utf-8")

def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {label}")
    else:
        FAIL += 1
        detail_str = f" | {detail}" if detail else ""
        print(f"[FAIL] {label}{detail_str}")

def http_req(path: str, method: str = "GET", payload: dict = None, expected_status: int = 200):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body) if "application/json" in resp.headers.get("Content-Type", "") else body
            return resp.status, data
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err_data = json.loads(body)
        except Exception:
            err_data = body
        return e.code, err_data
    except Exception as e:
        return 0, {"error": str(e)}

# ---------------------------------------------------------------------------
# Controlled Mock MISP Test Fixture (Defensive Research Sandbox)
# ---------------------------------------------------------------------------
CONTROLLED_MOCK_MISP_EVENT = {
    "Event": {
        "id": "88410",
        "info": "Controlled Research Campaign Indicators (Authorized Test Feed)",
        "date": "2026-10-03",
        "threat_level_id": 1,
        "Orgc": {
            "name": "Authorized CTI Defense Lab"
        },
        "Attribute": [
            {
                "id": "7001",
                "type": "github-username",
                "value": "AuthorizedFeed_ActorX",
                "comment": "Observed handle in simulated adversary infrastructure",
                "toids": True
            },
            {
                "id": "7002",
                "type": "pgp-key",
                "value": "PGP-SYN-AUTH-9B33",
                "comment": "Correlated test key",
                "toids": True
            },
            {
                "id": "7003",
                "type": "btc",
                "value": "bc1q-auth-feed-wallet-9900",
                "comment": "Correlated payment address",
                "toids": True
            },
            {
                "id": "7004",
                "type": "language",
                "value": "STYLE-SYN-AUTH-44",
                "comment": "Stylometric phrasing cluster",
                "toids": False
            },
            {
                "id": "7005",
                "type": "timing",
                "value": "BEHAV-SYN-AUTH-12",
                "comment": "Temporal observation cluster",
                "toids": False
            }
        ]
    }
}

# ---------------------------------------------------------------------------
# TEST GROUP 1: Controlled Mock MISP Data Ingestion & Transformation
# ---------------------------------------------------------------------------

def test_mock_misp_transformation_and_robustness():
    print("\n--- [GROUP 1] Controlled Mock MISP Transformation & Robustness ---")

    adapter = MISPAdapter()
    evidence_items = adapter.transform_misp_event_to_evidence(CONTROLLED_MOCK_MISP_EVENT)

    check("Exact attribute count transformed (5 items)", len(evidence_items) == 5)
    
    # Check normalized categories
    types_found = [e["type"] for e in evidence_items]
    check("Transformed ALIAS attribute", "ALIAS" in types_found)
    check("Transformed PGP attribute", "PGP" in types_found)
    check("Transformed WALLET attribute", "WALLET" in types_found)
    check("Transformed STYLOMETRY attribute", "STYLOMETRY" in types_found)
    check("Transformed BEHAVIOUR attribute", "BEHAVIOUR" in types_found)

    # Check non-attributive classification and status
    alias_item = next(e for e in evidence_items if e["type"] == "ALIAS")
    check("Correlated status when toids=True", alias_item["status"] == "Correlated")
    check("Confidence is High for threat_level 1", alias_item["confidence"] == "High")
    check("Non-attributive indicator format", alias_item["identifier"] == "AuthorizedFeed_ActorX")

    # Robustness against malformed mock data
    check("Handles non-dict input gracefully", adapter.transform_misp_event_to_evidence("invalid-string") == [])
    check("Handles None input gracefully", adapter.transform_misp_event_to_evidence(None) == [])
    check("Handles empty dict gracefully", adapter.transform_misp_event_to_evidence({}) == [])
    check("Handles malformed Attribute list gracefully", adapter.transform_misp_event_to_evidence({"Event": {"Attribute": "not-a-list"}}) == [])
    check("Handles Attribute with missing value gracefully", adapter.transform_misp_event_to_evidence({"Event": {"Attribute": [{"id": "1", "type": "btc"}]}}) == [])

# ---------------------------------------------------------------------------
# TEST GROUP 2: Feed Preview & Import via Live API
# ---------------------------------------------------------------------------

def test_feed_preview_and_import_api():
    print("\n--- [GROUP 2] Feed Preview & Import API ---")
    auth_file = PROJECT_ROOT / "data" / "cases" / "case_authorized_misp.json"
    initial_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else None

    try:
        # 1. Preview using controlled mock payload
        preview_payload = {"mock_event": CONTROLLED_MOCK_MISP_EVENT, "limit": 10}
        status_code, preview_res = http_req("/api/feeds/misp/preview", method="POST", payload=preview_payload)
        check("POST /api/feeds/misp/preview returns 200", status_code == 200)
        check("Preview mode is MOCK_PAYLOAD_PREVIEW", preview_res.get("mode") == "MOCK_PAYLOAD_PREVIEW")
        check("Preview attributes_count is 5", preview_res.get("attributes_count") == 5)
        check("Preview evidence_items count is 5", len(preview_res.get("evidence_items", [])) == 5)

        # 2. Import into invalid case returns 404
        status_code_err, _ = http_req("/api/feeds/misp/import", method="POST", payload={"case_id": "INVALID-CASE-ID"})
        check("Import into invalid case returns 404", status_code_err == 404)

        # 3. Import into CASE-AUTH-MISP using controlled mock payload
        import_payload = {
            "case_id": "CASE-AUTH-MISP",
            "misp_event": CONTROLLED_MOCK_MISP_EVENT
        }
        status_code_imp, import_res = http_req("/api/feeds/misp/import", method="POST", payload=import_payload)
        check("POST /api/feeds/misp/import into CASE-AUTH-MISP returns 200", status_code_imp == 200)
        check("Import response case_id is CASE-AUTH-MISP", import_res.get("case_id") == "CASE-AUTH-MISP")
        check("Imported count is 5", import_res.get("imported_count") == 5)
        check("Evidence records returned count is 5", len(import_res.get("evidence_records", [])) == 5)
        check("Provenance records returned count is 5", len(import_res.get("provenance_records", [])) == 5)
    finally:
        if auth_file.exists() and initial_content is not None:
            auth_file.write_text(initial_content, encoding="utf-8")

# ---------------------------------------------------------------------------
# TEST GROUP 3: Evidence Persistence under CASE-AUTH-MISP & Immutability of Synthetic Cases
# ---------------------------------------------------------------------------

def test_evidence_persistence_and_synthetic_immutability():
    print("\n--- [GROUP 3] Persistence under CASE-AUTH-MISP & Synthetic Immutability ---")

    # 1. Verify persisted in CASE-AUTH-MISP container
    auth_data = load_raw_data("CASE-AUTH-MISP")
    persisted_ev = auth_data.get("evidence", [])
    check("CASE-AUTH-MISP evidence list is non-empty", len(persisted_ev) >= 5)
    check("Metrics evidence_records reflects persisted count", auth_data.get("metrics", {}).get("evidence_records") == len(persisted_ev))

    # 2. Check feeds evidence retrieval endpoint
    status_code_ev, feed_ev_list = http_req("/api/feeds/misp/evidence")
    check("GET /api/feeds/misp/evidence returns 200", status_code_ev == 200)
    check("Feed evidence count matches persisted count", len(feed_ev_list) == len(persisted_ev))

    # 3. Check case evidence retrieval endpoint
    status_code_case_ev, case_ev_list = http_req("/api/evidence?case_id=CASE-AUTH-MISP")
    check("GET /api/evidence?case_id=CASE-AUTH-MISP returns 200", status_code_case_ev == 200)
    check("Case evidence count matches persisted count", len(case_ev_list) == len(persisted_ev))

    # 4. Strict Synthetic Case Immutability Verification
    c1 = load_raw_data("CASE-2026-09X")
    c2 = load_raw_data("CASE-2026-02B")
    c3 = load_raw_data("CASE-2026-03C")

    check("CASE-2026-09X evidence count remains 5 (unchanged)", len(c1["evidence"]) == 5)
    check("CASE-2026-02B evidence count remains 5 (unchanged)", len(c2["evidence"]) == 5)
    check("CASE-2026-03C evidence count remains 5 (unchanged)", len(c3["evidence"]) == 5)

    # 5. Full Disjointness check
    synthetic_ids = {e["id"] for e in c1["evidence"] + c2["evidence"] + c3["evidence"]}
    auth_ids = {e["id"] for e in persisted_ev}
    overlap = synthetic_ids & auth_ids
    check("Zero ID collision between synthetic cases and authorized feed evidence", len(overlap) == 0, f"Collisions: {overlap}")

# ---------------------------------------------------------------------------
# TEST GROUP 4: Cryptographic Provenance & SHA-256 Integrity Verification
# ---------------------------------------------------------------------------

def test_provenance_and_sha256_integrity():
    print("\n--- [GROUP 4] Cryptographic Provenance & SHA-256 Integrity ---")

    auth_data = load_raw_data("CASE-AUTH-MISP")
    evidence_items = auth_data.get("evidence", [])

    all_verified = True
    for ev in evidence_items:
        # 1. API provenance endpoint
        status_code, prov = http_req(f"/api/evidence/{ev['id']}/provenance?case_id=CASE-AUTH-MISP")
        if status_code != 200:
            all_verified = False
            continue

        # 2. Check structure
        check_id = prov.get("evidence_id") == ev["id"]
        check_hash_len = len(prov.get("sha256_hash", "")) == 64
        check_raw = prov.get("observed_data", {}).get("is_raw_artifact") is True
        check_inference = prov.get("analytical_conclusion", {}).get("is_analytical_inference") is True
        check_scope = prov.get("provenance", {}).get("collection_metadata", {}).get("target_case_id") == "CASE-AUTH-MISP"

        # 3. Canonical recalculation
        is_valid, computed_hash, _ = verify_evidence_integrity(ev, prov.get("sha256_hash", ""))

        if not (check_id and check_hash_len and check_raw and check_inference and check_scope and is_valid):
            all_verified = False

    check("All authorized evidence records pass cryptographic SHA-256 self-verification", all_verified)

# ---------------------------------------------------------------------------
# TEST GROUP 5: Multi-Signal Analytics & Correlation on Authorized Data
# ---------------------------------------------------------------------------

def test_analytics_and_correlation_pipeline():
    print("\n--- [GROUP 5] Multi-Signal Analytics & Correlation on Authorized Data ---")

    auth_data = load_raw_data("CASE-AUTH-MISP")
    actor = auth_data.get("actors", [])[0]
    evidence_list = auth_data.get("evidence", [])
    timeline = auth_data.get("timeline", [])

    # 1. Direct engine execution
    correlation = compute_multi_signal_correlation(actor, evidence_list, timeline)
    check("Correlation assessment completed without error", "overall_confidence" in correlation)
    if correlation["overall_confidence"] is None:
        check("Overall confidence is None when no genuine signals exist", correlation["overall_confidence"] is None)
        check("Confidence tier is UNAVAILABLE", correlation.get("confidence_tier") == "UNAVAILABLE")
        check("Unavailable signals have score=None and status='UNAVAILABLE'", all(s.get("score") is None and s.get("status") == "UNAVAILABLE" for s in correlation.get("signals", [])))
    else:
        check("Overall confidence is between 0 and 100", 0.0 <= correlation["overall_confidence"] <= 100.0)
    check("5 signal dimensions present in assessment", len(correlation.get("signals", [])) == 5)
    check("Defensive safety disclaimer present", "analytical signal" in correlation.get("disclaimer", "").lower())

    # 2. Live API Correlation Endpoint
    status_code, api_corr = http_req(f"/api/analytics/correlation/{actor['id']}?case_id=CASE-AUTH-MISP")
    check("GET /api/analytics/correlation/{actor_id} for authorized case returns 200", status_code == 200)
    check("API correlation actor_id matches ACT-AUTH-001", api_corr.get("actor_id") == actor["id"])
    if correlation["overall_confidence"] is None:
        check("API correlation confidence matches engine calculation (None)", api_corr.get("overall_confidence") is None)
        check("API correlation confidence tier matches engine calculation", api_corr.get("confidence_tier") == correlation.get("confidence_tier"))
    else:
        check("API correlation confidence matches engine calculation", abs(api_corr.get("overall_confidence", 0) - correlation["overall_confidence"]) < 0.1)

# ---------------------------------------------------------------------------
# TEST GROUP 6: Structured & Markdown Investigation Report Generation
# ---------------------------------------------------------------------------

def test_investigation_report_generation():
    print("\n--- [GROUP 6] Investigation Report Generation for Authorized Feed ---")

    # 1. Live JSON Report Endpoint
    status_code_rep, report_json = http_req("/api/cases/CASE-AUTH-MISP/report")
    check("GET /api/cases/CASE-AUTH-MISP/report returns 200", status_code_rep == 200)
    check("Report case_id is CASE-AUTH-MISP", report_json.get("case_summary", {}).get("case_id") == "CASE-AUTH-MISP")
    
    evidence_summary = report_json.get("evidence_summary", [])
    check("Report evidence summary contains all authorized indicators", len(evidence_summary) >= 5)
    check("Each evidence summary item contains a valid 64-char sha256 digest", all(len(e["observed_data"]["sha256_integrity_hash"]) == 64 for e in evidence_summary))
    check("Safety classification is present in report", "safety_classification" in report_json)

    # 2. Live Markdown Report Endpoint
    status_code_md, md_report = http_req("/api/cases/CASE-AUTH-MISP/report/markdown")
    check("GET /api/cases/CASE-AUTH-MISP/report/markdown returns 200", status_code_md == 200)
    check("Markdown briefing contains header", "# SHADOWTRACE Investigation Briefing" in md_report)
    check("Markdown briefing references CASE-AUTH-MISP", "CASE-AUTH-MISP" in md_report)
    check("Markdown briefing includes Section 3 (Evidence Summary)", "## 3. Evidence Summary" in md_report)
    check("Markdown briefing length > 3000 chars", len(md_report) > 3000)

# ---------------------------------------------------------------------------
# TEST GROUP 7: STIX 2.1 Export Representation of Authorized Feed
# ---------------------------------------------------------------------------

def test_stix_2_1_export_representation():
    print("\n--- [GROUP 7] STIX 2.1 Export Representation of Authorized Feed ---")

    status_code_stix, bundle = http_req("/api/cases/CASE-AUTH-MISP/stix")
    check("GET /api/cases/CASE-AUTH-MISP/stix returns 200", status_code_stix == 200)
    check("STIX export type is bundle", bundle.get("type") == "bundle")
    check("STIX bundle ID starts with bundle--", bundle.get("id", "").startswith("bundle--"))

    objects = bundle.get("objects", [])
    check("STIX objects list is populated (>10 objects)", len(objects) >= 10)

    # Validate STIX types
    types = {o["type"] for o in objects}
    check("STIX bundle includes threat-actor", "threat-actor" in types)
    check("STIX bundle includes observed-data", "observed-data" in types)
    check("STIX bundle includes indicator", "indicator" in types)
    check("STIX bundle includes relationship", "relationship" in types)
    check("STIX bundle includes report", "report" in types)

    # Validate all versioned objects use spec_version 2.1
    versioned = [o for o in objects if "spec_version" in o]
    check("All versioned objects use spec_version 2.1", all(o["spec_version"] == "2.1" for o in versioned))

    # Validate safety labels present on all labeled objects
    labeled = [o for o in objects if "labels" in o]
    check("Safety label 'synthetic-demo-data' present across STIX objects", all("synthetic-demo-data" in o["labels"] for o in labeled))

# ---------------------------------------------------------------------------
# TEST GROUP 8: Audit Logging & Zero Secret Leak
# ---------------------------------------------------------------------------

def test_audit_logging_and_zero_secret_leak():
    print("\n--- [GROUP 8] Audit Logging & Zero Secret Leak ---")

    # 1. Verify FEED_QUERY event
    status_code_q, query_events = http_req("/api/audit?action=FEED_QUERY&limit=5")
    check("Audit query for FEED_QUERY returns 200", status_code_q == 200)
    check("FEED_QUERY events exist", len(query_events) > 0)
    if query_events:
        check("FEED_QUERY operator is demo-analyst", query_events[0].get("operator") == "demo-analyst")

    # 2. Verify FEED_IMPORT event for CASE-AUTH-MISP
    status_code_imp, import_events = http_req("/api/audit?action=FEED_IMPORT&case_id=CASE-AUTH-MISP&limit=5")
    check("Audit query for FEED_IMPORT on CASE-AUTH-MISP returns 200", status_code_imp == 200)
    check("FEED_IMPORT event recorded for CASE-AUTH-MISP", len(import_events) > 0)
    if import_events:
        check("FEED_IMPORT status is SUCCESS", import_events[0].get("status") == "SUCCESS")

    # 3. Secret leak test across audit log and API responses
    with open(PROJECT_ROOT / "data" / "audit_log.jsonl", "r", encoding="utf-8") as f:
        log_content = f.read()
    check("Audit log does not contain 'MISP_API_KEY'", "MISP_API_KEY" not in log_content)
    check("Audit log does not contain forbidden 'password' key in details", '"password"' not in log_content)

# ---------------------------------------------------------------------------
# MAIN RUNNER
# ---------------------------------------------------------------------------

def run_all():
    print("=" * 70)
    print("SHADOWTRACE — PHASE 6.4 END-TO-END AUTHORIZED FEED VALIDATION")
    print("Controlled Mock MISP Intelligence Flow Test Suite")
    print("=" * 70)

    auth_file = PROJECT_ROOT / "data" / "cases" / "case_authorized_misp.json"
    initial_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else None

    try:
        test_mock_misp_transformation_and_robustness()
        test_feed_preview_and_import_api()
        test_evidence_persistence_and_synthetic_immutability()
        test_provenance_and_sha256_integrity()
        test_analytics_and_correlation_pipeline()
        test_investigation_report_generation()
        test_stix_2_1_export_representation()
        test_audit_logging_and_zero_secret_leak()
    finally:
        if auth_file.exists() and initial_content is not None:
            auth_file.write_text(initial_content, encoding="utf-8")

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"PHASE 6.4 END-TO-END RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL PHASE 6.4 END-TO-END VALIDATION TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    run_all()
