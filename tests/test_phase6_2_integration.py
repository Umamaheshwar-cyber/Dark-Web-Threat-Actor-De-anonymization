"""
SHADOWTRACE Automated Test Suite — Phase 6.2 MISP Integration & Feeds API
Tests the authorized MISP threat intelligence feed endpoints:
- GET /api/feeds/misp/status (Unconfigured & Configured modes, zero-secret leak)
- POST /api/feeds/misp/preview (Offline demo, mock payload preview, limit filter)
- POST /api/feeds/misp/import (Case-scoped import, provenance generation, 404 handling)
- Audit logging verification (FEED_QUERY, FEED_IMPORT)
- Case isolation and baseline data immutability verification.

All tests run locally; no live external network connections or real-person data.
"""

import sys
import os
import json
import urllib.request
import urllib.error
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.provenance import verify_evidence_integrity
from backend.data_store import load_raw_data

BASE_URL = "http://127.0.0.1:8000"

PASS = 0
FAIL = 0

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
# TEST GROUP 1: MISP Feed Status Endpoint & Zero Secret Leak
# ---------------------------------------------------------------------------

def test_misp_status_endpoint():
    print("\n--- [TEST GROUP 1] MISP Feed Status & Zero Secret Leak ---")

    # 1. Unconfigured mode (default)
    status_code, data = http_req("/api/feeds/misp/status")
    check("GET /api/feeds/misp/status returns 200", status_code == 200)
    check("Unconfigured mode reports configured == False", data.get("configured") is False)
    check("Unconfigured mode reports mode == OFFLINE_DEMO_MODE", data.get("mode") == "OFFLINE_DEMO_MODE")
    check("Unconfigured mode reports base_url is None", data.get("base_url") is None)
    check("Status message informs user of safe offline demo mode", "offline demo mode" in data.get("message", "").lower())

    # 2. Secret leak check: verify API key field never exists in status response
    check("Status response has no 'api_key' field", "api_key" not in data)
    check("Status response has no 'token' field", "token" not in data)

# ---------------------------------------------------------------------------
# TEST GROUP 2: MISP Preview Endpoint (Offline Demo & Mock Payload)
# ---------------------------------------------------------------------------

def test_misp_preview_endpoint():
    print("\n--- [TEST GROUP 2] MISP Preview Endpoint ---")

    # 1. Default offline preview
    status_code, data = http_req("/api/feeds/misp/preview", method="POST", payload={})
    check("POST /api/feeds/misp/preview returns 200", status_code == 200)
    check("Preview mode is OFFLINE_DEMO_MODE", data.get("mode") == "OFFLINE_DEMO_MODE")
    check("Preview events_count > 0", data.get("events_count", 0) > 0)
    check("Preview attributes_count == 3", data.get("attributes_count") == 3)
    
    items = data.get("evidence_items", [])
    check("Evidence items count matches attributes_count", len(items) == 3)
    
    types = {i["type"] for i in items}
    check("Evidence items include ALIAS, PGP, and WALLET types", {"ALIAS", "PGP", "WALLET"}.issubset(types))

    # 2. Preview with limit
    status_code, data_limited = http_req("/api/feeds/misp/preview", method="POST", payload={"limit": 2})
    check("Preview respects limit=2", len(data_limited.get("evidence_items", [])) == 2)

    # 3. Preview with custom mock payload
    mock_payload = {
        "mock_event": {
            "Event": {
                "id": "77110",
                "info": "Custom Security Research Event",
                "date": "2026-10-03",
                "threat_level_id": 1,
                "Attribute": [
                    {
                        "id": "901",
                        "type": "btc",
                        "value": "bc1q-custom-research-wallet-111",
                        "comment": "Observed wallet",
                        "toids": True
                    }
                ]
            }
        }
    }
    status_code, data_mock = http_req("/api/feeds/misp/preview", method="POST", payload=mock_payload)
    check("Preview with custom mock returns 200", status_code == 200)
    check("Preview mode indicates MOCK_PAYLOAD_PREVIEW", data_mock.get("mode") == "MOCK_PAYLOAD_PREVIEW")
    check("Mock preview converted single attribute", data_mock.get("attributes_count") == 1)
    
    mock_item = data_mock.get("evidence_items", [])[0]
    check("Mock item ID format", mock_item["id"] == "MISP-EV-77110-901")
    check("Mock item type WALLET", mock_item["type"] == "WALLET")
    check("Mock item confidence High (threat_level 1)", mock_item["confidence"] == "High")
    check("Mock item status Correlated (toids=True)", mock_item["status"] == "Correlated")

# ---------------------------------------------------------------------------
# TEST GROUP 3: MISP Case Import Endpoint & Phase 4 Provenance
# ---------------------------------------------------------------------------

def test_misp_import_endpoint():
    print("\n--- [TEST GROUP 3] MISP Case Import & Provenance ---")

    # 1. Error handling: Non-existent case -> 404
    status_code, err_data = http_req("/api/feeds/misp/import", method="POST", payload={"case_id": "CASE-NONEXISTENT"})
    check("Import into invalid case returns 404", status_code == 404)

    # 2. Valid import into primary case CASE-2026-09X
    import_payload = {"case_id": "CASE-2026-09X"}
    status_code, data = http_req("/api/feeds/misp/import", method="POST", payload=import_payload)
    check("Import into CASE-2026-09X returns 200", status_code == 200)
    check("Import response matches case_id", data.get("case_id") == "CASE-2026-09X")
    check("Import response imported_count == 3", data.get("imported_count") == 3)

    evidence_records = data.get("evidence_records", [])
    provenance_records = data.get("provenance_records", [])
    check("Evidence records count is 3", len(evidence_records) == 3)
    check("Provenance records count is 3", len(provenance_records) == 3)

    # Validate each provenance record
    all_hashes_valid = True
    for ev, prov in zip(evidence_records, provenance_records):
        check_id = prov.get("evidence_id") == ev.get("id")
        h = prov.get("sha256_hash", "")
        check_hash_len = len(h) == 64 and isinstance(h, str)
        check_raw = prov.get("observed_data", {}).get("is_raw_artifact") is True
        check_target_case = prov.get("provenance", {}).get("collection_metadata", {}).get("target_case_id") == "CASE-2026-09X"

        # Verify integrity with canonical recalculation
        is_valid, _, _ = verify_evidence_integrity(ev, h)
        if not (check_id and check_hash_len and check_raw and check_target_case and is_valid):
            all_hashes_valid = False

    check("All imported records have valid SHA-256 hashes and Phase 4 provenance", all_hashes_valid)

    # 3. Valid import into secondary case CASE-2026-02B (Case Scoping Check)
    import_payload_2 = {"case_id": "CASE-2026-02B"}
    status_code_2, data_2 = http_req("/api/feeds/misp/import", method="POST", payload=import_payload_2)
    check("Import into CASE-2026-02B returns 200", status_code_2 == 200)
    check("CASE-2026-02B import response matches case_id", data_2.get("case_id") == "CASE-2026-02B")
    
    prov_2 = data_2.get("provenance_records", [])[0]
    check("CASE-2026-02B provenance collection metadata scoped to CASE-2026-02B",
          prov_2.get("provenance", {}).get("collection_metadata", {}).get("target_case_id") == "CASE-2026-02B")

# ---------------------------------------------------------------------------
# TEST GROUP 4: Audit Logging for Feed Actions
# ---------------------------------------------------------------------------

def test_feed_audit_logging():
    print("\n--- [TEST GROUP 4] Feed Audit Logging ---")

    # 1. Check FEED_QUERY audit event
    status_code, query_events = http_req("/api/audit?action=FEED_QUERY&limit=5")
    check("Query audit events for FEED_QUERY returns 200", status_code == 200)
    check("At least one FEED_QUERY audit event recorded", len(query_events) > 0)
    if query_events:
        latest_q = query_events[0]
        check("FEED_QUERY operator is demo-analyst", latest_q.get("operator") == "demo-analyst")
        check("FEED_QUERY status is SUCCESS", latest_q.get("status") == "SUCCESS")
        check("FEED_QUERY details contain mode and attributes_count", "mode" in latest_q.get("details", {}))
        check("FEED_QUERY details contain no api_key", "api_key" not in latest_q.get("details", {}))

    # 2. Check FEED_IMPORT audit event
    status_code, import_events = http_req("/api/audit?action=FEED_IMPORT&limit=5")
    check("Query audit events for FEED_IMPORT returns 200", status_code == 200)
    check("At least one FEED_IMPORT audit event recorded", len(import_events) > 0)
    if import_events:
        latest_imp = import_events[0]
        check("FEED_IMPORT case_id is recorded", latest_imp.get("case_id") in ("CASE-2026-09X", "CASE-2026-02B"))
        check("FEED_IMPORT operator is demo-analyst", latest_imp.get("operator") == "demo-analyst")
        check("FEED_IMPORT status is SUCCESS", latest_imp.get("status") == "SUCCESS")
        check("FEED_IMPORT details contain imported_count", "imported_count" in latest_imp.get("details", {}))

# ---------------------------------------------------------------------------
# TEST GROUP 5: Baseline Case Immutability & Case Isolation
# ---------------------------------------------------------------------------

def test_case_immutability():
    print("\n--- [TEST GROUP 5] Case Immutability & Baseline Data Isolation ---")

    # Verify that existing case JSON files on disk were not overwritten or altered
    case1_data = load_raw_data("CASE-2026-09X")
    case2_data = load_raw_data("CASE-2026-02B")
    case3_data = load_raw_data("CASE-2026-03C")

    check("CASE-2026-09X baseline actor is ShadowX", case1_data["case"]["candidate"] == "ShadowX")
    check("CASE-2026-09X evidence count remains 5", len(case1_data["evidence"]) == 5)

    check("CASE-2026-02B baseline actor is CipherPhantom", case2_data["case"]["candidate"] == "CipherPhantom")
    check("CASE-2026-02B evidence count remains 5", len(case2_data["evidence"]) == 5)

    check("CASE-2026-03C baseline actor is GhostWeaver", case3_data["case"]["candidate"] == "GhostWeaver")
    check("CASE-2026-03C evidence count remains 5", len(case3_data["evidence"]) == 5)

# ---------------------------------------------------------------------------
# MAIN RUNNER
# ---------------------------------------------------------------------------

def run_all():
    print("=" * 70)
    print("SHADOWTRACE — PHASE 6.2 MISP INTEGRATION & FEEDS API TESTS")
    print("=" * 70)

    test_misp_status_endpoint()
    test_misp_preview_endpoint()
    test_misp_import_endpoint()
    test_feed_audit_logging()
    test_case_immutability()

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"PHASE 6.2 INTEGRATION RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL PHASE 6.2 INTEGRATION TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    run_all()
