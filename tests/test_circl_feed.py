"""
SHADOWTRACE Automated Test Suite — Public CIRCL MISP OSINT Feed Integration
Tests the public CIRCL OSINT feed adapter and API endpoints:
- Unit tests: CIRCLFeedAdapter, UUID validation, manifest parsing, transformation, bounded attributes, provenance.
- API endpoints:
  - GET /api/feeds/circl/status (reachability, manifest summary, zero-secret leak)
  - POST /api/feeds/circl/preview (read-only, non-persistent, bounded attributes, UUID validation)
  - POST /api/feeds/circl/import (isolated to CASE-AUTH-MISP, synthetic case immutability, provenance)
- Provenance and SHA-256 integrity verification.
- Audit trail verification (CIRCL_FEED_QUERY, CIRCL_FEED_IMPORT).
- Strict case isolation: synthetic cases (CASE-2026-09X, 02B, 03C) are immutable and reject external imports.
- Live public HTTPS CIRCL OSINT feed connectivity probe.
"""

import sys
import os
import json
import hashlib
import urllib.request
import urllib.error
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.authorized_adapter import (
    CIRCLFeedAdapter,
    CIRCLFeedError,
    CIRCLInvalidUUIDError,
    CIRCLConnectionError,
    DEFAULT_CIRCL_FEED_URL,
    map_misp_type_to_shadowtrace,
    map_misp_confidence
)
from backend.provenance import verify_evidence_integrity, generate_evidence_hash
from backend.data_store import load_raw_data, get_evidence_data, CASE_FILES

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

def http_req(path: str, method: str = "GET", payload: dict = None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
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
        return 0, str(e)


# Synthetic mock event conforming strictly to MISP JSON format for adapter testing
MOCK_CIRCL_EVENT = {
    "Event": {
        "id": "99999",
        "uuid": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
        "info": "CIRCL OSINT Test Advisory: Advanced Threat Group Activity",
        "date": "2026-10-03",
        "threat_level_id": 2,
        "Orgc": {
            "name": "CIRCL Computer Incident Response Center Luxembourg"
        },
        "Attribute": [
            {
                "id": "1001",
                "type": "ip-src",
                "value": "198.51.100.42",
                "comment": "Command and control node",
                "toids": True
            },
            {
                "id": "1002",
                "type": "domain",
                "value": "threat-indicator-sample.net",
                "comment": "Exfiltration staging domain",
                "toids": True
            },
            {
                "id": "1003",
                "type": "sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "comment": "Stager payload SHA-256",
                "toids": False
            },
            {
                "id": "1004",
                "type": "btc",
                "value": "bc1q-circl-test-wallet-9900",
                "comment": "Ransomware recipient address",
                "toids": False
            },
            {
                "id": "1005",
                "type": "github-username",
                "value": "CIRCL_ThreatActor_Dev",
                "comment": "Associated developer handle",
                "toids": True
            }
        ]
    }
}


def test_circl_adapter_unit():
    print("\n--- [GROUP 1] CIRCLFeedAdapter Unit Tests ---")
    adapter = CIRCLFeedAdapter()

    # 1. UUID Validation
    valid_uuid = "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
    check("validate_uuid accepts valid lowercase RFC 4122 UUID", adapter.validate_uuid(valid_uuid) == valid_uuid)
    check("validate_uuid accepts valid uppercase UUID", adapter.validate_uuid(valid_uuid.upper()) == valid_uuid.upper())
    
    invalid_uuids = [
        "not-a-uuid",
        "12345",
        "../traversal/path",
        "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d; rm -rf",
        "",
        None,
        12345
    ]
    for bad_u in invalid_uuids:
        try:
            adapter.validate_uuid(bad_u)
            check(f"validate_uuid rejects invalid '{bad_u}'", False, "Should have raised CIRCLInvalidUUIDError")
        except CIRCLInvalidUUIDError:
            check(f"validate_uuid rejects invalid '{bad_u}'", True)

    # 2. Transformation of Event to Evidence
    evidence_items = adapter.transform_circl_event_to_evidence(MOCK_CIRCL_EVENT, max_attributes=10)
    check("transform returns list of evidence records", len(evidence_items) == 5)
    
    first = evidence_items[0]
    check("Evidence ID prefix is CIRCL-EV-{uuid[:8]}-id", first["id"] == "CIRCL-EV-a1b2c3d4-1001")
    check("Type ip-src maps to INDICATOR", first["type"] == "INDICATOR")
    check("Identifier matches attribute value", first["identifier"] == "198.51.100.42")
    check("Confidence mapped correctly (threat_level_id 2 -> Medium)", first["confidence"] == "Medium")
    check("Status is Correlated when toids=True", first["status"] == "Correlated")
    check("Relationship contains event info and comment", "Command and control node" in first["relationship"])

    # 3. Type mappings for remaining attributes
    type_map = {e["identifier"]: e["type"] for e in evidence_items}
    check("domain maps to INDICATOR", type_map.get("threat-indicator-sample.net") == "INDICATOR")
    check("sha256 maps to INDICATOR", type_map.get("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "INDICATOR")
    check("btc maps to WALLET", type_map.get("bc1q-circl-test-wallet-9900") == "WALLET")
    check("github-username maps to ALIAS", type_map.get("CIRCL_ThreatActor_Dev") == "ALIAS")

    # 4. Attribute limit enforcement
    limited_items = adapter.transform_circl_event_to_evidence(MOCK_CIRCL_EVENT, max_attributes=2)
    check("transform strictly enforces max_attributes bound", len(limited_items) == 2)

    # 5. Provenance Generation and Integrity
    prov_record = adapter.build_provenance_for_evidence(first, MOCK_CIRCL_EVENT)
    check("build_provenance returns evidence_id", prov_record.get("evidence_id") == first["id"])
    
    prov = prov_record.get("provenance", {})
    admiralty = prov.get("admiralty_system", {})
    check("Admiralty reliability is B - Usually Reliable", admiralty.get("source_reliability") == "B - Usually Reliable")
    check("Admiralty credibility is 2 - Probably True", admiralty.get("information_credibility") == "2 - Probably True")
    check("Collection mode is PUBLIC_CIRCL_MISP_OSINT_FEED", prov.get("collection_metadata", {}).get("collection_mode") == "PUBLIC_CIRCL_MISP_OSINT_FEED")
    check("Target case is CASE-AUTH-MISP", prov.get("collection_metadata", {}).get("target_case_id") == "CASE-AUTH-MISP")
    
    # 6. Cryptographic SHA-256 verification
    calc_hash = generate_evidence_hash(first)
    check("Calculated SHA-256 hash matches record hash", prov_record.get("sha256_hash") == calc_hash)
    valid, _, _ = verify_evidence_integrity(first, prov_record.get("sha256_hash"))
    check("verify_evidence_integrity validates payload hash", valid)


def test_circl_api_endpoints():
    print("\n--- [GROUP 2] CIRCL Feed API Endpoints ---")

    # 1. GET /api/feeds/circl/status
    status_code, status_data = http_req("/api/feeds/circl/status?limit=3")
    check("GET /api/feeds/circl/status returns 200", status_code == 200)
    check("Response indicates available=True", status_data.get("available") is True)
    check("Mode is PUBLIC_CIRCL_OSINT_FEED", status_data.get("mode") == "PUBLIC_CIRCL_OSINT_FEED")
    check("Feed URL matches DEFAULT_CIRCL_FEED_URL", status_data.get("feed_url") == DEFAULT_CIRCL_FEED_URL)
    manifest = status_data.get("sample_manifest", [])
    check("Manifest sample contains requested limit items", len(manifest) <= 3 and len(manifest) > 0)
    if manifest:
        first_item = manifest[0]
        check("Manifest item has valid UUID", CIRCLFeedAdapter().validate_uuid(first_item.get("uuid")) == first_item.get("uuid"))
        check("Manifest item has info title", len(first_item.get("info", "")) > 0)
        check("Manifest item has threat_level", first_item.get("threat_level") in ["High", "Medium", "Low"])

    # 2. POST /api/feeds/circl/preview (Invalid UUID)
    bad_preview_code, bad_preview_err = http_req("/api/feeds/circl/preview", method="POST", payload={"event_uuid": "not-a-valid-uuid"})
    check("POST /api/feeds/circl/preview with bad UUID returns 400", bad_preview_code == 400)
    check("400 response contains UUID format error detail", "Invalid MISP event UUID" in str(bad_preview_err))

    # 3. POST /api/feeds/circl/preview (Valid preview)
    selected_uuid = manifest[0]["uuid"] if manifest else "55b7c901-614c-44d1-a638-440e950d210b"
    prev_code, prev_data = http_req("/api/feeds/circl/preview", method="POST", payload={"event_uuid": selected_uuid, "max_attributes": 3})
    check("POST /api/feeds/circl/preview with valid UUID returns 200", prev_code == 200)
    check("Preview returns requested event UUID", prev_data.get("event_uuid") == selected_uuid)
    check("Preview respects max_attributes limit", prev_data.get("attributes_count") <= 3)
    ev_items = prev_data.get("evidence_items", [])
    check("Preview returns normalized evidence records", len(ev_items) > 0)
    if ev_items:
        check("Preview evidence ID prefix is CIRCL-EV-", ev_items[0].get("id", "").startswith("CIRCL-EV-"))

    # Verify Preview has ZERO persistence
    auth_case_before = load_raw_data("CASE-AUTH-MISP")
    preview_ids = {e["id"] for e in ev_items}
    existing_ids = {e["id"] for e in auth_case_before.get("evidence", [])}
    check("Preview does NOT persist evidence into CASE-AUTH-MISP", preview_ids.isdisjoint(existing_ids))


def test_circl_import_and_isolation():
    print("\n--- [GROUP 3] CIRCL Import, Isolation & Immutability ---")

    # Record hashes of synthetic case files before any operation
    synthetic_files = {
        "CASE-2026-09X": CASE_FILES["CASE-2026-09X"],
        "CASE-2026-02B": CASE_FILES["CASE-2026-02B"],
        "CASE-2026-03C": CASE_FILES["CASE-2026-03C"]
    }
    hashes_before = {}
    for cid, path in synthetic_files.items():
        with open(path, "rb") as f:
            hashes_before[cid] = hashlib.sha256(f.read()).hexdigest()

    # Backup CASE-AUTH-MISP before import
    auth_case_path = CASE_FILES["CASE-AUTH-MISP"]
    with open(auth_case_path, "r", encoding="utf-8") as f:
        auth_case_original_content = f.read()

    try:
        # 1. Reject import into immutable synthetic cases
        for syn_cid in ["CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C"]:
            code, err = http_req("/api/feeds/circl/import", method="POST", payload={"case_id": syn_cid, "event_uuid": "55b7c901-614c-44d1-a638-440e950d210b"})
            check(f"POST /api/feeds/circl/import into {syn_cid} rejected with 400", code == 400)
            check(f"Rejection explicitly mentions restriction to CASE-AUTH-MISP", "strictly isolated to 'CASE-AUTH-MISP'" in str(err))

        # 2. Reject import into nonexistent case
        code, err = http_req("/api/feeds/circl/import", method="POST", payload={"case_id": "NON-EXISTENT-CASE"})
        check("POST /api/feeds/circl/import into non-existent case rejected with 400", code == 400)

        # 3. Successful import into dedicated CASE-AUTH-MISP container
        test_uuid = "55b7c901-614c-44d1-a638-440e950d210b"
        imp_code, imp_data = http_req(
            "/api/feeds/circl/import",
            method="POST",
            payload={"case_id": "CASE-AUTH-MISP", "event_uuid": test_uuid, "max_attributes": 2}
        )
        check("POST /api/feeds/circl/import into CASE-AUTH-MISP returns 200", imp_code == 200)
        check("Import response mode is PUBLIC_CIRCL_OSINT_FEED", imp_data.get("mode") == "PUBLIC_CIRCL_OSINT_FEED")
        check("Imported count is <= 2", imp_data.get("imported_count") <= 2 and imp_data.get("imported_count") > 0)
        check("Import response includes evidence records", len(imp_data.get("evidence_records", [])) > 0)
        check("Import response includes provenance records", len(imp_data.get("provenance_records", [])) > 0)

        # 4. Verify persisted records in CASE-AUTH-MISP
        auth_case_after = load_raw_data("CASE-AUTH-MISP")
        after_ids = [e["id"] for e in auth_case_after.get("evidence", [])]
        first_imp_id = imp_data.get("evidence_records", [])[0]["id"]
        check("Imported CIRCL evidence record exists in CASE-AUTH-MISP", first_imp_id in after_ids)

        # 5. Verify provenance report endpoint returns CIRCL provenance
        prov_code, prov_res = http_req(f"/api/evidence/{first_imp_id}/provenance?case_id=CASE-AUTH-MISP")
        check("GET /api/evidence/{id}/provenance returns 200", prov_code == 200)
        check("Provenance source_origin is PUBLIC_CIRCL_MISP_OSINT_FEED", prov_res.get("provenance", {}).get("source_origin") == "PUBLIC_CIRCL_MISP_OSINT_FEED")
        check("Provenance collection_mode is PUBLIC_CIRCL_MISP_OSINT_FEED", prov_res.get("provenance", {}).get("collection_metadata", {}).get("collection_mode") == "PUBLIC_CIRCL_MISP_OSINT_FEED")

        # 6. Verify synthetic baseline cases were NOT touched (strict hash comparison)
        for cid, path in synthetic_files.items():
            with open(path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            check(f"Baseline synthetic case {cid} is 100% byte-for-byte immutable", current_hash == hashes_before[cid])

    finally:
        # Restore CASE-AUTH-MISP to clean baseline state
        with open(auth_case_path, "w", encoding="utf-8") as f:
            f.write(auth_case_original_content)
        print("   -> Teardown: CASE-AUTH-MISP restored to baseline.")


def test_audit_logging_and_zero_credentials():
    print("\n--- [GROUP 4] Audit Logging & Zero-Secret Verification ---")
    audit_file = PROJECT_ROOT / "data" / "audit_log.jsonl"
    check("audit_log.jsonl exists", audit_file.exists())

    circl_query_events = []
    circl_import_events = []
    with open(audit_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            action = entry.get("action")
            if action == "CIRCL_FEED_QUERY":
                circl_query_events.append(entry)
            elif action == "CIRCL_FEED_IMPORT":
                circl_import_events.append(entry)

    check("CIRCL_FEED_QUERY audit events recorded", len(circl_query_events) > 0)
    check("CIRCL_FEED_IMPORT audit events recorded", len(circl_import_events) > 0)
    
    if circl_import_events:
        last_imp = circl_import_events[-1]
        check("Last CIRCL_FEED_IMPORT event status is SUCCESS", last_imp.get("status") == "SUCCESS")
        check("Last CIRCL_FEED_IMPORT case_id is CASE-AUTH-MISP", last_imp.get("case_id") == "CASE-AUTH-MISP")

    # Verify zero secrets/credentials in entire audit log
    with open(audit_file, "r", encoding="utf-8") as f:
        log_content = f.read()
    check("Audit log contains no 'api_key' secrets", '"api_key"' not in log_content)
    check("Audit log contains no 'password' secrets", '"password"' not in log_content)
    check("Audit log contains no 'token' secrets", '"token"' not in log_content)


def test_live_circl_https_connectivity():
    print("\n--- [GROUP 5] Live Public CIRCL OSINT Feed Connectivity Probe ---")
    url = f"{DEFAULT_CIRCL_FEED_URL}/manifest.json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SHADOWTRACE-OSINT-Probe/1.0", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            check("Direct HTTPS connection to circl.lu returns 200", resp.status == 200)
            data = json.loads(resp.read().decode("utf-8"))
            check("CIRCL manifest is a JSON object with events", isinstance(data, dict) and len(data) > 0)
            print(f"   -> Successfully probed public CIRCL feed ({len(data)} total OSINT events in manifest).")
    except Exception as e:
        check(f"Direct HTTPS connection to circl.lu", False, str(e))


def run_all():
    print("=" * 70)
    print("SHADOWTRACE — PUBLIC CIRCL MISP OSINT FEED VALIDATION SUITE")
    print("=" * 70)

    test_circl_adapter_unit()
    test_circl_api_endpoints()
    test_circl_import_and_isolation()
    test_audit_logging_and_zero_credentials()
    test_live_circl_https_connectivity()

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"CIRCL FEED VALIDATION RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL CIRCL OSINT FEED TESTS PASSED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    run_all()
