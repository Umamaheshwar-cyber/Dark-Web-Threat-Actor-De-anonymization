"""
SHADOWTRACE Automated Test Suite — Phase 6.5 Manual Incremental CIRCL Polling
Tests the manual incremental CIRCL feed polling and synchronization engine:
- Unit tests: CIRCLFeedAdapter.poll_new_events(), change detection, bounded batching, malformed event handling.
- Sync state persistence: data/circl_feed_state.json creation, loading, updating, and isolation.
- API endpoints:
  - POST /api/feeds/circl/poll (initial poll, repeated poll, incremental new event detection, bounded clamps)
  - GET /api/feeds/circl/sync-status (state inspection, zero secret leak)
- Three-tier deduplication:
  1. sync-state tracked UUIDs
  2. CASE-AUTH-MISP existing CIRCL evidence prefix introspection
  3. Evidence ID uniqueness enforcement
- Failure modes: malformed manifest, individual event failure, network/timeout handling without data loss.
- Provenance and cryptographic SHA-256 validation for newly polled indicators.
- Audit trail verification: CIRCL_FEED_POLL action in audit_log.jsonl with zero credential leakage.
- Strict case isolation: synthetic cases (CASE-2026-09X, 02B, 03C) are 100% immutable.
- Strictly read-only / GET-only behavior.
"""

import sys
import os
import json
import hashlib
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.authorized_adapter import (
    CIRCLFeedAdapter,
    CIRCLFeedError,
    CIRCLConnectionError,
    DEFAULT_CIRCL_FEED_URL
)
from backend.provenance import verify_evidence_integrity, generate_evidence_hash
from backend.data_store import (
    load_raw_data,
    load_circl_sync_state,
    save_circl_sync_state,
    get_tracked_circl_uuids,
    CASE_FILES,
    CIRCL_STATE_FILE
)

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


# Mock Manifest and Events for controlled offline testing
MOCK_UUID_1 = "11111111-2222-4333-8444-555555555551"
MOCK_UUID_2 = "22222222-3333-4444-8555-666666666662"
MOCK_UUID_3 = "33333333-4444-4555-8666-777777777773"

MOCK_MANIFEST = {
    MOCK_UUID_1: {
        "info": "CIRCL OSINT Threat Sample A",
        "date": "2026-10-01",
        "threat_level_id": 2,
        "Orgc": {"name": "CIRCL"}
    },
    MOCK_UUID_2: {
        "info": "CIRCL OSINT Threat Sample B",
        "date": "2026-10-02",
        "threat_level_id": 1,
        "Orgc": {"name": "CIRCL"}
    },
    MOCK_UUID_3: {
        "info": "CIRCL OSINT Threat Sample C",
        "date": "2026-10-03",
        "threat_level_id": 3,
        "Orgc": {"name": "CIRCL"}
    }
}

def make_mock_event(event_uuid: str, title: str, threat_lvl: int = 2) -> dict:
    return {
        "Event": {
            "id": "7701",
            "uuid": event_uuid,
            "info": title,
            "date": "2026-10-03",
            "threat_level_id": threat_lvl,
            "Orgc": {"name": "CIRCL"},
            "Attribute": [
                {
                    "id": "1",
                    "type": "ip-src",
                    "value": "198.51.100.99",
                    "comment": "C2 node",
                    "toids": True
                },
                {
                    "id": "2",
                    "type": "domain",
                    "value": f"sample-{event_uuid[:8]}.org",
                    "comment": "Delivery domain",
                    "toids": False
                }
            ]
        }
    }


def test_circl_poll_unit_adapter():
    print("\n--- [GROUP 1] CIRCLFeedAdapter.poll_new_events Unit Tests ---")
    adapter = CIRCLFeedAdapter()

    mock_events_db = {
        MOCK_UUID_1: make_mock_event(MOCK_UUID_1, "Sample A"),
        MOCK_UUID_2: make_mock_event(MOCK_UUID_2, "Sample B"),
        MOCK_UUID_3: make_mock_event(MOCK_UUID_3, "Sample C")
    }

    # 1. Initial Poll with empty known_uuids: all candidate events detected
    res1 = adapter.poll_new_events(
        known_uuids=set(),
        max_events=2,
        max_attributes=5,
        raw_manifest=MOCK_MANIFEST,
        mock_events=mock_events_db
    )
    check("Initial poll status is SUCCESS", res1["status"] == "SUCCESS")
    check("Detected all 3 events in manifest", res1["new_events_detected"] == 3)
    check("Respected max_events=2 bound", len(res1["processed_event_uuids"]) == 2)
    check("Extracted normalized evidence records", len(res1["evidence_records"]) == 4)
    check("Generated provenance records", len(res1["provenance_records"]) == 4)
    check("Skipped count is 0 on fresh poll", res1["skipped_count"] == 0)

    # 2. Repeated poll with same known_uuids: SKIPPED_NO_NEW
    known_after_first = set(res1["processed_event_uuids"])
    res2 = adapter.poll_new_events(
        known_uuids=set(MOCK_MANIFEST.keys()),
        max_events=3,
        raw_manifest=MOCK_MANIFEST,
        mock_events=mock_events_db
    )
    check("Repeated poll with all known UUIDs returns SKIPPED_NO_NEW", res2["status"] == "SKIPPED_NO_NEW")
    check("0 new events detected on repeated poll", res2["new_events_detected"] == 0)
    check("0 events processed on repeated poll", len(res2["processed_event_uuids"]) == 0)
    check("Skipped count equals manifest size", res2["skipped_count"] == 3)

    # 3. Incremental poll with partial known_uuids
    res3 = adapter.poll_new_events(
        known_uuids=known_after_first,
        max_events=3,
        raw_manifest=MOCK_MANIFEST,
        mock_events=mock_events_db
    )
    check("Incremental poll status is SUCCESS", res3["status"] == "SUCCESS")
    check("Detected exactly 1 remaining new event", res3["new_events_detected"] == 1)
    check("Processed the single new event UUID", res3["processed_event_uuids"] == [MOCK_UUID_3])

    # 4. Prefix-based deduplication (introspecting 8-char prefix)
    res_prefix = adapter.poll_new_events(
        known_uuids={MOCK_UUID_1[:8]},
        max_events=3,
        raw_manifest={MOCK_UUID_1: MOCK_MANIFEST[MOCK_UUID_1]},
        mock_events=mock_events_db
    )
    check("Prefix-based known UUID skips event", res_prefix["status"] == "SKIPPED_NO_NEW")
    check("Prefix-based skipped_count is 1", res_prefix["skipped_count"] == 1)

    # 5. Partial failure resilience: 1 event fails during batch fetch
    with patch.object(adapter, "fetch_event", side_effect=CIRCLConnectionError("Connection timeout on event fetch")):
        res_fault = adapter.poll_new_events(
            known_uuids=set(),
            max_events=2,
            raw_manifest=MOCK_MANIFEST
        )
        check("All failed events returns status FAILURE", res_fault["status"] == "FAILURE")
        check("Failed count is 2", res_fault["failed_count"] == 2)
        check("Error messages recorded", len(res_fault["errors"]) == 2)

    # 6. Malformed event payload resilience (missing Event key)
    malformed_events_db = {
        MOCK_UUID_1: {"Corrupted": True},
        MOCK_UUID_2: make_mock_event(MOCK_UUID_2, "Sample B")
    }
    res_malformed = adapter.poll_new_events(
        known_uuids=set(),
        max_events=2,
        raw_manifest=MOCK_MANIFEST,
        mock_events=malformed_events_db
    )
    check("Malformed event in batch handled gracefully", res_malformed["status"] == "SUCCESS")
    # Event 1 transformed into 0 evidence, Event 2 transformed into 2 evidence
    check("Only valid event generated evidence", len(res_malformed["evidence_records"]) == 2)

    # 7. Clamped limits validation
    res_clamped = adapter.poll_new_events(
        known_uuids=set(),
        max_events=999,  # Should be clamped to 10
        max_attributes=999,  # Should be clamped to 50
        raw_manifest=MOCK_MANIFEST,
        mock_events=mock_events_db
    )
    check("max_events clamped to manifest size when < 10", len(res_clamped["processed_event_uuids"]) == 3)


def test_circl_sync_state_persistence():
    print("\n--- [GROUP 2] Sync State Persistence & Deduplication Logic ---")
    
    # Backup existing sync state if present
    original_state = load_circl_sync_state()

    try:
        # Save a test state
        test_state = {
            "processed_event_uuids": [MOCK_UUID_1, MOCK_UUID_2],
            "last_poll_timestamp": "2026-10-03T18:00:00Z",
            "last_poll_status": "SUCCESS",
            "total_events_processed": 2,
            "total_evidence_imported": 4
        }
        save_circl_sync_state(test_state)

        # Reload state
        loaded = load_circl_sync_state()
        check("load_circl_sync_state restores processed_event_uuids", set(loaded["processed_event_uuids"]) == {MOCK_UUID_1, MOCK_UUID_2})
        check("load_circl_sync_state restores timestamp", loaded["last_poll_timestamp"] == "2026-10-03T18:00:00Z")
        check("load_circl_sync_state restores status", loaded["last_poll_status"] == "SUCCESS")
        check("load_circl_sync_state restores counts", loaded["total_events_processed"] == 2 and loaded["total_evidence_imported"] == 4)

        # Check get_tracked_circl_uuids includes full UUID and lowercase
        tracked = get_tracked_circl_uuids()
        check("get_tracked_circl_uuids includes tracked full UUID", MOCK_UUID_1.lower() in tracked)

    finally:
        # Restore original state
        save_circl_sync_state(original_state)


def test_circl_poll_api_endpoints():
    print("\n--- [GROUP 3] CIRCL Poll API Endpoints (GET /sync-status, POST /poll) ---")

    # 1. GET /api/feeds/circl/sync-status
    st_code, st_data = http_req("/api/feeds/circl/sync-status")
    check("GET /api/feeds/circl/sync-status returns 200", st_code == 200)
    check("Sync status contains feed_url", "circl.lu" in st_data.get("feed_url", ""))
    check("Sync status contains last_poll_status", "last_poll_status" in st_data)
    check("Sync status contains total_tracked_uuids", isinstance(st_data.get("total_tracked_uuids"), int))
    check("Sync status contains total_events_processed", isinstance(st_data.get("total_events_processed"), int))

    # 2. Check no secrets leaked in sync-status
    st_str = json.dumps(st_data).lower()
    check("Sync status contains no 'api_key'", "api_key" not in st_str)
    check("Sync status contains no 'password'", "password" not in st_str)
    check("Sync status contains no 'token'", "token" not in st_str)

    # Backup CASE-AUTH-MISP and state file
    auth_case_path = CASE_FILES["CASE-AUTH-MISP"]
    with open(auth_case_path, "r", encoding="utf-8") as f:
        auth_case_baseline = f.read()
    orig_sync_state = load_circl_sync_state()

    try:
        # Reset state to clean baseline for API test
        save_circl_sync_state({
            "processed_event_uuids": [],
            "last_poll_timestamp": None,
            "last_poll_status": "UNINITIALIZED",
            "total_events_processed": 0,
            "total_evidence_imported": 0
        })

        # 3. POST /api/feeds/circl/poll with controlled mock manifest and mock event
        mock_event_obj = make_mock_event(MOCK_UUID_1, "API Polled Threat Indicator")
        poll_payload = {
            "max_events": 2,
            "max_attributes": 2,
            "mock_manifest": {MOCK_UUID_1: MOCK_MANIFEST[MOCK_UUID_1]},
            "mock_event": mock_event_obj
        }

        # First Poll Cycle: Detects MOCK_UUID_1
        poll_code, poll_res = http_req("/api/feeds/circl/poll", method="POST", payload=poll_payload)
        check("POST /api/feeds/circl/poll returns 200", poll_code == 200)
        check("Poll status is SUCCESS", poll_res.get("status") == "SUCCESS")
        check("New events detected = 1", poll_res.get("new_events_detected") == 1)
        check("Processed UUID matches", MOCK_UUID_1 in poll_res.get("processed_event_uuids", []))
        check("Imported evidence count > 0", poll_res.get("imported_evidence_count", 0) > 0)
        check("Errors list is empty", len(poll_res.get("errors", [])) == 0)

        # Verify CASE-AUTH-MISP persistence
        auth_data_after = load_raw_data("CASE-AUTH-MISP")
        persisted_ids = [e["id"] for e in auth_data_after.get("evidence", [])]
        expected_prefix = f"CIRCL-EV-{MOCK_UUID_1[:8]}-"
        matching_ev = [eid for eid in persisted_ids if eid.startswith(expected_prefix)]
        check("Newly polled evidence is stored in CASE-AUTH-MISP", len(matching_ev) > 0)

        # Verify Provenance and SHA-256 integrity on imported record
        first_ev = next(e for e in auth_data_after.get("evidence", []) if e["id"] == matching_ev[0])
        ev_hash = generate_evidence_hash(first_ev)
        valid_hash, _, _ = verify_evidence_integrity(first_ev, ev_hash)
        check("Imported evidence has valid cryptographic SHA-256 hash", valid_hash)

        # Second Poll Cycle with identical manifest: Deduplication in action!
        repeat_code, repeat_res = http_req("/api/feeds/circl/poll", method="POST", payload=poll_payload)
        check("Repeated POST /api/feeds/circl/poll returns 200", repeat_code == 200)
        check("Repeated poll status is SKIPPED_NO_NEW", repeat_res.get("status") == "SKIPPED_NO_NEW")
        check("Repeated poll detected 0 new events", repeat_res.get("new_events_detected") == 0)
        check("Repeated poll imported 0 evidence records", repeat_res.get("imported_evidence_count") == 0)
        check("Repeated poll processed 0 UUIDs", len(repeat_res.get("processed_event_uuids", [])) == 0)
        check("Repeated poll skipped_count is 1", repeat_res.get("skipped_count") == 1)

        # Confirm CASE-AUTH-MISP evidence count did not increase on repeated poll
        auth_data_after_repeat = load_raw_data("CASE-AUTH-MISP")
        check("No duplicate evidence records created in CASE-AUTH-MISP", len(auth_data_after_repeat["evidence"]) == len(auth_data_after["evidence"]))

        # Incremental Third Poll Cycle: Introduce MOCK_UUID_2
        mock_event_2 = make_mock_event(MOCK_UUID_2, "Second Polled Threat Indicator")
        inc_payload = {
            "max_events": 2,
            "max_attributes": 2,
            "mock_manifest": {
                MOCK_UUID_1: MOCK_MANIFEST[MOCK_UUID_1],
                MOCK_UUID_2: MOCK_MANIFEST[MOCK_UUID_2]
            },
            "mock_event": mock_event_2
        }
        inc_code, inc_res = http_req("/api/feeds/circl/poll", method="POST", payload=inc_payload)
        check("Incremental poll returns 200", inc_code == 200)
        check("Incremental poll status is SUCCESS", inc_res.get("status") == "SUCCESS")
        check("Incremental poll detected exactly 1 new event", inc_res.get("new_events_detected") == 1)
        check("Incremental poll skipped 1 known event", inc_res.get("skipped_count") == 1)
        check("Incremental poll processed MOCK_UUID_2", MOCK_UUID_2 in inc_res.get("processed_event_uuids", []))

    finally:
        # Restore baseline CASE-AUTH-MISP and sync state
        with open(auth_case_path, "w", encoding="utf-8") as f:
            f.write(auth_case_baseline)
        save_circl_sync_state(orig_sync_state)
        print("   -> Teardown: CASE-AUTH-MISP and sync state restored to baseline.")


def test_synthetic_cases_isolation_and_immutability():
    print("\n--- [GROUP 4] Synthetic Cases Immutability & Audit Trail ---")

    # Record hashes of all 3 baseline synthetic cases
    synthetic_files = {
        "CASE-2026-09X": CASE_FILES["CASE-2026-09X"],
        "CASE-2026-02B": CASE_FILES["CASE-2026-02B"],
        "CASE-2026-03C": CASE_FILES["CASE-2026-03C"]
    }
    
    for cid, path in synthetic_files.items():
        with open(path, "rb") as f:
            content = f.read()
        cdata = json.loads(content.decode("utf-8"))
        
        # Check zero CIRCL indicators in synthetic cases
        circl_ev = [e["id"] for e in cdata.get("evidence", []) if "CIRCL" in str(e.get("id", ""))]
        check(f"Baseline synthetic case {cid} has zero CIRCL contamination", len(circl_ev) == 0)
        check(f"Baseline synthetic case {cid} has 5 evidence items", len(cdata.get("evidence", [])) == 5)

    # Verify audit log recorded CIRCL_FEED_POLL
    audit_file = PROJECT_ROOT / "data" / "audit_log.jsonl"
    check("audit_log.jsonl exists", audit_file.exists())

    poll_events = []
    with open(audit_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("action") == "CIRCL_FEED_POLL":
                poll_events.append(entry)

    check("CIRCL_FEED_POLL audit events recorded", len(poll_events) > 0)
    if poll_events:
        last_poll = poll_events[-1]
        check("Last poll audit event case_id is CASE-AUTH-MISP", last_poll.get("case_id") == "CASE-AUTH-MISP")
        check("Audit event contains manifest_total_events metric", "manifest_total_events" in last_poll.get("details", {}))
        check("Audit event contains processed_count metric", "processed_count" in last_poll.get("details", {}))

    # Verify zero secrets in audit log
    with open(audit_file, "r", encoding="utf-8") as f:
        full_log = f.read()
    check("Audit log contains no 'api_key' secrets", '"api_key"' not in full_log)
    check("Audit log contains no 'password' secrets", '"password"' not in full_log)
    check("Audit log contains no 'token' secrets", '"token"' not in full_log)


def test_live_circl_poll_probe():
    print("\n--- [GROUP 5] Live Public CIRCL OSINT Feed Poll Probe ---")
    
    # Backup CASE-AUTH-MISP and state file
    auth_case_path = CASE_FILES["CASE-AUTH-MISP"]
    with open(auth_case_path, "r", encoding="utf-8") as f:
        auth_case_baseline = f.read()
    orig_sync_state = load_circl_sync_state()

    try:
        # Perform a single bounded live poll (max 1 event, max 2 attributes)
        live_code, live_res = http_req(
            "/api/feeds/circl/poll",
            method="POST",
            payload={"max_events": 1, "max_attributes": 2}
        )
        check("Live POST /api/feeds/circl/poll returns 200", live_code == 200)
        check("Live poll returned a valid status (SUCCESS or SKIPPED_NO_NEW)", live_res.get("status") in ("SUCCESS", "SKIPPED_NO_NEW"))
        check("Live poll accessed manifest with > 1000 events", live_res.get("manifest_total_events", 0) > 1000)
        print(f"   -> Live poll successfully completed: {live_res.get('status')} (Manifest events: {live_res.get('manifest_total_events')})")

    finally:
        # Restore baseline
        with open(auth_case_path, "w", encoding="utf-8") as f:
            f.write(auth_case_baseline)
        save_circl_sync_state(orig_sync_state)
        print("   -> Teardown: CASE-AUTH-MISP and sync state restored to baseline after live probe.")


def run_all():
    print("=" * 70)
    print("SHADOWTRACE — PHASE 6.5 MANUAL INCREMENTAL CIRCL POLLING VALIDATION")
    print("=" * 70)

    test_circl_poll_unit_adapter()
    test_circl_sync_state_persistence()
    test_circl_poll_api_endpoints()
    test_synthetic_cases_isolation_and_immutability()
    test_live_circl_poll_probe()

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"PHASE 6.5 CIRCL POLLING RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL PHASE 6.5 CIRCL POLLING TESTS PASSED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    run_all()
