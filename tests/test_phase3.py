"""
SHADOWTRACE Automated Test Suite — Phase 3
Tests Multi-Case Switcher, Graph Node Inspection, Actor Drilldown, and Case Isolation.
"""

import sys
from pathlib import Path
import json
import urllib.request
import urllib.error

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

BASE_URL = "http://127.0.0.1:8000"

def get(path, expected_status=200):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")
            if status != expected_status:
                print(f"[FAIL] {path}: Expected {expected_status}, got {status}")
                return False, None
            if "application/json" in content_type:
                return True, json.loads(body)
            return True, body
    except urllib.error.HTTPError as e:
        if e.code == expected_status:
            return True, {"detail": "Expected HTTP error", "code": e.code}
        print(f"[FAIL] {path}: Expected {expected_status}, got {e.code}")
        return False, None
    except Exception as e:
        print(f"[FAIL] {path}: Unexpected exception: {e}")
        return False, None

def run_phase3_tests():
    print("=== RUNNING SHADOWTRACE PHASE 3 TEST SUITE ===")
    
    tests = [
        # 1. Multi-Case APIs
        ("List All Cases", "/api/cases", 200, lambda r: isinstance(r, list) and len(r) == 3 and {c["id"] for c in r} == {"CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C"}),
        ("Get Primary Case by ID", "/api/cases/CASE-2026-09X", 200, lambda r: r["id"] == "CASE-2026-09X" and r["candidate"] == "ShadowX"),
        ("Get Case 2 by ID", "/api/cases/CASE-2026-02B", 200, lambda r: r["id"] == "CASE-2026-02B" and r["candidate"] == "CipherPhantom"),
        ("Get Case 3 by ID", "/api/cases/CASE-2026-03C", 200, lambda r: r["id"] == "CASE-2026-03C" and r["candidate"] == "GhostWeaver"),
        ("Get Non-existent Case by ID", "/api/cases/CASE-NONEXISTENT", 404, lambda r: True),

        # 2. Case Scoping and Isolation
        ("Query Primary Case (Default no param)", "/api/case", 200, lambda r: r["id"] == "CASE-2026-09X"),
        ("Query Case 2 via Query Param", "/api/case?case_id=CASE-2026-02B", 200, lambda r: r["id"] == "CASE-2026-02B" and r["candidate"] == "CipherPhantom"),
        ("Actors in Case 2 (Isolation Check)", "/api/actors?case_id=CASE-2026-02B", 200, lambda r: len(r) == 2 and r[0]["id"] == "ACT-010" and all("ShadowX" not in json.dumps(a) for a in r)),
        ("Evidence in Case 2 (Isolation Check)", "/api/evidence?case_id=CASE-2026-02B", 200, lambda r: len(r) == 5 and r[0]["id"] == "EV-010"),
        ("Timeline in Case 3", "/api/timeline?case_id=CASE-2026-03C", 200, lambda r: len(r) == 6 and "Ghost_Weave99" in r[0]["detail"]),
        ("Graph in Case 3", "/api/graph?case_id=CASE-2026-03C", 200, lambda r: len(r["nodes"]) == 5 and r["nodes"][0]["id"] == "GhostWeaver"),
        ("Invalid Case Parameter Error Handling", "/api/actors?case_id=CASE-INVALID", 404, lambda r: True),

        # 3. Interactive Graph Node Inspection Endpoint
        ("Inspect Actor Node in Case 1", "/api/graph/node/ShadowX", 200, lambda r: r["id"] == "ShadowX" and r["type"] == "Actor" and len(r["connected_edges"]) > 0),
        ("Inspect PGP Node in Case 1", "/api/graph/node/PGP-SYN-8F21", 200, lambda r: r["id"] == "PGP-SYN-8F21" and r["type"] == "PGP" and len(r["related_evidence"]) > 0),
        ("Inspect Node in Case 2 with Scoping", "/api/graph/node/CipherPhantom?case_id=CASE-2026-02B", 200, lambda r: r["id"] == "CipherPhantom" and r["case_id"] == "CASE-2026-02B"),
        ("Inspect Non-existent Node", "/api/graph/node/DOES_NOT_EXIST", 404, lambda r: True),

        # 4. Actor Investigation Drill-Down
        ("ShadowX Drill-down (Default Case)", "/api/actors/ACT-001/drilldown", 200, lambda r: r["actor"]["name"] == "ShadowX" and r["correlation"]["overall_confidence"] == 86.1 and r["opsec"]["current_exposure_score"] == 68 and len(r["related_evidence"]) > 0),
        ("CipherPhantom Drill-down (Case 2)", "/api/actors/ACT-010/drilldown?case_id=CASE-2026-02B", 200, lambda r: r["actor"]["name"] == "CipherPhantom" and r["correlation"]["confidence_tier"] == "HIGH" and r["opsec"]["current_exposure_score"] == 73),
        ("Invalid Actor Drill-down ID", "/api/actors/ACT-999/drilldown", 404, lambda r: True),

        # 5. Backward Compatibility Safeguards (Phase 1 & Phase 2 unchanged routes)
        ("Backwards Compat: /api/case", "/api/case", 200, lambda r: r["id"] == "CASE-2026-09X"),
        ("Backwards Compat: /api/actors", "/api/actors", 200, lambda r: len(r) == 3 and r[0]["id"] == "ACT-001"),
        ("Backwards Compat: /api/evidence", "/api/evidence", 200, lambda r: len(r) == 5),
        ("Backwards Compat: /api/timeline", "/api/timeline", 200, lambda r: len(r) == 6),
        ("Backwards Compat: /api/graph", "/api/graph", 200, lambda r: len(r["nodes"]) == 6),
        ("Backwards Compat: /api/metrics", "/api/metrics", 200, lambda r: r["active_actors"] == 12),
        ("Backwards Compat: Phase 2 Correlation", "/api/analytics/correlation/ACT-001", 200, lambda r: r["overall_confidence"] == 86.1),
        ("Backwards Compat: Phase 2 Alias Similarity", "/api/analytics/alias-similarity?s1=ShadowX&s2=ShadowX2", 200, lambda r: r["combined_score"] > 88),
        ("Backwards Compat: Health Probe", "/api/health", 200, lambda r: r["status"] == "ok" and r["mode"] == "synthetic-demo"),
    ]

    passed = 0
    failed = 0

    for name, path, expected_status, validator in tests:
        success, res = get(path, expected_status)
        if success and (validator is None or validator(res)):
            print(f"[PASS] {name} ({path}) -> Status {expected_status}")
            passed += 1
        else:
            print(f"[FAIL] {name} ({path}) failed validation. Response: {res}")
            failed += 1

    print(f"\nPhase 3 Tests Total: {passed} passed, {failed} failed out of {len(tests)} tests.")
    if failed > 0:
        sys.exit(1)
    print("ALL PHASE 3 TESTS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    run_phase3_tests()
