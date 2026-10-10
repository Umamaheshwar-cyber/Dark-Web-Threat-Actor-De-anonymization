"""
SHADOWTRACE Automated Test Suite — Phase 5 Integration & API Runtime
Tests FastAPI endpoints for Phase 4 features:
- GET /api/cases/{case_id}/stix
- GET /api/cases/{case_id}/report
- GET /api/cases/{case_id}/report/markdown
- GET /api/evidence/{evidence_id}/provenance
- GET /api/audit
Plus error handling (404s) across all synthetic cases.
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

def run_phase5_tests():
    print("=== RUNNING SHADOWTRACE PHASE 5 INTEGRATION & API RUNTIME TESTS ===")

    tests = [
        # 1. STIX 2.1 Case Export API
        ("STIX Export Case 1", "/api/cases/CASE-2026-09X/stix", 200, lambda r: r["type"] == "bundle" and len(r["objects"]) > 0),
        ("STIX Export Case 2", "/api/cases/CASE-2026-02B/stix", 200, lambda r: r["type"] == "bundle" and len(r["objects"]) > 0),
        ("STIX Export Case 3", "/api/cases/CASE-2026-03C/stix", 200, lambda r: r["type"] == "bundle" and len(r["objects"]) > 0),
        ("STIX Export Non-existent Case", "/api/cases/CASE-INVALID/stix", 404, lambda r: True),

        # 2. Structured Investigation Report API (JSON)
        ("JSON Report Case 1", "/api/cases/CASE-2026-09X/report", 200, lambda r: "case_summary" in r and "actors" in r and "evidence_summary" in r and len(r["actors"]) > 0),
        ("JSON Report Case 2", "/api/cases/CASE-2026-02B/report", 200, lambda r: r["case_summary"]["case_id"] == "CASE-2026-02B"),
        ("JSON Report Case 3", "/api/cases/CASE-2026-03C/report", 200, lambda r: r["case_summary"]["case_id"] == "CASE-2026-03C"),
        ("JSON Report Non-existent Case", "/api/cases/CASE-INVALID/report", 404, lambda r: True),

        # 3. Markdown Investigation Report API
        ("Markdown Report Case 1", "/api/cases/CASE-2026-09X/report/markdown", 200, lambda r: isinstance(r, str) and "# SHADOWTRACE Investigation Briefing" in r),
        ("Markdown Report Case 2", "/api/cases/CASE-2026-02B/report/markdown", 200, lambda r: isinstance(r, str) and "CASE-2026-02B" in r),
        ("Markdown Report Non-existent Case", "/api/cases/CASE-INVALID/report/markdown", 404, lambda r: True),

        # 4. Evidence Provenance & Integrity API
        ("Evidence Provenance EV-001", "/api/evidence/EV-001/provenance", 200, lambda r: r["evidence_id"] == "EV-001" and "sha256_hash" in r and r["observed_data"]["is_raw_artifact"] is True),
        ("Evidence Provenance EV-010 (Case 2)", "/api/evidence/EV-010/provenance?case_id=CASE-2026-02B", 200, lambda r: r["evidence_id"] == "EV-010" and "sha256_hash" in r),
        ("Evidence Provenance Non-existent", "/api/evidence/EV-999/provenance", 404, lambda r: True),

        # 5. Audit Log Query API
        ("Query Audit Events", "/api/audit?limit=10", 200, lambda r: isinstance(r, list)),
        ("Query Audit Events filtered by case", "/api/audit?case_id=CASE-2026-09X&limit=5", 200, lambda r: isinstance(r, list)),
        ("Query Audit Events filtered by action", "/api/audit?action=REPORT_EXPORT&limit=5", 200, lambda r: isinstance(r, list)),
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

    print(f"\nPhase 5 Tests Total: {passed} passed, {failed} failed out of {len(tests)} tests.")
    if failed > 0:
        sys.exit(1)
    print("ALL PHASE 5 TESTS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    run_phase5_tests()
