"""
SHADOWTRACE Automated Test Suite — Phase 6.3 Authorized MISP Integration
Tests the authorized live MISP feed connectivity, environment variable handling,
SSL context creation, test-connection endpoint, and isolated CASE-AUTH-MISP container.

All tests run locally; no live external network connections or real-person data.
"""

import sys
import os
import json
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.authorized_adapter import (
    MISPAdapter,
    MISPConfigurationError,
    MISPConnectionError,
    MISPAuthenticationError
)
from backend.provenance import verify_evidence_integrity
from backend.data_store import (
    load_raw_data,
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
# TEST GROUP 1: Environment Variables & SSL Context Configuration
# ---------------------------------------------------------------------------

def test_environment_and_ssl_configuration():
    print("\n--- [TEST GROUP 1] MISP Environment Variables & SSL Context ---")

    # 1. SSL default verification
    adapter_default = MISPAdapter(base_url="https://misp.test", api_key="secret-key")
    ctx_default = adapter_default._build_ssl_context()
    check("Default SSL context verifies hostname and cert", ctx_default.check_hostname is True and ctx_default.verify_mode == ssl.CERT_REQUIRED)

    # 2. SSL verification disabled explicitly
    adapter_insecure = MISPAdapter(base_url="https://misp.test", api_key="secret-key", verify_ssl=False)
    ctx_insecure = adapter_insecure._build_ssl_context()
    check("Insecure SSL context disables cert check", ctx_insecure.check_hostname is False and ctx_insecure.verify_mode == ssl.CERT_NONE)

    # 3. Timeout configuration via argument and environment
    with patch.dict(os.environ, {"MISP_TIMEOUT": "25"}):
        adapter_env = MISPAdapter(base_url="https://misp.test", api_key="secret-key")
        check("Timeout parsed from MISP_TIMEOUT env var", adapter_env.timeout == 25)

    adapter_custom_timeout = MISPAdapter(base_url="https://misp.test", api_key="secret-key", timeout=30)
    check("Explicit timeout argument overrides default", adapter_custom_timeout.timeout == 30)

# ---------------------------------------------------------------------------
# TEST GROUP 2: MISPAdapter test_connection Method Unit Tests
# ---------------------------------------------------------------------------

def test_adapter_test_connection():
    print("\n--- [TEST GROUP 2] MISPAdapter.test_connection Method ---")

    # 1. Unconfigured raises MISPConfigurationError
    unconfigured_adapter = MISPAdapter(base_url="", api_key="")
    try:
        unconfigured_adapter.test_connection()
        check("Unconfigured adapter raises MISPConfigurationError", False)
    except MISPConfigurationError:
        check("Unconfigured adapter raises MISPConfigurationError", True)

    # 2. Mock successful response from /servers/getVersion
    adapter = MISPAdapter(base_url="https://misp.authorized.internal", api_key="test-auth-token")
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({"version": "2.4.190"}).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        res = adapter.test_connection()
        check("test_connection returns connected == True", res["connected"] is True)
        check("test_connection reports base_url without secret", res["base_url"] == "https://misp.authorized.internal")
        check("test_connection reports MISP version", res["version"] == "2.4.190")
        check("test_connection status is AUTHORIZED_ONLINE", res["status"] == "AUTHORIZED_ONLINE")

    # 3. Mock 401 Unauthorized response
    http_error_401 = urllib.error.HTTPError(
        url="https://misp.authorized.internal/servers/getVersion",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=None
    )
    with patch("urllib.request.urlopen", side_effect=http_error_401):
        try:
            adapter.test_connection()
            check("HTTP 401 raises MISPAuthenticationError", False)
        except MISPAuthenticationError:
            check("HTTP 401 raises MISPAuthenticationError", True)

    # 4. Mock Connection Failure
    url_error = urllib.error.URLError(reason="Connection refused")
    with patch("urllib.request.urlopen", side_effect=url_error):
        try:
            adapter.test_connection()
            check("URLError raises MISPConnectionError", False)
        except MISPConnectionError:
            check("URLError raises MISPConnectionError", True)

# ---------------------------------------------------------------------------
# TEST GROUP 3: Live API Endpoint: POST /api/feeds/misp/test-connection
# ---------------------------------------------------------------------------

def test_api_test_connection_endpoint():
    print("\n--- [TEST GROUP 3] API Endpoint: POST /api/feeds/misp/test-connection ---")

    # 1. Test when unconfigured (default state)
    status_code, data = http_req("/api/feeds/misp/test-connection", method="POST")
    check("POST /api/feeds/misp/test-connection returns 200", status_code == 200)
    check("Unconfigured status is UNCONFIGURED", data.get("status") == "UNCONFIGURED")
    check("connected is False when unconfigured", data.get("connected") is False)
    check("Zero secret leak: no api_key in response", "api_key" not in data)

# ---------------------------------------------------------------------------
# TEST GROUP 4: Dedicated Authorized Container (CASE-AUTH-MISP) Integration
# ---------------------------------------------------------------------------

def test_authorized_container_integration():
    print("\n--- [TEST GROUP 4] Dedicated Authorized Container (CASE-AUTH-MISP) ---")
    auth_file = PROJECT_ROOT / "data" / "cases" / "case_authorized_misp.json"
    initial_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else None

    try:
        # 1. Registered in CASE_FILES
        check("CASE-AUTH-MISP is registered in CASE_FILES", "CASE-AUTH-MISP" in CASE_FILES)

        # 2. Query case info via /api/cases/CASE-AUTH-MISP
        status_code, case_data = http_req("/api/cases/CASE-AUTH-MISP")
        check("GET /api/cases/CASE-AUTH-MISP returns 200", status_code == 200)
        check("Case ID is CASE-AUTH-MISP", case_data.get("id") == "CASE-AUTH-MISP")
        check("Classification indicates AUTHORIZED CTI", "AUTHORIZED CTI" in case_data.get("classification", ""))

        # 3. Ingest authorized MISP intelligence into CASE-AUTH-MISP
        import_payload = {"case_id": "CASE-AUTH-MISP"}
        status_code_imp, data_imp = http_req("/api/feeds/misp/import", method="POST", payload=import_payload)
        check("POST /api/feeds/misp/import into CASE-AUTH-MISP returns 200", status_code_imp == 200)
        check("Imported count > 0", data_imp.get("imported_count", 0) > 0)

        # 4. Read back imported evidence via GET /api/feeds/misp/evidence
        status_code_ev, feed_ev_list = http_req("/api/feeds/misp/evidence")
        check("GET /api/feeds/misp/evidence returns 200", status_code_ev == 200)
        check("Feeds evidence returns non-empty list", len(feed_ev_list) > 0)

        # 5. Read back via standard evidence endpoint GET /api/evidence?case_id=CASE-AUTH-MISP
        status_code_std, std_ev_list = http_req("/api/evidence?case_id=CASE-AUTH-MISP")
        check("GET /api/evidence?case_id=CASE-AUTH-MISP returns 200", status_code_std == 200)
        check("Standard evidence matches feeds evidence count", len(std_ev_list) == len(feed_ev_list))

        # 6. Verify cryptographic integrity of all items in CASE-AUTH-MISP
        all_valid = True
        for ev in std_ev_list:
            status_code_prov, prov_rec = http_req(f"/api/evidence/{ev['id']}/provenance?case_id=CASE-AUTH-MISP")
            if status_code_prov != 200:
                all_valid = False
                continue
            h = prov_rec.get("sha256_hash", "")
            is_valid, _, _ = verify_evidence_integrity(ev, h)
            if not is_valid:
                all_valid = False

        check("All evidence records in CASE-AUTH-MISP have valid SHA-256 integrity digests", all_valid)
    finally:
        if auth_file.exists() and initial_content is not None:
            auth_file.write_text(initial_content, encoding="utf-8")

# ---------------------------------------------------------------------------
# TEST GROUP 5: Baseline Synthetic Cases Immutability & Full Disjointness
# ---------------------------------------------------------------------------

def test_synthetic_cases_unaltered():
    print("\n--- [TEST GROUP 5] Synthetic Cases Immutability & Disjointness ---")

    # Load baseline synthetic data
    c1 = load_raw_data("CASE-2026-09X")
    c2 = load_raw_data("CASE-2026-02B")
    c3 = load_raw_data("CASE-2026-03C")
    c_auth = load_raw_data("CASE-AUTH-MISP")

    # 1. Exact evidence counts for synthetic cases must remain 5
    check("CASE-2026-09X evidence count is exactly 5", len(c1["evidence"]) == 5)
    check("CASE-2026-02B evidence count is exactly 5", len(c2["evidence"]) == 5)
    check("CASE-2026-03C evidence count is exactly 5", len(c3["evidence"]) == 5)

    # 2. Candidates remain synthetic candidates
    check("CASE-2026-09X candidate is ShadowX", c1["case"]["candidate"] == "ShadowX")
    check("CASE-2026-02B candidate is CipherPhantom", c2["case"]["candidate"] == "CipherPhantom")
    check("CASE-2026-03C candidate is GhostWeaver", c3["case"]["candidate"] == "GhostWeaver")

    # 3. Disjointness: No MISP evidence IDs exist in synthetic cases
    synthetic_ev_ids = {e["id"] for e in c1["evidence"] + c2["evidence"] + c3["evidence"]}
    auth_ev_ids = {e["id"] for e in c_auth["evidence"]}
    overlap = synthetic_ev_ids & auth_ev_ids
    check("Zero overlap between synthetic evidence IDs and authorized MISP evidence IDs", len(overlap) == 0, f"Overlap: {overlap}")

# ---------------------------------------------------------------------------
# MAIN RUNNER
# ---------------------------------------------------------------------------

def run_all():
    print("=" * 70)
    print("SHADOWTRACE — PHASE 6.3 AUTHORIZED MISP INTEGRATION TESTS")
    print("=" * 70)

    auth_file = PROJECT_ROOT / "data" / "cases" / "case_authorized_misp.json"
    initial_content = auth_file.read_text(encoding="utf-8") if auth_file.exists() else None

    try:
        test_environment_and_ssl_configuration()
        test_adapter_test_connection()
        test_api_test_connection_endpoint()
        test_authorized_container_integration()
        test_synthetic_cases_unaltered()
    finally:
        if auth_file.exists() and initial_content is not None:
            auth_file.write_text(initial_content, encoding="utf-8")

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"PHASE 6.3 AUTHORIZED RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL PHASE 6.3 AUTHORIZED TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    run_all()
