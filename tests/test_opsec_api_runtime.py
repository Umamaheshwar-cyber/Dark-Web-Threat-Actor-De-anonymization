"""
SHADOWTRACE — Runtime API OPSEC Isolation Regression Tests
Tests the actual HTTP drilldown endpoint (not just the Python engine layer)
to ensure the browser-facing API returns case-correct OPSEC event identifiers.

Guards specifically against the class of bug where:
- correlation_engine.py is fixed on disk but the server is still running
  old cached module code in memory, so tests pass but the UI remains broken.

All requests target the locally running Uvicorn server.
No external network, no Tor, no real-person data, synthetic demo data only.
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def http_get(path: str) -> dict:
    """Perform an HTTP GET and return the parsed JSON response."""
    url = f"{BASE_URL}{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_url": url}
    except Exception as e:
        return {"_connection_error": str(e), "_url": url}


# ---------------------------------------------------------------------------
# Expected per-case identifiers (what the UI should see)
# ---------------------------------------------------------------------------

CASE_DRILLDOWN = {
    "CASE-2026-02B": {
        "actor_id": "ACT-010",
        "expected_actor_name": "CipherPhantom",
        "expected_alias": "PhantomCrypt_dev",
        "expected_pgp": "PGP-SYN-3E99",
        "expected_wallet": "WALLET-SYN-BTC-901",
        "expected_score": 73,
        "forbidden": ["ShadowX2", "PGP-SYN-8F21", "WALLET-SYN-441",
                      "Ghost_Weave99", "PGP-SYN-9A72", "WALLET-SYN-XMR-333"],
    },
    "CASE-2026-09X": {
        "actor_id": "ACT-001",
        "expected_actor_name": "ShadowX",
        "expected_alias": "ShadowX2",
        "expected_pgp": "PGP-SYN-8F21",
        "expected_wallet": "WALLET-SYN-441",
        "expected_score": 68,
        "forbidden": ["PhantomCrypt_dev", "PGP-SYN-3E99", "WALLET-SYN-BTC-901",
                      "Ghost_Weave99", "PGP-SYN-9A72", "WALLET-SYN-XMR-333"],
    },
    "CASE-2026-03C": {
        "actor_id": "ACT-020",
        "expected_actor_name": "GhostWeaver",
        "expected_alias": "Ghost_Weave99",
        "expected_pgp": "PGP-SYN-9A72",
        "expected_wallet": "WALLET-SYN-XMR-333",
        "expected_score": 65,
        "forbidden": ["ShadowX2", "PGP-SYN-8F21", "WALLET-SYN-441",
                      "PhantomCrypt_dev", "PGP-SYN-3E99", "WALLET-SYN-BTC-901"],
    },
}

ALSO_TEST_OPSEC_EVAL_ENDPOINT = {
    "CASE-2026-02B": "ACT-010",
    "CASE-2026-09X": "ACT-001",
    "CASE-2026-03C": "ACT-020",
}


def test_server_reachable():
    print("\n--- [0] Server Reachability ---")
    data = http_get("/api/health")
    check(
        "Server is reachable at /api/health",
        "_connection_error" not in data and "_http_error" not in data,
        str(data.get("_connection_error", data.get("_http_error", "")))
    )


def test_drilldown_opsec_events_runtime():
    """
    Test the actual /api/actors/{id}/drilldown endpoint used by the UI.
    This is the PRIMARY regression guard — it catches stale in-memory server state.
    """
    print("\n--- [1] Drilldown API: OPSEC events use case-correct identifiers ---")

    for case_id, spec in CASE_DRILLDOWN.items():
        actor_id = spec["actor_id"]
        path = f"/api/actors/{actor_id}/drilldown?case_id={case_id}"
        data = http_get(path)

        check(
            f"{case_id}: Drilldown endpoint returns HTTP 200",
            "_http_error" not in data and "_connection_error" not in data,
            str(data.get("_connection_error", data.get("_http_error", "")))
        )
        if "_http_error" in data or "_connection_error" in data:
            continue

        opsec = data.get("opsec", {})
        events = opsec.get("contributing_events", [])
        all_desc = " ".join(e.get("description", "") for e in events)

        # Actor name in OPSEC block
        check(
            f"{case_id}: opsec.actor_name == '{spec['expected_actor_name']}'",
            opsec.get("actor_name") == spec["expected_actor_name"],
            f"Got: {opsec.get('actor_name')}"
        )

        # Exposure score unchanged
        check(
            f"{case_id}: opsec.current_exposure_score == {spec['expected_score']}",
            opsec.get("current_exposure_score") == spec["expected_score"],
            f"Got: {opsec.get('current_exposure_score')}"
        )

        # Own alias present
        check(
            f"{case_id}: own alias '{spec['expected_alias']}' in OPSEC event descriptions",
            spec["expected_alias"] in all_desc,
            f"Not found. Descriptions: {all_desc[:200]}"
        )

        # Own PGP present
        check(
            f"{case_id}: own PGP '{spec['expected_pgp']}' in OPSEC event descriptions",
            spec["expected_pgp"] in all_desc,
            f"Not found. Descriptions: {all_desc[:200]}"
        )

        # Own wallet present
        check(
            f"{case_id}: own wallet '{spec['expected_wallet']}' in OPSEC event descriptions",
            spec["expected_wallet"] in all_desc,
            f"Not found. Descriptions: {all_desc[:200]}"
        )

        # Foreign identifiers must NOT appear
        for foreign in spec["forbidden"]:
            check(
                f"{case_id}: foreign '{foreign}' NOT in OPSEC event descriptions",
                foreign not in all_desc,
                f"Found in: {all_desc[:200]}"
            )

        # Exactly 6 contributing events
        check(
            f"{case_id}: contributing_events has 6 items",
            len(events) == 6,
            f"Got {len(events)}"
        )


def test_opsec_eval_endpoint_runtime():
    """
    Test /api/analytics/opsec-evaluation/{actor_id} — the standalone evaluation endpoint.
    """
    print("\n--- [2] OPSEC-Evaluation API: returns case-correct identifiers ---")

    for case_id, actor_id in ALSO_TEST_OPSEC_EVAL_ENDPOINT.items():
        spec = CASE_DRILLDOWN[case_id]
        path = f"/api/analytics/opsec-evaluation/{actor_id}?case_id={case_id}"
        data = http_get(path)

        check(
            f"{case_id}: opsec-evaluation endpoint returns HTTP 200",
            "_http_error" not in data and "_connection_error" not in data,
            str(data.get("_http_error", data.get("_connection_error", "")))
        )
        if "_http_error" in data or "_connection_error" in data:
            continue

        events = data.get("contributing_events", [])
        all_desc = " ".join(e.get("description", "") for e in events)

        check(
            f"{case_id} (eval endpoint): actor_name == '{spec['expected_actor_name']}'",
            data.get("actor_name") == spec["expected_actor_name"],
            f"Got: {data.get('actor_name')}"
        )
        check(
            f"{case_id} (eval endpoint): own alias '{spec['expected_alias']}' present",
            spec["expected_alias"] in all_desc,
            f"Not found: {all_desc[:200]}"
        )
        for foreign in spec["forbidden"]:
            check(
                f"{case_id} (eval endpoint): foreign '{foreign}' NOT present",
                foreign not in all_desc,
                f"Found in: {all_desc[:200]}"
            )


def test_cipherphantom_full_dossier_smoke():
    """
    Explicit smoke test for the reported bug: ACT-010 / CASE-2026-02B.
    Verifies the exact identifiers mentioned in the bug report are absent
    and the correct ones are present in the live API response.
    """
    print("\n--- [3] CipherPhantom Bug Regression (ACT-010 / CASE-2026-02B) ---")

    data = http_get("/api/actors/ACT-010/drilldown?case_id=CASE-2026-02B")
    check(
        "ACT-010/CASE-2026-02B: Endpoint HTTP 200",
        "_http_error" not in data and "_connection_error" not in data
    )
    if "_http_error" in data or "_connection_error" in data:
        return

    opsec = data.get("opsec", {})
    events = opsec.get("contributing_events", [])
    all_desc = " ".join(e.get("description", "") for e in events)

    # These are the exact identifiers reported as incorrectly showing up in the UI
    check("BUG GUARD: 'ShadowX2' NOT in CipherPhantom OPSEC events",
          "ShadowX2" not in all_desc, f"STILL PRESENT: {all_desc[:300]}")
    check("BUG GUARD: 'PGP-SYN-8F21' NOT in CipherPhantom OPSEC events",
          "PGP-SYN-8F21" not in all_desc, f"STILL PRESENT: {all_desc[:300]}")
    check("BUG GUARD: 'WALLET-SYN-441' NOT in CipherPhantom OPSEC events",
          "WALLET-SYN-441" not in all_desc, f"STILL PRESENT: {all_desc[:300]}")

    # Correct CipherPhantom identifiers must now be present
    check("FIX VERIFY: 'PhantomCrypt_dev' in CipherPhantom OPSEC events",
          "PhantomCrypt_dev" in all_desc, f"Not found: {all_desc[:300]}")
    check("FIX VERIFY: 'PGP-SYN-3E99' in CipherPhantom OPSEC events",
          "PGP-SYN-3E99" in all_desc, f"Not found: {all_desc[:300]}")
    check("FIX VERIFY: 'WALLET-SYN-BTC-901' in CipherPhantom OPSEC events",
          "WALLET-SYN-BTC-901" in all_desc, f"Not found: {all_desc[:300]}")

    # Actor identity in dossier
    actor = data.get("actor", {})
    check("Dossier actor.name == 'CipherPhantom'", actor.get("name") == "CipherPhantom")
    check("Dossier actor.id == 'ACT-010'", actor.get("id") == "ACT-010")
    check("Dossier case_id == 'CASE-2026-02B'", data.get("case_id") == "CASE-2026-02B")


if __name__ == "__main__":
    print("=" * 68)
    print("SHADOWTRACE — Runtime API OPSEC Isolation Regression Tests")
    print("Testing actual HTTP endpoints served by the running backend.")
    print("=" * 68)

    test_server_reachable()
    test_drilldown_opsec_events_runtime()
    test_opsec_eval_endpoint_runtime()
    test_cipherphantom_full_dossier_smoke()

    print("\n" + "=" * 68)
    total = PASS + FAIL
    print(f"RUNTIME API RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL RUNTIME API OPSEC ISOLATION TESTS PASSED!")
        print("The browser-facing API now returns case-correct OPSEC events.")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED — check output above.")
    print("=" * 68)

    sys.exit(0 if FAIL == 0 else 1)
