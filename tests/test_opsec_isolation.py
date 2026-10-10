"""
SHADOWTRACE — OPSEC Isolation Regression Tests
Verifies that compute_opsec_exposure_evaluation() produces contributing_events
that reference ONLY the identifiers belonging to the supplied actor/case.

Bug being guarded:
  Prior to this fix, the function hardcoded ShadowX-specific identifiers
  (ShadowX2, PGP-SYN-8F21, WALLET-SYN-441) in every OPSEC response,
  regardless of which case was being evaluated.

All data is synthetic demo data only. No network access. No real-person identification.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.data_store import get_actors_data, load_raw_data
from backend.correlation_engine import compute_opsec_exposure_evaluation

SYNTHETIC_CASES = ["CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C"]

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


# ---------------------------------------------------------------------------
# Expected per-case identifiers
# ---------------------------------------------------------------------------

CASE_EXPECTED = {
    "CASE-2026-09X": {
        "own_alias": "ShadowX2",
        "own_pgp": "PGP-SYN-8F21",
        "own_wallet": "WALLET-SYN-441",
        "foreign_identifiers": ["PhantomCrypt_dev", "PGP-SYN-3E99", "WALLET-SYN-BTC-901",
                                 "Ghost_Weave99", "PGP-SYN-9A72", "WALLET-SYN-XMR-333"],
    },
    "CASE-2026-02B": {
        "own_alias": "PhantomCrypt_dev",
        "own_pgp": "PGP-SYN-3E99",
        "own_wallet": "WALLET-SYN-BTC-901",
        "foreign_identifiers": ["ShadowX2", "PGP-SYN-8F21", "WALLET-SYN-441",
                                 "Ghost_Weave99", "PGP-SYN-9A72", "WALLET-SYN-XMR-333"],
    },
    "CASE-2026-03C": {
        "own_alias": "Ghost_Weave99",
        "own_pgp": "PGP-SYN-9A72",
        "own_wallet": "WALLET-SYN-XMR-333",
        "foreign_identifiers": ["ShadowX2", "PGP-SYN-8F21", "WALLET-SYN-441",
                                 "PhantomCrypt_dev", "PGP-SYN-3E99", "WALLET-SYN-BTC-901"],
    },
}


def test_opsec_events_use_own_identifiers():
    print("\n--- [1] OPSEC contributing_events reference only case-own identifiers ---")

    for cid in SYNTHETIC_CASES:
        expected = CASE_EXPECTED[cid]
        actors = get_actors_data(cid)
        primary_actor = actors[0]
        raw_opsec = load_raw_data(cid).get("opsec", {})

        result = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)
        events = result.get("contributing_events", [])

        # Collect all description text from all events
        all_desc = " ".join(e.get("description", "") for e in events)

        # Own alias must appear in at least one event description
        check(
            f"{cid}: Own alias '{expected['own_alias']}' appears in OPSEC event descriptions",
            expected["own_alias"] in all_desc,
            f"Not found in: {all_desc[:200]}"
        )

        # Own PGP must appear
        check(
            f"{cid}: Own PGP '{expected['own_pgp']}' appears in OPSEC event descriptions",
            expected["own_pgp"] in all_desc,
            f"Not found in: {all_desc[:200]}"
        )

        # Own wallet must appear
        check(
            f"{cid}: Own wallet '{expected['own_wallet']}' appears in OPSEC event descriptions",
            expected["own_wallet"] in all_desc,
            f"Not found in: {all_desc[:200]}"
        )

        # Foreign identifiers must NOT appear
        for foreign_id in expected["foreign_identifiers"]:
            check(
                f"{cid}: Foreign identifier '{foreign_id}' does NOT appear in OPSEC event descriptions",
                foreign_id not in all_desc,
                f"Found in: {all_desc[:200]}"
            )


def test_opsec_result_actor_name_matches_case():
    print("\n--- [2] OPSEC result actor_name matches the case's primary actor ---")

    for cid in SYNTHETIC_CASES:
        actors = get_actors_data(cid)
        primary_actor = actors[0]
        raw_opsec = load_raw_data(cid).get("opsec", {})

        result = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)

        check(
            f"{cid}: result.actor_name == '{primary_actor['name']}'",
            result.get("actor_name") == primary_actor["name"],
            f"Got: {result.get('actor_name')}"
        )
        check(
            f"{cid}: result.actor_id == '{primary_actor['id']}'",
            result.get("actor_id") == primary_actor["id"],
            f"Got: {result.get('actor_id')}"
        )


def test_opsec_scores_unchanged():
    print("\n--- [3] OPSEC numeric scores unchanged after fix ---")

    expected_scores = {
        "CASE-2026-09X": 68,
        "CASE-2026-02B": 73,
        "CASE-2026-03C": 65,
    }

    for cid, expected_score in expected_scores.items():
        actors = get_actors_data(cid)
        primary_actor = actors[0]
        raw_opsec = load_raw_data(cid).get("opsec", {})

        result = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)
        score = result.get("current_exposure_score")

        check(
            f"{cid}: current_exposure_score == {expected_score} (unchanged)",
            score == expected_score,
            f"Got: {score}"
        )


def test_opsec_six_events_per_case():
    print("\n--- [4] OPSEC contributing_events always contains 6 items ---")

    for cid in SYNTHETIC_CASES:
        actors = get_actors_data(cid)
        primary_actor = actors[0]
        raw_opsec = load_raw_data(cid).get("opsec", {})

        result = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)
        events = result.get("contributing_events", [])

        check(
            f"{cid}: contributing_events has exactly 6 items",
            len(events) == 6,
            f"Got {len(events)}"
        )

        # Each event must have week/signal/points/description keys
        for i, ev in enumerate(events):
            check(
                f"{cid}: Event {i + 1} has all required keys",
                all(k in ev for k in ("week", "signal", "points", "description")),
                f"Keys present: {list(ev.keys())}"
            )


def test_shadowx_opsec_unchanged():
    """
    Verify that the CASE-2026-09X ShadowX OPSEC output is not broken by the fix.
    ShadowX's events must still reference its own identifiers correctly.
    """
    print("\n--- [5] ShadowX (CASE-2026-09X) OPSEC data unchanged after fix ---")

    actors = get_actors_data("CASE-2026-09X")
    primary = actors[0]  # ShadowX
    raw_opsec = load_raw_data("CASE-2026-09X").get("opsec", {})

    result = compute_opsec_exposure_evaluation(primary, raw_opsec)
    all_desc = " ".join(e["description"] for e in result["contributing_events"])

    check("ShadowX: actor_name is 'ShadowX'", result["actor_name"] == "ShadowX")
    check("ShadowX: 'ShadowX2' still appears in event descriptions", "ShadowX2" in all_desc,
          f"Not found: {all_desc[:200]}")
    check("ShadowX: 'PGP-SYN-8F21' still appears in event descriptions", "PGP-SYN-8F21" in all_desc,
          f"Not found: {all_desc[:200]}")
    check("ShadowX: 'WALLET-SYN-441' still appears in event descriptions", "WALLET-SYN-441" in all_desc,
          f"Not found: {all_desc[:200]}")
    check("ShadowX: current_exposure_score is 68", result["current_exposure_score"] == 68)

    # Confirm no CipherPhantom or GhostWeaver identifiers leaked in
    for foreign in ["PhantomCrypt_dev", "PGP-SYN-3E99", "WALLET-SYN-BTC-901",
                    "Ghost_Weave99", "PGP-SYN-9A72", "WALLET-SYN-XMR-333"]:
        check(f"ShadowX: '{foreign}' NOT in OPSEC event descriptions", foreign not in all_desc,
              f"Unexpectedly found: {foreign}")


if __name__ == "__main__":
    print("=" * 65)
    print("SHADOWTRACE — OPSEC ISOLATION REGRESSION TESTS")
    print("=" * 65)
    print("Verifying that each case's OPSEC events reference ONLY its own")
    print("synthetic identifiers. No cross-case contamination allowed.\n")

    test_opsec_events_use_own_identifiers()
    test_opsec_result_actor_name_matches_case()
    test_opsec_scores_unchanged()
    test_opsec_six_events_per_case()
    test_shadowx_opsec_unchanged()

    print("\n" + "=" * 65)
    total = PASS + FAIL
    print(f"OPSEC ISOLATION RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL OPSEC ISOLATION REGRESSION TESTS PASSED!")
    else:
        print(f"WARNING: {FAIL} test(s) FAILED.")
    print("=" * 65)

    import sys
    sys.exit(0 if FAIL == 0 else 1)
