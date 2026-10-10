"""
SHADOWTRACE Automated Test Suite — Phase 6.1 MISP Adapter
Tests the isolated authorized MISP intelligence adapter using mocked local MISP event payloads.
Offline tests only: no network connections to live MISP servers.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.authorized_adapter import (
    MISPAdapter,
    MISPConfigurationError,
    map_misp_type_to_shadowtrace,
    map_misp_confidence
)

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

def test_misp_mappings():
    print("\n--- [TEST GROUP 1] MISP Type & Confidence Mappings ---")
    
    check("Map github-username to ALIAS", map_misp_type_to_shadowtrace("github-username") == "ALIAS")
    check("Map pgp-key to PGP", map_misp_type_to_shadowtrace("pgp-key") == "PGP")
    check("Map btc to WALLET", map_misp_type_to_shadowtrace("btc") == "WALLET")
    check("Map unknown to INDICATOR", map_misp_type_to_shadowtrace("other-type") == "INDICATOR")

    check("Map threat_level 1 to High", map_misp_confidence(1) == "High")
    check("Map threat_level 2 to Medium", map_misp_confidence(2) == "Medium")
    check("Map threat_level 3 to Low", map_misp_confidence(3) == "Low")
    check("Map invalid threat_level to Low", map_misp_confidence("invalid") == "Low")

def test_adapter_configuration():
    print("\n--- [TEST GROUP 2] MISP Adapter Configuration & Error Handling ---")
    
    adapter_unconfigured = MISPAdapter(base_url="", api_key="")
    check("Adapter reports unconfigured when keys missing", not adapter_unconfigured.is_configured())

    try:
        adapter_unconfigured.fetch_events_rest()
        check("Raise MISPConfigurationError when fetching unconfigured", False)
    except MISPConfigurationError:
        check("Raise MISPConfigurationError when fetching unconfigured", True)

def test_misp_event_transformation():
    print("\n--- [TEST GROUP 3] Mock MISP Event Transformation & Provenance ---")

    mock_misp_event = {
        "Event": {
            "id": "998877",
            "info": "SHADOWTRACE Authorized Test Threat Event",
            "date": "2026-10-02",
            "threat_level_id": 2,
            "Orgc": {
                "name": "Authorized CTI Unit"
            },
            "Attribute": [
                {
                    "id": "1001",
                    "type": "github-username",
                    "value": "TestActorHandle",
                    "comment": "Observed handle in threat repository",
                    "toids": False
                },
                {
                    "id": "1002",
                    "type": "pgp-key",
                    "value": "0x1234567890ABCDEF",
                    "comment": "Correlated PGP public key",
                    "toids": True
                },
                {
                    "id": "1003",
                    "type": "btc",
                    "value": "bc1qtestwalletaddress000000000",
                    "comment": "Wallet indicator",
                    "toids": False
                }
            ]
        }
    }

    adapter = MISPAdapter(base_url="https://misp.local", api_key="dummy-key")
    evidence_items = adapter.transform_misp_event_to_evidence(mock_misp_event)

    check("Transformed exact attribute count", len(evidence_items) == 3)
    
    # Item 1: github-username (ALIAS)
    ev1 = evidence_items[0]
    check("Evidence 1 ID format", ev1["id"] == "MISP-EV-998877-1001")
    check("Evidence 1 type ALIAS", ev1["type"] == "ALIAS")
    check("Evidence 1 identifier", ev1["identifier"] == "TestActorHandle")
    check("Evidence 1 confidence Medium", ev1["confidence"] == "Medium")
    check("Evidence 1 default status Observed", ev1["status"] == "Observed")

    # Item 2: pgp-key (PGP, toids=True -> Correlated)
    ev2 = evidence_items[1]
    check("Evidence 2 type PGP", ev2["type"] == "PGP")
    check("Evidence 2 status Correlated when toids=True", ev2["status"] == "Correlated")

    # Provenance build test
    prov = adapter.build_provenance_for_evidence(ev1, mock_misp_event)
    check("Provenance has valid evidence_id", prov["evidence_id"] == ev1["id"])
    check("Provenance has 64-char sha256_hash", len(prov["sha256_hash"]) == 64)
    check("Provenance raw observed payload flag", prov["observed_data"]["is_raw_artifact"] is True)
    check("Provenance analytical conclusion flag", prov["analytical_conclusion"]["is_analytical_inference"] is True)

def run_all_tests():
    print("=== RUNNING PHASE 6.1 MISP ADAPTER TEST SUITE ===")
    test_misp_mappings()
    test_adapter_configuration()
    test_misp_event_transformation()

    print(f"\nMISP Adapter Tests Total: {PASS} passed, {FAIL} failed.")
    if FAIL > 0:
        sys.exit(1)
    print("ALL PHASE 6.1 MISP ADAPTER TESTS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    run_all_tests()
