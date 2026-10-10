"""
SHADOWTRACE Automated Test Suite — Phase 4 Step 1
Tests Evidence Integrity (SHA-256) & Provenance Tracking Core.
"""

import sys
from pathlib import Path
import re

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.provenance import (
    canonicalize_evidence_payload,
    generate_evidence_hash,
    verify_evidence_integrity,
    build_evidence_provenance
)
from backend.models import EvidenceProvenanceRecord


def run_phase4_step1_tests():
    print("=== RUNNING SHADOWTRACE PHASE 4 STEP 1 TEST SUITE ===")

    payload_a = {
        "id": "EV-001",
        "type": "ALIAS",
        "identifier": "ShadowX2",
        "timestamp": "2026-09-01 09:20",
        "relationship": "Alias similarity",
        "confidence": "Medium",
        "status": "Observed"
    }

    # 1. Deterministic canonicalization and SHA-256 generation
    hash_1 = generate_evidence_hash(payload_a)
    print(f"[TEST 1] Generated SHA-256: {hash_1}")
    assert len(hash_1) == 64, f"Hash length must be 64 characters, got {len(hash_1)}"
    assert re.match(r"^[0-9a-f]{64}$", hash_1), "Hash must be lowercase hexadecimal"
    print("[PASS] Hash is a valid 64-character lowercase hex SHA-256.")

    # 2. Same payload → same hash (key ordering independence)
    payload_a_reordered = {
        "status": "Observed",
        "confidence": "Medium",
        "identifier": "ShadowX2",
        "type": "ALIAS",
        "id": "EV-001",
        "relationship": "Alias similarity",
        "timestamp": "2026-09-01 09:20"
    }
    hash_2 = generate_evidence_hash(payload_a_reordered)
    assert hash_1 == hash_2, f"Hashes must be identical regardless of key order: {hash_1} vs {hash_2}"
    print("[PASS] Deterministic hashing verified (key ordering independent).")

    # 3. Payload with volatile 'sha256' key produces the same canonical hash
    payload_with_hash = dict(payload_a)
    payload_with_hash["sha256"] = "arbitrary_existing_hash"
    hash_with_meta = generate_evidence_hash(payload_with_hash)
    assert hash_1 == hash_with_meta, "Internal 'sha256' field should be excluded from canonical digest"
    print("[PASS] Volatile fields safely excluded from canonicalization.")

    # 4. Integrity Verification: Unmodified payload passes
    is_valid, computed, explanation = verify_evidence_integrity(payload_a, hash_1)
    assert is_valid is True, f"Integrity check failed: {explanation}"
    assert computed == hash_1
    print(f"[PASS] Integrity verification passed for valid payload: {explanation}")

    # 5. Tamper Detection: Modified payload fails verification
    tampered_payload = dict(payload_a)
    tampered_payload["identifier"] = "ShadowX_TAMPERED"
    is_tampered_valid, tampered_computed, tampered_explanation = verify_evidence_integrity(tampered_payload, hash_1)
    assert is_tampered_valid is False, "Tampered payload must fail verification"
    assert tampered_computed != hash_1
    print(f"[PASS] Tamper detection successfully triggered: {tampered_explanation}")

    # 6. Provenance Record Construction: Observed Data vs Analytical Conclusion
    prov = build_evidence_provenance(
        evidence_id="EV-001",
        raw_observed_payload=payload_a,
        source_origin="SYNTHETIC_COMMUNITY_REPO_01",
        observation_timestamp="2026-09-01 09:20",
        admiralty_reliability="A - Completely Reliable",
        admiralty_credibility="1 - Confirmed by Other Sources"
    )

    # Validate against Pydantic model
    validated_record = EvidenceProvenanceRecord(**prov)
    assert validated_record.evidence_id == "EV-001"
    assert validated_record.sha256_hash == hash_1

    # Verify clear distinction between observed raw data and analytical conclusion
    assert prov["observed_data"]["is_raw_artifact"] is True
    assert prov["observed_data"]["raw_payload"]["identifier"] == "ShadowX2"

    assert prov["analytical_conclusion"]["is_analytical_inference"] is True
    assert "safety_disclaimer" in prov["analytical_conclusion"]["assessment"]
    print("[PASS] Provenance record strictly separates raw observed data from analytical conclusions.")

    print("\nALL PHASE 4 STEP 1 TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_phase4_step1_tests()
