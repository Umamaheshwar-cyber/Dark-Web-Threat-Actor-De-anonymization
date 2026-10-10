"""
SHADOWTRACE — Evidence Integrity & Provenance Core (Phase 4 Step 1)
Defensive cybersecurity research prototype using synthetic intelligence artifacts only.
Provides deterministic canonical hashing (SHA-256) and provenance metadata tracking.
Strictly local and offline: no external network calls, no real-person identification.
"""

import hashlib
import json
from typing import Any, Dict, Optional, Tuple


def canonicalize_evidence_payload(payload: Dict[str, Any]) -> bytes:
    """
    Produce a deterministic byte representation of an evidence record.
    Filters out volatile/derived integrity keys (e.g. 'sha256') and sorts all keys recursively.
    """
    clean_dict = {
        k: v for k, v in payload.items()
        if k not in ("sha256", "sha256_hash", "integrity_status")
    }
    # Deterministic JSON encoding: sorted keys, compact separators, UTF-8 encoded
    canonical_json = json.dumps(clean_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical_json.encode("utf-8")


def generate_evidence_hash(payload: Dict[str, Any]) -> str:
    """
    Compute a 64-character lowercase SHA-256 hash from an evidence payload.
    """
    canonical_bytes = canonicalize_evidence_payload(payload)
    return hashlib.sha256(canonical_bytes).hexdigest().lower()


def verify_evidence_integrity(payload: Dict[str, Any], expected_hash: str) -> Tuple[bool, str, str]:
    """
    Verify whether the payload matches an expected SHA-256 hash.
    Returns:
        (is_valid: bool, computed_hash: str, explanation: str)
    """
    computed = generate_evidence_hash(payload)
    expected_clean = expected_hash.strip().lower()
    if computed == expected_clean:
        return True, computed, "Integrity verified: payload matches expected SHA-256 cryptographic digest."
    return False, computed, f"Integrity failure: expected '{expected_clean}', got '{computed}' (tampering detected)."


def build_evidence_provenance(
    evidence_id: str,
    raw_observed_payload: Dict[str, Any],
    source_origin: str,
    observation_timestamp: str,
    collection_metadata: Optional[Dict[str, Any]] = None,
    analytical_conclusion: Optional[Dict[str, Any]] = None,
    admiralty_reliability: str = "A - Completely Reliable",
    admiralty_credibility: str = "1 - Confirmed by Other Sources"
) -> Dict[str, Any]:
    """
    Construct a complete provenance record clearly delineating raw observed artifacts
    from analytical conclusions / hypotheses.
    """
    sha256_hash = generate_evidence_hash(raw_observed_payload)
    
    return {
        "evidence_id": evidence_id,
        "sha256_hash": sha256_hash,
        "observation_timestamp": observation_timestamp,
        "provenance": {
            "source_origin": source_origin,
            "collection_metadata": collection_metadata or {
                "collection_mode": "SYNTHETIC_RESEARCH_FIXTURE",
                "collector_tag": "CTI_DEFENSIVE_PIPELINE",
                "network_scope": "LOCAL_AUTHORIZED_ONLY"
            },
            "admiralty_system": {
                "source_reliability": admiralty_reliability,
                "information_credibility": admiralty_credibility
            }
        },
        # Strict boundary between objective observations and analytical hypotheses
        "observed_data": {
            "is_raw_artifact": True,
            "raw_payload": raw_observed_payload
        },
        "analytical_conclusion": {
            "is_analytical_inference": True,
            "assessment": analytical_conclusion or {
                "relationship": raw_observed_payload.get("relationship", "Observed association"),
                "confidence": raw_observed_payload.get("confidence", "Medium"),
                "status": raw_observed_payload.get("status", "Observed"),
                "safety_disclaimer": "Defensive analytical signal — not proof of real-world identity."
            }
        }
    }
