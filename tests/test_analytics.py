"""
SHADOWTRACE Automated Test Suite — Phase 1 & Phase 2
Tests both unit analytics functions and live API HTTP endpoints.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
import urllib.request
import urllib.error

# 1. Unit Tests for Analytics Engine
from backend.correlation_engine import (
    levenshtein_distance,
    levenshtein_similarity,
    jaro_winkler_similarity,
    ngram_similarity,
    compute_alias_similarity,
    compute_cryptographic_signal,
    compute_temporal_alignment_signal,
    compute_opsec_exposure_evaluation,
    compute_multi_signal_correlation
)

def run_unit_tests():
    print("\n--- [UNIT TESTS] Correlation & Analytics Engine ---")
    
    # Levenshtein
    dist = levenshtein_distance("ShadowX", "ShadowX2")
    assert dist == 1, f"Expected distance 1, got {dist}"
    lev_sim = levenshtein_similarity("ShadowX", "ShadowX2")
    assert round(lev_sim, 3) == 0.875, f"Expected 0.875, got {lev_sim}"
    print("[PASS] Levenshtein Distance & Similarity (ShadowX vs ShadowX2)")

    # Jaro-Winkler
    jw = jaro_winkler_similarity("ShadowX", "ShadowX2")
    assert jw > 0.95, f"Expected Jaro-Winkler > 0.95, got {jw}"
    print(f"[PASS] Jaro-Winkler Prefix Score: {round(jw * 100, 2)}%")

    # N-gram Overlap
    ng = ngram_similarity("ShadowX", "ShadowX2", n=2)
    assert round(ng, 2) == 0.86, f"Expected 0.86, got {round(ng, 2)}"
    print(f"[PASS] 2-Gram Overlap Score: {round(ng * 100, 2)}%")

    # Combined Alias Score
    alias_res = compute_alias_similarity("ShadowX", "ShadowX2")
    assert alias_res["combined_score"] > 88.0, f"Combined score too low: {alias_res['combined_score']}"
    assert "Levenshtein similarity" in alias_res["explanation"]
    print(f"[PASS] Combined Alias Score: {alias_res['combined_score']}% with explanation")

    # Cryptographic signal
    fake_actor = {"id": "ACT-001", "pgp": "PGP-SYN-8F21", "wallet": "WALLET-SYN-441"}
    fake_evidence = [
        {"type": "PGP", "identifier": "PGP-SYN-8F21"},
        {"type": "WALLET", "identifier": "WALLET-SYN-441"}
    ]
    crypto_res = compute_cryptographic_signal(fake_actor, fake_evidence)
    assert crypto_res["score"] == 95.0, f"Expected crypto score 95.0, got {crypto_res['score']}"
    assert crypto_res["pgp_correlated"] is True
    assert crypto_res["wallet_correlated"] is True
    print(f"[PASS] Cryptographic Reuse Score: {crypto_res['score']}%")

    # Multi-signal ensemble
    fake_actor_full = {
        "id": "ACT-001",
        "name": "ShadowX",
        "aliases": ["ShadowX", "ShadowX2"],
        "pgp": "PGP-SYN-8F21",
        "wallet": "WALLET-SYN-441",
        "stylometry": 78,
        "behaviour": 74
    }
    fake_timeline = [
        {"week": "Week 1", "date": "2026-09-01"},
        {"week": "Week 2", "date": "2026-09-08"},
        {"week": "Week 3", "date": "2026-09-15"},
        {"week": "Week 4", "date": "2026-09-22"},
        {"week": "Week 5", "date": "2026-09-29"},
        {"week": "Week 6", "date": "2026-09-30"}
    ]
    ensemble = compute_multi_signal_correlation(fake_actor_full, fake_evidence, fake_timeline)
    assert ensemble["overall_confidence"] >= 80.0
    assert ensemble["confidence_tier"] == "HIGH"
    assert len(ensemble["signals"]) == 5
    print(f"[PASS] Multi-Signal Ensemble for ShadowX: {ensemble['overall_confidence']}% ({ensemble['confidence_tier']})")


def run_api_tests():
    print("\n--- [API TESTS] Live HTTP Endpoint Verification ---")
    base_url = "http://127.0.0.1:8000"

    endpoints = [
        ("Root Shell", "/", 200),
        ("CSS Asset", "/static/style.css", 200),
        ("JS Asset", "/static/app.js", 200),
        ("Health Probe", "/api/health", 200),
        ("Case Endpoint", "/api/case", 200),
        ("Actors List", "/api/actors", 200),
        ("Actor Valid", "/api/actors/ACT-001", 200),
        ("Actor Invalid", "/api/actors/ACT-999", 404),
        ("Evidence List", "/api/evidence", 200),
        ("Timeline List", "/api/timeline", 200),
        ("Graph Dataset", "/api/graph", 200),
        ("Metrics Dataset", "/api/metrics", 200),
        ("Search Endpoint", "/api/search?q=ShadowX", 200),
        # Phase 2 Endpoints
        ("Phase 2 Alias Similarity", "/api/analytics/alias-similarity?s1=ShadowX&s2=ShadowX2", 200),
        ("Phase 2 Actor Correlation (Valid)", "/api/analytics/correlation/ACT-001", 200),
        ("Phase 2 Actor Correlation (Invalid)", "/api/analytics/correlation/ACT-999", 404),
        ("Phase 2 OPSEC Evaluation (Valid)", "/api/analytics/opsec-evaluation/ACT-001", 200),
        ("Phase 2 OPSEC Evaluation (Invalid)", "/api/analytics/opsec-evaluation/ACT-999", 404),
    ]

    passed = 0
    failed = 0

    for name, path, expected_status in endpoints:
        req = urllib.request.Request(f"{base_url}{path}")
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                if status == expected_status:
                    print(f"[PASS] {name} ({path}) -> {status}")
                    passed += 1
                else:
                    print(f"[FAIL] {name} ({path}) -> Expected {expected_status}, got {status}")
                    failed += 1
        except urllib.error.HTTPError as e:
            if e.code == expected_status:
                print(f"[PASS] {name} ({path}) -> {e.code} (Expected Error)")
                passed += 1
            else:
                print(f"[FAIL] {name} ({path}) -> Expected {expected_status}, got {e.code}")
                failed += 1
        except Exception as e:
            print(f"[FAIL] {name} ({path}) -> Exception: {e}")
            failed += 1

    print(f"\nAPI Tests Total: {passed} passed, {failed} failed out of {len(endpoints)} endpoints.")
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    run_unit_tests()
    run_api_tests()
    print("\nALL PHASE 1 & PHASE 2 TESTS EXECUTED SUCCESSFULLY!")
