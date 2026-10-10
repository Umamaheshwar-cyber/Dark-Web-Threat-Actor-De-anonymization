"""
SHADOWTRACE — Phase 4 Step 5: Final Integration & Verification Test Suite
Verifies that all Phase 4 components (provenance, integrity, audit logging, STIX export,
investigation reporting) work correctly together across all three synthetic cases.

Tests case isolation, cross-component data consistency, and end-to-end Phase 4 workflows.
Strictly offline, standard-library-only, synthetic demo data only.
No dark-web, Tor, real-person identification, or external network access.
"""

import sys
import os
import tempfile
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.data_store import (
    load_raw_data,
    get_actors_data,
    get_evidence_data,
    get_timeline_data,
    get_graph_data,
    DEFAULT_CASE_ID,
    list_cases,
)
from backend.provenance import (
    generate_evidence_hash,
    verify_evidence_integrity,
    build_evidence_provenance,
)
from backend.audit import record_audit_event, query_audit_events, sanitize_audit_details
from backend.stix_export import export_case_to_stix
from backend.reporting import generate_investigation_report, generate_investigation_report_markdown
from backend.correlation_engine import compute_multi_signal_correlation, compute_opsec_exposure_evaluation

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
# GROUP 1: Case Isolation — no actor/evidence bleed between cases
# ---------------------------------------------------------------------------

def test_case_isolation():
    print("\n--- [GROUP 1] Case Isolation ---")

    actor_id_sets = {}
    evidence_id_sets = {}
    evidence_identifier_sets = {}

    for cid in SYNTHETIC_CASES:
        actors = get_actors_data(cid)
        evidence = get_evidence_data(cid)
        actor_id_sets[cid] = {a["id"] for a in actors}
        evidence_id_sets[cid] = {e["id"] for e in evidence}
        evidence_identifier_sets[cid] = {e["identifier"] for e in evidence}

    # Verify actor ID disjointness across all case pairs
    case_list = SYNTHETIC_CASES
    for i in range(len(case_list)):
        for j in range(i + 1, len(case_list)):
            ca, cb = case_list[i], case_list[j]
            overlap_actors = actor_id_sets[ca] & actor_id_sets[cb]
            check(
                f"Actor IDs fully disjoint: {ca} vs {cb}",
                len(overlap_actors) == 0,
                f"Overlapping actor IDs: {overlap_actors}"
            )
            overlap_ev = evidence_id_sets[ca] & evidence_id_sets[cb]
            check(
                f"Evidence IDs fully disjoint: {ca} vs {cb}",
                len(overlap_ev) == 0,
                f"Overlapping evidence IDs: {overlap_ev}"
            )
            overlap_ident = evidence_identifier_sets[ca] & evidence_identifier_sets[cb]
            check(
                f"Evidence identifiers fully disjoint: {ca} vs {cb}",
                len(overlap_ident) == 0,
                f"Overlapping identifiers: {overlap_ident}"
            )


# ---------------------------------------------------------------------------
# GROUP 2: Evidence Integrity — SHA-256 hashes verify for all cases
# ---------------------------------------------------------------------------

def test_evidence_integrity_all_cases():
    print("\n--- [GROUP 2] Evidence Integrity Verification (All Cases) ---")

    for cid in SYNTHETIC_CASES:
        evidence = get_evidence_data(cid)
        check(
            f"{cid}: Evidence list is non-empty",
            len(evidence) > 0,
            f"Expected >0 items, got {len(evidence)}"
        )

        all_verified = True
        for ev in evidence:
            sha = generate_evidence_hash(ev)
            ok, computed, msg = verify_evidence_integrity(ev, sha)
            if not ok:
                all_verified = False
                print(f"  [!] Integrity failure for {ev.get('id')}: {msg}")

        check(
            f"{cid}: All {len(evidence)} evidence items pass SHA-256 self-verification",
            all_verified
        )

        # Cross-case hash isolation: hash of item from case A should NOT equal hash from case B
        if cid != "CASE-2026-09X":
            ref_evidence = get_evidence_data("CASE-2026-09X")
            hashes_cid = {generate_evidence_hash(e) for e in evidence}
            hashes_ref = {generate_evidence_hash(e) for e in ref_evidence}
            overlap_hashes = hashes_cid & hashes_ref
            check(
                f"{cid}: SHA-256 hashes are distinct from CASE-2026-09X (no payload collision)",
                len(overlap_hashes) == 0,
                f"Overlapping hashes: {overlap_hashes}"
            )


# ---------------------------------------------------------------------------
# GROUP 3: Provenance — build_evidence_provenance correctly separates
#          observed data from analytical conclusions for all cases
# ---------------------------------------------------------------------------

def test_provenance_structure_all_cases():
    print("\n--- [GROUP 3] Evidence Provenance Integrity (All Cases) ---")

    for cid in SYNTHETIC_CASES:
        evidence = get_evidence_data(cid)
        for ev in evidence[:2]:  # Sample first 2 items per case
            prov = build_evidence_provenance(
                evidence_id=ev["id"],
                raw_observed_payload=ev,
                source_origin="INTEGRATION_TEST_SYNTHETIC",
                observation_timestamp=ev.get("timestamp", "2026-09-01 00:00")
            )
            eid = ev["id"]

            check(
                f"{cid}/{eid}: Provenance has 'evidence_id'",
                prov.get("evidence_id") == eid
            )
            check(
                f"{cid}/{eid}: Provenance has valid 64-char SHA-256",
                isinstance(prov.get("sha256_hash"), str) and len(prov["sha256_hash"]) == 64
            )
            check(
                f"{cid}/{eid}: observed_data.is_raw_artifact is True",
                prov.get("observed_data", {}).get("is_raw_artifact") is True
            )
            check(
                f"{cid}/{eid}: analytical_conclusion.is_analytical_inference is True",
                prov.get("analytical_conclusion", {}).get("is_analytical_inference") is True
            )
            # Ensure the provenance hash matches a fresh re-computation
            fresh_hash = generate_evidence_hash(ev)
            check(
                f"{cid}/{eid}: Provenance hash matches independent re-computation",
                prov["sha256_hash"] == fresh_hash
            )


# ---------------------------------------------------------------------------
# GROUP 4: Audit Logging — events are case-scoped; queries isolate correctly
# ---------------------------------------------------------------------------

def test_audit_logging_case_isolation():
    print("\n--- [GROUP 4] Audit Log Case Isolation ---")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tf:
        tmp_path = Path(tf.name)

    try:
        # Record events for each case
        for cid in SYNTHETIC_CASES:
            for action in ("CASE_SWITCH", "EVIDENCE_VIEW"):
                record_audit_event(
                    action=action,
                    case_id=cid,
                    status="SUCCESS",
                    target_entity_id="INTEGRATION-TEST",
                    operator="demo-analyst",
                    details={"context": "Phase 4 Step 5 integration test"},
                    log_file=tmp_path
                )

        # Verify each case's events are correctly filtered
        for cid in SYNTHETIC_CASES:
            events = query_audit_events(case_id=cid, log_file=tmp_path)
            check(
                f"{cid}: audit query returns exactly 2 events",
                len(events) == 2,
                f"Got {len(events)}"
            )
            other_cases = [c for c in SYNTHETIC_CASES if c != cid]
            for ev in events:
                check(
                    f"{cid}: audit event case_id is '{cid}', not a different case",
                    ev["case_id"] == cid and ev["case_id"] not in other_cases,
                    f"Got case_id={ev.get('case_id')}"
                )

        # Verify action filtering
        switch_events = query_audit_events(action="CASE_SWITCH", log_file=tmp_path)
        check(
            f"Action filter CASE_SWITCH returns exactly 3 events (one per case)",
            len(switch_events) == 3,
            f"Got {len(switch_events)}"
        )
        check(
            "All filtered events have action=CASE_SWITCH",
            all(e["action"] == "CASE_SWITCH" for e in switch_events)
        )

        # Verify operator is demo-analyst (not a personal name)
        all_events = query_audit_events(log_file=tmp_path)
        check(
            "All audit events use 'demo-analyst' operator",
            all(e["operator"] == "demo-analyst" for e in all_events)
        )

        # Verify credential stripping
        leaked = record_audit_event(
            action="SEARCH",
            case_id="CASE-2026-09X",
            details={"query": "shadowx", "password": "hunter2", "token": "abc123"},
            log_file=tmp_path
        )
        check(
            "Audit sanitization strips 'password' from details",
            "password" not in leaked.get("details", {})
        )
        check(
            "Audit sanitization strips 'token' from details",
            "token" not in leaked.get("details", {})
        )
        check(
            "Audit sanitization preserves safe keys ('query')",
            "query" in leaked.get("details", {})
        )
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# GROUP 5: STIX Export — bundle case isolation & object count consistency
# ---------------------------------------------------------------------------

def test_stix_export_case_isolation():
    print("\n--- [GROUP 5] STIX 2.1 Export Case Isolation ---")

    bundles = {}
    for cid in SYNTHETIC_CASES:
        bundle = export_case_to_stix(cid)
        bundles[cid] = bundle
        actors = get_actors_data(cid)

        check(
            f"{cid}: STIX bundle type is 'bundle'",
            bundle.get("type") == "bundle"
        )
        check(
            f"{cid}: STIX bundle ID starts with 'bundle--'",
            bundle.get("id", "").startswith("bundle--")
        )
        check(
            f"{cid}: STIX objects list is non-empty",
            len(bundle.get("objects", [])) > 0
        )

        # Verify actor names appear in threat-actor objects — and only for this case
        threat_actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
        ta_names = {ta["name"] for ta in threat_actors}
        case_actor_names = {a["name"] for a in actors}
        check(
            f"{cid}: Threat-actor objects match case actors",
            ta_names == case_actor_names,
            f"Expected {case_actor_names}, got {ta_names}"
        )

        # Verify every object has spec_version 2.1
        versioned = [o for o in bundle["objects"] if "spec_version" in o]
        bad_version = [o for o in versioned if o["spec_version"] != "2.1"]
        check(
            f"{cid}: All versioned STIX objects have spec_version='2.1'",
            len(bad_version) == 0,
            f"{len(bad_version)} objects have wrong version"
        )

        # Verify safety labels on all objects
        labeled_objects = [o for o in bundle["objects"] if "labels" in o]
        missing_safety = [
            o["id"] for o in labeled_objects
            if "synthetic-demo-data" not in o.get("labels", [])
        ]
        check(
            f"{cid}: All labeled STIX objects carry 'synthetic-demo-data' label",
            len(missing_safety) == 0,
            f"Missing label on: {missing_safety[:3]}"
        )

    # Verify bundle IDs are distinct across cases (no UUID collision)
    bundle_ids = [b["id"] for b in bundles.values()]
    check(
        "All three STIX bundle IDs are distinct",
        len(set(bundle_ids)) == 3,
        f"IDs: {bundle_ids}"
    )

    # Verify actor STIX IDs are fully disjoint across bundles
    actor_stix_ids = {}
    for cid, bundle in bundles.items():
        actor_stix_ids[cid] = {
            o["id"] for o in bundle["objects"] if o["type"] == "threat-actor"
        }
    for i in range(len(SYNTHETIC_CASES)):
        for j in range(i + 1, len(SYNTHETIC_CASES)):
            ca, cb = SYNTHETIC_CASES[i], SYNTHETIC_CASES[j]
            overlap = actor_stix_ids[ca] & actor_stix_ids[cb]
            check(
                f"STIX threat-actor IDs disjoint: {ca} vs {cb}",
                len(overlap) == 0,
                f"Overlap: {overlap}"
            )


# ---------------------------------------------------------------------------
# GROUP 6: Investigation Report — data consistency with source data
# ---------------------------------------------------------------------------

def test_report_data_consistency():
    print("\n--- [GROUP 6] Investigation Report Data Consistency ---")

    for cid in SYNTHETIC_CASES:
        actors_raw = get_actors_data(cid)
        evidence_raw = get_evidence_data(cid)
        timeline_raw = get_timeline_data(cid)

        report = generate_investigation_report(cid)

        # Actor count matches
        check(
            f"{cid}: Report actor count matches data store ({len(actors_raw)})",
            len(report["actors"]) == len(actors_raw),
            f"Report has {len(report['actors'])}"
        )

        # Actor IDs in report match data store IDs exactly
        report_actor_ids = {a["actor_id"] for a in report["actors"]}
        raw_actor_ids = {a["id"] for a in actors_raw}
        check(
            f"{cid}: Report actor IDs exactly match data store",
            report_actor_ids == raw_actor_ids,
            f"Report: {report_actor_ids} | Store: {raw_actor_ids}"
        )

        # Evidence count matches
        check(
            f"{cid}: Report evidence count matches data store ({len(evidence_raw)})",
            len(report["evidence_summary"]) == len(evidence_raw),
            f"Report has {len(report['evidence_summary'])}"
        )

        # Evidence IDs in report match data store
        report_ev_ids = {e["evidence_id"] for e in report["evidence_summary"]}
        raw_ev_ids = {e["id"] for e in evidence_raw}
        check(
            f"{cid}: Report evidence IDs exactly match data store",
            report_ev_ids == raw_ev_ids,
            f"Report: {report_ev_ids} | Store: {raw_ev_ids}"
        )

        # Timeline count matches
        check(
            f"{cid}: Report timeline count matches data store ({len(timeline_raw)})",
            len(report["timeline"]) == len(timeline_raw),
            f"Report has {len(report['timeline'])}"
        )

        # Correlation analysis is present
        check(
            f"{cid}: Report includes correlation analysis",
            report["correlation_analysis"] is not None
        )
        corr = report["correlation_analysis"]
        check(
            f"{cid}: Correlation overall_confidence is a positive float",
            isinstance(corr.get("overall_correlation_confidence"), float)
            and corr["overall_correlation_confidence"] > 0
        )
        check(
            f"{cid}: Correlation disclaimer present",
            "NOT proof of real-world identity" in corr.get("disclaimer", "")
        )

        # OPSEC report is present
        check(
            f"{cid}: Report includes OPSEC exposure indicators",
            report["opsec_exposure_indicators"] is not None
        )
        opsec = report["opsec_exposure_indicators"]
        score = opsec.get("current_exposure_score")
        check(
            f"{cid}: OPSEC exposure score is integer in [0, 100]",
            isinstance(score, int) and 0 <= score <= 100,
            f"Got {score}"
        )

        # Safety classification is present
        sc = report.get("safety_classification", {})
        check(
            f"{cid}: Safety classification is SYNTHETIC_DEMO_DATA",
            sc.get("data_mode") == "SYNTHETIC_DEMO_DATA"
        )

        # Limitations list is non-empty
        check(
            f"{cid}: Limitations list has at least 6 items",
            len(report.get("limitations", [])) >= 6
        )


# ---------------------------------------------------------------------------
# GROUP 7: Cross-component consistency — report vs STIX vs raw data
# ---------------------------------------------------------------------------

def test_cross_component_consistency():
    print("\n--- [GROUP 7] Cross-Component Consistency (Report <-> STIX <-> Data Store) ---")

    for cid in SYNTHETIC_CASES:
        actors_raw = get_actors_data(cid)
        evidence_raw = get_evidence_data(cid)

        report = generate_investigation_report(cid)
        bundle = export_case_to_stix(cid)

        # Actor names in report match actor names in STIX
        report_actor_names = {a["synthetic_name"] for a in report["actors"]}
        stix_actor_names = {
            o["name"] for o in bundle["objects"] if o["type"] == "threat-actor"
        }
        check(
            f"{cid}: Report actor names match STIX threat-actor names",
            report_actor_names == stix_actor_names,
            f"Report: {report_actor_names} | STIX: {stix_actor_names}"
        )

        # Evidence IDs appear in both report and STIX (via custom properties)
        report_ev_ids = {e["evidence_id"] for e in report["evidence_summary"]}
        stix_ev_ids = {
            o.get("custom_properties", {}).get("x_shadowtrace_evidence_id")
            for o in bundle["objects"]
            if o["type"] == "observed-data"
        }
        check(
            f"{cid}: Report evidence IDs match STIX observed-data evidence IDs",
            report_ev_ids == stix_ev_ids,
            f"Report: {report_ev_ids} | STIX: {stix_ev_ids}"
        )

        # Correlation score in report is consistent with direct engine call
        primary_actor = actors_raw[0]
        direct_corr = compute_multi_signal_correlation(primary_actor, evidence_raw, get_timeline_data(cid))
        report_corr_confidence = report["correlation_analysis"]["overall_correlation_confidence"]
        direct_corr_confidence = direct_corr["overall_confidence"]
        check(
            f"{cid}: Report correlation score matches direct engine call ({direct_corr_confidence}%)",
            abs(report_corr_confidence - direct_corr_confidence) < 0.01,
            f"Report: {report_corr_confidence} vs Direct: {direct_corr_confidence}"
        )

        # OPSEC score in report is consistent with direct engine call
        raw_opsec = load_raw_data(cid).get("opsec", {})
        direct_opsec = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)
        report_opsec_score = report["opsec_exposure_indicators"]["current_exposure_score"]
        direct_opsec_score = direct_opsec["current_exposure_score"]
        check(
            f"{cid}: Report OPSEC score matches direct engine call ({direct_opsec_score})",
            report_opsec_score == direct_opsec_score,
            f"Report: {report_opsec_score} vs Direct: {direct_opsec_score}"
        )

        # Evidence SHA-256 hashes in report match independent computation
        for ev_item in report["evidence_summary"]:
            eid = ev_item["evidence_id"]
            raw_ev = next((e for e in evidence_raw if e["id"] == eid), None)
            if raw_ev is None:
                check(f"{cid}/{eid}: Raw evidence found in store", False, "Not found")
                continue
            independent_hash = generate_evidence_hash(raw_ev)
            report_hash = ev_item["observed_data"]["sha256_integrity_hash"]
            check(
                f"{cid}/{eid}: Report SHA-256 hash matches independent computation",
                report_hash == independent_hash,
                f"Report: {report_hash[:16]}… vs Computed: {independent_hash[:16]}…"
            )


# ---------------------------------------------------------------------------
# GROUP 8: Markdown report structural integrity
# ---------------------------------------------------------------------------

def test_markdown_report_structure():
    print("\n--- [GROUP 8] Markdown Report Structural Integrity ---")

    required_sections = [
        "## 1. Executive Case Summary",
        "## 2. Tracked Synthetic Actors",
        "## 3. Evidence Summary",
        "## 4. Multi-Signal Correlation Analysis",
        "## 5. OPSEC",
        "## 6. Relationship Topology",
        "## 7. Investigation Timeline",
        "## 8. Analytical Limitations",
        "## 9. Safety",
    ]

    for cid in SYNTHETIC_CASES:
        md = generate_investigation_report_markdown(cid)
        check(
            f"{cid}: Markdown report is a non-empty string",
            isinstance(md, str) and len(md) > 500
        )
        for section in required_sections:
            check(
                f"{cid}: Markdown contains section '{section[:40]}'",
                section in md,
                f"Missing in output"
            )
        check(
            f"{cid}: Markdown contains safety disclaimer",
            "NOT proof of real-world identity" in md or "not proof of real-world identity" in md.lower()
        )
        check(
            f"{cid}: Markdown contains case ID",
            cid in md
        )


# ---------------------------------------------------------------------------
# GROUP 9: End-to-end Phase 4 workflow per case
# ---------------------------------------------------------------------------

def test_end_to_end_phase4_workflow():
    print("\n--- [GROUP 9] End-to-End Phase 4 Workflow (Per Case) ---")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tf:
        tmp_path = Path(tf.name)

    try:
        for cid in SYNTHETIC_CASES:
            # Step 1: Generate report (triggers provenance & integrity internally)
            report = generate_investigation_report(cid)
            check(f"{cid}: E2E — report generated without exception", report is not None)

            # Step 2: Record REPORT_EXPORT audit event
            audit_ev = record_audit_event(
                action="REPORT_EXPORT",
                case_id=cid,
                status="SUCCESS",
                target_entity_id=f"REPORT-{cid}",
                operator="demo-analyst",
                details={"format": "dict", "sections": 9},
                log_file=tmp_path
            )
            check(
                f"{cid}: E2E — REPORT_EXPORT audit event recorded",
                audit_ev.get("action") == "REPORT_EXPORT" and audit_ev.get("case_id") == cid
            )

            # Step 3: Export to STIX
            bundle = export_case_to_stix(cid)
            check(
                f"{cid}: E2E — STIX bundle exported without exception",
                bundle.get("type") == "bundle"
            )

            # Step 4: Hash-verify all evidence in the case
            evidence_raw = get_evidence_data(cid)
            all_ok = True
            for ev in evidence_raw:
                h = generate_evidence_hash(ev)
                ok, _, _ = verify_evidence_integrity(ev, h)
                if not ok:
                    all_ok = False
            check(f"{cid}: E2E — all evidence items pass integrity verification", all_ok)

            # Step 5: Query audit log and confirm REPORT_EXPORT event is present
            logged = query_audit_events(
                case_id=cid, action="REPORT_EXPORT", log_file=tmp_path
            )
            check(
                f"{cid}: E2E — REPORT_EXPORT event found in audit log",
                any(e["case_id"] == cid and e["action"] == "REPORT_EXPORT" for e in logged)
            )
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# GROUP 10: Safety guardrails — confirm no live/dark-web/Tor functionality
# ---------------------------------------------------------------------------

def test_safety_guardrails():
    print("\n--- [GROUP 10] Safety Guardrails ---")

    import socket

    # Verify no network sockets are created by import of Phase 4 modules
    # (We check that the modules exist and are standard-library-only by inspecting
    # their __file__ attributes and confirming forbidden imports are absent.)
    import backend.provenance as prov_mod
    import backend.audit as audit_mod
    import backend.stix_export as stix_mod
    import backend.reporting as report_mod
    import inspect

    forbidden_modules = {"requests", "urllib3", "aiohttp", "httpx", "stem", "torpy", "scapy"}
    for mod, mod_name in [
        (prov_mod, "provenance"),
        (audit_mod, "audit"),
        (stix_mod, "stix_export"),
        (report_mod, "reporting"),
    ]:
        src = inspect.getsource(mod)
        for bad in forbidden_modules:
            check(
                f"{mod_name}: Does NOT import '{bad}'",
                f"import {bad}" not in src and f"from {bad}" not in src
            )

    # Verify all safety classifications in reports
    for cid in SYNTHETIC_CASES:
        report = generate_investigation_report(cid)
        sc = report.get("safety_classification", {})
        check(
            f"{cid}: safety_classification.data_mode == SYNTHETIC_DEMO_DATA",
            sc.get("data_mode") == "SYNTHETIC_DEMO_DATA"
        )
        check(
            f"{cid}: safety_classification.network_scope == LOCAL_AUTHORIZED_RESEARCH_ONLY",
            sc.get("network_scope") == "LOCAL_AUTHORIZED_RESEARCH_ONLY"
        )

    # Verify STIX bundles carry safety labels on all labeled objects
    for cid in SYNTHETIC_CASES:
        bundle = export_case_to_stix(cid)
        labeled = [o for o in bundle["objects"] if "labels" in o]
        missing = [o["id"] for o in labeled if "synthetic-demo-data" not in o["labels"]]
        check(
            f"{cid}: All STIX labeled objects carry 'synthetic-demo-data'",
            len(missing) == 0,
            f"Missing on: {missing[:3]}"
        )


# ---------------------------------------------------------------------------
# MAIN RUNNER
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("SHADOWTRACE — PHASE 4 STEP 5: FINAL INTEGRATION & VERIFICATION")
    print("=" * 70)
    print(f"Synthetic cases under test: {SYNTHETIC_CASES}")
    print("Offline / standard-library only / no external network access\n")

    test_case_isolation()
    test_evidence_integrity_all_cases()
    test_provenance_structure_all_cases()
    test_audit_logging_case_isolation()
    test_stix_export_case_isolation()
    test_report_data_consistency()
    test_cross_component_consistency()
    test_markdown_report_structure()
    test_end_to_end_phase4_workflow()
    test_safety_guardrails()

    print("\n" + "=" * 70)
    total = PASS + FAIL
    print(f"PHASE 4 STEP 5 INTEGRATION RESULTS: {PASS}/{total} passed, {FAIL} failed.")
    if FAIL == 0:
        print("ALL PHASE 4 STEP 5 INTEGRATION TESTS COMPLETED SUCCESSFULLY!")
    else:
        print(f"WARNING: {FAIL} integration test(s) FAILED — review output above.")
    print("=" * 70)

    sys.exit(0 if FAIL == 0 else 1)
