"""
SHADOWTRACE Automated Test Suite — Phase 4 Step 4
Tests Investigation Report Generation Core (Structured Dict & Markdown).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.reporting import (
    generate_investigation_report,
    generate_investigation_report_markdown
)
from backend.models import InvestigationReportModel


def run_phase4_step4_tests():
    print("=== RUNNING SHADOWTRACE PHASE 4 STEP 4 TEST SUITE ===")

    cases = ["CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C"]

    # 1-3. Generate report for all 3 synthetic cases
    for cid in cases:
        report_dict = generate_investigation_report(cid)
        print(f"\n--- Testing Report Generation for {cid} ---")

        # 5. Case summary section
        cs = report_dict.get("case_summary", {})
        assert cs.get("case_id") == cid
        assert "disclaimer" in cs and "DEFENSIVE" in cs["disclaimer"].upper()
        print(f"[PASS 5] Case Summary verified for {cid}: Title '{cs.get('title')}'")

        # 6. Actor information section
        actors = report_dict.get("actors", [])
        assert isinstance(actors, list) and len(actors) > 0
        for a in actors:
            assert "actor_id" in a and "synthetic_name" in a
            # 14. Analytical confidence is treated as an analytical signal, not identity proof
            assert "analytical_confidence" in a
            assert "NOT proof" in a.get("confidence_disclaimer", "")
        print(f"[PASS 6] Actor section verified: {len(actors)} actors with non-attributive disclaimers")

        # 7. Evidence information section
        evidence = report_dict.get("evidence_summary", [])
        assert isinstance(evidence, list) and len(evidence) > 0
        for ev in evidence:
            assert "evidence_id" in ev
            assert "category" in ev
            # 15. Delineate observed evidence from analytical conclusions
            obs = ev.get("observed_data", {})
            interp = ev.get("analytical_interpretation", {})
            assert "sha256_integrity_hash" in obs and len(obs["sha256_integrity_hash"]) == 64
            assert interp.get("is_conclusion") is True
            assert "not an observed physical fact" in interp.get("disclaimer", "")
        print(f"[PASS 7 & 15] Evidence section verified: {len(evidence)} items cleanly separating observed data from analytical conclusions.")

        # 8. Relationship information section
        rel = report_dict.get("relationships", [])
        assert isinstance(rel, list) and len(rel) > 0
        for r in rel:
            assert "source" in r and "target" in r and "relationship_type" in r
        print(f"[PASS 8] Relationships section verified: {len(rel)} links")

        # 9. Correlation analysis section
        corr = report_dict.get("correlation_analysis")
        assert corr is not None
        assert "overall_correlation_confidence" in corr
        assert "confidence_tier" in corr
        for sig in corr.get("analytical_signals", []):
            assert sig.get("type") == "Analytical Signal"
        assert "NOT proof" in corr.get("disclaimer", "")
        print(f"[PASS 9 & 14] Correlation analysis verified: Score {corr.get('overall_correlation_confidence')}% explicitly labelled 'Analytical Signal'.")

        # 10. OPSEC/exposure information section
        opsec = report_dict.get("opsec_exposure_indicators")
        assert opsec is not None
        assert "current_exposure_score" in opsec
        assert "exposure_level" in opsec
        assert len(opsec.get("observed_exposure_indicators", [])) > 0
        assert "non-predictive" in opsec.get("predictive_disclaimer", "").lower()
        print(f"[PASS 10] OPSEC exposure section verified: Score {opsec.get('current_exposure_score')}/100 non-predictive.")

        # 11. Timeline section
        timeline = report_dict.get("timeline", [])
        assert isinstance(timeline, list) and len(timeline) > 0
        for t in timeline:
            assert "week" in t and "date" in t and "event" in t and "detail" in t
        print(f"[PASS 11] Timeline section verified: {len(timeline)} milestones")

        # 12. Limitations section
        limitations = report_dict.get("limitations", [])
        assert isinstance(limitations, list) and len(limitations) >= 5
        print(f"[PASS 12] Limitations section verified: {len(limitations)} explicit limitation items")

        # 13. Synthetic/defensive safety classification
        sc = report_dict.get("safety_classification", {})
        assert sc.get("data_mode") == "SYNTHETIC_DEMO_DATA"
        assert sc.get("project_scope") == "DEFENSIVE_RESEARCH_PROTOTYPE"
        print(f"[PASS 13] Safety classification verified: {sc.get('data_mode')}")

        # Validate with Pydantic model
        validated_model = InvestigationReportModel(**report_dict)
        assert validated_model.case_summary["case_id"] == cid
        print(f"[PASS] Pydantic model validation successful for {cid}")

        # 16. Markdown report generation and section headers
        md_text = generate_investigation_report_markdown(cid)
        assert isinstance(md_text, str) and len(md_text) > 500
        required_headers = [
            "# ",
            "## 1. Executive Case Summary",
            "## 2. Tracked Synthetic Actors",
            "## 3. Evidence Summary & Cryptographic Integrity",
            "## 4. Multi-Signal Correlation Analysis",
            "## 5. OPSEC & Exposure Indicators",
            "## 6. Relationship Topology",
            "## 7. Investigation Timeline",
            "## 8. Analytical Limitations",
            "## 9. Safety & Research Classification"
        ]
        for h in required_headers:
            assert h in md_text, f"Missing required Markdown header '{h}' in report for {cid}"
        print(f"[PASS 16] Markdown report generated successfully ({len(md_text)} chars) with all 9 section headers.")

    # 4. Invalid case ID fails cleanly using existing data_store behavior (KeyError)
    try:
        generate_investigation_report("CASE-NONEXISTENT-999")
        assert False, "Should have raised KeyError for invalid case ID"
    except KeyError:
        print("\n[PASS 4] Invalid case ID fails cleanly with KeyError")

    print("\nALL PHASE 4 STEP 4 TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_phase4_step4_tests()
