"""
SHADOWTRACE Automated Test Suite — Phase 4 Step 3
Tests Synthetic STIX 2.1 Export Functionality & STIX Spec Compliance.
"""

import sys
from pathlib import Path
import json
import re

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.stix_export import export_case_to_stix


def run_phase4_step3_tests():
    print("=== RUNNING SHADOWTRACE PHASE 4 STEP 3 TEST SUITE ===")

    cases_to_test = ["CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C"]

    for cid in cases_to_test:
        bundle = export_case_to_stix(cid)
        print(f"\n--- Testing STIX 2.1 Export for {cid} ---")

        # 1. Bundle has type == "bundle"
        assert bundle.get("type") == "bundle", f"Expected type 'bundle', got {bundle.get('type')}"
        print(f"[PASS 1] Bundle type is 'bundle' for {cid}")

        # 2. Bundle ID starts with "bundle--"
        bundle_id = bundle.get("id", "")
        assert bundle_id.startswith("bundle--"), f"Bundle ID must start with 'bundle--', got {bundle_id}"
        assert re.match(r"^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", bundle_id), "Valid UUIDv5 format"
        print(f"[PASS 2] Bundle ID is valid: {bundle_id}")

        # 3. Bundle contains objects
        objects = bundle.get("objects", [])
        assert isinstance(objects, list) and len(objects) > 0, "Bundle must contain non-empty objects list"
        print(f"[PASS 3] Bundle contains {len(objects)} STIX objects for {cid}")

        bundle_object_ids = {obj["id"] for obj in objects}

        # 4. Every object has a valid STIX-style ID ("<type>--<UUID>")
        for obj in objects:
            obj_type = obj.get("type")
            obj_id = obj.get("id", "")
            assert obj_type, "STIX object must have a type"
            assert obj_id.startswith(f"{obj_type}--"), f"Object ID '{obj_id}' must start with '{obj_type}--'"
            assert re.match(rf"^{obj_type}--[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$", obj_id), f"Valid STIX ID format for {obj_id}"
        print(f"[PASS 4] All {len(objects)} objects have valid STIX-style IDs")

        # 5. Every applicable object has spec_version "2.1"
        for obj in objects:
            if obj.get("type") != "bundle":
                assert obj.get("spec_version") == "2.1", f"Expected spec_version '2.1' in {obj['id']}, got {obj.get('spec_version')}"
        print(f"[PASS 5] STIX spec_version '2.1' verified on all objects")

        # 6. Synthetic actor maps to threat-actor
        threat_actors = [obj for obj in objects if obj["type"] == "threat-actor"]
        assert len(threat_actors) > 0, "Bundle must contain at least one threat-actor object"
        for ta in threat_actors:
            assert "synthetic" in ta["description"].lower() or "demo" in ta["description"].lower() or "NOT represent a real person" in ta["description"]
            assert "synthetic-demo-data" in ta["labels"]
        print(f"[PASS 6] Threat actor mapped with synthetic disclaimers: {threat_actors[0]['name']}")

        # 7. Case maps to report
        reports = [obj for obj in objects if obj["type"] == "report"]
        assert len(reports) == 1, "Bundle must contain exactly one report object representing the case"
        rep = reports[0]
        assert cid in rep["name"] or cid in rep["description"]
        assert "published" in rep
        assert len(rep["object_refs"]) > 0
        print(f"[PASS 7] Case mapped to STIX report object with {len(rep['object_refs'])} object refs")

        # 8. Evidence maps to observed-data
        observed_data_objs = [obj for obj in objects if obj["type"] == "observed-data"]
        assert len(observed_data_objs) > 0, "Bundle must contain observed-data objects"
        for obs in observed_data_objs:
            assert "first_observed" in obs and "last_observed" in obs
            assert "objects" in obs
        print(f"[PASS 8] Evidence records mapped to {len(observed_data_objs)} observed-data objects")

        # 9. Indicators contain pattern, pattern_type, valid_from
        indicators = [obj for obj in objects if obj["type"] == "indicator"]
        print(f"[PASS 9] Generated {len(indicators)} STIX indicator objects")
        for ind in indicators:
            assert "pattern" in ind and ind["pattern_type"] == "stix"
            assert "valid_from" in ind

        # 10. Relationships reference only objects present in the bundle
        relationships = [obj for obj in objects if obj["type"] == "relationship"]
        print(f"[PASS 10] Validating {len(relationships)} relationship objects")
        for rel in relationships:
            assert rel["source_ref"] in bundle_object_ids, f"Source ref {rel['source_ref']} missing from bundle"
            assert rel["target_ref"] in bundle_object_ids, f"Target ref {rel['target_ref']} missing from bundle"
            assert rel["relationship_type"] in ("related-to", "uses", "indicates")

        # 11. Synthetic safety labels are present
        for obj in objects:
            labels = obj.get("labels", [])
            assert "synthetic-demo-data" in labels or "defensive-research-prototype" in labels, f"Safety labels missing in {obj['id']}"
        print(f"[PASS 11] Synthetic safety labels present across all objects")

        # 12. Analytical confidence is not represented as proof of identity
        for ta in threat_actors:
            assert "not represent a real person" in ta["description"].lower()
        print(f"[PASS 12] Analytical signals explicitly marked as non-attributive")

    # 16. Invalid case ID fails cleanly using project's existing error behavior (KeyError)
    try:
        export_case_to_stix("CASE-INVALID-999")
        assert False, "Should have raised KeyError for invalid case ID"
    except KeyError:
        print("\n[PASS 16] Invalid case ID fails cleanly with KeyError")

    print("\nALL PHASE 4 STEP 3 TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_phase4_step3_tests()
