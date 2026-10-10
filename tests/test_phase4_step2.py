"""
SHADOWTRACE Automated Test Suite — Phase 4 Step 2
Tests Lightweight Audit Logging (JSONL, filtering, sanitization, isolation).
"""

import sys
from pathlib import Path
import tempfile
import json
import re

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.audit import (
    record_audit_event,
    query_audit_events,
    sanitize_audit_details,
    DEFAULT_OPERATOR
)
from backend.models import AuditLogEntry


def run_phase4_step2_tests():
    print("=== RUNNING SHADOWTRACE PHASE 4 STEP 2 TEST SUITE ===")

    # Use a temporary file for isolated test persistence
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        temp_log_path = Path(tf.name)

    try:
        # 1. Audit event creation & schema compliance
        ev1 = record_audit_event(
            action="CASE_SWITCH",
            case_id="CASE-2026-09X",
            status="SUCCESS",
            details={"previous_case": "NONE", "new_case": "CASE-2026-09X"},
            log_file=temp_log_path
        )
        assert ev1["event_id"].startswith("AUD-"), f"Event ID must start with AUD-: {ev1['event_id']}"
        assert ev1["operator"] == "demo-analyst", f"Default operator must be demo-analyst, got {ev1['operator']}"
        assert ev1["action"] == "CASE_SWITCH"
        assert ev1["case_id"] == "CASE-2026-09X"
        print("[PASS] Audit event created with required structure and demo operator.")

        # Validate with Pydantic model
        validated_entry = AuditLogEntry(**ev1)
        assert validated_entry.event_id == ev1["event_id"]
        print("[PASS] Audit event validated successfully against AuditLogEntry model.")

        # 2. Unique event IDs and valid ISO timestamp
        ev2 = record_audit_event(
            action="EVIDENCE_VIEW",
            case_id="CASE-2026-09X",
            target_entity_id="EV-001",
            details={"category": "ALIAS"},
            log_file=temp_log_path
        )
        assert ev1["event_id"] != ev2["event_id"], "Event IDs must be unique"
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ev2["timestamp"]), "Timestamp must be ISO 8601"
        print("[PASS] Event IDs are unique and timestamp is valid ISO 8601.")

        # 3. JSONL persistence verification
        with temp_log_path.open("r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        assert len(lines) == 2, f"Expected 2 lines in JSONL file, found {len(lines)}"
        first_line_json = json.loads(lines[0])
        assert first_line_json["event_id"] == ev1["event_id"]
        print("[PASS] JSONL file persistence verified (append-only valid JSON per line).")

        # 4. Record additional events for filtering
        record_audit_event(
            action="ACTOR_DRILLDOWN",
            case_id="CASE-2026-02B",
            target_entity_id="ACT-010",
            details={"candidate": "CipherPhantom"},
            log_file=temp_log_path
        )
        record_audit_event(
            action="SEARCH",
            case_id="CASE-2026-09X",
            details={"query": "ShadowX"},
            log_file=temp_log_path
        )
        record_audit_event(
            action="REPORT_EXPORT",
            case_id="CASE-2026-03C",
            details={"format": "JSON"},
            log_file=temp_log_path
        )

        # 5. Query recent events (reverse chronological)
        all_events = query_audit_events(log_file=temp_log_path)
        assert len(all_events) == 5, f"Expected 5 total events, got {len(all_events)}"
        assert all_events[0]["action"] == "REPORT_EXPORT", "Most recent event must be first"
        print("[PASS] Query returns recent events in reverse chronological order.")

        # 6. Filter by case_id
        c1_events = query_audit_events(case_id="CASE-2026-09X", log_file=temp_log_path)
        assert len(c1_events) == 3, f"Expected 3 events for Case 1, got {len(c1_events)}"
        assert all(e["case_id"] == "CASE-2026-09X" for e in c1_events)
        print("[PASS] Case ID filtering isolates events strictly.")

        # 7. Filter by action
        drilldown_events = query_audit_events(action="ACTOR_DRILLDOWN", log_file=temp_log_path)
        assert len(drilldown_events) == 1, f"Expected 1 drilldown event, got {len(drilldown_events)}"
        assert drilldown_events[0]["target_entity_id"] == "ACT-010"
        print("[PASS] Action filtering verified.")

        # 8. Query limit handling
        limited = query_audit_events(limit=2, log_file=temp_log_path)
        assert len(limited) == 2, f"Expected 2 events with limit=2, got {len(limited)}"
        print("[PASS] Query limit handling verified.")

        # 9. Safety & sanitization: No secrets or credentials in audit logs
        tainted_details = {
            "query": "ShadowX",
            "password": "super_secret_password",
            "auth_token": "bearer_xyz123",
            "private_key": "rsa_priv_key_data",
            "safe_metric": 42
        }
        clean_details = sanitize_audit_details(tainted_details)
        assert "password" not in clean_details
        assert "auth_token" not in clean_details
        assert "private_key" not in clean_details
        assert clean_details["query"] == "ShadowX"
        assert clean_details["safe_metric"] == 42

        ev_sanitized = record_audit_event(
            action="EVIDENCE_VERIFY",
            case_id="CASE-2026-09X",
            details=tainted_details,
            log_file=temp_log_path
        )
        assert "password" not in ev_sanitized["details"]
        assert "auth_token" not in ev_sanitized["details"]
        print("[PASS] Safety enforcement: credential and secret keys stripped from audit log entries.")

    finally:
        if temp_log_path.exists():
            temp_log_path.unlink()

    print("\nALL PHASE 4 STEP 2 TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    run_phase4_step2_tests()
