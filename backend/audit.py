"""
SHADOWTRACE — Lightweight Audit Logging System (Phase 4 Step 2)
Defensive cybersecurity research prototype using synthetic intelligence artifacts only.
Provides an append-only JSONL audit trail for synthetic investigation actions.
Strictly local: no external network calls, no database, no credential storage.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_AUDIT_LOG_FILE = DATA_DIR / "audit_log.jsonl"

DEFAULT_OPERATOR = "demo-analyst"

SUPPORTED_ACTIONS = {
    "CASE_SWITCH",
    "EVIDENCE_VIEW",
    "EVIDENCE_VERIFY",
    "ACTOR_DRILLDOWN",
    "SEARCH",
    "REPORT_EXPORT",
    "FEED_QUERY",
    "FEED_IMPORT",
    "CIRCL_FEED_QUERY",
    "CIRCL_FEED_IMPORT",
    "CIRCL_FEED_POLL"
}

FORBIDDEN_DETAIL_KEYS = {
    "password", "secret", "token", "credential", "private_key", "auth_token", "api_key"
}


def sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sanitize audit details to ensure no secrets, credentials, or tokens are logged.
    """
    if not details:
        return {}
    clean: Dict[str, Any] = {}
    for k, v in details.items():
        k_lower = str(k).lower()
        if any(bad in k_lower for bad in FORBIDDEN_DETAIL_KEYS):
            continue
        clean[k] = v
    return clean


def record_audit_event(
    action: str,
    case_id: str,
    status: str = "SUCCESS",
    target_entity_id: Optional[str] = None,
    operator: str = DEFAULT_OPERATOR,
    details: Optional[Dict[str, Any]] = None,
    log_file: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Record an append-only audit event to a local JSONL log file.
    """
    target_path = log_file or DEFAULT_AUDIT_LOG_FILE
    target_path.parent.mkdir(parents=True, exist_ok=True)

    event_id = f"AUD-{uuid.uuid4().hex[:12].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    clean_details = sanitize_audit_details(details)

    event_record = {
        "event_id": event_id,
        "timestamp": timestamp,
        "action": action.upper(),
        "case_id": case_id,
        "target_entity_id": target_entity_id,
        "operator": operator,
        "status": status.upper(),
        "details": clean_details
    }

    line = json.dumps(event_record, ensure_ascii=False) + "\n"
    with target_path.open("a", encoding="utf-8") as f:
        f.write(line)

    return event_record


def query_audit_events(
    case_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 50,
    log_file: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve and filter recent audit events from the local JSONL log file.
    Returns events in reverse chronological order (newest first).
    """
    target_path = log_file or DEFAULT_AUDIT_LOG_FILE
    if not target_path.exists():
        return []

    records: List[Dict[str, Any]] = []
    with target_path.open("r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                rec = json.loads(line_str)
                records.append(rec)
            except json.JSONDecodeError:
                continue

    # Filter by case_id
    if case_id:
        cid_clean = case_id.strip()
        records = [r for r in records if r.get("case_id") == cid_clean]

    # Filter by action
    if action:
        act_clean = action.strip().upper()
        records = [r for r in records if r.get("action") == act_clean]

    # Reverse chronological (newest first)
    records.reverse()

    if limit > 0:
        return records[:limit]
    return records
