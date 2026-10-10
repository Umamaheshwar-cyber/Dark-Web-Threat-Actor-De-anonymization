from pathlib import Path
import json
from typing import Any, Dict, List, Optional, Set

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CASES_DIR = DATA_DIR / "cases"
DEFAULT_DATA_FILE = CASES_DIR / "case_authorized_misp.json"
CIRCL_STATE_FILE = DATA_DIR / "circl_feed_state.json"

DEFAULT_CASE_ID = "CASE-AUTH-MISP"

# Production case registry (real / authorized cases only)
CASE_FILES: Dict[str, Path] = {
    "CASE-AUTH-MISP": CASES_DIR / "case_authorized_misp.json",
}

DEFAULT_CIRCL_SYNC_STATE: Dict[str, Any] = {
    "processed_event_uuids": [],
    "last_poll_timestamp": None,
    "last_poll_status": "UNINITIALIZED",
    "total_events_processed": 0,
    "total_evidence_imported": 0
}

def load_circl_sync_state() -> Dict[str, Any]:
    """Load persistent CIRCL feed synchronization state from data/circl_feed_state.json."""
    if not CIRCL_STATE_FILE.exists():
        return dict(DEFAULT_CIRCL_SYNC_STATE)
    try:
        with CIRCL_STATE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return dict(DEFAULT_CIRCL_SYNC_STATE)
            return {
                "processed_event_uuids": list(data.get("processed_event_uuids", [])),
                "last_poll_timestamp": data.get("last_poll_timestamp"),
                "last_poll_status": data.get("last_poll_status", "UNINITIALIZED"),
                "total_events_processed": int(data.get("total_events_processed", 0)),
                "total_evidence_imported": int(data.get("total_evidence_imported", 0))
            }
    except Exception:
        return dict(DEFAULT_CIRCL_SYNC_STATE)

def save_circl_sync_state(state: Dict[str, Any]) -> None:
    """Persist CIRCL feed synchronization state to data/circl_feed_state.json."""
    clean_state = {
        "processed_event_uuids": sorted(list(set(state.get("processed_event_uuids", [])))),
        "last_poll_timestamp": state.get("last_poll_timestamp"),
        "last_poll_status": str(state.get("last_poll_status", "SUCCESS")),
        "total_events_processed": int(state.get("total_events_processed", 0)),
        "total_evidence_imported": int(state.get("total_evidence_imported", 0))
    }
    with CIRCL_STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(clean_state, f, indent=2, ensure_ascii=False)

def get_tracked_circl_uuids() -> Set[str]:
    """
    Retrieve all CIRCL event identifiers already tracked or present in the platform.
    Combines:
    1. Full UUIDs tracked in data/circl_feed_state.json
    2. Event UUID prefixes from existing evidence records in CASE-AUTH-MISP (e.g. CIRCL-EV-{uuid[:8]}-*)
    """
    state = load_circl_sync_state()
    tracked = {str(u).strip().lower() for u in state.get("processed_event_uuids", []) if u}

    # Inspect CASE-AUTH-MISP for any CIRCL-EV-* indicators previously imported
    auth_file = CASES_DIR / "case_authorized_misp.json"
    if auth_file.exists():
        try:
            with auth_file.open("r", encoding="utf-8") as f:
                cdata = json.load(f)
            for ev in cdata.get("evidence", []):
                ev_id = str(ev.get("id", ""))
                if ev_id.startswith("CIRCL-EV-"):
                    parts = ev_id.split("-")
                    if len(parts) >= 3:
                        tracked.add(parts[2].strip().lower())
        except Exception:
            pass

    return tracked

def append_authorized_misp_evidence(evidence_records: List[Dict[str, Any]]) -> int:
    """
    Append normalized MISP evidence records specifically to the isolated authorized container
    (data/cases/case_authorized_misp.json). Never touches synthetic case files.
    """
    auth_file = CASES_DIR / "case_authorized_misp.json"
    if not auth_file.exists():
        return 0
    try:
        with auth_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        
        existing_ids = {e["id"] for e in data.get("evidence", [])}
        new_records = [r for r in evidence_records if r.get("id") not in existing_ids]
        data["evidence"].extend(new_records)
        data.setdefault("metrics", {})["evidence_records"] = len(data["evidence"])
        
        with auth_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return len(new_records)
    except Exception:
        return 0

def resolve_case_file(case_id: Optional[str] = None) -> Path:
    """Resolve file path for a case ID with strict validation."""
    if not case_id or not isinstance(case_id, str):
        return DEFAULT_DATA_FILE if DEFAULT_DATA_FILE.exists() else CASE_FILES[DEFAULT_CASE_ID]
    
    cid = case_id.strip()
    if cid in CASE_FILES:
        path = CASE_FILES[cid]
        if path.exists():
            return path
        # Fallback to default file if it matches primary ID
        if cid == "CASE-AUTH-MISP" and DEFAULT_DATA_FILE.exists():
            return DEFAULT_DATA_FILE
    
    raise KeyError(f"Case '{case_id}' not found.")

def load_raw_data(case_id: Optional[str] = None) -> Dict[str, Any]:
    """Load raw dataset for a given case."""
    target_file = resolve_case_file(case_id)
    with target_file.open("r", encoding="utf-8") as f:
        return json.load(f)

def list_cases() -> List[Dict[str, Any]]:
    """List summary metadata for registered production cases."""
    distinct_ids = [DEFAULT_CASE_ID]
    summaries = []
    for cid in distinct_ids:
        try:
            data = load_raw_data(cid)
            c = data.get("case", {})
            m = data.get("metrics", {})
            summaries.append({
                "id": c.get("id", cid),
                "candidate": c.get("candidate", "Unknown"),
                "status": c.get("status", "ACTIVE"),
                "classification": c.get("classification", "AUTHORIZED CTI INTELLIGENCE"),
                "description": c.get("description", ""),
                "active_actors": m.get("active_actors", len(data.get("actors", []))),
                "evidence_records": m.get("evidence_records", len(data.get("evidence", [])))
            })
        except Exception:
            continue
    return summaries

def get_case_data(case_id: Optional[str] = None) -> Dict[str, Any]:
    return load_raw_data(case_id)["case"]

def get_actors_data(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return load_raw_data(case_id)["actors"]

def get_actor_by_id(actor_id: str, case_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    actors = get_actors_data(case_id)
    return next((a for a in actors if a["id"] == actor_id), None)

def get_evidence_data(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return load_raw_data(case_id)["evidence"]

def get_timeline_data(case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return load_raw_data(case_id)["timeline"]

def get_graph_data(case_id: Optional[str] = None) -> Dict[str, Any]:
    return load_raw_data(case_id)["graph"]

def get_opsec_by_actor(actor_id: str, case_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    data = load_raw_data(case_id)["opsec"]
    if data.get("actor_id") == actor_id:
        return data
    return None

def get_metrics_data(case_id: Optional[str] = None) -> Dict[str, Any]:
    return load_raw_data(case_id)["metrics"]

def search_synthetic_data(query: str, case_id: Optional[str] = None) -> List[Dict[str, str]]:
    q = query.strip().lower()
    if not q:
        return []
    
    data = load_raw_data(case_id)
    results: List[Dict[str, str]] = []

    for actor in data.get("actors", []):
        haystack = json.dumps(actor).lower()
        if q in haystack:
            results.append({
                "kind": "ACTOR",
                "id": actor["id"],
                "title": actor["name"]
            })

    for item in data.get("evidence", []):
        haystack = json.dumps(item).lower()
        if q in haystack:
            results.append({
                "kind": "EVIDENCE",
                "id": item["id"],
                "title": item["identifier"]
            })

    for node in data.get("graph", {}).get("nodes", []):
        if q in node["id"].lower():
            results.append({
                "kind": node["type"].upper(),
                "id": node["id"],
                "title": node["id"]
            })

    return results[:20]

def get_node_details(node_id: str, case_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve deep-dive metadata, connected relationships, and correlated evidence for a graph node."""
    data = load_raw_data(case_id)
    graph = data.get("graph", {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    evidence_list = data.get("evidence", [])
    actors_list = data.get("actors", [])
    cid = data.get("case", {}).get("id", DEFAULT_CASE_ID)

    target_node = next((n for n in nodes if n["id"].lower() == node_id.strip().lower()), None)
    if not target_node:
        return None

    # Find connected edges
    connected_edges = []
    neighbor_ids = set()
    for edge in edges:
        if edge["source"].lower() == target_node["id"].lower():
            connected_edges.append(edge)
            neighbor_ids.add(edge["target"])
        elif edge["target"].lower() == target_node["id"].lower():
            connected_edges.append(edge)
            neighbor_ids.add(edge["source"])

    # Resolve neighbors
    neighbor_nodes = []
    for nid in neighbor_ids:
        neighbor_obj = next((n for n in nodes if n["id"].lower() == nid.lower()), None)
        if neighbor_obj:
            neighbor_nodes.append({"id": neighbor_obj["id"], "type": neighbor_obj["type"]})

    # Find related evidence
    related_evidence = []
    target_clean = target_node["id"].lower()
    for ev in evidence_list:
        if (ev.get("identifier", "").lower() == target_clean or
            ev.get("id", "").lower() == target_clean or
            target_clean in ev.get("relationship", "").lower()):
            related_evidence.append(ev)

    # Check if this node corresponds to an actor for extra properties
    matched_actor = next((a for a in actors_list if a["name"].lower() == target_clean or a["id"].lower() == target_clean), None)
    properties = {
        "x": target_node.get("x"),
        "y": target_node.get("y")
    }
    if matched_actor:
        properties["actor_id"] = matched_actor["id"]
        properties["tier"] = matched_actor["tier"]
        properties["confidence"] = matched_actor["confidence"]
        properties["pgp"] = matched_actor["pgp"]
        properties["wallet"] = matched_actor["wallet"]
        properties["aliases"] = matched_actor["aliases"]

    return {
        "id": target_node["id"],
        "type": target_node["type"],
        "case_id": cid,
        "properties": properties,
        "connected_edges": connected_edges,
        "neighbor_nodes": neighbor_nodes,
        "related_evidence": related_evidence
    }
