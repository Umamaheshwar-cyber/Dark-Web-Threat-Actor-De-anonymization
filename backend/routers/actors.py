from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models import Actor, ActorDrillDown, Evidence, TimelineEvent, GraphNode
from backend.data_store import (
    get_actors_data,
    get_actor_by_id,
    get_evidence_data,
    get_timeline_data,
    get_graph_data,
    load_raw_data,
    DEFAULT_CASE_ID
)
from backend.correlation_engine import (
    compute_multi_signal_correlation,
    compute_opsec_exposure_evaluation
)

router = APIRouter(prefix="/api/actors", tags=["actors"])

@router.get("", response_model=List[Actor])
def get_actors(case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")):
    """Retrieve cataloged synthetic threat actor clusters for a case."""
    try:
        return get_actors_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

@router.get("/{actor_id}", response_model=Actor)
def get_actor(
    actor_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """Retrieve single synthetic threat actor profile by identifier."""
    try:
        actor = get_actor_by_id(actor_id, case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    if not actor:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_id}' not found.")
    return actor

@router.get("/{actor_id}/drilldown", response_model=ActorDrillDown)
def get_actor_drilldown(
    actor_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """
    Retrieve comprehensive actor investigation dossier:
    profile, aliases, connected graph nodes, related evidence, timeline milestones,
    Phase 2 multi-signal correlation assessment, and dynamic OPSEC evaluation.
    """
    try:
        raw_case = load_raw_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    actor = get_actor_by_id(actor_id, case_id)
    if not actor:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_id}' not found in case.")

    cid = raw_case.get("case", {}).get("id", case_id or DEFAULT_CASE_ID)
    evidence_list = get_evidence_data(case_id)
    timeline_list = get_timeline_data(case_id)
    graph_data = get_graph_data(case_id)
    raw_opsec = raw_case.get("opsec", {})

    # Compute Phase 2 Correlation and OPSEC
    correlation = compute_multi_signal_correlation(actor, evidence_list, timeline_list)
    opsec = compute_opsec_exposure_evaluation(actor, raw_opsec)

    # Filter related evidence for this actor
    actor_identifiers = set([actor["id"].lower(), actor["name"].lower()] + [a.lower() for a in actor.get("aliases", [])])
    if actor.get("pgp"):
        actor_identifiers.add(actor["pgp"].lower())
    if actor.get("wallet"):
        actor_identifiers.add(actor["wallet"].lower())

    related_evidence = []
    for ev in evidence_list:
        ident = ev.get("identifier", "").lower()
        rel = ev.get("relationship", "").lower()
        if ident in actor_identifiers or any(ai in rel for ai in actor_identifiers):
            related_evidence.append(ev)

    # Filter timeline items
    related_timeline = []
    for ev in timeline_list:
        detail_lower = ev.get("detail", "").lower()
        title_lower = ev.get("event", "").lower()
        if any(ai in detail_lower or ai in title_lower for ai in actor_identifiers):
            related_timeline.append(ev)
    if not related_timeline:
        related_timeline = timeline_list  # fallback to full timeline if no direct keyword match

    # Filter connected graph nodes
    actor_name_lower = actor["name"].lower()
    connected_node_ids = set([actor["name"]])
    for edge in graph_data.get("edges", []):
        if edge["source"].lower() == actor_name_lower:
            connected_node_ids.add(edge["target"])
        elif edge["target"].lower() == actor_name_lower:
            connected_node_ids.add(edge["source"])

    connected_nodes = [n for n in graph_data.get("nodes", []) if n["id"] in connected_node_ids]

    return {
        "actor": actor,
        "case_id": cid,
        "correlation": correlation,
        "opsec": opsec,
        "related_evidence": related_evidence,
        "related_timeline": related_timeline,
        "connected_nodes": connected_nodes
    }
