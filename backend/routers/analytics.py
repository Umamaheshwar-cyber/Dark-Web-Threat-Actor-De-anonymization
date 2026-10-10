from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models import (
    TimelineEvent,
    GraphData,
    GraphNodeDetail,
    OpsecSignal,
    Metrics,
    AliasSimilarityBreakdown,
    CorrelationAssessment,
    OpsecEvaluation
)
from backend.data_store import (
    get_timeline_data,
    get_graph_data,
    get_node_details,
    get_opsec_by_actor,
    get_metrics_data,
    get_actor_by_id,
    get_evidence_data,
    load_raw_data
)
from backend.correlation_engine import (
    compute_alias_similarity,
    compute_opsec_exposure_evaluation,
    compute_multi_signal_correlation
)

router = APIRouter(prefix="/api", tags=["analytics"])

# --- Existing Phase 1 Endpoints (Updated with optional case_id) ---

@router.get("/timeline", response_model=List[TimelineEvent])
def get_timeline(case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")):
    """Retrieve chronological investigation event milestones."""
    try:
        return get_timeline_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

@router.get("/graph", response_model=GraphData)
def get_graph(case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")):
    """Retrieve identity correlation relationship graph nodes and edges."""
    try:
        return get_graph_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

@router.get("/graph/node/{node_id}", response_model=GraphNodeDetail)
def get_node_info(
    node_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """
    Retrieve inspection details for a selected graph node:
    type, attributes, connected relationships, neighbor nodes, and correlated evidence.
    """
    try:
        node_detail = get_node_details(node_id, case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    if not node_detail:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in case graph.")
    return node_detail

@router.get("/opsec/{actor_id}", response_model=OpsecSignal)
def get_opsec(
    actor_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """Retrieve observable OPSEC exposure signals over time for an actor."""
    try:
        opsec = get_opsec_by_actor(actor_id, case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    if not opsec:
        raise HTTPException(status_code=404, detail="OPSEC data not found")
    return opsec

@router.get("/metrics", response_model=Metrics)
def get_metrics(case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")):
    """Retrieve high-level investigation summary metrics."""
    try:
        return get_metrics_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

# --- Phase 2 Analytics & Correlation Engine Endpoints ---

@router.get("/analytics/alias-similarity", response_model=AliasSimilarityBreakdown)
def get_alias_similarity(
    s1: str = Query(..., description="First alias/handle string (e.g. ShadowX)"),
    s2: str = Query(..., description="Second alias/handle string (e.g. ShadowX2)")
):
    """
    Compute multi-algorithm alias similarity between two synthetic candidates.
    Combines Levenshtein similarity, Jaro-Winkler prefix alignment, and 2-gram overlap.
    """
    if not s1.strip() or not s2.strip():
        raise HTTPException(status_code=400, detail="Both candidate alias strings must be non-empty.")
    return compute_alias_similarity(s1.strip(), s2.strip())

@router.get("/analytics/correlation/{actor_id}", response_model=CorrelationAssessment)
def get_actor_correlation(
    actor_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """
    Compute explainable multi-signal correlation assessment for a synthetic actor.
    Ensemble includes: Cryptographic/wallet reuse (35%), Alias similarity (20%),
    Temporal alignment (15%), Stylometry (15%), and Behaviour (15%).
    """
    try:
        actor = get_actor_by_id(actor_id, case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    if not actor:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_id}' not found.")

    evidence = get_evidence_data(case_id)
    timeline = get_timeline_data(case_id)

    assessment = compute_multi_signal_correlation(actor, evidence, timeline)
    return assessment

@router.get("/analytics/opsec-evaluation/{actor_id}", response_model=OpsecEvaluation)
def get_opsec_evaluation(
    actor_id: str,
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """
    Compute dynamic, itemized OPSEC exposure assessment for an actor.
    Breaks down observable operational hygiene mistakes and their score impact.
    """
    try:
        actor = get_actor_by_id(actor_id, case_id)
        raw_data = load_raw_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    
    if not actor:
        raise HTTPException(status_code=404, detail=f"Actor '{actor_id}' not found.")

    raw_opsec = raw_data.get("opsec", {})
    return compute_opsec_exposure_evaluation(actor, raw_opsec)
