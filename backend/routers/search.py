from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from backend.models import SearchResponse
from backend.data_store import search_synthetic_data

router = APIRouter(prefix="/api/search", tags=["search"])

@router.get("", response_model=SearchResponse)
def search(
    q: str = "",
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """Perform multi-entity search across synthetic actors, evidence, and graph nodes."""
    try:
        results = search_synthetic_data(q, case_id)
        return {"query": q, "results": results}
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
