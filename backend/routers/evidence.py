from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models import Evidence
from backend.data_store import get_evidence_data

router = APIRouter(prefix="/api/evidence", tags=["evidence"])

@router.get("", response_model=List[Evidence])
def get_evidence(case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")):
    """Retrieve cataloged synthetic evidence records for a case."""
    try:
        return get_evidence_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
