from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from backend.models import Case, CaseSummary
from backend.data_store import get_case_data, list_cases

router = APIRouter(tags=["cases"])

@router.get("/api/cases", response_model=List[CaseSummary])
def get_cases():
    """List all registered synthetic demo cases."""
    return list_cases()

@router.get("/api/cases/{case_id}", response_model=Case)
def get_case_by_id(case_id: str):
    """Retrieve metadata for a specific synthetic case."""
    try:
        return get_case_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

@router.get("/api/case", response_model=Case)
def get_case(case_id: Optional[str] = Query(None, description="Case identifier (defaults to primary CASE-AUTH-MISP)")):
    """Retrieve case metadata (defaults to primary CASE-AUTH-MISP)."""
    try:
        return get_case_data(case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
