from fastapi import APIRouter, HTTPException, Query, Path
from fastapi.responses import PlainTextResponse
from typing import List, Dict, Any, Optional

from backend.models import (
    EvidenceProvenanceRecord,
    AuditLogEntry,
    InvestigationReportModel
)
from backend.data_store import (
    load_raw_data,
    get_evidence_data,
    resolve_case_file
)
from backend.provenance import (
    generate_evidence_hash,
    build_evidence_provenance
)
from backend.audit import (
    record_audit_event,
    query_audit_events
)
from backend.stix_export import export_case_to_stix
from backend.reporting import (
    generate_investigation_report,
    generate_investigation_report_markdown
)

router = APIRouter(tags=["reports"])

@router.get("/api/cases/{case_id}/stix")
def get_case_stix(case_id: str = Path(..., description="Synthetic case identifier")):
    """Export synthetic case to STIX 2.1 JSON Bundle."""
    try:
        resolve_case_file(case_id)
        bundle = export_case_to_stix(case_id)
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="SUCCESS",
            details={"export_type": "stix_2.1"}
        )
        return bundle
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    except Exception as e:
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="FAILURE",
            details={"export_type": "stix_2.1", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/cases/{case_id}/report")
def get_case_report(case_id: str = Path(..., description="Synthetic case identifier")):
    """Generate structured investigation report dictionary (9 sections)."""
    try:
        resolve_case_file(case_id)
        report = generate_investigation_report(case_id)
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="SUCCESS",
            details={"export_type": "json_report"}
        )
        return report
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    except Exception as e:
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="FAILURE",
            details={"export_type": "json_report", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/cases/{case_id}/report/markdown", response_class=PlainTextResponse)
def get_case_report_markdown(case_id: str = Path(..., description="Synthetic case identifier")):
    """Generate professional Markdown investigation briefing."""
    try:
        resolve_case_file(case_id)
        md_text = generate_investigation_report_markdown(case_id)
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="SUCCESS",
            details={"export_type": "markdown_report"}
        )
        return md_text
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    except Exception as e:
        record_audit_event(
            action="REPORT_EXPORT",
            case_id=case_id,
            status="FAILURE",
            details={"export_type": "markdown_report", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/evidence/{evidence_id}/provenance", response_model=EvidenceProvenanceRecord)
def get_evidence_provenance(
    evidence_id: str = Path(..., description="Evidence record identifier"),
    case_id: Optional[str] = Query(None, description="Optional synthetic case identifier")
):
    """Retrieve SHA-256 integrity hash and provenance metadata for an evidence record."""
    try:
        cases_to_check = [case_id] if case_id else ["CASE-2026-09X", "CASE-2026-02B", "CASE-2026-03C", "CASE-AUTH-MISP"]
        target_ev = None
        found_cid = "CASE-2026-09X"

        for cid in cases_to_check:
            try:
                ev_list = get_evidence_data(cid)
                match = next((e for e in ev_list if e.get("id") == evidence_id), None)
                if match:
                    target_ev = match
                    found_cid = cid
                    break
            except Exception:
                continue

        if not target_ev:
            raise HTTPException(status_code=404, detail=f"Evidence record '{evidence_id}' not found.")

        # Differentiate authorized feed provenance metadata from synthetic research fixture metadata
        if found_cid == "CASE-AUTH-MISP" or evidence_id.startswith("MISP-") or evidence_id.startswith("CIRCL-"):
            if evidence_id.startswith("CIRCL-"):
                source_origin = "PUBLIC_CIRCL_MISP_OSINT_FEED"
                collection_meta = {
                    "collection_mode": "PUBLIC_CIRCL_MISP_OSINT_FEED",
                    "target_case_id": found_cid,
                    "network_scope": "PUBLIC_AUTHORIZED_OSINT_FEED",
                    "attribution_policy": "DEFENSIVE_OBSERVABLE_CTI_ONLY"
                }
            else:
                source_origin = "AUTHORIZED_MISP_FEED"
                collection_meta = {
                    "collection_mode": "AUTHORIZED_MISP_REST_API",
                    "target_case_id": found_cid,
                    "network_scope": "AUTHORIZED_EXTERNAL_FEED"
                }
            admiralty_rel = "B - Usually Reliable"
            admiralty_cred = "2 - Probably True"
        else:
            source_origin = "SYNTHETIC_DEMO_REPOSITORY"
            collection_meta = None
            admiralty_rel = "A - Completely Reliable"
            admiralty_cred = "1 - Confirmed by Other Sources"

        provenance_rec = build_evidence_provenance(
            evidence_id=evidence_id,
            raw_observed_payload=target_ev,
            source_origin=source_origin,
            observation_timestamp=target_ev.get("timestamp", "2026-09-01 00:00"),
            collection_metadata=collection_meta,
            admiralty_reliability=admiralty_rel,
            admiralty_credibility=admiralty_cred
        )

        record_audit_event(
            action="EVIDENCE_VERIFY",
            case_id=found_cid,
            status="SUCCESS",
            target_entity_id=evidence_id,
            details={"status": "integrity_verified", "sha256": provenance_rec.get("sha256_hash")}
        )

        return provenance_rec
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/audit", response_model=List[AuditLogEntry])
def get_audit_events(
    case_id: Optional[str] = Query(None, description="Filter audit events by case ID"),
    action: Optional[str] = Query(None, description="Filter audit events by action category"),
    limit: int = Query(50, description="Maximum audit records to return", ge=1, le=500)
):
    """Retrieve recent audit log entries in reverse chronological order without recording a new audit event."""
    try:
        events = query_audit_events(case_id=case_id, action=action, limit=limit)
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
