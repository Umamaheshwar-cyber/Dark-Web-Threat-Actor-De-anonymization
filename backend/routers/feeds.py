"""
SHADOWTRACE — Authorized MISP Feeds Router (Phase 6.2)
Provides read-only API access to authorized MISP threat intelligence feeds,
evidence preview normalization, and case-scoped indicator imports with Phase 4 provenance.
Strictly offline fallback when unconfigured; never exposes API credentials or real-person data.
"""

import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Dict, Any, Optional, Set

from backend.models import (
    MISPStatusResponse,
    MISPPreviewRequest,
    MISPPreviewResponse,
    MISPImportRequest,
    MISPImportResponse,
    MISPConnectionTestResponse,
    Evidence,
    EvidenceProvenanceRecord,
    CIRCLManifestItem,
    CIRCLFeedStatusResponse,
    CIRCLPreviewRequest,
    CIRCLPreviewResponse,
    CIRCLImportRequest,
    CIRCLImportResponse,
    CIRCLPollRequest,
    CIRCLPollResponse,
    CIRCLSyncStatusResponse
)
from backend.authorized_adapter import (
    MISPAdapter,
    MISPAdapterError,
    MISPConfigurationError,
    MISPConnectionError,
    MISPAuthenticationError,
    CIRCLFeedAdapter,
    CIRCLFeedError,
    CIRCLInvalidUUIDError,
    CIRCLConnectionError,
    map_misp_confidence
)
from backend.audit import record_audit_event
from backend.data_store import (
    resolve_case_file,
    append_authorized_misp_evidence,
    get_evidence_data,
    load_circl_sync_state,
    save_circl_sync_state,
    get_tracked_circl_uuids
)

router = APIRouter(prefix="/api/feeds/misp", tags=["feeds"])

# Authorized synthetic sample fixture for safe offline demo / testing mode
SAMPLE_OFFLINE_MISP_EVENT: Dict[str, Any] = {
    "Event": {
        "id": "10442",
        "info": "Authorized Defensive Threat Indicator Feed (Synthetic Sample)",
        "date": "2026-10-02",
        "threat_level_id": 2,
        "Orgc": {
            "name": "Authorized CTI Research Network"
        },
        "Attribute": [
            {
                "id": "5001",
                "type": "github-username",
                "value": "SyntheticDev_99",
                "comment": "Observed handle in threat repository metadata",
                "toids": False
            },
            {
                "id": "5002",
                "type": "pgp-key",
                "value": "PGP-SYN-FEED-7A11",
                "comment": "Correlated synthetic public key",
                "toids": True
            },
            {
                "id": "5003",
                "type": "btc",
                "value": "bc1q-synthetic-demo-wallet-7700",
                "comment": "Observed wallet address in simulated campaign",
                "toids": False
            }
        ]
    }
}


def _mask_api_key(err: Exception) -> str:
    """Ensure no MISP API key is ever leaked into error strings or logs."""
    msg = str(err)
    key = os.getenv("MISP_API_KEY", "")
    if key and key in msg:
        msg = msg.replace(key, "[REDACTED_KEY]")
    return msg


@router.get("/status", response_model=MISPStatusResponse)
def get_misp_status():
    """
    Check the current configuration and operational status of the authorized MISP feed.
    Zero secrets or credentials exposed.
    """
    adapter = MISPAdapter()
    if adapter.is_configured():
        return MISPStatusResponse(
            configured=True,
            base_url=adapter.base_url,
            mode="AUTHORIZED_LIVE_FEED",
            message="Authorized MISP feed configured and active (read-only mode)."
        )
    return MISPStatusResponse(
        configured=False,
        base_url=None,
        mode="OFFLINE_DEMO_MODE",
        message="MISP adapter unconfigured. Running in safe offline demo mode using synthetic test fixtures."
    )


@router.post("/test-connection", response_model=MISPConnectionTestResponse)
def test_misp_connection():
    """
    Test connectivity and credentials against the authorized MISP instance.
    Uses a lightweight read-only probe. Never exposes API credentials.
    """
    adapter = MISPAdapter()
    if not adapter.is_configured():
        return MISPConnectionTestResponse(
            connected=False,
            base_url=None,
            status="UNCONFIGURED",
            message="MISP adapter is unconfigured. Set MISP_URL and MISP_API_KEY environment variables.",
            version=None
        )
    try:
        res = adapter.test_connection()
        return MISPConnectionTestResponse(
            connected=True,
            base_url=res.get("base_url"),
            status="AUTHORIZED_ONLINE",
            message=res.get("message", "Connection verified successfully."),
            version=res.get("version")
        )
    except MISPAuthenticationError:
        return MISPConnectionTestResponse(
            connected=False,
            base_url=adapter.base_url,
            status="AUTHENTICATION_FAILED",
            message="MISP authentication failed: invalid API key or unauthorized access.",
            version=None
        )
    except (MISPConnectionError, Exception) as e:
        safe_msg = _mask_api_key(e)
        return MISPConnectionTestResponse(
            connected=False,
            base_url=adapter.base_url,
            status="CONNECTION_FAILED",
            message=f"Failed to connect to authorized MISP instance: {safe_msg}",
            version=None
        )


@router.post("/preview", response_model=MISPPreviewResponse)
def preview_misp_feed(req: Optional[MISPPreviewRequest] = Body(None)):
    """
    Preview and normalize external threat indicators from an authorized MISP feed.
    Supports live query or offline mock payload preview. Read-only operation.
    """
    params = req or MISPPreviewRequest()
    adapter = MISPAdapter()

    evidence_items: List[Dict[str, Any]] = []
    events_count = 0
    mode = "OFFLINE_DEMO_MODE"

    try:
        # Case A: Explicit mock payload supplied (e.g. for offline testing)
        if params.mock_event:
            mode = "MOCK_PAYLOAD_PREVIEW"
            events_count = 1
            evidence_items = adapter.transform_misp_event_to_evidence(params.mock_event)
        # Case B: Live authorized MISP feed configured
        elif adapter.is_configured():
            mode = "AUTHORIZED_LIVE_FEED"
            search_args: Dict[str, Any] = {"returnFormat": "json", "limit": params.limit}
            if params.query:
                search_args["value"] = params.query
            misp_events = adapter.fetch_events_rest(search_args)
            events_count = len(misp_events)
            for ev in misp_events:
                evidence_items.extend(adapter.transform_misp_event_to_evidence(ev))
        # Case C: Offline fallback to synthetic research fixture
        else:
            mode = "OFFLINE_DEMO_MODE"
            events_count = 1
            evidence_items = adapter.transform_misp_event_to_evidence(SAMPLE_OFFLINE_MISP_EVENT)

        # Apply user limit if requested
        if params.limit and len(evidence_items) > params.limit:
            evidence_items = evidence_items[:params.limit]

        # Audit log the query
        record_audit_event(
            action="FEED_QUERY",
            case_id="GLOBAL_FEED",
            status="SUCCESS",
            details={
                "mode": mode,
                "query": params.query,
                "limit": params.limit,
                "attributes_count": len(evidence_items)
            }
        )

        return MISPPreviewResponse(
            mode=mode,
            events_count=events_count,
            attributes_count=len(evidence_items),
            evidence_items=[Evidence(**e) for e in evidence_items]
        )

    except MISPAuthenticationError as e:
        record_audit_event(
            action="FEED_QUERY",
            case_id="GLOBAL_FEED",
            status="FAILURE",
            details={"error": "MISP authentication failure"}
        )
        raise HTTPException(status_code=401, detail="MISP feed authentication failed. Check credentials.")
    except (MISPConnectionError, MISPConfigurationError) as e:
        safe_msg = _mask_api_key(e)
        record_audit_event(
            action="FEED_QUERY",
            case_id="GLOBAL_FEED",
            status="FAILURE",
            details={"error": safe_msg}
        )
        raise HTTPException(status_code=502, detail=f"MISP feed connection error: {safe_msg}")
    except Exception as e:
        safe_msg = _mask_api_key(e)
        raise HTTPException(status_code=500, detail=f"Unexpected error previewing MISP feed: {safe_msg}")


@router.post("/import", response_model=MISPImportResponse)
def import_misp_to_case(req: MISPImportRequest = Body(...)):
    """
    Import and normalize threat indicators from an authorized MISP feed into a specific case scope.
    Generates cryptographic Phase 4 provenance records for each imported evidence item.
    Does not overwrite or corrupt baseline case files. Strictly case-scoped.
    """
    # 1. Validate target case exists
    try:
        resolve_case_file(req.case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Target case '{req.case_id}' not found.")

    adapter = MISPAdapter()
    evidence_items: List[Dict[str, Any]] = []
    source_event: Dict[str, Any] = {}
    mode = "OFFLINE_DEMO_MODE"

    try:
        # Determine source MISP event
        if req.misp_event:
            mode = "MOCK_PAYLOAD_IMPORT"
            source_event = req.misp_event
            evidence_items = adapter.transform_misp_event_to_evidence(source_event)
        elif adapter.is_configured():
            mode = "AUTHORIZED_LIVE_FEED"
            fetched = adapter.fetch_events_rest({"limit": 5})
            if fetched:
                source_event = fetched[0]
                evidence_items = adapter.transform_misp_event_to_evidence(source_event)
            else:
                source_event = {}
                evidence_items = []
        else:
            mode = "OFFLINE_DEMO_MODE"
            source_event = SAMPLE_OFFLINE_MISP_EVENT
            evidence_items = adapter.transform_misp_event_to_evidence(source_event)

        # Apply limit if requested
        if req.limit and len(evidence_items) > req.limit:
            evidence_items = evidence_items[:req.limit]

        # Generate Phase 4 Provenance and Integrity records for each item
        provenance_records = []
        for ev in evidence_items:
            prov = adapter.build_provenance_for_evidence(ev, source_event)
            # Add target case scope to collection metadata
            prov["provenance"]["collection_metadata"]["target_case_id"] = req.case_id
            provenance_records.append(prov)

        # If target case is the dedicated authorized container, persist the imported records safely
        if req.case_id == "CASE-AUTH-MISP":
            append_authorized_misp_evidence(evidence_items)

        # Record audit trail
        record_audit_event(
            action="FEED_IMPORT",
            case_id=req.case_id,
            status="SUCCESS",
            details={
                "mode": mode,
                "imported_count": len(evidence_items),
                "source_event_id": str(source_event.get("Event", source_event).get("id", "UNKNOWN"))
            }
        )

        return MISPImportResponse(
            case_id=req.case_id,
            mode=mode,
            imported_count=len(evidence_items),
            evidence_records=[Evidence(**e) for e in evidence_items],
            provenance_records=[EvidenceProvenanceRecord(**p) for p in provenance_records]
        )

    except HTTPException:
        raise
    except Exception as e:
        safe_msg = _mask_api_key(e)
        record_audit_event(
            action="FEED_IMPORT",
            case_id=req.case_id,
            status="FAILURE",
            details={"error": safe_msg}
        )
        raise HTTPException(status_code=500, detail=f"Failed to import MISP evidence: {safe_msg}")


@router.get("/evidence", response_model=List[Evidence])
def get_authorized_misp_evidence():
    """
    Retrieve all imported authorized threat indicators currently stored in the
    dedicated CASE-AUTH-MISP container. Strictly separated from synthetic cases.
    """
    try:
        raw_items = get_evidence_data("CASE-AUTH-MISP")
        return [Evidence(**e) for e in raw_items]
    except Exception:
        return []


# ==============================================================================
# Public CIRCL MISP OSINT Feed Endpoints
# Strictly read-only / pull-only over HTTPS. No credentials or dark-web access.
# Imports are strictly scoped to CASE-AUTH-MISP to preserve synthetic isolation.
# ==============================================================================

circl_router = APIRouter(prefix="/api/feeds/circl", tags=["circl-feeds"])


@circl_router.get("/status", response_model=CIRCLFeedStatusResponse)
def get_circl_status(limit: int = Query(5, ge=1, le=20)):
    """
    Check the current status and reachability of the public CIRCL MISP OSINT feed.
    Retrieves a small sample of recent event summaries from manifest.json.
    Strictly read-only; no credentials required.
    """
    adapter = CIRCLFeedAdapter()
    try:
        manifest_items = adapter.fetch_manifest(limit=limit)
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="SUCCESS",
            details={
                "action": "status",
                "manifest_count": len(manifest_items),
                "feed_url": adapter.feed_url
            }
        )
        return CIRCLFeedStatusResponse(
            available=True,
            feed_url=adapter.feed_url,
            mode="PUBLIC_CIRCL_OSINT_FEED",
            message="CIRCL public OSINT feed is reachable. Defensive threat indicators available for preview/import.",
            sample_manifest=[CIRCLManifestItem(**item) for item in manifest_items]
        )
    except (CIRCLConnectionError, CIRCLFeedError, Exception) as e:
        safe_msg = str(e)
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="FAILURE",
            details={"action": "status", "error": safe_msg}
        )
        return CIRCLFeedStatusResponse(
            available=False,
            feed_url=adapter.feed_url,
            mode="PUBLIC_CIRCL_OSINT_FEED",
            message=f"CIRCL public OSINT feed is currently unreachable: {safe_msg}",
            sample_manifest=[]
        )


@circl_router.post("/preview", response_model=CIRCLPreviewResponse)
def preview_circl_feed(req: Optional[CIRCLPreviewRequest] = Body(None)):
    """
    Preview and normalize observable threat indicators from a CIRCL public OSINT event.
    Bounded attribute extraction; read-only preview without persistence.
    """
    params = req or CIRCLPreviewRequest()
    adapter = CIRCLFeedAdapter()

    target_uuid = params.event_uuid
    try:
        if not target_uuid:
            manifest = adapter.fetch_manifest(limit=1)
            if not manifest:
                raise HTTPException(status_code=502, detail="No events available in CIRCL feed manifest.")
            target_uuid = manifest[0]["uuid"]

        clean_uuid = adapter.validate_uuid(target_uuid)
        event_payload = adapter.fetch_event(clean_uuid)
        evidence_items = adapter.transform_circl_event_to_evidence(
            event_payload,
            max_attributes=params.max_attributes
        )

        event_obj = event_payload.get("Event", event_payload)
        event_info = str(event_obj.get("info", "CIRCL OSINT Threat Event"))
        threat_level_id = event_obj.get("threat_level_id", 3)
        threat_level = map_misp_confidence(threat_level_id)

        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="SUCCESS",
            details={
                "action": "preview",
                "event_uuid": clean_uuid,
                "attributes_count": len(evidence_items)
            }
        )

        return CIRCLPreviewResponse(
            feed_url=adapter.feed_url,
            event_uuid=clean_uuid,
            event_info=event_info,
            threat_level=threat_level,
            attributes_count=len(evidence_items),
            evidence_items=[Evidence(**e) for e in evidence_items]
        )
    except CIRCLInvalidUUIDError as e:
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="FAILURE",
            details={"action": "preview", "error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))
    except CIRCLConnectionError as e:
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="FAILURE",
            details={"action": "preview", "error": str(e)}
        )
        raise HTTPException(status_code=502, detail=f"CIRCL feed connection error: {e}")
    except CIRCLFeedError as e:
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="FAILURE",
            details={"action": "preview", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"CIRCL feed processing error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        record_audit_event(
            action="CIRCL_FEED_QUERY",
            case_id="GLOBAL_CIRCL_FEED",
            status="FAILURE",
            details={"action": "preview", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"Unexpected error previewing CIRCL event: {e}")


@circl_router.post("/import", response_model=CIRCLImportResponse)
def import_circl_to_case(req: CIRCLImportRequest = Body(...)):
    """
    Import and normalize observable threat indicators from a CIRCL public OSINT event
    into the dedicated authorized container (CASE-AUTH-MISP).
    Generates cryptographic Phase 4 provenance records. Immutable baseline cases cannot be targeted.
    """
    # 1. Enforce strict case isolation: only CASE-AUTH-MISP is permitted
    if req.case_id != "CASE-AUTH-MISP":
        raise HTTPException(
            status_code=400,
            detail=f"Target case '{req.case_id}' is restricted. External feed imports are strictly isolated to 'CASE-AUTH-MISP'."
        )

    try:
        resolve_case_file(req.case_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Target case '{req.case_id}' not found.")

    adapter = CIRCLFeedAdapter()
    target_uuid = req.event_uuid

    try:
        if not target_uuid:
            manifest = adapter.fetch_manifest(limit=1)
            if not manifest:
                raise HTTPException(status_code=502, detail="No events available in CIRCL feed manifest.")
            target_uuid = manifest[0]["uuid"]

        clean_uuid = adapter.validate_uuid(target_uuid)
        event_payload = adapter.fetch_event(clean_uuid)
        evidence_items = adapter.transform_circl_event_to_evidence(
            event_payload,
            max_attributes=req.max_attributes
        )

        provenance_records = []
        for ev in evidence_items:
            prov = adapter.build_provenance_for_evidence(ev, event_payload)
            prov["provenance"]["collection_metadata"]["target_case_id"] = req.case_id
            provenance_records.append(prov)

        # Append to CASE-AUTH-MISP
        append_authorized_misp_evidence(evidence_items)

        # Audit trail
        record_audit_event(
            action="CIRCL_FEED_IMPORT",
            case_id=req.case_id,
            status="SUCCESS",
            details={
                "action": "import",
                "event_uuid": clean_uuid,
                "imported_count": len(evidence_items)
            }
        )

        return CIRCLImportResponse(
            case_id=req.case_id,
            mode="PUBLIC_CIRCL_OSINT_FEED",
            imported_count=len(evidence_items),
            event_uuid=clean_uuid,
            evidence_records=[Evidence(**e) for e in evidence_items],
            provenance_records=[EvidenceProvenanceRecord(**p) for p in provenance_records]
        )
    except CIRCLInvalidUUIDError as e:
        record_audit_event(
            action="CIRCL_FEED_IMPORT",
            case_id=req.case_id,
            status="FAILURE",
            details={"action": "import", "error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))
    except CIRCLConnectionError as e:
        record_audit_event(
            action="CIRCL_FEED_IMPORT",
            case_id=req.case_id,
            status="FAILURE",
            details={"action": "import", "error": str(e)}
        )
        raise HTTPException(status_code=502, detail=f"CIRCL feed connection error: {e}")
    except CIRCLFeedError as e:
        record_audit_event(
            action="CIRCL_FEED_IMPORT",
            case_id=req.case_id,
            status="FAILURE",
            details={"action": "import", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"CIRCL feed processing error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        record_audit_event(
            action="CIRCL_FEED_IMPORT",
            case_id=req.case_id,
            status="FAILURE",
            details={"action": "import", "error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"Unexpected error importing CIRCL event: {e}")


@circl_router.post("/poll", response_model=CIRCLPollResponse)
def poll_circl_feed(req: Optional[CIRCLPollRequest] = Body(None)):
    """
    Manually trigger an incremental poll against the public CIRCL MISP OSINT feed.
    Detects genuinely new events compared to previously processed UUIDs and existing
    evidence in CASE-AUTH-MISP. Bounded execution; never downloads the entire feed.
    """
    params = req or CIRCLPollRequest()
    adapter = CIRCLFeedAdapter()

    tracked_uuids = get_tracked_circl_uuids()

    try:
        mock_events = None
        if params.mock_event:
            mock_events = {"_default_": params.mock_event}

        poll_result = adapter.poll_new_events(
            known_uuids=tracked_uuids,
            max_events=params.max_events,
            max_attributes=params.max_attributes,
            force_refresh=params.force_refresh,
            raw_manifest=params.mock_manifest,
            mock_events=mock_events
        )

        imported_evidence = poll_result["evidence_records"]
        processed_uuids = poll_result["processed_event_uuids"]
        status = poll_result["status"]

        # Append new evidence records strictly into CASE-AUTH-MISP
        actual_imported_count = 0
        if imported_evidence:
            actual_imported_count = append_authorized_misp_evidence(imported_evidence)

        # Update persistent sync state
        current_state = load_circl_sync_state()
        existing_uuids = set(current_state.get("processed_event_uuids", []))
        existing_uuids.update(processed_uuids)

        now_iso = datetime.now(timezone.utc).isoformat()
        new_state = {
            "processed_event_uuids": sorted(list(existing_uuids)),
            "last_poll_timestamp": now_iso,
            "last_poll_status": status,
            "total_events_processed": current_state.get("total_events_processed", 0) + len(processed_uuids),
            "total_evidence_imported": current_state.get("total_evidence_imported", 0) + actual_imported_count
        }
        save_circl_sync_state(new_state)

        # Audit trail
        record_audit_event(
            action="CIRCL_FEED_POLL",
            case_id="CASE-AUTH-MISP",
            status="SUCCESS" if status in ("SUCCESS", "SKIPPED_NO_NEW") else status,
            details={
                "status": status,
                "manifest_total_events": poll_result["manifest_total_events"],
                "new_events_detected": poll_result["new_events_detected"],
                "processed_count": len(processed_uuids),
                "imported_evidence_count": actual_imported_count,
                "skipped_count": poll_result["skipped_count"],
                "failed_count": poll_result["failed_count"],
                "processed_uuids": processed_uuids
            }
        )

        return CIRCLPollResponse(
            status=status,
            polled_at=now_iso,
            manifest_total_events=poll_result["manifest_total_events"],
            new_events_detected=poll_result["new_events_detected"],
            processed_event_uuids=processed_uuids,
            imported_evidence_count=actual_imported_count,
            skipped_count=poll_result["skipped_count"],
            failed_count=poll_result["failed_count"],
            errors=poll_result["errors"]
        )

    except CIRCLConnectionError as e:
        record_audit_event(
            action="CIRCL_FEED_POLL",
            case_id="CASE-AUTH-MISP",
            status="FAILURE",
            details={"error": str(e)}
        )
        raise HTTPException(status_code=502, detail=f"CIRCL feed connection error: {e}")
    except CIRCLFeedError as e:
        record_audit_event(
            action="CIRCL_FEED_POLL",
            case_id="CASE-AUTH-MISP",
            status="FAILURE",
            details={"error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"CIRCL feed processing error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        record_audit_event(
            action="CIRCL_FEED_POLL",
            case_id="CASE-AUTH-MISP",
            status="FAILURE",
            details={"error": str(e)}
        )
        raise HTTPException(status_code=500, detail=f"Unexpected error during CIRCL feed poll: {e}")


@circl_router.get("/sync-status", response_model=CIRCLSyncStatusResponse)
def get_circl_sync_status():
    """
    Retrieve current synchronization metrics, tracked event count, and timestamp of last poll.
    Zero credentials exposed.
    """
    state = load_circl_sync_state()
    tracked_uuids = get_tracked_circl_uuids()
    adapter = CIRCLFeedAdapter()

    return CIRCLSyncStatusResponse(
        feed_url=adapter.feed_url,
        last_poll_timestamp=state.get("last_poll_timestamp"),
        last_poll_status=state.get("last_poll_status", "UNINITIALIZED"),
        total_tracked_uuids=len(tracked_uuids),
        total_events_processed=state.get("total_events_processed", 0),
        total_evidence_imported=state.get("total_evidence_imported", 0)
    )


