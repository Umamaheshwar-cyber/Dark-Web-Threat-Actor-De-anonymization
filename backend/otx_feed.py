"""AlienVault OTX (Open Threat Exchange) Feed Integration Engine for SHADOWTRACE.

Ingests pulses, adversary campaigns, and multi-vector threat indicators (IOCs)
from AT&T Cybersecurity / AlienVault OTX, providing actor-attributed intelligence.

DISCLAIMER: AUTHORIZED PUBLIC CTI — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Query
import requests

from backend.database import db_count, db_get, db_get_all, db_insert

# Load environment configuration safely
try:
    load_dotenv()
except Exception:
    for enc in ["utf-16", "utf-16-le", "utf-8", "utf-8-sig"]:
        try:
            load_dotenv(encoding=enc)
            if os.getenv("OTX_API_KEY"):
                break
        except Exception:
            pass

OTX_API_KEY = os.getenv("OTX_API_KEY")

router = APIRouter(prefix="/otx", tags=["alienvault-otx"])

DISCLAIMER = "AUTHORIZED PUBLIC CTI — NOT PROOF OF IDENTITY"
PROVENANCE = "ALIENVAULT_OTX_PUBLIC_FEED"
BASE_URL = "https://otx.alienvault.com/api/v1"

MAX_PULSES_PER_POLL = 50
MAX_IOCS_PER_POLL = 500

# Common Known Threat Actor patterns for tag extraction
ACTOR_PATTERN = re.compile(
    r"(?i)\b(apt\s*\d+|lazarus|revil|conti|fin\s*\d+|sandworm|cozy\s*bear|fancy\s*bear|"
    r"wizard\s*spider|lockbit|blackcat|alphv|scattered\s*spider|darkside|babuk|"
    r"storm-\d+|volt\s*typhoon|salt\s*typhoon|gamaredon|kimsuky|turla|muddywater|"
    r"ta\d+|unc\d+|charming\s*kitten|mustang\s*panda|oilrig|sidecopy|oceanlotus)\b"
)

# Global IOC deduplication cache
_seen_otx_iocs: Set[str] = set()

otx_state: Dict[str, Any] = {
    "configured": bool(OTX_API_KEY),
    "last_poll": None,
    "total_pulses": 0,
    "total_iocs": 0,
    "status": "READY" if bool(OTX_API_KEY) else "NOT_CONFIGURED",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_api_headers() -> Dict[str, str]:
    headers = {
        "User-Agent": "SHADOWTRACE-CTI-Agent/1.0",
        "Accept": "application/json",
    }
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    return headers


def _extract_actor_tags(pulse: Dict[str, Any]) -> List[str]:
    """Extract recognized threat actor identities and campaigns from pulse metadata."""
    actors: Set[str] = set()

    # Check adversary field
    adv = pulse.get("adversary")
    if adv and isinstance(adv, str) and adv.strip():
        actors.add(adv.strip())

    # Check tags
    tags = pulse.get("tags") or []
    if isinstance(tags, list):
        for t in tags:
            if not isinstance(t, str):
                continue
            match = ACTOR_PATTERN.search(t)
            if match:
                actors.add(match.group(0).upper())
            elif t.lower().startswith("apt") or "bear" in t.lower() or "spider" in t.lower():
                actors.add(t.strip())

    # Check pulse name
    name = pulse.get("name") or ""
    match = ACTOR_PATTERN.search(name)
    if match:
        actors.add(match.group(0).upper())

    return sorted(list(actors))


def _feed_features(record: Dict[str, Any]) -> None:
    """Propagate OTX indicator into Relationship Graph and Dead Drop systems."""
    ioc_type = str(record.get("ioc_type", "")).lower()
    ioc_val = record.get("ioc_value", "")
    first_seen = record.get("first_seen") or _now_iso()

    # 1. IPv4 / IPv6 -> Relationship Graph IP node
    if "ipv4" in ioc_type or "ipv6" in ioc_type or "ip" in ioc_type:
        try:
            from backend import relationship_graph
            ip_clean = ioc_val.split(":")[0]
            node_id = f"IP-{ip_clean}"
            relationship_graph.add_node(
                node_id,
                "IP",
                ip_clean,
                properties={"source": record.get("source"), "pulse_name": record.get("pulse_name")},
                timestamp=first_seen,
            )
        except Exception:
            pass

    # 2. Domain / Hostname -> Relationship Graph DOMAIN node
    if "domain" in ioc_type or "hostname" in ioc_type:
        try:
            from backend import relationship_graph
            node_id = f"DOMAIN-{ioc_val}"
            relationship_graph.add_node(
                node_id,
                "DOMAIN",
                ioc_val,
                properties={"source": record.get("source"), "pulse_name": record.get("pulse_name")},
                timestamp=first_seen,
            )
        except Exception:
            pass

    # 3. URL -> Dead Drop paste extraction check
    if "url" in ioc_type:
        try:
            from backend import dead_drop
            dead_drop.extract_paste_urls(ioc_val)
        except Exception:
            pass

    # 4. Actor tags -> Relationship Graph ALIAS nodes
    actor_tags = record.get("actor_tags") or []
    if actor_tags:
        try:
            from backend import relationship_graph
            for tag in actor_tags:
                node_id = f"ALIAS-{tag}"
                relationship_graph.add_node(
                    node_id,
                    "ALIAS",
                    tag,
                    properties={"tag_type": "threat_actor", "source": record.get("source")},
                    timestamp=first_seen,
                )
        except Exception:
            pass


def _normalize_and_store_ioc(
    pulse: Dict[str, Any],
    ind: Dict[str, Any],
    actor_tags: List[str],
) -> Optional[Dict[str, Any]]:
    """Deduplicate and normalize an OTX indicator record."""
    val = ind.get("indicator")
    if not val:
        return None

    clean_val = str(val).strip()
    if clean_val in _seen_otx_iocs:
        return None

    _seen_otx_iocs.add(clean_val)

    ev_uuid = str(uuid.uuid4())
    fs = ind.get("created") or pulse.get("created") or _now_iso()
    ls = pulse.get("modified") or fs

    countries = pulse.get("targeted_countries") or []
    if isinstance(countries, str):
        countries = [countries]

    malware = pulse.get("malware_families") or []
    if isinstance(malware, str):
        malware = [malware]

    record = {
        "evidence_id": f"OTX-EV-{ev_uuid}",
        "source": "ALIENVAULT_OTX",
        "pulse_id": str(pulse.get("id") or ""),
        "pulse_name": str(pulse.get("name") or "Unknown Pulse"),
        "author": str(pulse.get("author_name") or pulse.get("author") or "AlienVault"),
        "actor_tags": actor_tags,
        "malware_families": malware,
        "targeted_countries": countries,
        "ioc_type": ind.get("type", "unknown"),
        "ioc_value": clean_val,
        "description": ind.get("description") or pulse.get("description") or "",
        "first_seen": fs,
        "last_seen": ls,
        "provenance": PROVENANCE,
        "sha256_hash": hashlib.sha256(clean_val.encode("utf-8")).hexdigest(),
        "disclaimer": DISCLAIMER,
        "created_at": _now_iso(),
    }

    db_insert("otx_evidence", record)
    _feed_features(record)
    return record


def poll_alienvault_otx() -> Dict[str, Any]:
    """Execute live pulse and indicator ingestion from AlienVault OTX."""
    if not OTX_API_KEY:
        raise HTTPException(
            status_code=400,
            detail="OTX_API_KEY is not configured in .env file. Please add OTX_API_KEY to .env.",
        )

    headers = _get_api_headers()
    pulses_url = f"{BASE_URL}/pulses/subscribed?limit={MAX_PULSES_PER_POLL}"

    try:
        resp = requests.get(pulses_url, headers=headers, timeout=20)
        if resp.status_code == 403 or resp.status_code == 401:
            otx_state["status"] = "AUTHENTICATION_FAILED"
            raise HTTPException(
                status_code=401,
                detail="AlienVault OTX authentication failed. Please check your OTX_API_KEY.",
            )
        resp.raise_for_status()
        data = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        otx_state["status"] = "ERROR"
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to AlienVault OTX: {str(e)}",
        )

    pulse_results = data.get("results") or []
    new_pulses_count = 0
    new_iocs_count = 0
    pulses_seen = set()

    for p in pulse_results[:MAX_PULSES_PER_POLL]:
        p_id = str(p.get("id"))
        if not p_id:
            continue

        actor_tags = _extract_actor_tags(p)
        if p_id not in pulses_seen:
            pulses_seen.add(p_id)
            new_pulses_count += 1

        indicators = p.get("indicators") or []
        for ind in indicators:
            if new_iocs_count >= MAX_IOCS_PER_POLL:
                break
            rec = _normalize_and_store_ioc(p, ind, actor_tags)
            if rec:
                new_iocs_count += 1

        if new_iocs_count >= MAX_IOCS_PER_POLL:
            break

    records = db_get_all("otx_evidence")
    pulse_set = set(r.get("pulse_id") for r in records if r.get("pulse_id"))

    otx_state["last_poll"] = _now_iso()
    otx_state["total_pulses"] = len(pulse_set)
    otx_state["total_iocs"] = len(records)
    otx_state["status"] = "ONLINE"

    return {
        "status": "SUCCESS",
        "pulses_imported": new_pulses_count,
        "iocs_imported": new_iocs_count,
        "total_pulses": len(pulse_set),
        "total_iocs": len(records),
        "disclaimer": DISCLAIMER,
    }


# --- API Endpoints ---

@router.get("/status")
def get_otx_status() -> Dict[str, Any]:
    """Retrieve AlienVault OTX connection status and key presence (without exposing keys)."""
    records = db_get_all("otx_evidence")
    pulse_set = set(r.get("pulse_id") for r in records if r.get("pulse_id"))
    return {
        "configured": bool(OTX_API_KEY),
        "status": otx_state["status"],
        "last_poll": otx_state["last_poll"],
        "total_pulses": len(pulse_set),
        "total_iocs": len(records),
        "disclaimer": DISCLAIMER,
    }


@router.get("/poll")
def trigger_otx_poll() -> Dict[str, Any]:
    """Trigger manual polling of subscribed pulses and indicators from AlienVault OTX."""
    return poll_alienvault_otx()


@router.get("/pulses")
def list_otx_pulses(limit: int = Query(50, ge=1, le=100)) -> List[Dict[str, Any]]:
    """List all imported AlienVault OTX pulses."""
    records = db_get_all("otx_evidence")
    pulses_dict = {}
    for r in records:
        pid = r.get("pulse_id")
        if pid and pid not in pulses_dict:
            pulses_dict[pid] = {
                "pulse_id": pid,
                "pulse_name": r.get("pulse_name"),
                "author": r.get("author"),
                "actor_tags": r.get("actor_tags") or [],
                "malware_families": r.get("malware_families") or [],
                "targeted_countries": r.get("targeted_countries") or [],
                "created": r.get("created_at"),
            }
    return list(pulses_dict.values())[:limit]


@router.get("/evidence")
def list_otx_evidence(limit: int = Query(200, ge=1, le=1000)) -> List[Dict[str, Any]]:
    """Retrieve normalized AlienVault OTX evidence records."""
    return db_get_all("otx_evidence", limit=limit)


@router.get("/stats")
def get_otx_stats() -> Dict[str, Any]:
    """Aggregate statistics for AlienVault OTX intelligence."""
    records = db_get_all("otx_evidence")
    ioc_types: Dict[str, int] = Counter()
    actor_dist: Dict[str, int] = Counter()
    pulse_set = set()

    for item in records:
        if item.get("pulse_id"):
            pulse_set.add(item["pulse_id"])
        ioc_types[item.get("ioc_type", "unknown")] += 1
        tags = item.get("actor_tags") or []
        if isinstance(tags, str):
            import json
            try:
                tags = json.loads(tags)
            except Exception:
                tags = [tags]
        for a in tags:
            actor_dist[a] += 1

    return {
        "total_pulses": len(pulse_set),
        "total_iocs": len(records),
        "total_unique_actors": len(actor_dist),
        "ioc_type_breakdown": dict(ioc_types),
        "actor_breakdown": dict(actor_dist.most_common(20)),
        "last_poll": otx_state["last_poll"],
        "status": otx_state["status"],
        "disclaimer": DISCLAIMER,
    }


@router.get("/actors")
def get_otx_actors() -> Dict[str, Any]:
    """Retrieve unique threat actor clusters and campaigns detected across all OTX pulses."""
    records = db_get_all("otx_evidence")
    actor_dist: Dict[str, int] = Counter()
    for item in records:
        tags = item.get("actor_tags") or []
        if isinstance(tags, str):
            import json
            try:
                tags = json.loads(tags)
            except Exception:
                tags = [tags]
        for a in tags:
            actor_dist[a] += 1

    return {
        "unique_actors": sorted(list(actor_dist.keys())),
        "total_actors": len(actor_dist),
        "actor_distribution": dict(actor_dist.most_common(50)),
        "disclaimer": DISCLAIMER,
    }
