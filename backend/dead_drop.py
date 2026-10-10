"""Dead Drop Channel Fingerprinting Engine for Threat Actor C2 & Exfiltration Analysis.

Monitors, extracts, and correlates paste site channels (Pastebin, Ghostbin, PrivateBin,
Rentry, etc.), profiles behavioral drop cadences and URL structures, and calculates
an OPSEC rotation score.

DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

from backend.database import db_get, db_get_all, db_insert

router = APIRouter(tags=["dead-drops"])

DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

paste_correlations: List[Dict[str, Any]] = []

SUPPORTED_PASTE_DOMAINS = [
    "pastebin.com",
    "ghostbin.co",
    "ghostbin.com",
    "privatebin.net",
    "privatebin.info",
    "hastebin.com",
    "paste.ee",
    "dpaste.com",
    "dpaste.org",
    "rentry.co",
    "rentry.org",
    "bin.bz",
    "paste.mozilla.org",
    "termbin.com",
]

URL_PATTERN = re.compile(
    r"https?://(?:[a-zA-Z0-9.\-_]+\.)?(?:"
    + "|".join(re.escape(d) for d in SUPPORTED_PASTE_DOMAINS)
    + r")/[^\s<>\"'{}|\\^`]+",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            pass
    return datetime.now(timezone.utc)


def extract_paste_urls(text: str) -> List[Dict[str, Any]]:
    """Scan text for paste URLs and extract structured metadata."""
    found: List[Dict[str, Any]] = []
    if not text:
        return found

    for match in URL_PATTERN.finditer(text):
        raw_url = match.group(0)
        try:
            parsed = urlparse(raw_url)
            host = (parsed.netloc or "").lower()
            path = parsed.path or ""

            # Match domain
            matched_site = "unknown"
            for domain in SUPPORTED_PASTE_DOMAINS:
                if host == domain or host.endswith("." + domain):
                    matched_site = domain
                    break

            # Extract paste ID (last non-empty path segment)
            segments = [s for s in path.strip("/").split("/") if s and s.lower() not in ("raw", "d", "p", "v")]
            paste_id = segments[-1] if segments else "root"

            # Determine URL pattern
            path_lower = path.lower()
            is_raw = "/raw" in path_lower or path_lower.endswith("/raw")
            is_self_destruct = (
                "/d/" in path_lower
                or "burn" in path_lower
                or "destruct" in path_lower
                or "privatebin" in matched_site
                or "once" in path_lower
            )

            if is_raw:
                url_pattern_type = "RAW"
            elif is_self_destruct:
                url_pattern_type = "SELF_DESTRUCT"
            else:
                url_pattern_type = "STANDARD"

            found.append({
                "site_name": matched_site,
                "paste_id": paste_id,
                "full_url": raw_url,
                "is_raw": is_raw,
                "is_self_destruct": is_self_destruct,
                "url_pattern": url_pattern_type,
            })
        except Exception:
            pass

    return found


def calculate_opsec_score(
    sites_used: List[str],
    has_self_destruct: bool,
    pattern_count: int,
) -> float:
    """Calculate the OPSEC rotation score (0.0 to 1.0)."""
    num_sites = len(set(sites_used))
    if num_sites == 1:
        score = 0.1
    elif num_sites == 2:
        score = 0.4
    else:
        score = 0.7

    if has_self_destruct:
        score += 0.2
    if pattern_count > 1:
        score += 0.1

    return min(1.0, round(score, 2))


def update_alias_paste_profile(alias: str) -> Optional[Dict[str, Any]]:
    """Compute and update the behavioral dead drop profile for an alias."""
    events = db_get_all("paste_events", "alias", alias)
    if not events:
        return None

    # Sites used and loyalty
    site_counts = Counter(e["site_name"] for e in events)
    sites_used = list(site_counts.keys())
    preferred_site = site_counts.most_common(1)[0][0] if site_counts else "NONE"
    site_loyalty = "SINGLE_SITE" if len(sites_used) == 1 else "MULTI_SITE"

    # Pattern consistency
    pattern_counts = Counter(e["url_pattern"] for e in events)
    dominant_pattern_count = pattern_counts.most_common(1)[0][1] if pattern_counts else 0
    pattern_consistency = round(dominant_pattern_count / len(events), 2) if events else 1.0

    # Drop cadence analysis
    sorted_events = sorted(events, key=lambda x: _parse_ts(x["detected_at"]))
    if len(sorted_events) < 2:
        drop_cadence = "SPORADIC"
    else:
        intervals = []
        for i in range(1, len(sorted_events)):
            t1 = _parse_ts(sorted_events[i - 1]["detected_at"])
            t2 = _parse_ts(sorted_events[i]["detected_at"])
            intervals.append(abs((t2 - t1).total_seconds()))

        avg_interval = sum(intervals) / len(intervals)
        if any(sec < 120 for sec in intervals) or avg_interval < 300:
            drop_cadence = "BURST"
        elif all(180 <= sec <= 86400 for sec in intervals):
            drop_cadence = "REGULAR"
        else:
            drop_cadence = "SPORADIC"

    has_self_destruct = any(e.get("is_self_destruct") for e in events)
    opsec_score = calculate_opsec_score(
        sites_used=sites_used,
        has_self_destruct=has_self_destruct,
        pattern_count=len(pattern_counts),
    )

    profile = {
        "alias": alias,
        "total_pastes_detected": len(events),
        "sites_used": sites_used,
        "site_loyalty": site_loyalty,
        "preferred_site": preferred_site,
        "url_pattern_consistency": pattern_consistency,
        "drop_cadence": drop_cadence,
        "opsec_rotation_score": opsec_score,
        "paste_events": events,
        "disclaimer": DISCLAIMER,
    }

    return profile


def recompute_correlations() -> List[Dict[str, Any]]:
    """Correlate pairs of aliases based on shared paste sites and URL patterns."""
    correlations: List[Dict[str, Any]] = []
    all_events = db_get_all("paste_events")
    aliases = sorted(set(e["alias"] for e in all_events if e.get("alias")))
    profiles = {a: update_alias_paste_profile(a) for a in aliases}
    alias_keys = [a for a in aliases if profiles.get(a)]

    for i in range(len(alias_keys)):
        for j in range(i + 1, len(alias_keys)):
            a = profiles[alias_keys[i]]
            b = profiles[alias_keys[j]]

            shared = set(a["sites_used"]) & set(b["sites_used"])
            if not shared:
                continue

            for site in shared:
                same_pref = (a["preferred_site"] == b["preferred_site"] == site)
                if same_pref:
                    correlations.append({
                        "alias_a": a["alias"],
                        "alias_b": b["alias"],
                        "shared_site": site,
                        "correlation_type": "SAME_SITE_PATTERN",
                        "confidence": 0.60,
                        "disclaimer": DISCLAIMER,
                    })
                else:
                    correlations.append({
                        "alias_a": a["alias"],
                        "alias_b": b["alias"],
                        "shared_site": site,
                        "correlation_type": "SHARED_SITE",
                        "confidence": 0.40,
                        "disclaimer": DISCLAIMER,
                    })

    paste_correlations.clear()
    paste_correlations.extend(correlations)
    return paste_correlations


def process_post(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Hook called from capture_engine for every captured post."""
    try:
        alias = evidence.get("alias")
        if not alias:
            return []

        post_id = evidence.get("post_id") or evidence.get("evidence_id") or "UNKNOWN"
        content = evidence.get("content") or ""
        ts = evidence.get("timestamp_posted") or evidence.get("captured_at") or _now_iso()

        extracted = extract_paste_urls(content)
        recorded: List[Dict[str, Any]] = []

        for item in extracted:
            event = {
                "event_id": f"PASTE-EV-{uuid.uuid4().hex[:8]}",
                "site_name": item["site_name"],
                "paste_id": item["paste_id"],
                "full_url": item["full_url"],
                "is_raw": 1 if item["is_raw"] else 0,
                "is_self_destruct": 1 if item["is_self_destruct"] else 0,
                "url_pattern": item["url_pattern"],
                "alias": alias,
                "post_id": str(post_id),
                "detected_at": ts,
            }
            db_insert("paste_events", event)
            recorded.append(event)

        if recorded:
            update_alias_paste_profile(alias)
            recompute_correlations()

        return recorded
    except Exception:
        return []


# --- API Endpoints ---

@router.get("/deaddrops/profiles")
def get_all_deaddrop_profiles() -> List[Dict[str, Any]]:
    """Retrieve dead drop behavioral profiles for all tracked aliases."""
    all_events = db_get_all("paste_events")
    aliases = sorted(set(e["alias"] for e in all_events if e.get("alias")))
    return [p for p in [update_alias_paste_profile(a) for a in aliases] if p]


@router.get("/deaddrops/profiles/{alias}")
def get_single_deaddrop_profile(alias: str) -> Dict[str, Any]:
    """Retrieve full dead drop behavioral profile for a single alias."""
    prof = update_alias_paste_profile(alias)
    if not prof:
        raise HTTPException(status_code=404, detail=f"No dead drop profile found for alias '{alias}'")
    return prof


@router.get("/deaddrops/events")
def get_all_paste_events() -> List[Dict[str, Any]]:
    """Retrieve all detected paste events across all platforms."""
    return db_get_all("paste_events")


@router.get("/deaddrops/correlations")
def get_paste_correlations() -> List[Dict[str, Any]]:
    """Retrieve cross-alias dead drop channel correlations."""
    return recompute_correlations()


@router.get("/deaddrops/stats")
def get_deaddrops_stats() -> Dict[str, Any]:
    """Retrieve platform-wide paste site distribution and OPSEC metrics."""
    events = db_get_all("paste_events")
    site_dist: Dict[str, int] = Counter()
    for e in events:
        site_dist[e.get("site_name", "unknown")] += 1

    aliases = sorted(set(e["alias"] for e in events if e.get("alias")))
    profiles = [p for p in [update_alias_paste_profile(a) for a in aliases] if p]
    opsec_scores = [p.get("opsec_rotation_score", 0.0) for p in profiles]
    avg_opsec = round(sum(opsec_scores) / len(opsec_scores), 2) if opsec_scores else 0.0

    return {
        "total_pastes_detected": len(events),
        "total_aliases_profiled": len(profiles),
        "site_distribution": dict(site_dist),
        "average_opsec_rotation_score": avg_opsec,
        "disclaimer": DISCLAIMER,
    }
