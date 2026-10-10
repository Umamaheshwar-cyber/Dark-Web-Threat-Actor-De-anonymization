"""Temporal Rhythm Analysis Engine for Threat Actor Attribution.

Tracks post timestamps, models 7x24 activity heatmaps, identifies sleep cycles,
predicts probable timezone offsets and geographic bands, and detects cultural
working patterns and holiday absence gaps.

DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException

from backend.database import db_get, db_get_all, db_insert

router = APIRouter(tags=["temporal-rhythm"])

DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

DAY_NAMES = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(val: Any) -> Optional[datetime]:
    if not val:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)
    if isinstance(val, str):
        try:
            s = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None
    return None


def _calculate_sleep_window(hour_counts: List[int]) -> Tuple[int, int]:
    """Find the likely sleep window (lowest activity 7-hour contiguous circular window)."""
    window_size = 7
    best_start = 23
    min_sum = float("inf")

    for start in range(24):
        cur_sum = sum(hour_counts[(start + i) % 24] for i in range(window_size))
        if cur_sum < min_sum:
            min_sum = cur_sum
            best_start = start

    end = (best_start + window_size) % 24
    return best_start, end


def _predict_timezone(sleep_start: int, sleep_end: int, peak_hours: List[int]) -> Tuple[str, str]:
    """Predict timezone band and UTC offset using sleep window and peak activity hours."""
    # Assuming standard human sleep center in local solar time is around 03:30 to 04:00 AM.
    # Sleep midpoint in UTC:
    if sleep_end < sleep_start:
        sleep_midpoint_utc = (sleep_start + (sleep_end + 24 - sleep_start) / 2.0) % 24
    else:
        sleep_midpoint_utc = (sleep_start + sleep_end) / 2.0

    # Local target sleep midpoint ~ 03:30 (3.5)
    offset_est = 3.5 - sleep_midpoint_utc
    # Normalize between -12 and +14
    while offset_est < -12.0:
        offset_est += 24.0
    while offset_est > 14.0:
        offset_est -= 24.0

    # Also consider peak hours center (typical peak ~15:00-18:00 local time)
    if peak_hours:
        avg_peak = sum(peak_hours) / len(peak_hours)
        peak_offset = 16.0 - avg_peak
        while peak_offset < -12.0:
            peak_offset += 24.0
        while peak_offset > 14.0:
            peak_offset -= 24.0
        # Weighted combination: 60% sleep cycle, 40% peak activity
        offset_est = (0.6 * offset_est) + (0.4 * peak_offset)

    # Check for India IST special case (~ +5.5)
    if 5.0 <= offset_est <= 6.0:
        return "INDIA", "UTC+5:30"
    if 6.0 < offset_est <= 9.5:
        return "EAST ASIA", "UTC+6 to UTC+9"
    if 9.5 < offset_est <= 14.0:
        return "PACIFIC/OCEANIA", "UTC+9 to UTC+12"
    if 2.5 <= offset_est < 5.0:
        return "MIDDLE EAST/SOUTH ASIA", "UTC+3 to UTC+5"
    if -1.5 <= offset_est < 2.5:
        return "EUROPE/AFRICA", "UTC-1 to UTC+2"
    if -9.0 <= offset_est < -1.5:
        return "AMERICAS", "UTC-8 to UTC-5"

    return "AMERICAS", "UTC-8 to UTC-5"


def _detect_cultural_pattern(day_counts: List[int], total_posts: int) -> str:
    """Analyze weekly rhythm for cultural/religious work patterns."""
    if total_posts < 3:
        return "INSUFFICIENT_DATA"

    weekday_total = sum(day_counts[0:5])  # Mon-Fri
    weekend_total = sum(day_counts[5:7])  # Sat-Sun
    weekday_avg = weekday_total / 5.0
    weekend_avg = weekend_total / 2.0

    fri_count = day_counts[4]
    sun_count = day_counts[6]

    # Weekend drop -> Western
    if weekday_avg > 0 and (weekend_avg / weekday_avg) < 0.45:
        return "WESTERN"

    # Friday drop -> Islamic pattern (Friday prayer / weekend)
    if weekday_avg > 0 and (fri_count < 0.3 * weekday_avg) and (fri_count < day_counts[3]):
        return "ISLAMIC"

    # Sunday drop -> Christian pattern
    if weekday_avg > 0 and (sun_count < 0.3 * weekday_avg) and (day_counts[5] > sun_count):
        return "CHRISTIAN"

    # Uniform activity across all 7 days -> East Asian work culture
    if weekday_avg > 0 and (weekend_avg / weekday_avg) >= 0.75:
        return "EAST_ASIAN"

    return "WESTERN"


def _detect_holiday_gaps(posts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect unexplained multi-day absences (> 3 days)."""
    if len(posts) < 2:
        return []

    sorted_posts = sorted(posts, key=lambda p: p["dt"])
    gaps = []

    for i in range(1, len(sorted_posts)):
        prev_dt = sorted_posts[i - 1]["dt"]
        curr_dt = sorted_posts[i]["dt"]
        delta = curr_dt - prev_dt
        days = delta.total_seconds() / 86400.0

        if days > 3.0:
            gaps.append({
                "start": prev_dt.isoformat(),
                "end": curr_dt.isoformat(),
                "gap_days": round(days, 1),
                "signal": "POTENTIAL_HOLIDAY_GAP",
                "note": "Activity gap detected — possible local holiday or travel",
            })

    return gaps


def compute_alias_profile(alias: str) -> Dict[str, Any]:
    """Compute the full temporal rhythm profile for an alias."""
    raw_posts = db_get_all("temporal_posts", "alias", alias)
    if not raw_posts:
        return {
            "alias": alias,
            "total_posts": 0,
            "disclaimer": DISCLAIMER,
        }

    posts = []
    for p in raw_posts:
        p_copy = dict(p)
        dt = _parse_timestamp(p_copy.get("timestamp")) or datetime.now(timezone.utc)
        p_copy["dt"] = dt
        posts.append(p_copy)

    # 7x24 grid: rows = 0..6 (Mon..Sun), cols = 0..23 (hour UTC)
    heatmap = [[0 for _ in range(24)] for _ in range(7)]
    hour_counts = [0] * 24
    day_counts = [0] * 7
    posts_per_day: Dict[str, int] = Counter()

    for p in posts:
        d = int(p["day_of_week"])
        h = int(p["hour"])
        heatmap[d][h] += 1
        hour_counts[h] += 1
        day_counts[d] += 1
        date_str = p["dt"].strftime("%Y-%m-%d")
        posts_per_day[date_str] += 1

    # Peak hours (top hours with posts)
    sorted_hours = sorted(range(24), key=lambda h: hour_counts[h], reverse=True)
    max_h_val = hour_counts[sorted_hours[0]] if sorted_hours else 0
    if max_h_val > 0:
        peak_hours = [h for h in sorted_hours if hour_counts[h] > 0][:3]
    else:
        peak_hours = []

    # Peak days
    sorted_days = sorted(range(7), key=lambda d: day_counts[d], reverse=True)
    max_d_val = day_counts[sorted_days[0]] if sorted_days else 0
    if max_d_val > 0:
        peak_days = [DAY_NAMES[d] for d in sorted_days if day_counts[d] > 0][:2]
    else:
        peak_days = []

    sleep_start, sleep_end = _calculate_sleep_window(hour_counts)
    tz_band, utc_offset = _predict_timezone(sleep_start, sleep_end, peak_hours)
    cultural = _detect_cultural_pattern(day_counts, len(posts))
    gaps = _detect_holiday_gaps(posts)

    all_dts = [p["dt"] for p in posts]
    first_seen = min(all_dts).isoformat()
    last_seen = max(all_dts).isoformat()
    active_days = len(posts_per_day)

    profile = {
        "alias": alias,
        "total_posts": len(posts),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "active_days": active_days,
        "heatmap": heatmap,
        "peak_hours": peak_hours,
        "peak_days": peak_days,
        "sleep_window": {
            "start": sleep_start,
            "end": sleep_end,
        },
        "predicted_timezone_band": tz_band,
        "predicted_utc_offset": utc_offset,
        "cultural_pattern": cultural,
        "holiday_gaps": gaps,
        "posts_per_day": dict(sorted(posts_per_day.items())),
        "disclaimer": DISCLAIMER,
    }

    return profile


def log_post(evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hook called from capture engine whenever post evidence is captured."""
    try:
        alias = evidence.get("alias")
        if not alias:
            return None

        post_id = evidence.get("post_id") or evidence.get("evidence_id") or "unknown"
        ts_raw = evidence.get("timestamp_posted") or evidence.get("captured_at") or _now_iso()
        dt = _parse_timestamp(ts_raw) or datetime.now(timezone.utc)

        hour = dt.hour
        day_of_week = dt.weekday()
        day_name = DAY_NAMES[day_of_week]

        entry = {
            "post_id": str(post_id),
            "alias": alias,
            "timestamp": dt.isoformat(),
            "hour": hour,
            "day_of_week": day_of_week,
            "day_name": day_name,
            "created_at": _now_iso(),
        }

        existing = db_get_all("temporal_posts", "post_id", str(post_id))
        if not any(e.get("alias") == alias for e in existing):
            db_insert("temporal_posts", entry)

        profile = compute_alias_profile(alias)
        return profile
    except Exception:
        return None


# --- API Endpoints ---

@router.get("/temporal/profiles")
def get_all_temporal_profiles() -> List[Dict[str, Any]]:
    """Retrieve temporal rhythm profiles for all tracked aliases."""
    all_posts = db_get_all("temporal_posts")
    aliases = sorted(set(p.get("alias") for p in all_posts if p.get("alias")))
    return [compute_alias_profile(alias) for alias in aliases]


@router.get("/temporal/profiles/{alias}")
def get_single_temporal_profile(alias: str) -> Dict[str, Any]:
    """Retrieve full temporal rhythm analysis for a single alias."""
    posts = db_get_all("temporal_posts", "alias", alias)
    if not posts:
        raise HTTPException(status_code=404, detail=f"No temporal profile found for alias '{alias}'")
    return compute_alias_profile(alias)


@router.get("/temporal/heatmap/{alias}")
def get_alias_heatmap(alias: str) -> Dict[str, Any]:
    """Retrieve only the 7x24 heatmap grid for an alias."""
    posts = db_get_all("temporal_posts", "alias", alias)
    if not posts:
        raise HTTPException(status_code=404, detail=f"No temporal profile found for alias '{alias}'")

    prof = compute_alias_profile(alias)
    return {
        "alias": alias,
        "heatmap": prof.get("heatmap", []),
        "days": DAY_NAMES,
        "hours": list(range(24)),
        "disclaimer": DISCLAIMER,
    }


@router.get("/temporal/stats")
def get_temporal_stats() -> Dict[str, Any]:
    """Overall temporal analytics across all profiled aliases."""
    all_posts = db_get_all("temporal_posts")
    aliases = sorted(set(p.get("alias") for p in all_posts if p.get("alias")))
    profiles = [compute_alias_profile(a) for a in aliases]
    tz_dist: Dict[str, int] = Counter()
    culture_dist: Dict[str, int] = Counter()

    for prof in profiles:
        tz = prof.get("predicted_timezone_band", "UNKNOWN")
        cult = prof.get("cultural_pattern", "UNKNOWN")
        tz_dist[tz] += 1
        culture_dist[cult] += 1

    return {
        "total_aliases_tracked": len(profiles),
        "total_posts_logged": len(all_posts),
        "timezone_distribution": dict(tz_dist),
        "cultural_pattern_distribution": dict(culture_dist),
        "disclaimer": DISCLAIMER,
    }
