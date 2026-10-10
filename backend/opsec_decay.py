"""OPSEC decay model for captured local-test-forum posts.

Scores post content for information-leakage signals, tracks per-alias
timelines, and estimates a simple linear decay curve.

This module is an APIRouter. Register it later in backend/main.py.
"""

from __future__ import annotations

import math
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from backend.database import db_count, db_get, db_get_all, db_insert

router = APIRouter(tags=["opsec-decay"])

_scored_evidence_ids = set()

BASE_SCORE = 100
CRITICAL_THRESHOLD = 40

TIMEZONE_KEYWORDS = (
    "morning",
    "afternoon",
    "evening",
    "night",
    "est",
    "pst",
    "ist",
    "utc",
    "gmt",
)
WEATHER_KEYWORDS = (
    "rain",
    "snow",
    "sunny",
    "cold",
    "hot",
    "weather",
    "storm",
    "wind",
    "humid",
    "monsoon",
)
EMOTION_KEYWORDS = (
    "girlfriend",
    "boyfriend",
    "wife",
    "husband",
    "family",
    "mom",
    "dad",
    "sick",
    "tired",
    "angry",
    "frustrated",
    "lonely",
    "depressed",
)
LOCATION_PHRASES = (
    "near me",
    "here in",
    "based in",
    "living in",
)
LOCATION_KEYWORDS = (
    "city",
    "country",
    "street",
    "road",
    "local",
    "from",
)

TECHNICAL_TERMS = {
    "api",
    "http",
    "https",
    "json",
    "uuid",
    "sha",
    "sha256",
    "opsec",
    "utc",
    "gmt",
    "est",
    "pst",
    "ist",
    "url",
    "html",
    "css",
    "sql",
    "tcp",
    "ip",
    "vpn",
    "pgp",
    "python",
    "fastapi",
    "linux",
    "windows",
    "docker",
    "github",
    "shadowtrace",
    "misp",
    "circl",
    "stix",
    "bitcoin",
    "ethereum",
    "wallet",
    "post",
    "thread",
    "forum",
    "alias",
    "evidence",
    "capture",
    "engine",
    "server",
    "client",
    "token",
    "hash",
}

SIGNAL_DEFS = (
    ("TIMEZONE_LEAK", -10),
    ("WEATHER_MENTION", -8),
    ("LANGUAGE_SLIP", -15),
    ("PERSONAL_EMOTION", -20),
    ("LOCATION_HINT", -30),
    ("NAME_FRAGMENT", -40),
)

_NAME_RE = re.compile(r"\b[A-Z][a-z]{1,}\b")
_TIME_AMPM_RE = re.compile(
    r"(?:\b(?:[01]?\d|2[0-3])(?::[0-5]\d)?\s*(?:AM|PM|am|pm)\b)|(?:(?<![A-Za-z])(?:AM|PM)(?![A-Za-z]))"
)
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
_ARABIC_RE = re.compile(r"[\u0600-\u06FF]")
_CHINESE_RE = re.compile(r"[\u4E00-\u9FFF]")
_HINDI_RE = re.compile(r"[\u0900-\u097F]")
_SENTENCE_START_RE = re.compile(r"(?:^|[.!?]\s+)([A-Z][a-z]+)")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _has_word(text: str, word: str) -> bool:
    try:
        return re.search(r"\b" + re.escape(word) + r"\b", text, re.IGNORECASE) is not None
    except Exception:
        return False


def _detect_timezone(text: str) -> bool:
    try:
        if _TIME_AMPM_RE.search(text):
            return True
        lower = text.lower()
        for word in TIMEZONE_KEYWORDS:
            if _has_word(lower, word):
                return True
        return False
    except Exception:
        return False


def _detect_weather(text: str) -> bool:
    try:
        lower = text.lower()
        return any(_has_word(lower, word) for word in WEATHER_KEYWORDS)
    except Exception:
        return False


def _detect_language_slip(text: str) -> bool:
    try:
        return bool(
            _CYRILLIC_RE.search(text)
            or _ARABIC_RE.search(text)
            or _CHINESE_RE.search(text)
            or _HINDI_RE.search(text)
        )
    except Exception:
        return False


def _detect_emotion(text: str) -> bool:
    try:
        lower = text.lower()
        return any(_has_word(lower, word) for word in EMOTION_KEYWORDS)
    except Exception:
        return False


def _detect_location(text: str) -> bool:
    try:
        lower = text.lower()
        for phrase in LOCATION_PHRASES:
            if phrase in lower:
                return True
        return any(_has_word(lower, word) for word in LOCATION_KEYWORDS)
    except Exception:
        return False


def _detect_name_fragment(text: str) -> bool:
    try:
        sentence_starts = set()
        for match in _SENTENCE_START_RE.finditer(text.strip()):
            sentence_starts.add((match.start(1), match.group(1)))
        start_spans = {span[0] for span in sentence_starts}
        for match in _NAME_RE.finditer(text):
            word = match.group(0)
            if match.start() in start_spans:
                continue
            if word.lower() in TECHNICAL_TERMS:
                continue
            if word.lower() in TIMEZONE_KEYWORDS or word.lower() in WEATHER_KEYWORDS:
                continue
            if word.lower() in EMOTION_KEYWORDS or word.lower() in LOCATION_KEYWORDS:
                continue
            return True
        return False
    except Exception:
        return False


def analyze_content(content: str):
    """Return (score, signals, impact) for a post body. Crash-safe."""
    try:
        text = content if isinstance(content, str) else str(content or "")
        detectors = {
            "TIMEZONE_LEAK": _detect_timezone,
            "WEATHER_MENTION": _detect_weather,
            "LANGUAGE_SLIP": _detect_language_slip,
            "PERSONAL_EMOTION": _detect_emotion,
            "LOCATION_HINT": _detect_location,
            "NAME_FRAGMENT": _detect_name_fragment,
        }
        signals = []
        impact = 0
        for name, penalty in SIGNAL_DEFS:
            try:
                if detectors[name](text):
                    signals.append(name)
                    impact += penalty
            except Exception:
                continue
        score = max(0, BASE_SCORE + impact)
        return score, signals, impact
    except Exception:
        return BASE_SCORE, [], 0


def _linear_regression(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0, ys[-1] if ys else float(BASE_SCORE)
    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_xx = sum(x * x for x in xs)
    denom = (n * sum_xx) - (sum_x * sum_x)
    if abs(denom) < 1e-12:
        return 0.0, (sum_y / n)
    slope = ((n * sum_xy) - (sum_x * sum_y)) / denom
    intercept = (sum_y - slope * sum_x) / n
    return slope, intercept


def _alert_level(score: float) -> str:
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"


def _trend_label(slope: float) -> str:
    if slope <= -0.01:
        return "DECLINING"
    if slope >= 0.01:
        return "IMPROVING"
    return "STABLE"


def _rebuild_decay(alias: str) -> dict:
    events = db_get_all("opsec_scores", "alias", alias, order_by="id ASC")
    if not events:
        return {
            "alias": alias,
            "current_score": BASE_SCORE,
            "trend": "STABLE",
            "decay_rate": 0.0,
            "predicted_critical_score": CRITICAL_THRESHOLD,
            "predicted_critical_date": None,
            "alert_level": "LOW",
        }

    current_score = events[-1].get("score", BASE_SCORE)
    trend = "STABLE"
    decay_rate = 0.0
    predicted_date = None

    if len(events) >= 3:
        xs = []
        ys = []
        t0 = _parse_iso(events[0].get("timestamp")) or _now()
        for idx, event in enumerate(events):
            ts = _parse_iso(event.get("timestamp"))
            if ts is None:
                xs.append(float(idx))
            else:
                xs.append((ts - t0).total_seconds() / 86400.0)
            ys.append(float(event.get("score", BASE_SCORE)))
        slope, _intercept = _linear_regression(xs, ys)
        decay_rate = round(slope, 2)
        trend = _trend_label(slope)
        if trend == "DECLINING" and slope < 0:
            if current_score <= CRITICAL_THRESHOLD:
                predicted_date = _iso(_now())
            else:
                days = (CRITICAL_THRESHOLD - current_score) / slope
                if math.isfinite(days) and days >= 0:
                    predicted_date = _iso(_now() + timedelta(days=days))

    return {
        "alias": alias,
        "current_score": current_score,
        "trend": trend,
        "decay_rate": decay_rate,
        "predicted_critical_score": CRITICAL_THRESHOLD,
        "predicted_critical_date": predicted_date,
        "alert_level": _alert_level(current_score),
    }


def score_post(evidence: dict) -> dict:
    """Score one captured evidence record and append it to the alias timeline."""
    try:
        if not isinstance(evidence, dict):
            return {}
        evidence_id = evidence.get("evidence_id")
        post_id = evidence.get("post_id") or evidence_id or str(uuid.uuid4())
        alias = evidence.get("alias") or "unknown"
        content = evidence.get("content") or ""
        timestamp = (
            evidence.get("timestamp_captured")
            or evidence.get("timestamp_posted")
            or _iso(_now())
        )
        score, signals, impact = analyze_content(content)
        event = {
            "alias": alias,
            "post_id": post_id,
            "timestamp": timestamp,
            "score": score,
            "signals_detected": signals,
            "score_impact": impact,
            "created_at": _iso(_now()),
        }
        try:
            db_insert("opsec_scores", event)
        except Exception:
            pass
        if evidence_id:
            _scored_evidence_ids.add(evidence_id)
        try:
            evidence["opsec_content_score"] = score
            evidence["opsec_signals_detected"] = list(signals)
            evidence["opsec_content_impact"] = impact
        except Exception:
            pass
        _rebuild_decay(alias)
        print(
            "[%s] OPSEC SCORE alias=%s post_id=%s score=%s impact=%s signals=%s"
            % (_iso(_now()), alias, post_id, score, impact, ",".join(signals) or "none"),
            flush=True,
        )
        return event
    except Exception as exc:
        print("[%s] OPSEC SCORE ERROR: %s" % (_iso(_now()), exc), flush=True)
        return {}


def score_all_captured_evidence() -> dict:
    """Score every captured evidence record that has not been scored yet."""
    scored = 0
    skipped = 0
    errors = 0
    try:
        records = db_get_all("captured_posts")
        for record in records:
            try:
                evidence_id = record.get("evidence_id")
                if evidence_id in _scored_evidence_ids:
                    skipped += 1
                    continue
                result = score_post(record)
                if result:
                    scored += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
    except Exception as exc:
        return {"scored": scored, "skipped": skipped, "errors": errors, "detail": str(exc)}
    return {"scored": scored, "skipped": skipped, "errors": errors}


@router.get("/opsec/scores")
def get_all_scores():
    try:
        all_scores = db_get_all("opsec_scores")
        aliases = sorted(set(r.get("alias") for r in all_scores if r.get("alias")))
        results = []
        for alias in aliases:
            results.append(_rebuild_decay(alias))
        return results
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/opsec/scores/{alias}")
def get_alias_score(alias: str):
    try:
        timeline = db_get_all("opsec_scores", "alias", alias, order_by="id ASC")
        if not timeline:
            raise HTTPException(status_code=404, detail="Alias not found")
        return {
            "alias": alias,
            "timeline": timeline,
            "decay_curve": _rebuild_decay(alias),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/opsec/alerts")
def get_opsec_alerts():
    try:
        alerts = []
        all_scores = db_get_all("opsec_scores")
        aliases = sorted(set(r.get("alias") for r in all_scores if r.get("alias")))
        for alias in aliases:
            curve = _rebuild_decay(alias)
            if curve.get("alert_level") in ("HIGH", "CRITICAL"):
                alerts.append(curve)
        return alerts
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/opsec/score-post")
def trigger_score_all():
    try:
        return score_all_captured_evidence()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
