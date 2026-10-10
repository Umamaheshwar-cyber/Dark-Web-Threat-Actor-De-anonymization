"""Native Language Ghost Detection Engine for Dark Web Threat Actor Analysis.

Analyzes non-native (L2) English error patterns, syntactic transfer, and
embedded non-Latin scripts to detect probable native language families.

All outputs represent statistical and linguistic indicators only:
DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, HTTPException

from backend.database import db_get, db_get_all, db_insert

router = APIRouter(tags=["language-ghost"])

DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

_alias_post_ids: Dict[str, List[str]] = {}

# Script ranges regex
SCRIPT_PATTERNS = [
    ("CYRILLIC", re.compile(r"[\u0400-\u04FF\u0500-\u052F]"), "SLAVIC"),
    ("ARABIC", re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]"), "SEMITIC"),
    ("HEBREW", re.compile(r"[\u0590-\u05FF]"), "SEMITIC"),
    ("CJK", re.compile(r"[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF]"), "SINO-TIBETAN"),
    ("TAMIL", re.compile(r"[\u0B80-\u0BFF]"), "DRAVIDIAN"),
    ("DEVANAGARI", re.compile(r"[\u0900-\u097F]"), "INDIC"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_scripts(text: str) -> List[Tuple[str, str]]:
    """Detect non-Latin writing scripts present in text."""
    detected = []
    for script_name, regex, family in SCRIPT_PATTERNS:
        if regex.search(text):
            detected.append((script_name, family))
    return detected


# L2 Error Pattern Rules
# Each rule: (language_family, pattern_type, regex_pattern, confidence_weight)
L2_RULES: List[Tuple[str, str, re.Pattern, float]] = [
    # --- SLAVIC ---
    (
        "SLAVIC",
        "MISSING_ARTICLE",
        re.compile(
            r"\b(?:go\s+to|come\s+to|arrive\s+at|download|upload|connect\s+to|look\s+at|"
            r"install\s+on|open|close|send\s+to|write\s+to|enter)\s+"
            r"(?:store|car|server|database|computer|file|exploit|forum|group|system|payload|password)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "SLAVIC",
        "MISSING_COPULA",
        re.compile(
            r"\b(?:he|she|this|it|they|we)\s+"
            r"(?:programmer|coder|hacker|admin|engineer|good\s+guy|bad\s+guy|student|friend)\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    (
        "SLAVIC",
        "PREPOSITION_ERROR",
        re.compile(
            r"\b(?:depends?\s+from|congratulate\s+with|interested\s+for|made\s+a?\s*photo)\b",
            re.IGNORECASE,
        ),
        0.70,
    ),

    # --- SEMITIC ---
    (
        "SEMITIC",
        "ARTICLE_OVERUSE_RESUMPTIVE_PRONOUN",
        re.compile(
            r"\bthe\s+\w+\s+(?:it\s+is|it\s+was|he\s+is|he\s+was|she\s+is|she\s+was)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "SEMITIC",
        "VERB_SUBJECT_INVERSION",
        re.compile(
            r"\b(?:is|was)\s+(?:good|bad|safe|easy|hard|working)\s+(?:this|that|the)\s+\w+\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "SEMITIC",
        "DUAL_PLURAL_CONFUSION",
        re.compile(
            r"\b(?:both\s+two|two\s+two|each\s+two)\b",
            re.IGNORECASE,
        ),
        0.70,
    ),

    # --- SINO-TIBETAN ---
    (
        "SINO-TIBETAN",
        "MISSING_PLURAL_MARKER",
        re.compile(
            r"\b(?:many|several|few|two|three|four|five|six|seven|eight|nine|ten|hundred|thousand)\s+"
            r"(?:hacker|attack|server|computer|bug|error|tool|payload|file|exploit|user|post)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "SINO-TIBETAN",
        "TOPIC_COMMENT_STRUCTURE",
        re.compile(
            r"(?:^|[.!?]\s*)(?:this|that|these|the)\s+\w+,\s+(?:i|we|they|you)\s+\w+",
            re.IGNORECASE,
        ),
        0.70,
    ),
    (
        "SINO-TIBETAN",
        "TENSE_ERROR_ASPECT",
        re.compile(
            r"\b(?:yesterday|last\s+(?:night|week|month|year))\b.*?\b(?:fix|download|hack|attack|break|delete|send|write)\b(?!ed|ing|s\b)",
            re.IGNORECASE,
        ),
        0.75,
    ),
    (
        "SINO-TIBETAN",
        "ALREADY_PRESENT_TENSE",
        re.compile(
            r"\b(?:already)\s+(?:fix|hack|download|test|attack|delete|send|write|make|find)\b(?!ed|ing)",
            re.IGNORECASE,
        ),
        0.70,
    ),

    # --- DRAVIDIAN ---
    (
        "DRAVIDIAN",
        "SOV_WORD_ORDER",
        re.compile(
            r"\b(?:i|we|he|she|they)\s+the\s+\w+\s+(?:deleted|downloaded|uploaded|tested|fixed|created|sent|hacked|started)\b",
            re.IGNORECASE,
        ),
        0.65,
    ),
    (
        "DRAVIDIAN",
        "ITSELF_OVERUSE",
        re.compile(
            r"\b(?:it|this|that|today|yesterday|now|there|here|he|she)\s+itself\b",
            re.IGNORECASE,
        ),
        0.70,
    ),
    (
        "DRAVIDIAN",
        "TRANSLITERATION_MARKERS",
        re.compile(
            r"\b(?:machan|macha|anna|thambi|broda|da|di|pa|la|yaar)\b",
            re.IGNORECASE,
        ),
        0.65,
    ),

    # --- ROMANCE ---
    (
        "ROMANCE",
        "DOUBLE_NEGATIVE",
        re.compile(
            r"\b(?:don't|doesn't|didn't|can't|cannot|never|not)\s+.*?\b(?:nothing|nobody|no\s+one|nowhere)\b",
            re.IGNORECASE,
        ),
        0.60,
    ),
    (
        "ROMANCE",
        "FALSE_FRIEND_PREPOSITION",
        re.compile(
            r"\b(?:i\s+am\s+agree|i'm\s+agree|explain\s+me|discuss\s+about)\b",
            re.IGNORECASE,
        ),
        0.65,
    ),

    # --- GERMANIC ---
    (
        "GERMANIC",
        "COMPOUND_HYPHENATION",
        re.compile(
            r"\b[a-zA-Z]{3,}-[a-zA-Z]{3,}-[a-zA-Z]{3,}(?:-[a-zA-Z]{3,})*\b",
        ),
        0.60,
    ),
    (
        "GERMANIC",
        "VERB_FINAL_PERFECT",
        re.compile(
            r"\b(?:i|we|they|he|she)\s+.*?([a-zA-Z]+ed|[a-zA-Z]+en)\s+have\b",
            re.IGNORECASE,
        ),
        0.65,
    ),
    (
        "GERMANIC",
        "MID_SENTENCE_NOUN_CAPITALIZATION",
        re.compile(
            r"(?<![.!?]\s)(?<!^)\b(?:the|a|an)\s+([A-Z][a-z]{3,})\b",
        ),
        0.55,
    ),
]


def extract_l2_patterns(text: str) -> List[Dict[str, Any]]:
    """Scan text for L2 syntax interference patterns."""
    detected = []
    content = str(text or "")
    for family, p_type, regex, conf in L2_RULES:
        matches = regex.findall(content)
        if matches:
            evidence_str = str(matches[0]) if isinstance(matches[0], str) else " ".join(matches[0])
            detected.append({
                "language_family": family,
                "pattern_type": p_type,
                "evidence": evidence_str.strip(),
                "confidence": conf
            })
    return detected


def analyze_text(content: str, post_id: str = "", alias: str = "") -> Dict[str, Any]:
    """Perform complete native language ghost analysis on a text post. Crash-safe."""
    try:
        raw_text = str(content or "")

        # 1. Detect scripts
        scripts = detect_scripts(raw_text)
        script_detected = scripts[0][0] if scripts else None
        script_family = scripts[0][1] if scripts else None

        # 2. Extract L2 patterns
        patterns = extract_l2_patterns(raw_text)

        # 3. Vote tallying
        family_scores: Dict[str, float] = Counter()

        for p in patterns:
            family_scores[p["language_family"]] += p["confidence"]

        if script_family:
            family_scores[script_family] += 1.5

        if family_scores:
            top_family, top_weight = family_scores.most_common(1)[0]
        else:
            top_family = "NONE"
            top_weight = 0.0

        # 4. Confidence scoring
        if script_detected:
            # Script confirmed: 0.85 - 1.00
            extra = min(0.15, len(patterns) * 0.05)
            confidence_score = round(0.85 + extra, 2)
            confidence_level = "HIGH"
        elif top_weight >= 1.2:
            # Multiple patterns: 0.60 - 0.84
            confidence_score = round(min(0.84, 0.60 + (top_weight - 1.0) * 0.1), 2)
            confidence_level = "MEDIUM"
        elif top_weight > 0.0:
            # Few patterns: 0.30 - 0.59
            confidence_score = round(min(0.59, 0.30 + top_weight * 0.25), 2)
            confidence_level = "LOW"
        else:
            confidence_score = 0.0
            confidence_level = "NONE"

        return {
            "post_id": post_id,
            "alias": alias,
            "content": raw_text,
            "detected_patterns": patterns,
            "script_detected": script_detected,
            "predicted_language_family": top_family,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "analyzed_at": _now_iso(),
            "disclaimer": DISCLAIMER
        }
    except Exception as e:
        return {
            "post_id": post_id,
            "alias": alias,
            "content": str(content or ""),
            "detected_patterns": [],
            "script_detected": None,
            "predicted_language_family": "NONE",
            "confidence_score": 0.0,
            "confidence_level": "NONE",
            "error": str(e),
            "analyzed_at": _now_iso(),
            "disclaimer": DISCLAIMER
        }


def update_alias_language_profile(alias: str) -> Optional[Dict[str, Any]]:
    """Aggregate all post language analyses for an alias. Crash-safe."""
    try:
        if not alias:
            return None

        posts_records = db_get_all("captured_posts", "alias", alias)
        if not posts_records:
            return None

        analyses = [
            analyze_text(p.get("content") or "", post_id=p.get("post_id"), alias=alias)
            for p in posts_records
        ]

        if not analyses:
            return None

        total_posts = len(analyses)
        votes: Dict[str, int] = Counter()
        scripts_confirmed: Set[str] = set()
        scores: List[float] = []

        for a in analyses:
            fam = a.get("predicted_language_family", "NONE")
            votes[fam] += 1
            if a.get("script_detected"):
                scripts_confirmed.add(a["script_detected"])
            if a.get("confidence_score") is not None:
                scores.append(float(a["confidence_score"]))

        # Exclude 'NONE' if there are actual language votes
        real_votes = {k: v for k, v in votes.items() if k != "NONE"}
        if real_votes:
            top_fam = max(real_votes, key=real_votes.get)
        else:
            top_fam = "NONE"

        # Mean confidence
        mean_conf = round(sum(scores) / max(1, len(scores)), 2)

        # Confidence level
        if scripts_confirmed or mean_conf >= 0.85:
            conf_level = "HIGH"
        elif mean_conf >= 0.60:
            conf_level = "MEDIUM"
        elif mean_conf >= 0.30:
            conf_level = "LOW"
        else:
            conf_level = "NONE"

        profile = {
            "alias": alias,
            "total_posts_analyzed": total_posts,
            "language_family_votes": dict(votes),
            "predicted_native_language_family": top_fam,
            "confidence_score": mean_conf,
            "confidence_level": conf_level,
            "script_confirmations": sorted(list(scripts_confirmed)),
            "last_updated": _now_iso(),
            "disclaimer": DISCLAIMER,
        }

        db_insert("language_profiles", profile)
        return profile
    except Exception:
        return None


def analyze_post(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hook invoked by capture_engine when new post evidence is stored. Crash-safe."""
    try:
        if not isinstance(record, dict):
            return None

        alias = str(record.get("alias") or "").strip()
        post_id = str(record.get("post_id") or record.get("evidence_id") or "").strip()
        content = record.get("content") or ""

        if not alias or not post_id:
            return None

        analysis = analyze_text(content, post_id=post_id, alias=alias)
        update_alias_language_profile(alias)
        return analysis
    except Exception:
        return None


# --- API Endpoints ---

@router.get("/language/profiles")
def get_all_language_profiles() -> List[Dict[str, Any]]:
    """Retrieve native language ghost profiles for all tracked aliases."""
    return db_get_all("language_profiles")


@router.get("/language/profiles/{alias}")
def get_single_language_profile(alias: str) -> Dict[str, Any]:
    """Retrieve full native language analysis for a single alias."""
    prof = db_get("language_profiles", "alias", alias)
    if not prof:
        raise HTTPException(status_code=404, detail=f"No language profile found for alias '{alias}'")

    posts_records = db_get_all("captured_posts", "alias", alias)
    posts = [
        analyze_text(p.get("content") or "", post_id=p.get("post_id"), alias=alias)
        for p in posts_records
    ]

    return {
        "profile": prof,
        "posts": posts,
        "disclaimer": DISCLAIMER,
    }


@router.get("/language/posts/{post_id}")
def get_post_language(post_id: str) -> Dict[str, Any]:
    """Retrieve native language ghost analysis for a specific post."""
    post = db_get("captured_posts", "post_id", post_id)
    if not post:
        post = db_get("captured_posts", "evidence_id", post_id)
    if not post:
        raise HTTPException(status_code=404, detail=f"No language analysis found for post '{post_id}'")
    return analyze_text(post.get("content") or "", post_id=post.get("post_id"), alias=post.get("alias"))


@router.get("/language/stats")
def get_language_stats() -> Dict[str, Any]:
    """Overall statistics across all analyzed posts and language families."""
    profiles = db_get_all("language_profiles")
    total_posts = sum(int(p.get("total_posts_analyzed") or 0) for p in profiles)
    family_distribution: Dict[str, int] = Counter()
    for prof in profiles:
        fam = prof.get("predicted_native_language_family", "NONE")
        family_distribution[fam] += 1

    return {
        "total_posts_analyzed": total_posts,
        "total_aliases_profiled": len(profiles),
        "family_distribution": dict(family_distribution),
        "disclaimer": DISCLAIMER,
    }
