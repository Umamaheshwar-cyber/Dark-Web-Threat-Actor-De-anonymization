"""Psycholinguistic Fingerprinting Engine for Dark Web Threat Actor Analysis.

Extracts stylistic and psycholinguistic feature vectors from forum posts,
constructs running alias profiles, and computes cross-alias stylometric
similarity assessments.

All outputs represent statistical and stylometric indicators only:
DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import hashlib
import math
import re
import string
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.database import db_count, db_get, db_get_all, db_insert

router = APIRouter(tags=["psycholinguistic"])

DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

_alias_post_ids: Dict[str, List[str]] = {}

# Common English stopwords (standard NLTK/linguistic baseline)
COMMON_STOPWORDS: Set[str] = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

# Common spelling quirks / typos / internet slang patterns
COMMON_MISSPELLINGS_DICT: Dict[str, str] = {
    "teh": "the",
    "recieve": "receive",
    "seperate": "separate",
    "definately": "definitely",
    "occured": "occurred",
    "untill": "until",
    "alot": "a lot",
    "wierd": "weird",
    "tommorrow": "tomorrow",
    "goverment": "government",
    "thier": "their",
    "realy": "really",
    "becuase": "because",
    "privet": "hello (Russian)",
    "привет": "hello (Cyrillic)",
    "wat": "what",
    "plz": "please",
    "thx": "thanks",
    "u": "you",
    "ur": "your",
    "thru": "through",
    "probly": "probably",
    "dis": "this",
    "dat": "that"
}

FEATURE_WEIGHTS: Dict[str, float] = {
    "vocabulary_richness": 0.25,
    "avg_sentence_length": 0.20,
    "punctuation_ratio": 0.15,
    "uppercase_ratio": 0.10,
    "stopword_ratio": 0.10,
    "avg_word_length": 0.10,
    "digit_ratio": 0.05,
    "exclamation_count": 0.05
}


class CompareRequest(BaseModel):
    alias_a: str = Field(..., min_length=1, description="First alias to compare")
    alias_b: str = Field(..., min_length=1, description="Second alias to compare")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_stylistic_features(text: str) -> Dict[str, Any]:
    """Extract 14 psycholinguistic and stylistic features from post content.

    Crash-safe: handles empty or non-string input gracefully.
    """
    try:
        content = str(text or "")
        total_chars = len(content)

        # Paragraphs
        paragraphs = [p.strip() for p in re.split(r"\n+", content) if p.strip()]
        paragraph_count = max(1, len(paragraphs))

        # Sentences: split on terminal punctuation (. ! ?)
        sentences = [s.strip() for s in re.split(r"[.!?]+", content) if s.strip()]
        sentence_count = len(sentences)
        if sentence_count == 0 and content.strip():
            sentence_count = 1
            sentences = [content.strip()]

        # Words: extract word tokens
        words = re.findall(r"\b\w+\b", content.lower(), re.UNICODE)
        total_words = len(words)
        unique_words = len(set(words))

        # Letters and uppercase
        letters = [ch for ch in content if ch.isalpha()]
        total_letters = len(letters)
        uppercase_count = sum(1 for ch in content if ch.isupper())

        # Digits
        digits_count = sum(1 for ch in content if ch.isdigit())

        # Punctuation marks
        punctuation_count = sum(1 for ch in content if ch in string.punctuation)

        # Specific counts
        exclamation_count = content.count("!")
        question_count = content.count("?")
        ellipsis_count = len(re.findall(r"\.\.\.|…", content))
        bracket_usage = sum(content.count(b) for b in ("(", ")", "[", "]", "{", "}"))

        # Misspellings detection
        detected_misspellings: List[str] = []
        for word in words:
            if word in COMMON_MISSPELLINGS_DICT:
                detected_misspellings.append(word)
        # Also check lower content for cyrillic or specific quirks
        for quirk in ("привет", "privet"):
            if quirk in content.lower() and quirk not in detected_misspellings:
                detected_misspellings.append(quirk)

        # Stopwords
        stopword_count = sum(1 for w in words if w in COMMON_STOPWORDS)

        # Feature ratios (safe division)
        avg_sentence_length = round(total_words / max(1, sentence_count), 3) if sentence_count > 0 else 0.0
        avg_word_length = round(sum(len(w) for w in words) / max(1, total_words), 3) if total_words > 0 else 0.0
        punctuation_ratio = round(punctuation_count / max(1, total_chars), 4) if total_chars > 0 else 0.0
        vocabulary_richness = round(unique_words / max(1, total_words), 4) if total_words > 0 else 0.0
        uppercase_ratio = round(uppercase_count / max(1, total_letters), 4) if total_letters > 0 else 0.0
        digit_ratio = round(digits_count / max(1, total_chars), 4) if total_chars > 0 else 0.0
        stopword_ratio = round(stopword_count / max(1, total_words), 4) if total_words > 0 else 0.0
        avg_paragraph_length = round(total_words / max(1, paragraph_count), 3) if paragraph_count > 0 else 0.0

        return {
            "avg_sentence_length": avg_sentence_length,
            "avg_word_length": avg_word_length,
            "punctuation_ratio": punctuation_ratio,
            "vocabulary_richness": vocabulary_richness,
            "uppercase_ratio": uppercase_ratio,
            "exclamation_count": exclamation_count,
            "question_count": question_count,
            "digit_ratio": digit_ratio,
            "common_misspellings": sorted(list(set(detected_misspellings))),
            "stopword_ratio": stopword_ratio,
            "avg_paragraph_length": avg_paragraph_length,
            "ellipsis_count": ellipsis_count,
            "bracket_usage": bracket_usage,
            "sentence_count": sentence_count,
            "word_count": total_words,
            "char_count": total_chars
        }
    except Exception as e:
        return {
            "avg_sentence_length": 0.0,
            "avg_word_length": 0.0,
            "punctuation_ratio": 0.0,
            "vocabulary_richness": 0.0,
            "uppercase_ratio": 0.0,
            "exclamation_count": 0,
            "question_count": 0,
            "digit_ratio": 0.0,
            "common_misspellings": [],
            "stopword_ratio": 0.0,
            "avg_paragraph_length": 0.0,
            "ellipsis_count": 0,
            "bracket_usage": 0,
            "sentence_count": 0,
            "word_count": 0,
            "char_count": 0,
            "error": str(e)
        }


def _compute_style_signature(alias: str, mean_features: Dict[str, Any]) -> str:
    """Generate deterministic SHA-256 fingerprint from mean stylometric values."""
    try:
        raw_keys = sorted([k for k in mean_features if k.startswith("mean_")])
        formatted = ";".join(f"{k}:{mean_features[k]}" for k in raw_keys)
        payload = f"{alias}|{formatted}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
    except Exception:
        return hashlib.sha256(str(alias).encode("utf-8")).hexdigest()


def update_alias_profile(alias: str) -> Optional[Dict[str, Any]]:
    """Recalculate running mean profile for an alias from all associated posts."""
    try:
        if not alias:
            return None

        posts = db_get_all("captured_posts", "alias", alias)
        if not posts:
            return None

        features_list = [extract_stylistic_features(p.get("content") or "") for p in posts]
        count = len(features_list)

        def _mean(key: str) -> float:
            vals = [float(f.get(key, 0.0) or 0.0) for f in features_list]
            return round(sum(vals) / count, 4)

        all_misspellings = set()
        for f in features_list:
            for m in f.get("common_misspellings", []):
                all_misspellings.add(m)

        mean_data: Dict[str, Any] = {
            "mean_avg_sentence_length": _mean("avg_sentence_length"),
            "mean_vocabulary_richness": _mean("vocabulary_richness"),
            "mean_punctuation_ratio": _mean("punctuation_ratio"),
            "mean_uppercase_ratio": _mean("uppercase_ratio"),
            "mean_exclamation_count": _mean("exclamation_count"),
            "mean_question_count": _mean("question_count"),
            "mean_digit_ratio": _mean("digit_ratio"),
            "mean_stopword_ratio": _mean("stopword_ratio"),
            "mean_avg_paragraph_length": _mean("avg_paragraph_length"),
            "mean_ellipsis_count": _mean("ellipsis_count"),
            "mean_bracket_usage": _mean("bracket_usage"),
            "mean_sentence_count": _mean("sentence_count"),
        }

        signature = _compute_style_signature(alias, mean_data)

        profile = {
            "alias": alias,
            "post_count": count,
            **mean_data,
            "common_misspellings": sorted(list(all_misspellings)),
            "style_signature": signature,
            "last_updated": _now_iso(),
            "disclaimer": DISCLAIMER,
        }

        db_insert("psycho_profiles", profile)
        return profile
    except Exception:
        return None


def profile_post(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hook called by capture engine whenever new/edited post evidence is stored.

    Extracts features, records them under post_id, and updates the alias mean profile.
    Crash-safe.
    """
    try:
        if not isinstance(record, dict):
            return None

        alias = str(record.get("alias") or "").strip()
        post_id = str(record.get("post_id") or record.get("evidence_id") or "")
        content = record.get("content") or ""

        if not alias or not post_id:
            return None

        features = extract_stylistic_features(content)
        features["post_id"] = post_id
        features["alias"] = alias
        features["captured_at"] = record.get("timestamp_captured") or _now_iso()
        features["version"] = record.get("version", 1)

        update_alias_profile(alias)
        return features
    except Exception:
        return None


def compare_profiles(alias_a: str, alias_b: str) -> Dict[str, Any]:
    """Compare two alias profiles with weighted psycholinguistic feature distance."""
    prof_a = db_get("psycho_profiles", "alias", alias_a)
    prof_b = db_get("psycho_profiles", "alias", alias_b)

    if not prof_a:
        raise HTTPException(status_code=404, detail=f"Profile for alias '{alias_a}' not found.")
    if not prof_b:
        raise HTTPException(status_code=404, detail=f"Profile for alias '{alias_b}' not found.")

    feature_comparison: Dict[str, Any] = {}
    weighted_diff_sum = 0.0
    total_weight = 0.0

    # Ratio/bounded features mapped to "mean_" prefix
    bounded_features = {
        "vocabulary_richness",
        "punctuation_ratio",
        "uppercase_ratio",
        "stopword_ratio",
        "digit_ratio"
    }

    for feat, weight in FEATURE_WEIGHTS.items():
        key = f"mean_{feat}"
        val_a = float(prof_a.get(key, 0.0) or 0.0)
        val_b = float(prof_b.get(key, 0.0) or 0.0)

        if feat in bounded_features:
            diff = abs(val_a - val_b)
        else:
            denom = max(val_a, val_b, 1.0)
            diff = abs(val_a - val_b) / denom

        diff = max(0.0, min(1.0, diff))
        sim = round(1.0 - diff, 4)

        weighted_diff_sum += weight * diff
        total_weight += weight

        feature_comparison[feat] = {
            "alias_a": val_a,
            "alias_b": val_b,
            "difference": round(diff, 4),
            "similarity": sim,
            "weight": weight
        }

    norm_weighted_diff = weighted_diff_sum / max(0.001, total_weight)
    similarity_score = round(max(0.0, min(1.0, 1.0 - norm_weighted_diff)), 4)

    # Determine confidence and verdict
    if similarity_score >= 0.85:
        confidence = "HIGH"
        verdict = "LIKELY SAME PERSON"
    elif similarity_score >= 0.70:
        confidence = "MEDIUM"
        verdict = "POSSIBLY SAME PERSON"
    elif similarity_score >= 0.50:
        confidence = "LOW"
        verdict = "WEAK SIMILARITY"
    else:
        confidence = "NONE"
        verdict = "DIFFERENT WRITING STYLES"

    return {
        "alias_a": alias_a,
        "alias_b": alias_b,
        "similarity_score": similarity_score,
        "confidence": confidence,
        "verdict": verdict,
        "feature_comparison": feature_comparison,
        "disclaimer": DISCLAIMER
    }


# --- API Routes ---

@router.get("/psycho/profiles")
def get_all_profiles() -> List[Dict[str, Any]]:
    """Retrieve all alias psycholinguistic writing style profiles."""
    return db_get_all("psycho_profiles")


@router.get("/psycho/profiles/{alias}")
def get_single_profile(alias: str) -> Dict[str, Any]:
    """Retrieve writing style profile for a single alias along with post feature vectors."""
    prof = db_get("psycho_profiles", "alias", alias)
    if not prof:
        raise HTTPException(status_code=404, detail=f"No psycholinguistic profile found for alias '{alias}'")

    posts_records = db_get_all("captured_posts", "alias", alias)
    posts = [
        {
            **extract_stylistic_features(p.get("content") or ""),
            "post_id": p.get("post_id"),
            "alias": alias,
            "captured_at": p.get("timestamp_captured"),
            "version": p.get("version", 1),
        }
        for p in posts_records
    ]

    return {
        "profile": prof,
        "posts_analyzed": posts,
        "disclaimer": DISCLAIMER,
    }


@router.post("/psycho/compare")
def compare_aliases_endpoint(req: CompareRequest) -> Dict[str, Any]:
    """Compare writing styles of two aliases to estimate identity similarity."""
    return compare_profiles(req.alias_a.strip(), req.alias_b.strip())


@router.get("/psycho/stats")
def get_psycho_stats() -> Dict[str, Any]:
    """High-level statistics on extracted profiles and analyzed posts."""
    profiles = db_get_all("psycho_profiles")
    total_posts = sum(int(p.get("post_count") or 0) for p in profiles)
    return {
        "total_profiles": len(profiles),
        "total_posts_analyzed": total_posts,
        "active_aliases": [p["alias"] for p in profiles if p.get("alias")],
        "disclaimer": DISCLAIMER,
    }
