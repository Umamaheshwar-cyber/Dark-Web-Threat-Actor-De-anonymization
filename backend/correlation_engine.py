"""
SHADOWTRACE — Synthetic Analytics & Correlation Engine
Defensive cybersecurity research prototype using synthetic intelligence artifacts only.
All calculations are analytical indicators, not definitive identity attribution.
"""

from typing import List, Dict, Any, Optional, Set
import math
from datetime import datetime


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    if s1_lower == s2_lower:
        return 0
    if not s1_lower:
        return len(s2_lower)
    if not s2_lower:
        return len(s1_lower)

    dp = [[0] * (len(s2_lower) + 1) for _ in range(len(s1_lower) + 1)]
    for i in range(len(s1_lower) + 1):
        dp[i][0] = i
    for j in range(len(s2_lower) + 1):
        dp[0][j] = j

    for i in range(1, len(s1_lower) + 1):
        for j in range(1, len(s2_lower) + 1):
            cost = 0 if s1_lower[i - 1] == s2_lower[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,       # deletion
                dp[i][j - 1] + 1,       # insertion
                dp[i - 1][j - 1] + cost # substitution
            )
    return dp[len(s1_lower)][len(s2_lower)]


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Calculate normalized Levenshtein similarity score between 0.0 and 1.0."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


def jaro_similarity(s1: str, s2: str) -> float:
    """Calculate Jaro similarity score between 0.0 and 1.0."""
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    if s1_lower == s2_lower:
        return 1.0

    len1, len2 = len(s1_lower), len(s2_lower)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1_lower[i] == s2_lower[j]:
                s1_matches[i] = True
                s2_matches[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    k = 0
    transpositions = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1_lower[i] != s2_lower[k]:
            transpositions += 1
        k += 1

    t = transpositions / 2.0
    return (matches / len1 + matches / len2 + (matches - t) / matches) / 3.0


def jaro_winkler_similarity(s1: str, s2: str, prefix_weight: float = 0.1, max_prefix: int = 4) -> float:
    """Calculate Jaro-Winkler similarity giving weight to shared prefix characters."""
    j_sim = jaro_similarity(s1, s2)
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    prefix_len = 0
    for c1, c2 in zip(s1_lower, s2_lower):
        if c1 == c2:
            prefix_len += 1
            if prefix_len == max_prefix:
                break
        else:
            break
    return j_sim + (prefix_len * prefix_weight * (1.0 - j_sim))


def get_ngrams(s: str, n: int = 2) -> Set[str]:
    """Generate set of character n-grams from string."""
    s_clean = s.strip().lower()
    if len(s_clean) < n:
        return {s_clean}
    return {s_clean[i:i + n] for i in range(len(s_clean) - n + 1)}


def ngram_similarity(s1: str, s2: str, n: int = 2) -> float:
    """Calculate Jaccard similarity across character n-grams."""
    ngrams1 = get_ngrams(s1, n)
    ngrams2 = get_ngrams(s2, n)
    intersection = ngrams1.intersection(ngrams2)
    union = ngrams1.union(ngrams2)
    if not union:
        return 1.0 if not ngrams1 and not ngrams2 else 0.0
    return len(intersection) / len(union)


def compute_alias_similarity(s1: str, s2: str) -> Dict[str, Any]:
    """
    Combine Levenshtein, Jaro-Winkler, and 2-gram overlap into an explainable score.
    Weights: 0.35 Levenshtein + 0.35 Jaro-Winkler + 0.30 N-gram overlap.
    """
    lev = levenshtein_similarity(s1, s2)
    jw = jaro_winkler_similarity(s1, s2)
    ng = ngram_similarity(s1, s2, n=2)

    combined = (0.35 * lev) + (0.35 * jw) + (0.30 * ng)
    score_pct = round(combined * 100, 2)

    dist = levenshtein_distance(s1, s2)
    explanation = (
        f"Alias comparison between '{s1}' and '{s2}': "
        f"Levenshtein similarity is {round(lev * 100, 1)}% (edit distance: {dist}), "
        f"Jaro-Winkler prefix alignment is {round(jw * 100, 1)}%, "
        f"and bigram character overlap is {round(ng * 100, 1)}%. "
        f"Combined weighted alias score: {score_pct}%."
    )

    return {
        "candidate_a": s1,
        "candidate_b": s2,
        "levenshtein_score": round(lev * 100, 2),
        "jaro_winkler_score": round(jw * 100, 2),
        "ngram_overlap_score": round(ng * 100, 2),
        "combined_score": score_pct,
        "explanation": explanation
    }


LEGACY_SYNTHETIC_ACTOR_IDS: Set[str] = {
    "ACT-001", "ACT-002", "ACT-003", 
    "ACT-010", "ACT-011", 
    "ACT-020", "ACT-021"
}

LEGACY_SYNTHETIC_ACTOR_NAMES: Set[str] = {
    "SHADOWX", "SHADOWX2", "FORUM-ALIAS-17", "MARKETPLACE-ALIAS-04",
    "CIPHERPHANTOM", "NODEWATCHER", "PHANTOMCRYPT_DEV",
    "GHOSTWEAVER", "PACKETDRIFTER", "GHOST_WEAVE99"
}

def is_synthetic_case(actor: Dict[str, Any], evidence_list: Optional[List[Dict[str, Any]]] = None) -> bool:
    """
    Determine if the actor belongs to an explicitly isolated legacy synthetic regression case.
    DEFAULT BEHAVIOR: Returns False for all real, authorized, OSINT, feed, unknown, or unclassified cases.
    Returns True ONLY if the entity strictly matches known legacy synthetic research fixtures.
    """
    if not actor or not isinstance(actor, dict):
        return False

    actor_id = str(actor.get("id", "")).strip().upper()
    actor_name = str(actor.get("name", "")).strip().upper()
    note = str(actor.get("note", "")).upper()

    # Rule 1: Any explicit authorized / real CTI markers immediately disqualify from synthetic mode
    if (
        actor_id.startswith("ACT-AUTH-") or 
        "AUTH" in actor_id or 
        "MISP" in actor_id or
        "AUTHORIZED" in actor_name or 
        "CIRCL" in actor_name or 
        "FEED" in actor_name or
        "MISP" in note or 
        "AUTHORIZED" in note or 
        "CIRCL" in note or 
        "NON-ATTRIBUTIVE" in note
    ):
        return False

    # Rule 2: Any authorized or CIRCL evidence records disqualify
    if evidence_list:
        for ev in evidence_list:
            ev_id = str(ev.get("id", "")).upper()
            if ev_id.startswith("CIRCL-") or ev_id.startswith("MISP-"):
                return False
            rel = str(ev.get("relationship", "")).upper()
            if "CIRCL OSINT" in rel or "AUTHORIZED" in rel or "PUBLIC OSINT" in rel:
                return False

    # Rule 3: Explicit legacy synthetic regression fixtures
    if actor_id in LEGACY_SYNTHETIC_ACTOR_IDS or actor_name in LEGACY_SYNTHETIC_ACTOR_NAMES:
        return True

    if "SYNTHETIC" in note:
        return True

    # Rule 4: Default is safe (non-synthetic / real data rules apply)
    return False


def compute_cryptographic_signal(actor: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluate cryptographic PGP and cryptocurrency wallet reuse signals.
    In real/authorized cases, identifiers are only evaluated if genuine source-provided values exist.
    """
    is_synth = is_synthetic_case(actor, evidence_list)
    raw_pgp = actor.get("pgp")
    raw_wallet = actor.get("wallet")

    actor_pgp = str(raw_pgp).strip() if raw_pgp else ""
    actor_wallet = str(raw_wallet).strip() if raw_wallet else ""

    # In real/authorized cases, filter out synthetic placeholders
    if not is_synth:
        if "-SYN-" in actor_pgp.upper() or "SYNTHETIC" in actor_pgp.upper():
            actor_pgp = ""
        if "-SYN-" in actor_wallet.upper() or "SYNTHETIC" in actor_wallet.upper():
            actor_wallet = ""

    # If neither PGP nor wallet is available
    if not actor_pgp and not actor_wallet:
        if not is_synth:
            return {
                "score": None,
                "pgp_identifier": None,
                "wallet_identifier": None,
                "pgp_correlated": False,
                "wallet_correlated": False,
                "status": "UNAVAILABLE",
                "explanation": "Not available from source — no authenticated cryptographic keys or cryptocurrency wallets provided by source."
            }
        else:
            return {
                "score": 15.0,
                "pgp_identifier": "",
                "wallet_identifier": "",
                "pgp_correlated": False,
                "wallet_correlated": False,
                "status": "AVAILABLE",
                "explanation": "No confirmed cryptographic key or wallet identifier matches found in evidence cluster."
            }

    pgp_matches = [e for e in evidence_list if e.get("type") == "PGP" and str(e.get("identifier", "")).strip() == actor_pgp] if actor_pgp else []
    wallet_matches = [e for e in evidence_list if e.get("type") == "WALLET" and str(e.get("identifier", "")).strip() == actor_wallet] if actor_wallet else []

    has_pgp = len(pgp_matches) > 0
    has_wallet = len(wallet_matches) > 0

    if has_pgp and has_wallet:
        score = 95.0
        reason = (
            f"Dual high-entropy cryptographic reuse: PGP key '{actor_pgp}' "
            f"and cryptocurrency wallet '{actor_wallet}' both correlate across independent evidence records."
        )
    elif has_pgp:
        score = 85.0
        reason = f"High-entropy PGP reuse: key '{actor_pgp}' correlated across evidence."
    elif has_wallet:
        score = 80.0
        reason = f"High-entropy wallet reuse: cryptocurrency wallet '{actor_wallet}' correlated across evidence."
    else:
        if not is_synth:
            return {
                "score": None,
                "pgp_identifier": actor_pgp or None,
                "wallet_identifier": actor_wallet or None,
                "pgp_correlated": False,
                "wallet_correlated": False,
                "status": "UNAVAILABLE",
                "explanation": "Not available from source — cryptographic identifiers present but no correlated matches found in evidence."
            }
        else:
            score = 15.0
            reason = "Cryptographic identifiers provided by source but no matching records found in evidence cluster."

    return {
        "score": score,
        "pgp_identifier": actor_pgp or None,
        "wallet_identifier": actor_wallet or None,
        "pgp_correlated": has_pgp,
        "wallet_correlated": has_wallet,
        "status": "AVAILABLE",
        "explanation": reason
    }


def compute_temporal_alignment_signal(
    timeline_events: List[Dict[str, Any]],
    is_synth: bool = False
) -> Dict[str, Any]:
    """
    Evaluate temporal co-occurrence across investigation milestones.
    Evaluates regular observation cadence and event clustering.
    If insufficient real events exist, returns unavailable rather than a fabricated 50%.
    """
    if len(timeline_events) < 2:
        if is_synth:
            return {
                "score": 50.0,
                "event_count": len(timeline_events),
                "cadence_days_avg": 0,
                "status": "AVAILABLE",
                "explanation": "Insufficient temporal events to establish correlation cadence."
            }
        return {
            "score": None,
            "event_count": len(timeline_events),
            "cadence_days_avg": 0,
            "status": "UNAVAILABLE",
            "explanation": "Not available from source — insufficient temporal milestones to establish correlation cadence."
        }

    # Parse dates from timeline events
    parsed_dates = []
    for ev in timeline_events:
        d_str = ev.get("date") or ev.get("timestamp")
        if d_str:
            clean_date = str(d_str).split(" ")[0].split("T")[0]
            try:
                parsed_dates.append(datetime.strptime(clean_date, "%Y-%m-%d"))
            except ValueError:
                pass

    if len(parsed_dates) < 2:
        if is_synth:
            return {
                "score": 60.0,
                "event_count": len(timeline_events),
                "cadence_days_avg": 0,
                "status": "AVAILABLE",
                "explanation": "Event sequence observed without parseable timestamp intervals."
            }
        return {
            "score": None,
            "event_count": len(timeline_events),
            "cadence_days_avg": 0,
            "status": "UNAVAILABLE",
            "explanation": "Not available from source — event sequence observed without parseable timestamp intervals."
        }

    parsed_dates.sort()
    intervals = [(parsed_dates[i] - parsed_dates[i - 1]).days for i in range(1, len(parsed_dates))]
    avg_interval = sum(intervals) / len(intervals)

    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    if avg_interval <= 8 and std_dev <= 4.0:
        score = 80.0
        reason = (
            f"High temporal correlation: observations occur with an average cadence of {avg_interval:.1f} days "
            f"(std dev: {std_dev:.1f} days), demonstrating sustained operational synchronization across {len(timeline_events)} milestones."
        )
    else:
        score = 65.0
        reason = f"Moderate temporal alignment: observations average {avg_interval:.1f} days apart."

    return {
        "score": score,
        "event_count": len(timeline_events),
        "cadence_days_avg": round(avg_interval, 1),
        "status": "AVAILABLE",
        "explanation": reason
    }


def compute_opsec_exposure_evaluation(actor: Dict[str, Any], raw_opsec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate dynamic OPSEC exposure index based on observable signals.
    For real/authorized cases without genuine OPSEC telemetry, returns an explicit unavailable state.
    """
    is_synth = is_synthetic_case(actor)
    actor_id = actor.get("id", "ACT-AUTH-001" if not is_synth else "ACT-001")
    actor_name = actor.get("name", "Authorized Feed Cluster" if not is_synth else "UnknownActor")

    if not is_synth:
        # Check if source actually provides genuine, non-synthetic OPSEC telemetry
        raw_values = raw_opsec.get("values")
        raw_labels = raw_opsec.get("labels")
        if raw_values and isinstance(raw_values, list) and len(raw_values) > 0 and raw_labels and isinstance(raw_labels, list) and len(raw_labels) > 0:
            current_score = raw_values[-1]
            level = "High Exposure" if current_score >= 65 else "Moderate Exposure" if current_score >= 40 else "Low Exposure"
            return {
                "actor_id": actor_id,
                "actor_name": actor_name,
                "current_exposure_score": current_score,
                "exposure_level": level,
                "trend_labels": raw_labels,
                "trend_values": raw_values,
                "contributing_events": raw_opsec.get("contributing_events", []),
                "explanation": f"Source-provided operational security exposure index of {current_score}/100 ({level})."
            }
        return {
            "actor_id": actor_id,
            "actor_name": actor_name,
            "current_exposure_score": None,
            "exposure_level": "Not available from source",
            "trend_labels": [],
            "trend_values": [],
            "contributing_events": [],
            "explanation": "Not available from source — public CIRCL and authorized MISP threat feeds do not publish operational security exposure telemetry."
        }

    labels = raw_opsec.get("labels", ["Week 1", "Week 2", "Week 3", "Week 4", "Week 5", "Week 6"])
    raw_values = raw_opsec.get("values", [31, 36, 42, 51, 59, 68])

    actor_aliases = actor.get("aliases", [actor_name])
    correlated_alias = actor_aliases[1] if len(actor_aliases) > 1 else actor_name
    actor_pgp = actor.get("pgp", "PGP-SYN-UNKNOWN")
    actor_wallet = actor.get("wallet", "WALLET-SYN-UNKNOWN")

    week_labels = labels if len(labels) >= 6 else [f"Week {i + 1}" for i in range(6)]

    events = [
        {
            "week": week_labels[0],
            "signal": "Alias Similarity",
            "points": 15,
            "description": (
                f"Observable handle variation '{correlated_alias}' registered in close proximity "
                f"to primary candidate '{actor_name}'."
            )
        },
        {
            "week": week_labels[1],
            "signal": "PGP Key Reuse",
            "points": 25,
            "description": (
                f"Synthetic public key '{actor_pgp}' linked across multiple monitored platforms."
            )
        },
        {
            "week": week_labels[2],
            "signal": "Stylometric Leak",
            "points": 20,
            "description": "Consistent syntax and punctuation patterns matched across forum communications."
        },
        {
            "week": week_labels[3],
            "signal": "Wallet Address Reuse",
            "points": 25,
            "description": (
                f"Identical synthetic cryptocurrency wallet '{actor_wallet}' published in public thread."
            )
        },
        {
            "week": week_labels[4],
            "signal": "Temporal Cadence Synchronization",
            "points": 15,
            "description": "Synchronous activity windows detected between alias transition nodes."
        },
        {
            "week": week_labels[5],
            "signal": "Multi-Signal Convergence",
            "points": 20,
            "description": (
                f"Intersection of cryptographic ('{actor_pgp}'/'{actor_wallet}'), temporal, and "
                f"stylometric indicators confirms high observable profile for '{actor_name}'."
            )
        }
    ]

    current_exposure = raw_values[-1] if raw_values else 68
    exposure_level = "High Exposure" if current_exposure >= 65 else "Moderate Exposure" if current_exposure >= 40 else "Low Exposure"

    return {
        "actor_id": actor_id,
        "actor_name": actor_name,
        "current_exposure_score": current_exposure,
        "exposure_level": exposure_level,
        "trend_labels": labels,
        "trend_values": raw_values,
        "contributing_events": events,
        "explanation": (
            f"Synthetic actor {actor_name} exhibits an OPSEC exposure index of {current_exposure}/100 ({exposure_level}). "
            f"Primary exposure drivers include cryptographic identifier reuse (PGP/wallet) and persistent alias variations."
        )
    }


def compute_multi_signal_correlation(
    actor: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Ensemble correlation assessment across 5 dimensions:
    - Cryptographic / Wallet identifier reuse (base weight 35%)
    - Alias string similarity (base weight 20%)
    - Temporal cadence alignment (base weight 15%)
    - Stylometric similarity score (base weight 15%)
    - Behavioural similarity score (base weight 15%)

    For real/authorized CTI data:
    - Excludes unavailable signals from weighted calculations
    - Renormalizes weights ONLY across genuinely available signals
    - Never treats missing data as zero or positive
    - When all signals are unavailable, returns None for overall_confidence with tier UNAVAILABLE
    """
    is_synth = is_synthetic_case(actor, evidence_list)

    # 1. Cryptographic signal (base weight 0.35)
    crypto_res = compute_cryptographic_signal(actor, evidence_list)
    crypto_score = crypto_res.get("score")
    crypto_avail = crypto_score is not None

    # 2. Alias similarity (base weight 0.20)
    aliases = actor.get("aliases", [])
    actor_name = actor.get("name", "UnknownActor")
    alias_breakdown = None
    alias_score = None
    alias_avail = False
    target_alias = None

    if is_synth:
        target_alias = aliases[1] if len(aliases) > 1 else (aliases[0] if aliases else actor_name)
        alias_breakdown = compute_alias_similarity(actor_name, target_alias)
        alias_score = alias_breakdown["combined_score"]
        alias_avail = True
        alias_explanation = alias_breakdown["explanation"]
    else:
        distinct_aliases = [a for a in aliases if a and str(a).strip().lower() != actor_name.lower()]
        if distinct_aliases:
            target_alias = distinct_aliases[0]
            alias_breakdown = compute_alias_similarity(actor_name, target_alias)
            alias_score = alias_breakdown["combined_score"]
            alias_avail = True
            alias_explanation = alias_breakdown["explanation"]
        else:
            target_alias = None
            alias_score = None
            alias_avail = False
            alias_explanation = "Not available from source — insufficient source-provided candidate aliases to perform similarity analysis."

    # 3. Temporal alignment (base weight 0.15)
    temporal_res = compute_temporal_alignment_signal(timeline_events, is_synth=is_synth)
    temporal_score = temporal_res.get("score")
    temporal_avail = temporal_score is not None

    # 4. Stylometry score (base weight 0.15)
    raw_stylometry = actor.get("stylometry")
    stylometry_score = None
    stylometry_avail = False
    if is_synth:
        stylometry_score = float(raw_stylometry if raw_stylometry is not None else 75)
        stylometry_avail = True
        stylometry_reason = f"Synthetically analyzed language and phrasing patterns matched at {stylometry_score}%."
    else:
        if raw_stylometry is not None:
            try:
                stylometry_score = float(raw_stylometry)
                stylometry_avail = True
                stylometry_reason = f"Source-provided stylometric analysis matched at {stylometry_score}%."
            except (ValueError, TypeError):
                stylometry_score = None
                stylometry_avail = False
                stylometry_reason = "Not available from source — invalid stylometry measurement."
        else:
            stylometry_score = None
            stylometry_avail = False
            stylometry_reason = "Not available from source — no unstructured natural language text corpus available for stylometric analysis."

    # 5. Behaviour score (base weight 0.15)
    raw_behaviour = actor.get("behaviour")
    behaviour_score = None
    behaviour_avail = False
    if is_synth:
        behaviour_score = float(raw_behaviour if raw_behaviour is not None else 70)
        behaviour_avail = True
        behaviour_reason = f"Operational activity hours and interaction behaviors aligned at {behaviour_score}%."
    else:
        if raw_behaviour is not None:
            try:
                behaviour_score = float(raw_behaviour)
                behaviour_avail = True
                behaviour_reason = f"Source-provided behavioural observation aligned at {behaviour_score}%."
            except (ValueError, TypeError):
                behaviour_score = None
                behaviour_avail = False
                behaviour_reason = "Not available from source — no operational interaction telemetry available for behavioural profiling."
        else:
            behaviour_score = None
            behaviour_avail = False
            behaviour_reason = "Not available from source — no operational interaction telemetry available for behavioural profiling."

    # Ensemble signal definitions
    dimension_specs = [
        {
            "dimension": "Cryptographic & Wallet Reuse",
            "score": crypto_score,
            "base_weight": 0.35,
            "available": crypto_avail,
            "explanation": crypto_res["explanation"]
        },
        {
            "dimension": "Alias Similarity",
            "score": alias_score,
            "base_weight": 0.20,
            "available": alias_avail,
            "explanation": alias_explanation
        },
        {
            "dimension": "Temporal Alignment",
            "score": temporal_score,
            "base_weight": 0.15,
            "available": temporal_avail,
            "explanation": temporal_res["explanation"]
        },
        {
            "dimension": "Stylometric Similarity",
            "score": stylometry_score,
            "base_weight": 0.15,
            "available": stylometry_avail,
            "explanation": stylometry_reason
        },
        {
            "dimension": "Behavioural Similarity",
            "score": behaviour_score,
            "base_weight": 0.15,
            "available": behaviour_avail,
            "explanation": behaviour_reason
        }
    ]

    available_dims = [d for d in dimension_specs if d["available"]]
    available_weight_sum = sum(d["base_weight"] for d in available_dims)

    signals: List[Dict[str, Any]] = []

    if available_weight_sum > 0:
        overall_confidence_calc = 0.0
        for d in dimension_specs:
            if d["available"]:
                renorm_weight = round(d["base_weight"] / available_weight_sum, 4)
                weighted_score = round(d["score"] * renorm_weight, 2)
                overall_confidence_calc += weighted_score
                signals.append({
                    "dimension": d["dimension"],
                    "score": d["score"],
                    "weight": renorm_weight,
                    "weighted_score": weighted_score,
                    "explanation": d["explanation"],
                    "status": "AVAILABLE"
                })
            else:
                signals.append({
                    "dimension": d["dimension"],
                    "score": None,
                    "weight": 0.0,
                    "weighted_score": None,
                    "explanation": d["explanation"],
                    "status": "UNAVAILABLE"
                })

        final_score = round(overall_confidence_calc, 1)
        if final_score >= 75.0:
            tier = "HIGH"
        elif final_score >= 50.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        if is_synth:
            summary = (
                f"Multi-signal correlation for candidate '{actor_name}' against cluster yields a "
                f"{final_score}% overall confidence score ({tier} CONFIDENCE). "
                f"The link is heavily reinforced by verified synthetic PGP/wallet identifier reuse and high alias proximity."
            )
        else:
            summary = (
                f"Multi-signal correlation for '{actor_name}' yields a "
                f"{final_score}% overall confidence score ({tier} CONFIDENCE) across {len(available_dims)} available signal dimensions."
            )
    else:
        final_score = None
        tier = "UNAVAILABLE"
        for d in dimension_specs:
            signals.append({
                "dimension": d["dimension"],
                "score": None,
                "weight": 0.0,
                "weighted_score": None,
                "explanation": d["explanation"],
                "status": "UNAVAILABLE"
            })
        summary = (
            f"No source-backed correlation available — authorized external source provides atomic indicators without persona telemetry for '{actor_name}'."
        )

    return {
        "actor_id": actor.get("id"),
        "actor_name": actor_name,
        "primary_alias": actor_name,
        "correlated_alias": target_alias,
        "overall_confidence": final_score,
        "confidence_tier": tier,
        "signals": signals,
        "alias_breakdown": alias_breakdown,
        "summary": summary,
        "disclaimer": "Defensive cybersecurity analytical signal — not definitive real-world identity attribution."
    }
