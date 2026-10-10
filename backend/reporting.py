"""
SHADOWTRACE — Investigation Report Generation Core (Phase 4 Step 4)
Generates structured dictionary and professional Markdown investigation reports from synthetic cases.
Strictly offline, standard-library-only implementation using synthetic research artifacts.
Delineates raw observed evidence from analytical interpretations; non-attributive.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import re
from backend.data_store import (
    load_raw_data,
    get_actors_data,
    get_evidence_data,
    get_timeline_data,
    get_graph_data,
    get_opsec_by_actor,
    DEFAULT_CASE_ID
)
from backend.correlation_engine import (
    compute_multi_signal_correlation,
    compute_opsec_exposure_evaluation
)
from backend.provenance import (
    generate_evidence_hash,
    build_evidence_provenance
)

SYNTHETIC_SAFETY_DISCLAIMER = (
    "Defensive cybersecurity research prototype using synthetic intelligence artifacts only. "
    "Correlation scores and confidence metrics represent analytical signals, NOT proof of real-world identity."
)

AUTHORIZED_SAFETY_DISCLAIMER = (
    "Authorized threat intelligence briefing derived from public OSINT feeds (CIRCL). "
    "Defensive observables only — not proof of individual or organization attribution."
)

SYNTHETIC_LIMITATIONS_LIST = [
    "All intelligence artifacts in this dossier are synthetic demo data generated for defensive cybersecurity research.",
    "Correlation values (e.g. 86.1%) represent probabilistic analytical signals and do NOT establish real-world legal identity.",
    "No dark-web, Tor, private-system, or unauthorized infrastructure connections are present in this dataset.",
    "Observations may be incomplete; absence of observed evidence is not proof of absence of activity.",
    "OPSEC exposure values represent observable identity-leak indicators and are not predictive of future human errors.",
    "This report is an internal research briefing and makes no claim of court or legal admissibility."
]

AUTHORIZED_LIMITATIONS_LIST = [
    "Threat intelligence indicators are ingested from authorized public MISP OSINT feeds (CIRCL).",
    "All indicators are defensive technical observables and do NOT establish real-world identity or individual attribution.",
    "No dark-web, Tor, private-system, or unauthorized infrastructure connections are present in this dataset.",
    "Observations represent published threat feed indicators and may be incomplete; absence of an observable is not proof of absence of threat activity.",
    "Persona-level metrics (stylometry, behaviour, OPSEC tracking) are not available from source in technical threat feeds.",
    "This report is an internal research briefing and makes no claim of legal admissibility."
]

SYNTHETIC_SAFETY_CLASSIFICATION = {
    "data_mode": "SYNTHETIC_DEMO_DATA",
    "project_scope": "DEFENSIVE_RESEARCH_PROTOTYPE",
    "attribution_policy": "ANALYTICAL_SIGNALS_ONLY_NOT_IDENTITY_PROOF",
    "network_scope": "LOCAL_AUTHORIZED_RESEARCH_ONLY"
}

AUTHORIZED_SAFETY_CLASSIFICATION = {
    "data_mode": "AUTHORIZED_PUBLIC_CTI",
    "project_scope": "DEFENSIVE_RESEARCH_PROTOTYPE",
    "attribution_policy": "DEFENSIVE_OBSERVABLES_ONLY_NO_ATTRIBUTION",
    "network_scope": "PUBLIC_AUTHORIZED_OSINT_FEED"
}

def is_synthetic_case_id(case_id: str) -> bool:
    cid = str(case_id).strip().upper()
    if cid in ("CASE-2026-09X", "CASE-SYN-001", "CASE-2026-02B", "CASE-SYN-002", "CASE-2026-03C", "CASE-SYN-003"):
        return True
    if cid.startswith("CASE-AUTH-") or "MISP" in cid or "CIRCL" in cid:
        return False
    return False


def format_report_timestamp() -> str:
    """Return current ISO 8601 UTC timestamp for report header."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def generate_investigation_report(case_id: str) -> Dict[str, Any]:
    """
    Generate a structured investigation report dictionary for a given case.
    Preserves authentic provenance and Admiralty ratings for real CTI data.
    """
    raw_data = load_raw_data(case_id)  # Will raise KeyError if invalid case_id
    case_info = raw_data.get("case", {})
    cid = case_info.get("id", case_id)
    gen_time = format_report_timestamp()
    is_synth = is_synthetic_case_id(case_id)

    actors_raw = get_actors_data(case_id)
    evidence_raw = get_evidence_data(case_id)
    timeline_raw = get_timeline_data(case_id)
    graph_raw = get_graph_data(case_id)
    raw_opsec = raw_data.get("opsec", {})

    # 1. Case Summary
    if is_synth:
        case_summary = {
            "case_id": cid,
            "title": f"SHADOWTRACE Investigation Briefing — {cid} ({case_info.get('candidate', 'SyntheticCandidate')})",
            "candidate_subject": case_info.get("candidate", "Unknown"),
            "status": case_info.get("status", "ACTIVE"),
            "classification": case_info.get("classification", "SYNTHETIC DEMO DATA"),
            "description": case_info.get("description", ""),
            "report_generated_at": gen_time,
            "disclaimer": SYNTHETIC_SAFETY_DISCLAIMER
        }
    else:
        case_summary = {
            "case_id": cid,
            "title": f"SHADOWTRACE Investigation Briefing — {cid} ({case_info.get('candidate', 'Authorized Feed Subject')})",
            "candidate_subject": case_info.get("candidate", "Authorized Feed Subject"),
            "status": case_info.get("status", "AUTHORIZED CTI FEED"),
            "classification": case_info.get("classification", "AUTHORIZED CTI INTELLIGENCE"),
            "description": case_info.get("description", "Authorized CTI feed indicators imported from authenticated MISP instance. Strictly non-attributive."),
            "report_generated_at": gen_time,
            "disclaimer": AUTHORIZED_SAFETY_DISCLAIMER
        }

    # 2. Actors Section
    actors_report: List[Dict[str, Any]] = []
    for a in actors_raw:
        if is_synth:
            actors_report.append({
                "actor_id": a.get("id"),
                "synthetic_name": a.get("name"),
                "tier": a.get("tier"),
                "analytical_confidence": a.get("confidence"),
                "confidence_disclaimer": "Analytical signal — NOT proof of real-world identity.",
                "aliases": a.get("aliases", []),
                "synthetic_pgp": a.get("pgp"),
                "synthetic_wallet": a.get("wallet"),
                "stylometry_score": a.get("stylometry"),
                "behaviour_score": a.get("behaviour"),
                "note": a.get("note", "")
            })
        else:
            actors_report.append({
                "actor_id": a.get("id"),
                "entity_name": a.get("name", "Authorized Feed Cluster"),
                "tier": a.get("tier", "Tier 1 — Monitored Feed"),
                "analytical_confidence": None,
                "confidence_disclaimer": "Defensive analytical signal — NOT proof of real-world identity or attribution.",
                "aliases": [],
                "pgp": None,
                "wallet": None,
                "stylometry_score": None,
                "behaviour_score": None,
                "note": a.get("note", "Authorized threat intelligence indicators from authenticated MISP instance.")
            })

    # 3. Evidence Summary (Delineating observed data vs analytical conclusions)
    evidence_report: List[Dict[str, Any]] = []
    for ev in evidence_raw:
        sha256_hash = generate_evidence_hash(ev)
        ev_id = str(ev.get("id", "EV-000"))
        timestamp = ev.get("timestamp")

        if is_synth:
            source_origin = "SYNTHETIC_DEMO_REPOSITORY"
            obs_time = timestamp or "2026-09-01 00:00"
            collection_meta = {
                "collection_mode": "SYNTHETIC_RESEARCH_FIXTURE",
                "collector_tag": "CTI_DEFENSIVE_PIPELINE",
                "network_scope": "LOCAL_AUTHORIZED_ONLY"
            }
            admiralty_rel = "A - Completely Reliable"
            admiralty_cred = "1 - Confirmed by Other Sources"
        else:
            if ev_id.startswith("CIRCL-"):
                source_origin = "PUBLIC_CIRCL_MISP_OSINT_FEED"
                collection_meta = {
                    "collection_mode": "PUBLIC_CIRCL_MISP_OSINT_FEED",
                    "target_case_id": cid,
                    "network_scope": "PUBLIC_AUTHORIZED_OSINT_FEED",
                    "attribution_policy": "DEFENSIVE_OBSERVABLE_CTI_ONLY"
                }
            elif ev_id.startswith("MISP-"):
                source_origin = "AUTHORIZED_MISP_FEED"
                collection_meta = {
                    "collection_mode": "AUTHORIZED_MISP_REST_API",
                    "target_case_id": cid,
                    "network_scope": "AUTHORIZED_EXTERNAL_FEED",
                    "attribution_policy": "DEFENSIVE_OBSERVABLE_CTI_ONLY"
                }
            else:
                source_origin = "Not available from source"
                collection_meta = {
                    "collection_mode": "Not available from source",
                    "target_case_id": cid
                }
            obs_time = timestamp or "Not available from source"
            admiralty_rel = "B - Usually Reliable"
            admiralty_cred = "2 - Probably True"

        prov = build_evidence_provenance(
            evidence_id=ev_id,
            raw_observed_payload=ev,
            source_origin=source_origin,
            observation_timestamp=obs_time,
            collection_metadata=collection_meta,
            admiralty_reliability=admiralty_rel,
            admiralty_credibility=admiralty_cred
        )
        evidence_report.append({
            "evidence_id": ev_id,
            "category": ev.get("type"),
            "observed_data": {
                "identifier": ev.get("identifier"),
                "observation_timestamp": obs_time,
                "sha256_integrity_hash": sha256_hash
            },
            "analytical_interpretation": {
                "relationship": ev.get("relationship"),
                "confidence": ev.get("confidence", "Medium"),
                "status": ev.get("status", "Observed"),
                "is_conclusion": True,
                "disclaimer": "Analytical interpretation — not an observed physical fact."
            },
            "provenance_metadata": prov.get("provenance", {})
        })

    # 4. Relationship Summary (Preserving only existing case relationships)
    relationships_report: List[Dict[str, Any]] = []
    for edge in graph_raw.get("edges", []):
        src = edge.get("source")
        tgt = edge.get("target")
        rel_type = edge.get("relationship")
        conf = edge.get("confidence")

        supporting_ev = [
            e.get("id") for e in evidence_raw
            if e.get("identifier") in (src, tgt) or rel_type.lower() in e.get("relationship", "").lower()
        ]

        relationships_report.append({
            "source": src,
            "target": tgt,
            "relationship_type": rel_type,
            "confidence": conf,
            "supporting_evidence_ids": supporting_ev
        })

    # 5. Correlation Analysis (Phase 2 Multi-Signal Engine)
    correlation_report: Optional[Dict[str, Any]] = None
    if actors_raw:
        primary_actor = actors_raw[0]
        corr_res = compute_multi_signal_correlation(primary_actor, evidence_raw, timeline_raw)
        
        signals_labelled = []
        for sig in corr_res.get("signals", []):
            signals_labelled.append({
                "signal_name": sig.get("dimension"),
                "signal_score": sig.get("score"),
                "weight": sig.get("weight"),
                "weighted_contribution": sig.get("weighted_score"),
                "type": "Analytical Signal",
                "explanation": sig.get("explanation")
            })

        correlation_report = {
            "primary_candidate": primary_actor.get("name"),
            "overall_correlation_confidence": corr_res.get("overall_confidence"),
            "confidence_tier": corr_res.get("confidence_tier"),
            "analytical_signals": signals_labelled,
            "summary": corr_res.get("summary"),
            "disclaimer": "Analytical signal ensemble — NOT proof of real-world identity."
        }

    # 6. OPSEC / Exposure Indicators
    opsec_report: Optional[Dict[str, Any]] = None
    if actors_raw:
        primary_actor = actors_raw[0]
        opsec_res = compute_opsec_exposure_evaluation(primary_actor, raw_opsec)
        
        opsec_report = {
            "actor_id": primary_actor.get("id"),
            "actor_name": primary_actor.get("name"),
            "current_exposure_score": opsec_res.get("current_exposure_score"),
            "exposure_level": opsec_res.get("exposure_level"),
            "trend_labels": opsec_res.get("trend_labels"),
            "trend_values": opsec_res.get("trend_values"),
            "observed_exposure_indicators": opsec_res.get("contributing_events"),
            "assessment_summary": opsec_res.get("explanation"),
            "predictive_disclaimer": "Describes observed historical exposure indicators only; non-predictive."
        }

    # 7. Timeline (Preserving chronological order and exact terminology)
    timeline_report: List[Dict[str, Any]] = []
    for item in timeline_raw:
        timeline_report.append({
            "week": item.get("week"),
            "date": item.get("date"),
            "event": item.get("event"),
            "detail": item.get("detail")
        })

    # Assemble structured report dictionary
    report_dict = {
        "case_summary": case_summary,
        "actors": actors_report,
        "evidence_summary": evidence_report,
        "relationships": relationships_report,
        "correlation_analysis": correlation_report,
        "opsec_exposure_indicators": opsec_report,
        "timeline": timeline_report,
        "limitations": SYNTHETIC_LIMITATIONS_LIST if is_synth else AUTHORIZED_LIMITATIONS_LIST,
        "safety_classification": SYNTHETIC_SAFETY_CLASSIFICATION if is_synth else AUTHORIZED_SAFETY_CLASSIFICATION
    }

    return report_dict


def generate_investigation_report_markdown(case_id: str) -> str:
    """
    Generate a professional Markdown investigation briefing for a given case.
    Accurately delineates synthetic research artifacts from real authorized CTI feeds.
    
    Args:
        case_id: Case identifier (synthetic or authorized CTI)
        
    Returns:
        Formatted Markdown string ready for rendering or briefing output.
    """
    report = generate_investigation_report(case_id)
    cs = report["case_summary"]
    corr = report["correlation_analysis"] or {}
    opsec = report["opsec_exposure_indicators"] or {}
    is_synth = is_synthetic_case_id(case_id)

    lines = []
    lines.append(f"# {cs['title']}")
    lines.append(f"**Case ID:** `{cs['case_id']}` | **Status:** `{cs['status']}` | **Classification:** `{cs['classification']}`")
    lines.append(f"**Report Generated:** `{cs['report_generated_at']}`\n")
    lines.append(f"> **Disclaimer:** {cs['disclaimer']}\n")

    lines.append("## 1. Executive Case Summary")
    lines.append(f"{cs['description']}\n")
    lines.append(f"* **Candidate Subject:** `{cs['candidate_subject']}`")
    lines.append(f"* **Tracked Actors:** {len(report['actors'])}")
    lines.append(f"* **Evidence Artifacts:** {len(report['evidence_summary'])}")
    lines.append(f"* **Correlated Relationships:** {len(report['relationships'])}\n")

    if is_synth:
        lines.append("## 2. Tracked Synthetic Actors")
        for a in report["actors"]:
            lines.append(f"### Actor: {a['synthetic_name']} (`{a['actor_id']}`)")
            lines.append(f"* **Threat Tier:** {a['tier']}")
            lines.append(f"* **Analytical Confidence:** `{a['analytical_confidence']}%` ({a['confidence_disclaimer']})")
            lines.append(f"* **Aliases:** {', '.join(a['aliases'])}")
            lines.append(f"* **Synthetic PGP Key:** `{a['synthetic_pgp']}`")
            lines.append(f"* **Synthetic Wallet:** `{a['synthetic_wallet']}`")
            lines.append(f"* **Stylometry / Behaviour Scores:** `{a['stylometry_score']}%` / `{a['behaviour_score']}%`")
            if a.get("note"):
                lines.append(f"* **Note:** {a['note']}")
            lines.append("")
    else:
        lines.append("## 2. Tracked Feed Entities")
        for a in report["actors"]:
            ent_name = a.get("entity_name") or a.get("synthetic_name") or "Authorized Feed Cluster"
            lines.append(f"### Entity: {ent_name} (`{a['actor_id']}`)")
            lines.append(f"* **Threat Tier:** {a['tier']}")
            lines.append(f"* **Attribution Status:** None (Defensive technical observables only — strictly non-attributive)")
            lines.append(f"* **Aliases:** None")
            lines.append(f"* **PGP Key:** Not available from source")
            lines.append(f"* **Wallet:** Not available from source")
            lines.append(f"* **Stylometry / Behaviour Scores:** Not available from source")
            if a.get("note"):
                lines.append(f"* **Note:** {a['note']}")
            lines.append("")

    lines.append("## 3. Evidence Summary & Cryptographic Integrity")
    lines.append("| Evidence ID | Category | Observed Identifier | Timestamp | SHA-256 Digest | Status & Interpretation |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for ev in report["evidence_summary"]:
        obs = ev["observed_data"]
        interp = ev["analytical_interpretation"]
        trunc_hash = obs["sha256_integrity_hash"][:16] + "…"
        lines.append(f"| `{ev['evidence_id']}` | `{ev['category']}` | `{obs['identifier']}` | {obs['observation_timestamp']} | `{trunc_hash}` | {interp['relationship']} ({interp['status']}) |")
    lines.append("")

    lines.append("## 4. Multi-Signal Correlation Analysis")
    if corr:
        overall_conf = corr.get("overall_correlation_confidence")
        conf_tier = corr.get("confidence_tier", "UNAVAILABLE")
        if overall_conf is not None:
            lines.append(f"**Overall Correlation Confidence:** `{overall_conf}%` (**{conf_tier} CONFIDENCE**)")
        else:
            lines.append(f"**Overall Correlation Confidence:** `UNAVAILABLE` (**{conf_tier}**)")
        lines.append(f"*{corr.get('summary')}*\n")
        lines.append("| Signal Dimension | Signal Score | Weight | Contribution | Type | Explanation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for sig in corr.get("analytical_signals", []):
            score_disp = f"`{sig['signal_score']}%`" if sig.get("signal_score") is not None else "`N/A`"
            weight_disp = f"`{sig['weight']}`" if sig.get("weight") is not None else "`0.0`"
            contrib_disp = f"`+{sig['weighted_contribution']}%`" if sig.get("weighted_contribution") is not None else "`0.0%`"
            lines.append(f"| {sig['signal_name']} | {score_disp} | {weight_disp} | {contrib_disp} | **{sig['type']}** | {sig['explanation']} |")
        lines.append(f"\n> **Notice:** {corr.get('disclaimer')}\n")

    lines.append("## 5. OPSEC & Exposure Indicators")
    if opsec:
        exp_score = opsec.get("current_exposure_score")
        exp_level = opsec.get("exposure_level", "UNAVAILABLE")
        if exp_score is not None:
            lines.append(f"**Current Exposure Index:** `{exp_score}/100` (**{exp_level}**)")
        else:
            lines.append(f"**Current Exposure Index:** `UNAVAILABLE` (**{exp_level}**)")
        lines.append(f"*{opsec.get('assessment_summary')}*\n")
        obs_events = opsec.get("observed_exposure_indicators", [])
        if obs_events:
            lines.append("### Observed Exposure Events:")
            for event in obs_events:
                lines.append(f"* **{event.get('week')} ({event.get('signal')}):** +{event.get('points')} pts — {event.get('description')}")
        else:
            lines.append("### Observed Exposure Events: None (No persona-level OPSEC tracking available for external feed)")
        lines.append(f"\n> **Note:** {opsec.get('predictive_disclaimer')}\n")

    lines.append("## 6. Relationship Topology")
    lines.append("| Source Entity | Relationship Type | Target Entity | Link Confidence |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for rel in report["relationships"]:
        lines.append(f"| `{rel['source']}` | {rel['relationship_type']} | `{rel['target']}` | `{rel['confidence']}` |")
    lines.append("")

    lines.append("## 7. Investigation Timeline")
    for t in report["timeline"]:
        lines.append(f"* **{t['week']} ({t['date']}):** **{t['event']}** — {t['detail']}")
    lines.append("")

    lines.append("## 8. Analytical Limitations")
    for lim in report["limitations"]:
        lines.append(f"* {lim}")
    lines.append("")

    lines.append("## 9. Safety & Research Classification")
    sc = report["safety_classification"]
    lines.append(f"* **Data Mode:** `{sc['data_mode']}`")
    lines.append(f"* **Project Scope:** `{sc['project_scope']}`")
    lines.append(f"* **Attribution Policy:** `{sc['attribution_policy']}`")
    lines.append(f"* **Network Scope:** `{sc['network_scope']}`")

    return "\n".join(lines)
