"""
SHADOWTRACE — STIX 2.1 Export Module (Phase 4 Step 3 & Real Data Migration Phase 2)
Converts SHADOWTRACE case datasets into structurally valid STIX 2.1 JSON Bundles.
Strictly offline, standard-library-only implementation.
Delineates synthetic demo cases from authorized public CTI feeds (CIRCL/MISP).
Does NOT fabricate attribution, fake relationships, or synthetic labels for real CTI data.
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional
import uuid

from backend.data_store import (
    load_raw_data,
    get_actor_by_id,
    get_evidence_data,
    get_timeline_data,
    get_graph_data,
    DEFAULT_CASE_ID
)
from backend.correlation_engine import compute_multi_signal_correlation

STIX_SPEC_VERSION = "2.1"
DEFAULT_TIMESTAMP = "2026-09-30T00:00:00.000Z"
SYNTHETIC_SAFETY_LABELS = ["synthetic-demo-data", "defensive-research-prototype"]
AUTHORIZED_SAFETY_LABELS = ["authorized-cti", "public-osint", "defensive-research"]
SAFETY_LABELS = SYNTHETIC_SAFETY_LABELS  # Backward-compatible alias


def is_synthetic_case_id(case_id: str) -> bool:
    """Identify if a case ID corresponds to synthetic research demo cases."""
    cid = str(case_id).strip().upper()
    if cid in ("CASE-2026-09X", "CASE-SYN-001", "CASE-2026-02B", "CASE-SYN-002", "CASE-2026-03C", "CASE-SYN-003"):
        return True
    if cid.startswith("CASE-AUTH-") or "MISP" in cid or "CIRCL" in cid:
        return False
    return False


def generate_stix_uuid(namespace_str: str) -> str:
    """Generate a deterministic UUIDv5 for a given STIX entity string."""
    namespace_uuid = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # UUIDv5 DNS namespace
    return str(uuid.uuid5(namespace_uuid, namespace_str))


def format_iso_timestamp(dt_str: Optional[str] = None) -> str:
    """Format a date/timestamp string into STIX-compliant ISO 8601 UTC format."""
    if not dt_str or dt_str == "Not available from source":
        return DEFAULT_TIMESTAMP
    clean = str(dt_str).strip()
    if "T" in clean and clean.endswith("Z"):
        return clean
    try:
        if " " in clean:
            dt = datetime.strptime(clean, "%Y-%m-%d %H:%M")
        else:
            dt = datetime.strptime(clean, "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        return DEFAULT_TIMESTAMP


def detect_ioc_type(identifier: str, ev_type: Optional[str] = None) -> Optional[str]:
    """
    Detect genuine technical observable IOC type (IP, Domain, URL, Hashes)
    or synthetic persona types (PGP, WALLET, ALIAS).
    Returns normalized type string or None if not a valid IOC.
    """
    ident = str(identifier).strip()
    if not ident:
        return None

    # 1. IP addresses
    try:
        ip = ipaddress.ip_address(ident)
        if ip.version == 4:
            return "ipv4-addr"
        elif ip.version == 6:
            return "ipv6-addr"
    except ValueError:
        pass

    # 2. URLs
    if re.match(r"^https?://[^\s]+$", ident, re.IGNORECASE):
        return "url"

    # 3. Cryptographic Hashes
    if re.fullmatch(r"[0-9a-fA-F]{64}", ident):
        return "file:sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ident):
        return "file:sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", ident):
        return "file:md5"

    # 4. Domain name (valid FQDN, at least one dot, valid chars, TLD >= 2 letters, not an IP)
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,63}$"
    if re.fullmatch(domain_pattern, ident):
        return "domain-name"

    # 5. Synthetic Types (PGP, WALLET, ALIAS)
    norm_type = str(ev_type or "").strip().upper()
    if norm_type in ("PGP", "WALLET", "ALIAS"):
        return norm_type.lower()

    return None


def build_stix_feed_identity(case_id: str) -> Dict[str, Any]:
    """Create a neutral STIX 2.1 identity SDO for the public CIRCL MISP feed provider."""
    ident_id_str = f"{case_id}:identity:circl-misp-feed"
    stix_id = f"identity--{generate_stix_uuid(ident_id_str)}"
    pub_ts = format_iso_timestamp()

    return {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": pub_ts,
        "modified": pub_ts,
        "name": "CIRCL Public OSINT Feed",
        "identity_class": "organization",
        "description": "Computer Incident Response Center Luxembourg (CIRCL) Public OSINT MISP Threat Sharing Feed.",
        "labels": AUTHORIZED_SAFETY_LABELS
    }


def build_stix_threat_actor(actor: Dict[str, Any], case_id: str) -> Optional[Dict[str, Any]]:
    """
    Map an actor to a STIX 2.1 threat-actor object ONLY for synthetic cases.
    For real authorized CTI cases, returns None to avoid fabricated attribution.
    """
    if not is_synthetic_case_id(case_id):
        # Do not fabricate a threat-actor SDO for external feeds
        return None

    actor_id_str = f"{case_id}:actor:{actor.get('id', 'ACT-001')}"
    stix_id = f"threat-actor--{generate_stix_uuid(actor_id_str)}"
    created_ts = format_iso_timestamp()

    aliases = list(actor.get("aliases", [actor.get("name", "SyntheticActor")]))
    if actor.get("name") and actor.get("name") not in aliases:
        aliases.insert(0, actor.get("name"))

    return {
        "type": "threat-actor",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": created_ts,
        "modified": created_ts,
        "name": actor.get("name", "Synthetic Threat Actor"),
        "description": (
            f"Defensive research prototype synthetic actor cluster '{actor.get('name')}' ({actor.get('id')}). "
            f"{actor.get('note', '')} This profile does NOT represent a real person or real-world threat actor."
        ),
        "threat_actor_types": ["crime-syndicate"],
        "aliases": aliases,
        "labels": SYNTHETIC_SAFETY_LABELS + [actor.get("tier", "tier-1").lower().replace(" ", "-")],
        "confidence": int(actor.get("confidence", 75)),
        "custom_properties": {
            "x_shadowtrace_synthetic_pgp": actor.get("pgp"),
            "x_shadowtrace_synthetic_wallet": actor.get("wallet"),
            "x_shadowtrace_stylometry_score": actor.get("stylometry"),
            "x_shadowtrace_behaviour_score": actor.get("behaviour")
        }
    }


def build_stix_observed_data(ev: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """Map an evidence record to a STIX 2.1 observed-data object."""
    is_synth = is_synthetic_case_id(case_id)
    ev_id_str = f"{case_id}:evidence:{ev.get('id', 'EV-001')}"
    stix_id = f"observed-data--{generate_stix_uuid(ev_id_str)}"
    obs_time = format_iso_timestamp(ev.get("timestamp"))

    ev_type = ev.get("type", "ARTIFACT").upper()
    identifier = ev.get("identifier", "SYNTHETIC_IDENTIFIER")
    ioc_type = detect_ioc_type(identifier, ev_type)

    # Map observable to STIX Cyber Observables (SCOs) inside objects dictionary
    sco_key = "0"
    if ioc_type == "ipv4-addr":
        objects = {sco_key: {"type": "ipv4-addr", "value": identifier}}
    elif ioc_type == "ipv6-addr":
        objects = {sco_key: {"type": "ipv6-addr", "value": identifier}}
    elif ioc_type == "domain-name":
        objects = {sco_key: {"type": "domain-name", "value": identifier}}
    elif ioc_type == "url":
        objects = {sco_key: {"type": "url", "value": identifier}}
    elif ioc_type == "file:sha256":
        objects = {sco_key: {"type": "file", "hashes": {"SHA-256": identifier}}}
    elif ioc_type == "file:sha1":
        objects = {sco_key: {"type": "file", "hashes": {"SHA-1": identifier}}}
    elif ioc_type == "file:md5":
        objects = {sco_key: {"type": "file", "hashes": {"MD5": identifier}}}
    elif ioc_type == "pgp":
        objects = {
            sco_key: {
                "type": "user-account",
                "account_login": identifier,
                "display_name": f"Synthetic PGP Key {identifier}" if is_synth else f"PGP Key {identifier}"
            }
        }
    elif ioc_type == "wallet":
        objects = {
            sco_key: {
                "type": "user-account",
                "account_login": identifier,
                "display_name": f"Synthetic Cryptocurrency Wallet {identifier}" if is_synth else f"Cryptocurrency Wallet {identifier}"
            }
        }
    elif ioc_type == "alias":
        objects = {
            sco_key: {
                "type": "user-account",
                "account_login": identifier,
                "account_type": "forum-alias"
            }
        }
    else:
        objects = {
            sco_key: {
                "type": "artifact",
                "payload_bin": identifier,
                "mime_type": "text/plain"
            }
        }

    custom_props: Dict[str, Any] = {
        "x_shadowtrace_evidence_id": ev.get("id"),
        "x_shadowtrace_relationship": ev.get("relationship"),
        "x_shadowtrace_status": ev.get("status")
    }
    if ev.get("confidence") is not None:
        custom_props["x_shadowtrace_confidence"] = ev.get("confidence")

    return {
        "type": "observed-data",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": obs_time,
        "modified": obs_time,
        "first_observed": obs_time,
        "last_observed": obs_time,
        "number_observed": 1,
        "objects": objects,
        "labels": SYNTHETIC_SAFETY_LABELS if is_synth else AUTHORIZED_SAFETY_LABELS,
        "custom_properties": custom_props
    }


def build_stix_indicator(ev: Dict[str, Any], case_id: str) -> Optional[Dict[str, Any]]:
    """Generate a STIX 2.1 indicator object ONLY for valid technical or persona observables."""
    is_synth = is_synthetic_case_id(case_id)
    ev_type = ev.get("type", "").upper()
    identifier = ev.get("identifier", "").strip()

    ioc_type = detect_ioc_type(identifier, ev_type)
    if not ioc_type:
        return None

    ind_id_str = f"{case_id}:indicator:{ev.get('id', 'EV-001')}"
    stix_id = f"indicator--{generate_stix_uuid(ind_id_str)}"
    valid_ts = format_iso_timestamp(ev.get("timestamp"))

    if ioc_type == "ipv4-addr":
        pattern = f"[ipv4-addr:value = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (IPv4: {identifier})"
        desc = f"Public threat intelligence indicator for IPv4 address '{identifier}'."
    elif ioc_type == "ipv6-addr":
        pattern = f"[ipv6-addr:value = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (IPv6: {identifier})"
        desc = f"Public threat intelligence indicator for IPv6 address '{identifier}'."
    elif ioc_type == "domain-name":
        pattern = f"[domain-name:value = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (Domain: {identifier})"
        desc = f"Public threat intelligence indicator for domain name '{identifier}'."
    elif ioc_type == "url":
        pattern = f"[url:value = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (URL: {identifier})"
        desc = f"Public threat intelligence indicator for URL '{identifier}'."
    elif ioc_type == "file:sha256":
        pattern = f"[file:hashes.'SHA-256' = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (SHA-256: {identifier})"
        desc = f"Public threat intelligence indicator for file hash SHA-256 '{identifier}'."
    elif ioc_type == "file:sha1":
        pattern = f"[file:hashes.'SHA-1' = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (SHA-1: {identifier})"
        desc = f"Public threat intelligence indicator for file hash SHA-1 '{identifier}'."
    elif ioc_type == "file:md5":
        pattern = f"[file:hashes.'MD5' = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Public CTI Indicator (MD5: {identifier})"
        desc = f"Public threat intelligence indicator for file hash MD5 '{identifier}'."
    elif ioc_type == "pgp":
        pattern = f"[user-account:account_login = '{identifier}']"
        ind_type = "anomalous-activity"
        name = f"Synthetic Indicator (PGP: {identifier})" if is_synth else f"Public CTI Indicator (PGP: {identifier})"
        desc = f"Indicator pattern for PGP key identifier '{identifier}'."
    elif ioc_type == "wallet":
        pattern = f"[user-account:account_login = '{identifier}']"
        ind_type = "malicious-activity"
        name = f"Synthetic Indicator (WALLET: {identifier})" if is_synth else f"Public CTI Indicator (WALLET: {identifier})"
        desc = f"Indicator pattern for cryptocurrency wallet identifier '{identifier}'."
    elif ioc_type == "alias":
        pattern = f"[user-account:account_login = '{identifier}']"
        ind_type = "attribution-indicator"
        name = f"Synthetic Indicator (ALIAS: {identifier})" if is_synth else f"Public CTI Indicator (ALIAS: {identifier})"
        desc = f"Indicator pattern for handle/alias identifier '{identifier}'."
    else:
        return None

    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": valid_ts,
        "modified": valid_ts,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_ts,
        "name": name,
        "description": desc,
        "indicator_types": [ind_type],
        "labels": SYNTHETIC_SAFETY_LABELS if is_synth else AUTHORIZED_SAFETY_LABELS
    }


def build_stix_relationship(
    source_ref: str,
    target_ref: str,
    rel_type: str,
    case_id: str,
    confidence: Optional[int] = None,
    description: str = "",
    labels: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Create a STIX 2.1 relationship object connecting two valid bundle objects."""
    rel_id_str = f"{case_id}:rel:{source_ref}:{target_ref}:{rel_type}"
    stix_id = f"relationship--{generate_stix_uuid(rel_id_str)}"
    created_ts = format_iso_timestamp()
    is_synth = is_synthetic_case_id(case_id)
    rel_labels = labels if labels is not None else (SYNTHETIC_SAFETY_LABELS if is_synth else AUTHORIZED_SAFETY_LABELS)

    obj: Dict[str, Any] = {
        "type": "relationship",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": created_ts,
        "modified": created_ts,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description or f"CTI relationship ({rel_type})",
        "labels": rel_labels
    }
    if confidence is not None:
        obj["confidence"] = confidence

    return obj


def build_stix_report(
    case_info: Dict[str, Any],
    object_refs: List[str],
    case_id: str
) -> Dict[str, Any]:
    """Map case metadata to a STIX 2.1 report object."""
    is_synth = is_synthetic_case_id(case_id)
    report_id_str = f"{case_id}:report:{case_info.get('id', case_id)}"
    stix_id = f"report--{generate_stix_uuid(report_id_str)}"
    pub_ts = format_iso_timestamp()

    if is_synth:
        return {
            "type": "report",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": pub_ts,
            "modified": pub_ts,
            "name": f"SHADOWTRACE Synthetic Investigation Report — {case_info.get('id', case_id)}",
            "description": (
                f"Defensive research report for synthetic case {case_info.get('id', case_id)} "
                f"(Target Subject: '{case_info.get('candidate', 'SyntheticCandidate')}'). "
                f"{case_info.get('description', '')} All data is synthetic demo data. Correlation is an analytical signal."
            ),
            "published": pub_ts,
            "report_types": ["threat-actor", "vulnerability-assessment"],
            "object_refs": object_refs,
            "labels": SYNTHETIC_SAFETY_LABELS + ["investigation-dossier"]
        }
    else:
        return {
            "type": "report",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": pub_ts,
            "modified": pub_ts,
            "name": f"SHADOWTRACE CTI Report — {case_info.get('id', case_id)}",
            "description": (
                f"Authorized public threat intelligence dossier for {case_info.get('id', case_id)} "
                f"(Target Subject: '{case_info.get('candidate', 'Authorized Feed Subject')}'). "
                f"Ingested from authorized public MISP OSINT feeds (CIRCL). "
                f"Defensive technical observables only — strictly non-attributive."
            ),
            "published": pub_ts,
            "report_types": ["threat-report", "vulnerability-assessment"],
            "object_refs": object_refs,
            "labels": AUTHORIZED_SAFETY_LABELS + ["threat-report"]
        }


def export_case_to_stix(case_id: str) -> Dict[str, Any]:
    """
    Export a SHADOWTRACE case to a structurally valid STIX 2.1 JSON Bundle.
    
    Args:
        case_id: Case identifier (e.g. 'CASE-2026-09X', 'CASE-AUTH-MISP')
        
    Returns:
        Python dictionary conforming to STIX 2.1 Bundle specifications.
    """
    raw_data = load_raw_data(case_id)  # Will raise KeyError if case_id is invalid
    case_info = raw_data.get("case", {})
    cid = case_info.get("id", case_id)
    is_synth = is_synthetic_case_id(cid)

    stix_objects: List[Dict[str, Any]] = []
    bundle_object_ids: List[str] = []

    # Map actors to threat-actor SDOs (Synthetic only) or create Feed Identity (Authorized CTI)
    actor_stix_map: Dict[str, str] = {}  # actor_id -> stix_id
    actor_name_stix_map: Dict[str, str] = {}  # actor_name -> stix_id

    if is_synth:
        for actor in raw_data.get("actors", []):
            ta_obj = build_stix_threat_actor(actor, cid)
            if ta_obj:
                stix_objects.append(ta_obj)
                bundle_object_ids.append(ta_obj["id"])
                actor_stix_map[actor["id"]] = ta_obj["id"]
                actor_name_stix_map[actor["name"]] = ta_obj["id"]
    else:
        # For real authorized CTI, publish feed provider identity instead of fabricated threat-actor
        feed_ident = build_stix_feed_identity(cid)
        stix_objects.append(feed_ident)
        bundle_object_ids.append(feed_ident["id"])

    # Map evidence to observed-data SDOs and optional indicators
    ev_stix_map: Dict[str, str] = {}  # evidence_id -> stix_id (observed-data)
    ev_ident_stix_map: Dict[str, str] = {}  # evidence_identifier -> stix_id

    for ev in raw_data.get("evidence", []):
        obs_obj = build_stix_observed_data(ev, cid)
        stix_objects.append(obs_obj)
        bundle_object_ids.append(obs_obj["id"])
        ev_stix_map[ev["id"]] = obs_obj["id"]
        ev_ident_stix_map[ev["identifier"]] = obs_obj["id"]

        # Synthetic only: connect primary synthetic actor to observed evidence
        if is_synth:
            primary_actor_stix = list(actor_stix_map.values())[0] if actor_stix_map else None
            if primary_actor_stix:
                rel_obj = build_stix_relationship(
                    source_ref=primary_actor_stix,
                    target_ref=obs_obj["id"],
                    rel_type="related-to",
                    case_id=cid,
                    confidence=75,
                    description=f"Synthetic correlation signal: {ev.get('relationship', 'Observed association')}"
                )
                stix_objects.append(rel_obj)
                bundle_object_ids.append(rel_obj["id"])

        # Create STIX indicator if evidence is a valid observable
        ind_obj = build_stix_indicator(ev, cid)
        if ind_obj:
            stix_objects.append(ind_obj)
            bundle_object_ids.append(ind_obj["id"])

            # Link indicator to observed-data
            ind_rel = build_stix_relationship(
                source_ref=ind_obj["id"],
                target_ref=obs_obj["id"],
                rel_type="indicates",
                case_id=cid,
                confidence=80 if is_synth else None,
                description=f"Technical indicator for observed data '{ev.get('identifier')}'"
            )
            stix_objects.append(ind_rel)
            bundle_object_ids.append(ind_rel["id"])

    # Map existing graph edges to STIX relationships
    graph = raw_data.get("graph", {})
    for edge in graph.get("edges", []):
        src_name = edge["source"]
        tgt_name = edge["target"]

        # Resolve source and target refs from bundle objects only
        src_ref = actor_name_stix_map.get(src_name) or ev_ident_stix_map.get(src_name)
        tgt_ref = actor_name_stix_map.get(tgt_name) or ev_ident_stix_map.get(tgt_name)

        if src_ref and tgt_ref and src_ref in bundle_object_ids and tgt_ref in bundle_object_ids:
            conf_val = 85 if edge.get("confidence") == "High" else 65
            rel_type = "uses" if "reuse" in edge.get("relationship", "").lower() else "related-to"
            
            graph_rel = build_stix_relationship(
                source_ref=src_ref,
                target_ref=tgt_ref,
                rel_type=rel_type,
                case_id=cid,
                confidence=conf_val if is_synth else None,
                description=f"Graph relationship: {edge.get('relationship')}"
            )
            stix_objects.append(graph_rel)
            bundle_object_ids.append(graph_rel["id"])

    # Build STIX Report SDO referencing all objects in bundle
    report_obj = build_stix_report(case_info, list(bundle_object_ids), cid)
    stix_objects.append(report_obj)
    bundle_object_ids.append(report_obj["id"])

    # Construct final STIX 2.1 Bundle
    bundle_uuid = generate_stix_uuid(f"{cid}:bundle")
    bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid}",
        "objects": stix_objects
    }

    return bundle
