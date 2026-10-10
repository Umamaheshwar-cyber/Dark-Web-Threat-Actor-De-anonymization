"""Enhanced Relationship Graph Engine for Threat Actor Correlation.

Extracts infrastructure and identity indicators (crypto wallets, IPs, emails,
domains, paste sites) from captured evidence, builds a multi-relational graph,
and forms threat actor clusters.

DISCLAIMER: ANALYTICAL CLUSTER — NOT CONFIRMED IDENTITY
"""

from __future__ import annotations

import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.database import db_get, db_get_all, db_insert

router = APIRouter(tags=["relationship-graph"])

CLUSTER_DISCLAIMER = "ANALYTICAL CLUSTER — NOT CONFIRMED IDENTITY"
DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

# Regex extractors
BTC_REGEX = re.compile(r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,60})\b")
ETH_REGEX = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)

PASTE_DOMAINS = {
    "pastebin.com",
    "ghostbin.co",
    "ghostbin.com",
    "privatebin.net",
    "privatebin.info",
    "rentry.co",
    "rentry.org",
    "hastebin.com",
    "dpaste.org",
}


class LinkAliasesBody(BaseModel):
    alias_a: str = Field(..., min_length=1)
    alias_b: str = Field(..., min_length=1)
    confidence: float = Field(0.9, ge=0.0, le=1.0)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_node(
    node_id: str,
    node_type: str,
    label: str,
    properties: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Upsert a node in the graph."""
    ts = timestamp or _now_iso()
    existing = db_get("graph_nodes", "node_id", node_id)
    if existing:
        existing_props = existing.get("properties") or {}
        if isinstance(existing_props, str):
            import json
            try:
                existing_props = json.loads(existing_props)
            except Exception:
                existing_props = {}
        if properties:
            existing_props.update(properties)
        node = {
            "node_id": node_id,
            "node_type": existing.get("node_type") or node_type,
            "label": existing.get("label") or label,
            "properties": existing_props,
            "first_seen": existing.get("first_seen") or ts,
            "last_seen": ts,
        }
        db_insert("graph_nodes", node)
        return {**node, "id": node_id, "type": node["node_type"]}

    node = {
        "node_id": node_id,
        "node_type": node_type,
        "label": label,
        "properties": properties or {},
        "first_seen": ts,
        "last_seen": ts,
    }
    db_insert("graph_nodes", node)
    return {**node, "id": node_id, "type": node_type}


def add_edge(
    source: str,
    target: str,
    edge_type: str,
    confidence: float = 0.9,
    evidence_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Upsert an edge in the graph."""
    ts = timestamp or _now_iso()

    # Check for existing matching edge
    all_edges = db_get_all("graph_edges")
    for e in all_edges:
        if e.get("source") == source and e.get("target") == target and e.get("edge_type") == edge_type:
            e_conf = max(float(e.get("confidence") or 0.0), confidence)
            ev_ids = e.get("evidence_ids") or []
            if isinstance(ev_ids, str):
                import json
                try:
                    ev_ids = json.loads(ev_ids)
                except Exception:
                    ev_ids = [ev_ids]
            if evidence_id and evidence_id not in ev_ids:
                ev_ids.append(evidence_id)
            edge_data = {
                "id": e["id"],
                "source": source,
                "target": target,
                "edge_type": edge_type,
                "confidence": e_conf,
                "evidence_ids": ev_ids,
                "first_seen": e.get("first_seen") or ts,
                "last_seen": ts,
            }
            db_insert("graph_edges", edge_data)
            return edge_data

    new_edge = {
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "confidence": confidence,
        "evidence_ids": [evidence_id] if evidence_id else [],
        "first_seen": ts,
        "last_seen": ts,
    }
    db_insert("graph_edges", new_edge)
    return new_edge


def cluster_aliases(alias_a: str, alias_b: str, confidence: float = 0.9) -> Dict[str, Any]:
    """Cluster two aliases under an ACTOR node and record relationships."""
    alias_a_id = f"ALIAS-{alias_a}"
    alias_b_id = f"ALIAS-{alias_b}"

    # Ensure alias nodes exist
    add_node(alias_a_id, "ALIAS", alias_a)
    add_node(alias_b_id, "ALIAS", alias_b)

    # Check if either alias already belongs to an ACTOR node
    actor_id: Optional[str] = None
    all_edges = db_get_all("graph_edges")
    for e in all_edges:
        if e["edge_type"] == "belongs_to":
            if e["source"] == alias_a_id:
                actor_id = e["target"]
                break
            elif e["source"] == alias_b_id:
                actor_id = e["target"]
                break

    if not actor_id:
        actor_uuid = str(uuid.uuid4())[:8]
        actor_id = f"ACTOR-{actor_uuid}"
        add_node(
            actor_id,
            "ACTOR",
            f"Cluster {actor_uuid}",
            properties={"disclaimer": CLUSTER_DISCLAIMER},
        )

    # Link both aliases to the ACTOR node
    add_edge(alias_a_id, actor_id, "belongs_to", confidence=confidence)
    add_edge(alias_b_id, actor_id, "belongs_to", confidence=confidence)

    # Link aliases directly as same_person
    add_edge(alias_a_id, alias_b_id, "same_person", confidence=confidence)

    return {
        "actor_id": actor_id,
        "alias_a": alias_a,
        "alias_b": alias_b,
        "confidence": confidence,
        "label": CLUSTER_DISCLAIMER,
    }


def extract_indicators(text: str) -> Dict[str, Set[str]]:
    """Extract all relevant threat indicators from text."""
    indicators: Dict[str, Set[str]] = {
        "wallets": set(),
        "ips": set(),
        "emails": set(),
        "pastes": set(),
        "domains": set(),
    }

    if not text:
        return indicators

    # 1. Wallets
    for m in BTC_REGEX.finditer(text):
        indicators["wallets"].add(m.group(0))
    for m in ETH_REGEX.finditer(text):
        indicators["wallets"].add(m.group(0))

    # 2. IPs
    for m in IP_REGEX.finditer(text):
        indicators["ips"].add(m.group(0))

    # 3. Emails
    for m in EMAIL_REGEX.finditer(text):
        indicators["emails"].add(m.group(0).lower())

    # 4. URLs / Pastes / Domains
    for m in URL_REGEX.finditer(text):
        raw_url = m.group(0)
        try:
            parsed = urlparse(raw_url)
            host = (parsed.netloc or "").lower()
            if any(host == p or host.endswith("." + p) for p in PASTE_DOMAINS):
                indicators["pastes"].add(raw_url)
            elif host:
                indicators["domains"].add(host)
        except Exception:
            pass

    return indicators


def process_post(evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Auto-extraction hook called from capture_engine for every captured post."""
    try:
        alias = evidence.get("alias")
        if not alias:
            return None

        content = evidence.get("content") or ""
        evidence_id = evidence.get("evidence_id") or evidence.get("post_id") or "UNKNOWN"
        ts = evidence.get("timestamp_posted") or evidence.get("captured_at") or _now_iso()
        forum_name = evidence.get("forum_name") or "LOCAL_TEST_FORUM"

        alias_id = f"ALIAS-{alias}"
        forum_id = f"FORUM-{forum_name}"

        # 1. Register ALIAS node
        add_node(alias_id, "ALIAS", alias, timestamp=ts)

        # 2. Register FORUM node and ALIAS -> FORUM edge
        add_node(forum_id, "FORUM", forum_name, timestamp=ts)
        add_edge(alias_id, forum_id, "posted_on", confidence=1.0, evidence_id=evidence_id, timestamp=ts)

        # 3. Extract indicators
        extracted = extract_indicators(content)

        # Wallets
        for w in extracted["wallets"]:
            wallet_id = f"WALLET-{w[:10]}"
            add_node(wallet_id, "WALLET", w, properties={"full_address": w}, timestamp=ts)
            add_edge(alias_id, wallet_id, "mentioned_wallet", confidence=0.95, evidence_id=evidence_id, timestamp=ts)

        # IPs
        for ip in extracted["ips"]:
            ip_id = f"IP-{ip}"
            add_node(ip_id, "IP", ip, properties={"ip": ip}, timestamp=ts)
            add_edge(alias_id, ip_id, "mentioned_ip", confidence=0.90, evidence_id=evidence_id, timestamp=ts)

        # Emails
        for email in extracted["emails"]:
            email_id = f"EMAIL-{email}"
            add_node(email_id, "EMAIL", email, properties={"email": email}, timestamp=ts)
            add_edge(alias_id, email_id, "mentioned_email", confidence=0.90, evidence_id=evidence_id, timestamp=ts)

        # Pastes
        for paste in extracted["pastes"]:
            paste_id = f"PASTE-{paste[:20]}"
            add_node(paste_id, "PASTE", paste, properties={"url": paste}, timestamp=ts)
            add_edge(alias_id, paste_id, "used_paste", confidence=0.95, evidence_id=evidence_id, timestamp=ts)

        # Domains
        for dom in extracted["domains"]:
            domain_id = f"DOMAIN-{dom}"
            add_node(domain_id, "DOMAIN", dom, properties={"domain": dom}, timestamp=ts)
            add_edge(alias_id, domain_id, "mentioned_domain", confidence=0.85, evidence_id=evidence_id, timestamp=ts)

        return {
            "alias_id": alias_id,
            "evidence_id": evidence_id,
            "extracted_count": {k: len(v) for k, v in extracted.items()},
        }
    except Exception:
        return None


# --- API Endpoints ---

@router.get("/graph/nodes")
def get_all_nodes() -> List[Dict[str, Any]]:
    """Retrieve all nodes in the relationship graph."""
    nodes_list = db_get_all("graph_nodes")
    return [{**n, "id": n.get("node_id"), "type": n.get("node_type")} for n in nodes_list]


@router.get("/graph/edges")
def get_all_edges() -> List[Dict[str, Any]]:
    """Retrieve all edges in the relationship graph."""
    return db_get_all("graph_edges")


@router.get("/graph/stats")
def get_graph_stats() -> Dict[str, Any]:
    """Retrieve graph topology metrics and breakdown."""
    nodes_list = db_get_all("graph_nodes")
    edges_list = db_get_all("graph_edges")
    node_breakdown: Dict[str, int] = Counter()
    for n in nodes_list:
        node_breakdown[n.get("node_type", "UNKNOWN")] += 1

    # Connected degree per alias
    alias_degree: Dict[str, int] = Counter()
    connected_nodes: Set[str] = set()

    for e in edges_list:
        src = e["source"]
        tgt = e["target"]
        connected_nodes.add(src)
        connected_nodes.add(tgt)
        if src.startswith("ALIAS-"):
            alias = src[6:]
            alias_degree[alias] += 1
        if tgt.startswith("ALIAS-"):
            alias = tgt[6:]
            alias_degree[alias] += 1

    most_connected_alias = alias_degree.most_common(1)[0][0] if alias_degree else None
    isolated_nodes = [n["node_id"] for n in nodes_list if n.get("node_id") not in connected_nodes]

    return {
        "total_nodes": len(nodes_list),
        "total_edges": len(edges_list),
        "node_breakdown": dict(node_breakdown),
        "most_connected_alias": most_connected_alias,
        "isolated_nodes": isolated_nodes,
        "disclaimer": DISCLAIMER,
    }


@router.get("/graph/alias/{alias}")
def get_alias_subgraph(alias: str) -> Dict[str, Any]:
    """Retrieve neighborhood subgraph (all connected nodes and edges) for a specific alias."""
    alias_id = f"ALIAS-{alias}"
    alias_node = db_get("graph_nodes", "node_id", alias_id)
    if not alias_node:
        raise HTTPException(status_code=404, detail=f"No graph node found for alias '{alias}'")

    alias_node_norm = {**alias_node, "id": alias_node.get("node_id"), "type": alias_node.get("node_type")}
    connected_edges = []
    neighbor_ids = {alias_id}

    edges_list = db_get_all("graph_edges")
    for e in edges_list:
        if e["source"] == alias_id or e["target"] == alias_id:
            connected_edges.append(e)
            neighbor_ids.add(e["source"])
            neighbor_ids.add(e["target"])

    nodes_list = db_get_all("graph_nodes")
    nodes_dict = {n.get("node_id"): {**n, "id": n.get("node_id"), "type": n.get("node_type")} for n in nodes_list}
    subgraph_nodes = [nodes_dict[nid] for nid in neighbor_ids if nid in nodes_dict]

    return {
        "alias": alias,
        "alias_node": alias_node_norm,
        "nodes": subgraph_nodes,
        "edges": connected_edges,
        "disclaimer": DISCLAIMER,
    }


@router.get("/graph/export")
def export_full_graph() -> Dict[str, Any]:
    """Export the complete relationship graph as nodes + edges JSON."""
    nodes_list = [{**n, "id": n.get("node_id"), "type": n.get("node_type")} for n in db_get_all("graph_nodes")]
    edges_list = db_get_all("graph_edges")
    return {
        "nodes": nodes_list,
        "edges": edges_list,
        "total_nodes": len(nodes_list),
        "total_edges": len(edges_list),
        "disclaimer": DISCLAIMER,
    }


@router.post("/graph/link-aliases")
def link_aliases_endpoint(body: LinkAliasesBody) -> Dict[str, Any]:
    """Manually link two aliases into a threat actor cluster."""
    result = cluster_aliases(body.alias_a, body.alias_b, confidence=body.confidence)
    return result
