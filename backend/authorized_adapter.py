"""
SHADOWTRACE — Authorized MISP Intelligence Adapter (Phase 6.1)
Provides an isolated, read-only adapter to query authorized MISP REST APIs or normalize
mocked MISP event payloads into SHADOWTRACE Evidence and Provenance records.
Strictly non-attributive: normalizes observable indicators without real-person attribution.
"""

import os
import json
import re
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from backend.provenance import (
    generate_evidence_hash,
    build_evidence_provenance
)

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DEFAULT_CIRCL_FEED_URL = "https://www.circl.lu/doc/misp/feed-osint"


class MISPAdapterError(Exception):
    """Base exception for MISP Adapter errors."""
    pass


class MISPConfigurationError(MISPAdapterError):
    """Raised when required MISP connection settings are missing."""
    pass


class MISPConnectionError(MISPAdapterError):
    """Raised when connection to MISP instance fails or times out."""
    pass


class MISPAuthenticationError(MISPAdapterError):
    """Raised when MISP API key is invalid or unauthorized (401/403)."""
    pass


class CIRCLFeedError(MISPAdapterError):
    """Base exception for public CIRCL feed errors."""
    pass


class CIRCLInvalidUUIDError(CIRCLFeedError):
    """Raised when an event UUID does not match standard UUID format."""
    pass


class CIRCLConnectionError(CIRCLFeedError):
    """Raised when connection to public CIRCL feed fails or times out."""
    pass



def map_misp_type_to_shadowtrace(misp_type: str) -> str:
    """Map a MISP attribute type to a SHADOWTRACE evidence category."""
    if not misp_type or not isinstance(misp_type, str):
        return "INDICATOR"
    
    t = misp_type.strip().lower()
    if any(k in t for k in ("alias", "username", "handle", "github", "twitter", "forum")):
        return "ALIAS"
    elif any(k in t for k in ("pgp", "gpg", "key")):
        return "PGP"
    elif any(k in t for k in ("btc", "crypto", "wallet", "xmr", "eth", "bitcoin")):
        return "WALLET"
    elif any(k in t for k in ("stylometry", "syntax", "language", "phrasing")):
        return "STYLOMETRY"
    elif any(k in t for k in ("behaviour", "behavior", "timing", "cadence")):
        return "BEHAVIOUR"
    else:
        return "INDICATOR"


def map_misp_confidence(threat_level_id: Any) -> str:
    """Map MISP threat level ID to a SHADOWTRACE confidence rating."""
    try:
        t_id = int(threat_level_id)
        if t_id == 1:
            return "High"
        elif t_id == 2:
            return "Medium"
        else:
            return "Low"
    except (TypeError, ValueError):
        return "Low"


class MISPAdapter:
    """
    Authorized MISP Intelligence Adapter.
    Queries MISP REST API or processes mock MISP payloads into SHADOWTRACE Evidence records.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None
    ):
        self.base_url = (base_url or os.getenv("MISP_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("MISP_API_KEY", "")
        
        env_ssl = os.getenv("MISP_VERIFY_SSL", "true").strip().lower() in ("true", "1", "yes")
        self.verify_ssl = verify_ssl if verify_ssl is not None else env_ssl
        
        env_timeout = int(os.getenv("MISP_TIMEOUT", "15"))
        self.timeout = timeout if timeout is not None else env_timeout

    def is_configured(self) -> bool:
        """Return True if base URL and API key are provided."""
        return bool(self.base_url and self.api_key)

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build standard library SSL context adhering to verify_ssl flag."""
        if self.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def test_connection(self) -> Dict[str, Any]:
        """
        Verify connectivity and credentials against the authorized MISP instance.
        Never returns or exposes the API key.
        """
        if not self.is_configured():
            raise MISPConfigurationError(
                "MISP adapter is not configured. Set MISP_URL and MISP_API_KEY environment variables."
            )

        version_url = f"{self.base_url}/servers/getVersion"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json"
        }
        req = urllib.request.Request(version_url, headers=headers, method="GET")
        ctx = self._build_ssl_context()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                version = data.get("version", "unknown") if isinstance(data, dict) else "unknown"
                return {
                    "connected": True,
                    "base_url": self.base_url,
                    "version": str(version),
                    "status": "AUTHORIZED_ONLINE",
                    "message": f"Successfully connected to authorized MISP instance (version {version})."
                }
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise MISPAuthenticationError(f"MISP authentication failed: HTTP {e.code} (invalid API key or unauthorized).")
            # If getVersion is 404 or restricted, fallback to restSearch limit 1
            if e.code == 404:
                try:
                    events = self.fetch_events_rest({"returnFormat": "json", "limit": 1})
                    return {
                        "connected": True,
                        "base_url": self.base_url,
                        "version": "accessible",
                        "status": "AUTHORIZED_ONLINE",
                        "message": "Successfully connected to authorized MISP instance via restSearch."
                    }
                except Exception as fallback_err:
                    raise fallback_err
            raise MISPConnectionError(f"MISP HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise MISPConnectionError(f"Failed to connect to MISP instance at {self.base_url}: {e.reason}")
        except json.JSONDecodeError as e:
            raise MISPAdapterError(f"Failed to parse MISP response: {e}")

    def fetch_events_rest(self, search_params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Query MISP REST API search endpoint (/events/restSearch).
        Requires MISP_URL and MISP_API_KEY configuration.
        """
        if not self.is_configured():
            raise MISPConfigurationError(
                "MISP adapter is not configured. Set MISP_URL and MISP_API_KEY environment variables."
            )

        url = f"{self.base_url}/events/restSearch"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        payload = search_params or {"returnFormat": "json", "limit": 50}

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
        ctx = self._build_ssl_context()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status == 401 or resp.status == 403:
                    raise MISPAuthenticationError("Invalid MISP API key or unauthorized access.")
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                # MISP restSearch usually returns {"response": {"Event": [...]}} or list of events
                if isinstance(data, dict):
                    if "response" in data and isinstance(data["response"], dict):
                        return data["response"].get("Event", [])
                    elif "Event" in data:
                        return data["Event"]
                return data if isinstance(data, list) else []
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise MISPAuthenticationError(f"MISP authentication failed: HTTP {e.code}")
            raise MISPConnectionError(f"MISP HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise MISPConnectionError(f"Failed to connect to MISP instance at {self.base_url}: {e.reason}")
        except json.JSONDecodeError as e:
            raise MISPAdapterError(f"Failed to parse MISP JSON response: {e}")

    def transform_misp_event_to_evidence(self, misp_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Transform a MISP Event record (or event dict) into normalized SHADOWTRACE Evidence dicts.
        Treats incoming data as observed intelligence (default status: 'Observed').
        Safely handles malformed payloads.
        """
        if not isinstance(misp_event, dict):
            return []

        event_obj = misp_event.get("Event", misp_event)
        if not isinstance(event_obj, dict):
            return []

        event_id = str(event_obj.get("id") or event_obj.get("uuid") or "UNKNOWN-EVENT")
        event_info = str(event_obj.get("info", "Authorized MISP Intelligence Event"))
        threat_level = event_obj.get("threat_level_id", 3)
        confidence = map_misp_confidence(threat_level)
        event_date = str(event_obj.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d")))

        attributes = event_obj.get("Attribute", [])
        if not isinstance(attributes, list):
            attributes = []

        evidence_list: List[Dict[str, Any]] = []

        for attr in attributes:
            if not isinstance(attr, dict):
                continue
            
            attr_id = str(attr.get("id", "0"))
            misp_type = str(attr.get("type", "text"))
            value = attr.get("value", "")
            if not value:
                continue

            comment = str(attr.get("comment", ""))
            relationship = f"{event_info} - {comment}" if comment else event_info
            
            # Default status is Observed unless MISP explicitly indicates correlation/IDS flag (toids)
            toids = bool(attr.get("toids", False))
            status = "Correlated" if toids else "Observed"

            ev_id = f"MISP-EV-{event_id}-{attr_id}"
            ev_type = map_misp_type_to_shadowtrace(misp_type)

            evidence_record = {
                "id": ev_id,
                "type": ev_type,
                "identifier": str(value),
                "timestamp": str(event_date),
                "relationship": relationship,
                "confidence": confidence,
                "status": status
            }

            evidence_list.append(evidence_record)

        return evidence_list

    def build_provenance_for_evidence(
        self,
        evidence_payload: Dict[str, Any],
        misp_event: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build an enriched Phase 4 provenance and integrity record for a transformed MISP evidence item.
        Safely handles malformed payloads.
        """
        if not isinstance(misp_event, dict):
            event_obj = {}
        else:
            event_obj = misp_event.get("Event", misp_event)
            if not isinstance(event_obj, dict):
                event_obj = {}

        orgc = event_obj.get("Orgc", {})
        org_name = orgc.get("name", "Authorized MISP Organisation") if isinstance(orgc, dict) else "Authorized MISP Organisation"
        event_id = str(event_obj.get("id") or event_obj.get("uuid") or "0")

        collection_meta = {
            "collection_mode": "AUTHORIZED_MISP_REST_API",
            "misp_event_id": event_id,
            "creator_org": org_name,
            "network_scope": "AUTHORIZED_EXTERNAL_FEED"
        }

        return build_evidence_provenance(
            evidence_id=evidence_payload["id"],
            raw_observed_payload=evidence_payload,
            source_origin=f"MISP_EVENT_{event_id}",
            observation_timestamp=evidence_payload["timestamp"],
            collection_metadata=collection_meta,
            admiralty_reliability="B - Usually Reliable",
            admiralty_credibility="2 - Probably True"
        )


class CIRCLFeedAdapter:
    """
    Public CIRCL MISP OSINT Feed Adapter.
    Strictly read-only / pull-only. Requires no credentials, tokens, or API keys.
    Queries the public manifest.json and fetches explicitly selected event JSON files.
    """

    def __init__(
        self,
        feed_url: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 15
    ):
        self.feed_url = (feed_url or DEFAULT_CIRCL_FEED_URL).rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build standard library SSL context adhering to verify_ssl flag."""
        if self.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def validate_uuid(self, event_uuid: str) -> str:
        """Strictly validate that the identifier conforms to RFC 4122 UUID format."""
        if not event_uuid or not isinstance(event_uuid, str):
            raise CIRCLInvalidUUIDError(f"Invalid UUID: '{event_uuid}'")
        clean_uuid = event_uuid.strip()
        if not UUID_REGEX.match(clean_uuid):
            raise CIRCLInvalidUUIDError(f"Invalid MISP event UUID format: '{event_uuid}'")
        return clean_uuid

    def fetch_manifest_raw(self) -> Dict[str, Any]:
        """
        Fetch raw manifest.json dictionary from public CIRCL feed.
        Strictly reads manifest headers/summaries only; does NOT download individual event files.
        """
        url = f"{self.feed_url}/manifest.json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SHADOWTRACE-OSINT-Adapter/1.0", "Accept": "application/json"}
        )
        ctx = self._build_ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status != 200:
                    raise CIRCLConnectionError(f"HTTP {resp.status} fetching CIRCL manifest")
                data = json.loads(resp.read().decode("utf-8"))
                if not isinstance(data, dict):
                    raise CIRCLFeedError("CIRCL manifest is not a valid JSON dictionary")
                return data
        except urllib.error.HTTPError as e:
            raise CIRCLConnectionError(f"CIRCL manifest HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise CIRCLConnectionError(f"Failed to connect to CIRCL feed at {self.feed_url}: {e.reason}")
        except json.JSONDecodeError as e:
            raise CIRCLFeedError(f"Failed to parse CIRCL manifest JSON: {e}")

    def fetch_manifest(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Fetch manifest.json and return a bounded list of event summaries.
        Does NOT download individual event files.
        """
        data = self.fetch_manifest_raw()
        summaries: List[Dict[str, Any]] = []
        for uuid, meta in data.items():
            if not UUID_REGEX.match(str(uuid)) or not isinstance(meta, dict):
                continue
            orgc = meta.get("Orgc", {})
            orgc_name = orgc.get("name", "CIRCL") if isinstance(orgc, dict) else "CIRCL"
            threat_lvl = meta.get("threat_level_id", meta.get("Event", {}).get("threat_level_id", 3))
            summaries.append({
                "uuid": str(uuid),
                "info": str(meta.get("info", "CIRCL OSINT Threat Event")),
                "date": str(meta.get("date", "")),
                "threat_level": map_misp_confidence(threat_lvl),
                "threat_level_id": threat_lvl,
                "orgc": str(orgc_name)
            })
            if len(summaries) >= limit:
                break
        return summaries

    def poll_new_events(
        self,
        known_uuids: Optional[Set[str]] = None,
        max_events: int = 3,
        max_attributes: int = 15,
        force_refresh: bool = False,
        raw_manifest: Optional[Dict[str, Any]] = None,
        mock_events: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Incrementally detect and fetch ONLY newly observed event UUIDs from manifest.
        Guarantees bounded execution and never downloads the whole feed.
        """
        # Clamp bounds
        clamped_max_events = max(1, min(10, int(max_events)))
        clamped_max_attrs = max(1, min(50, int(max_attributes)))

        known = {str(u).strip().lower() for u in (known_uuids or set()) if u}

        # 1. Fetch manifest
        manifest_data = raw_manifest if raw_manifest is not None else self.fetch_manifest_raw()
        total_manifest = len(manifest_data)

        # 2. Identify candidate new UUIDs
        candidate_uuids: List[str] = []
        skipped_count = 0

        for uuid_str, meta in manifest_data.items():
            clean_uuid = str(uuid_str).strip()
            if not UUID_REGEX.match(clean_uuid):
                continue
            
            uuid_lower = clean_uuid.lower()
            uuid_prefix = uuid_lower[:8]

            if not force_refresh and (uuid_lower in known or uuid_prefix in known):
                skipped_count += 1
                continue

            candidate_uuids.append(clean_uuid)

        # 3. Select bounded batch of new events
        selected_uuids = candidate_uuids[:clamped_max_events]

        if not selected_uuids:
            return {
                "status": "SKIPPED_NO_NEW",
                "manifest_total_events": total_manifest,
                "new_events_detected": 0,
                "processed_event_uuids": [],
                "evidence_records": [],
                "provenance_records": [],
                "skipped_count": skipped_count,
                "failed_count": 0,
                "errors": []
            }

        # 4. Fetch and transform selected events
        processed_uuids: List[str] = []
        all_evidence: List[Dict[str, Any]] = []
        all_provenance: List[Dict[str, Any]] = []
        errors: List[str] = []
        failed_count = 0

        for u in selected_uuids:
            try:
                if mock_events and u in mock_events:
                    event_data = mock_events[u]
                elif mock_events and "_default_" in mock_events:
                    event_data = mock_events["_default_"]
                else:
                    event_data = self.fetch_event(u)
                ev_items = self.transform_circl_event_to_evidence(event_data, max_attributes=clamped_max_attrs)
                for item in ev_items:
                    prov = self.build_provenance_for_evidence(item, event_data)
                    all_evidence.append(item)
                    all_provenance.append(prov)
                processed_uuids.append(u)
            except Exception as e:
                failed_count += 1
                errors.append(f"Failed to process event {u}: {str(e)}")

        status = "SUCCESS"
        if failed_count > 0:
            status = "PARTIAL" if processed_uuids else "FAILURE"

        return {
            "status": status,
            "manifest_total_events": total_manifest,
            "new_events_detected": len(candidate_uuids),
            "processed_event_uuids": processed_uuids,
            "evidence_records": all_evidence,
            "provenance_records": all_provenance,
            "skipped_count": skipped_count,
            "failed_count": failed_count,
            "errors": errors
        }

    def fetch_event(self, event_uuid: str) -> Dict[str, Any]:
        """
        Fetch a single selected event JSON file: <feed_url>/<UUID>.json.
        Validates the UUID format strictly before constructing the request URL.
        """
        clean_uuid = self.validate_uuid(event_uuid)
        url = f"{self.feed_url}/{clean_uuid}.json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SHADOWTRACE-OSINT-Adapter/1.0", "Accept": "application/json"}
        )
        ctx = self._build_ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                if resp.status != 200:
                    raise CIRCLConnectionError(f"HTTP {resp.status} fetching CIRCL event {clean_uuid}")
                data = json.loads(resp.read().decode("utf-8"))
                if not isinstance(data, dict):
                    raise CIRCLFeedError(f"Invalid event JSON structure for {clean_uuid}")
                return data
        except urllib.error.HTTPError as e:
            raise CIRCLConnectionError(f"CIRCL event HTTP error {e.code} for {clean_uuid}: {e.reason}")
        except urllib.error.URLError as e:
            raise CIRCLConnectionError(f"Failed to connect to CIRCL feed for event {clean_uuid}: {e.reason}")
        except json.JSONDecodeError as e:
            raise CIRCLFeedError(f"Failed to parse event JSON for {clean_uuid}: {e}")

    def transform_circl_event_to_evidence(
        self,
        event_payload: Dict[str, Any],
        max_attributes: int = 15
    ) -> List[Dict[str, Any]]:
        """
        Normalize observable threat indicators from a CIRCL event into SHADOWTRACE Evidence dicts.
        Applies a strict upper bound on the number of attributes processed. Non-attributive.
        """
        if not isinstance(event_payload, dict):
            return []
        event_obj = event_payload.get("Event", event_payload)
        if not isinstance(event_obj, dict):
            return []

        event_uuid = str(event_obj.get("uuid") or event_obj.get("id") or "UNKNOWN-CIRCL")
        event_info = str(event_obj.get("info", "CIRCL Public OSINT Feed Event"))
        threat_level = event_obj.get("threat_level_id", 3)
        confidence = map_misp_confidence(threat_level)
        event_date = str(event_obj.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d")))

        attributes = event_obj.get("Attribute", [])
        if not isinstance(attributes, list):
            attributes = []

        evidence_list: List[Dict[str, Any]] = []

        for attr in attributes:
            if len(evidence_list) >= max_attributes:
                break
            if not isinstance(attr, dict):
                continue
            
            attr_id = str(attr.get("id", len(evidence_list) + 1))
            misp_type = str(attr.get("type", "text"))
            value = attr.get("value", "")
            if not value:
                continue

            comment = str(attr.get("comment", ""))
            relationship = f"CIRCL OSINT: {event_info} - {comment}" if comment else f"CIRCL OSINT: {event_info}"
            toids = bool(attr.get("toids", False))
            status = "Correlated" if toids else "Observed"

            ev_id = f"CIRCL-EV-{event_uuid[:8]}-{attr_id}"
            ev_type = map_misp_type_to_shadowtrace(misp_type)

            evidence_record = {
                "id": ev_id,
                "type": ev_type,
                "identifier": str(value),
                "timestamp": str(event_date),
                "relationship": relationship,
                "confidence": confidence,
                "status": status
            }
            evidence_list.append(evidence_record)

        return evidence_list

    def build_provenance_for_evidence(
        self,
        evidence_payload: Dict[str, Any],
        event_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build an enriched Phase 4 provenance and integrity record for a transformed CIRCL evidence item.
        """
        if not isinstance(event_payload, dict):
            event_obj = {}
        else:
            event_obj = event_payload.get("Event", event_payload)
            if not isinstance(event_obj, dict):
                event_obj = {}

        orgc = event_obj.get("Orgc", {})
        org_name = orgc.get("name", "CIRCL Computer Incident Response Center Luxembourg") if isinstance(orgc, dict) else "CIRCL"
        event_uuid = str(event_obj.get("uuid") or event_obj.get("id") or "UNKNOWN")

        collection_meta = {
            "collection_mode": "PUBLIC_CIRCL_MISP_OSINT_FEED",
            "circl_feed_url": self.feed_url,
            "circl_event_uuid": event_uuid,
            "creator_org": org_name,
            "target_case_id": "CASE-AUTH-MISP",
            "network_scope": "PUBLIC_AUTHORIZED_OSINT_FEED",
            "attribution_policy": "DEFENSIVE_OBSERVABLE_CTI_ONLY"
        }

        return build_evidence_provenance(
            evidence_id=evidence_payload["id"],
            raw_observed_payload=evidence_payload,
            source_origin=f"CIRCL_OSINT_FEED_{event_uuid[:8]}",
            observation_timestamp=evidence_payload.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            collection_metadata=collection_meta,
            admiralty_reliability="B - Usually Reliable",
            admiralty_credibility="2 - Probably True"
        )

