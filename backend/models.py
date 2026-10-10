from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class Case(BaseModel):
    id: str = Field(..., description="Unique case identifier")
    candidate: str = Field(..., description="Target candidate/alias subject")
    status: str = Field(..., description="Current investigation status")
    classification: str = Field(..., description="Synthetic data classification disclaimer")
    description: str = Field(..., description="Case scope and defensive research overview")

class Actor(BaseModel):
    id: str = Field(..., description="Synthetic actor cluster identifier")
    name: str = Field(..., description="Primary actor handle or identifier")
    tier: str = Field(..., description="Activity/threat tier level")
    confidence: Optional[int] = Field(None, description="Analytical correlation confidence percentage or None if unavailable")
    aliases: List[str] = Field(default_factory=list, description="Associated synthetic aliases")
    pgp: Optional[str] = Field(None, description="Correlated PGP key fingerprint or None if unavailable")
    wallet: Optional[str] = Field(None, description="Correlated cryptocurrency wallet or None if unavailable")
    stylometry: Optional[int] = Field(None, description="Stylometric similarity score or None if unavailable")
    behaviour: Optional[int] = Field(None, description="Behavioural similarity score or None if unavailable")
    note: str = Field(..., description="Defensive analytical disclaimer note")

class Evidence(BaseModel):
    id: str = Field(..., description="Evidence record identifier")
    type: str = Field(..., description="Evidence category: ALIAS, PGP, STYLOMETRY, WALLET, BEHAVIOUR")
    identifier: str = Field(..., description="Observed identifier value")
    timestamp: str = Field(..., description="Recorded timestamp of synthetic observation")
    relationship: str = Field(..., description="Analytical relationship or linkage rationale")
    confidence: str = Field(..., description="Confidence rating: Low, Medium, High")
    status: str = Field(..., description="Verification status: Observed, Correlated, Analysed")

class TimelineEvent(BaseModel):
    week: str = Field(..., description="Investigation timeline week milestone")
    date: str = Field(..., description="Calendar date of synthetic event (YYYY-MM-DD)")
    event: str = Field(..., description="Summary title of the milestone event")
    detail: str = Field(..., description="Detailed description of the observation or correlation")

class GraphNode(BaseModel):
    id: str = Field(..., description="Unique graph entity identifier")
    type: str = Field(..., description="Entity category: Actor, Alias, PGP, Wallet")
    x: float = Field(..., description="X layout coordinate percentage")
    y: float = Field(..., description="Y layout coordinate percentage")

class GraphEdge(BaseModel):
    source: str = Field(..., description="Source node identifier")
    target: str = Field(..., description="Target node identifier")
    relationship: str = Field(..., description="Observed relationship type")
    confidence: str = Field(..., description="Link confidence: Medium, High")

class GraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list, description="Graph entity nodes")
    edges: List[GraphEdge] = Field(default_factory=list, description="Graph relationship edges")

class OpsecSignal(BaseModel):
    actor_id: str = Field(..., description="Associated actor ID")
    labels: List[str] = Field(default_factory=list, description="Time series intervals (weeks)")
    values: List[int] = Field(default_factory=list, description="Observable identity exposure signal index")
    description: str = Field(..., description="Analytical description of the signal metric")

class Metrics(BaseModel):
    active_actors: int = Field(..., description="Total synthetic active actor candidates")
    evidence_records: int = Field(..., description="Cataloged evidence records count")
    correlated_identifiers: int = Field(..., description="Correlated identifiers count")
    high_confidence_links: int = Field(..., description="High-confidence links count")
    opsec_signals: int = Field(..., description="Observable OPSEC exposure signals count")

class SearchResultItem(BaseModel):
    kind: str = Field(..., description="Entity kind: ACTOR, EVIDENCE, or node type")
    id: str = Field(..., description="Entity identifier")
    title: str = Field(..., description="Entity display name or title")

class SearchResponse(BaseModel):
    query: str = Field(..., description="Search query string")
    results: List[SearchResultItem] = Field(default_factory=list, description="Matching synthetic artifacts")

# Phase 2 Analytics & Correlation Engine Models

class AliasSimilarityBreakdown(BaseModel):
    candidate_a: str = Field(..., description="First alias handle")
    candidate_b: str = Field(..., description="Second alias handle")
    levenshtein_score: float = Field(..., description="Normalized Levenshtein similarity percentage (0-100)")
    jaro_winkler_score: float = Field(..., description="Jaro-Winkler similarity percentage (0-100)")
    ngram_overlap_score: float = Field(..., description="Character n-gram overlap percentage (0-100)")
    combined_score: float = Field(..., description="Weighted ensemble alias similarity score (0-100)")
    explanation: str = Field(..., description="Explainable breakdown of algorithmic calculation")

class SignalContribution(BaseModel):
    dimension: str = Field(..., description="Signal name / analytical dimension")
    score: Optional[float] = Field(None, description="Individual dimension raw score (0-100), or None if unavailable")
    weight: float = Field(..., description="Relative weight in ensemble (0.0 - 1.0)")
    weighted_score: Optional[float] = Field(None, description="Score contribution (score * weight), or None if unavailable")
    explanation: str = Field(..., description="Observable rationale and evidence context")
    status: Optional[str] = Field("AVAILABLE", description="Availability status: AVAILABLE or UNAVAILABLE")

class CorrelationAssessment(BaseModel):
    actor_id: str = Field(..., description="Actor identifier")
    actor_name: str = Field(..., description="Primary actor handle")
    primary_alias: Optional[str] = Field(None, description="Primary candidate handle")
    correlated_alias: Optional[str] = Field(None, description="Correlated target alias")
    overall_confidence: Optional[float] = Field(None, description="Final multi-signal confidence score (0-100), or None if unavailable")
    confidence_tier: str = Field(..., description="Confidence category: HIGH, MEDIUM, LOW, or UNAVAILABLE")
    signals: List[SignalContribution] = Field(..., description="Contributing analytical signals")
    alias_breakdown: Optional[AliasSimilarityBreakdown] = Field(None, description="Detailed alias similarity calculations")
    summary: str = Field(..., description="Investigative synthesis summary")
    disclaimer: str = Field(..., description="Defensive research safety disclaimer")

class OpsecEventItem(BaseModel):
    week: str = Field(..., description="Timeline milestone week")
    signal: str = Field(..., description="Category of observable exposure")
    points: int = Field(..., description="Exposure points added to index")
    description: str = Field(..., description="Observable operational hygiene event details")

class OpsecEvaluation(BaseModel):
    actor_id: str = Field(..., description="Actor identifier")
    actor_name: str = Field(..., description="Actor display name")
    current_exposure_score: Optional[int] = Field(None, description="Current cumulative exposure score (0-100), or None if unavailable")
    exposure_level: str = Field(..., description="Exposure rating: Low, Moderate, High, or Not available from source")
    trend_labels: List[str] = Field(default_factory=list, description="Investigation timeline intervals")
    trend_values: List[int] = Field(default_factory=list, description="Historical exposure index progression")
    contributing_events: List[OpsecEventItem] = Field(default_factory=list, description="Itemized exposure triggers")
    explanation: str = Field(..., description="Overall OPSEC risk assessment")

# Phase 3 Interactive Graph, Drill-Down & Multi-Case Models

class CaseSummary(BaseModel):
    id: str = Field(..., description="Unique case identifier")
    candidate: str = Field(..., description="Target candidate/alias subject")
    status: str = Field(..., description="Current investigation status")
    classification: str = Field(..., description="Synthetic data classification disclaimer")
    description: str = Field(..., description="Case scope overview")
    active_actors: int = Field(..., description="Total synthetic actors in this case")
    evidence_records: int = Field(..., description="Total synthetic evidence items in this case")

class GraphNodeDetail(BaseModel):
    id: str = Field(..., description="Node identifier")
    type: str = Field(..., description="Entity category: Actor, Alias, PGP, Wallet, Evidence")
    case_id: str = Field(..., description="Associated case identifier")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Entity attributes")
    connected_edges: List[GraphEdge] = Field(default_factory=list, description="Directly connected relationships")
    neighbor_nodes: List[Dict[str, str]] = Field(default_factory=list, description="Connected neighbor nodes with id and type")
    related_evidence: List[Evidence] = Field(default_factory=list, description="Associated evidence records")

class ActorDrillDown(BaseModel):
    actor: Actor = Field(..., description="Core actor profile")
    case_id: str = Field(..., description="Case identifier")
    correlation: CorrelationAssessment = Field(..., description="Phase 2 multi-signal correlation assessment")
    opsec: OpsecEvaluation = Field(..., description="Dynamic OPSEC exposure evaluation")
    related_evidence: List[Evidence] = Field(default_factory=list, description="Correlated evidence records")
    related_timeline: List[TimelineEvent] = Field(default_factory=list, description="Associated timeline events")
    connected_nodes: List[GraphNode] = Field(default_factory=list, description="Directly connected graph nodes")

# Phase 4 Step 1: Evidence Provenance & Integrity Model

class EvidenceProvenanceRecord(BaseModel):
    evidence_id: str = Field(..., description="Evidence identifier (e.g. EV-001)")
    sha256_hash: str = Field(..., description="Canonical 64-char SHA-256 hash")
    observation_timestamp: str = Field(..., description="Recorded observation timestamp")
    provenance: Dict[str, Any] = Field(..., description="Source origin, collection and Admiralty metadata")
    observed_data: Dict[str, Any] = Field(..., description="Objective observed artifact data")
    analytical_conclusion: Dict[str, Any] = Field(..., description="Subjective analytical inferences and confidence")

# Phase 4 Step 2: Audit Logging Model

class AuditLogEntry(BaseModel):
    event_id: str = Field(..., description="Unique audit event identifier (e.g. AUD-...)")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    action: str = Field(..., description="Audit action category")
    case_id: str = Field(..., description="Target synthetic case identifier")
    target_entity_id: Optional[str] = Field(default=None, description="Optional target identifier")
    operator: str = Field(default="demo-analyst", description="Operator identity")
    status: str = Field(default="SUCCESS", description="Operation status (SUCCESS, FAILURE, ERROR)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Sanitized event metadata")

# Phase 4 Step 4: Investigation Report Model

class InvestigationReportModel(BaseModel):
    case_summary: Dict[str, Any] = Field(..., description="Case metadata and disclaimer")
    actors: List[Dict[str, Any]] = Field(..., description="Tracked actors list")
    evidence_summary: List[Dict[str, Any]] = Field(..., description="Evidence records with integrity hashes")
    relationships: List[Dict[str, Any]] = Field(..., description="Graph relationship links")
    correlation_analysis: Optional[Dict[str, Any]] = Field(default=None, description="Multi-signal correlation assessment")
    opsec_exposure_indicators: Optional[Dict[str, Any]] = Field(default=None, description="OPSEC exposure trend evaluation")
    timeline: List[Dict[str, Any]] = Field(..., description="Chronological milestone events")
    limitations: List[str] = Field(..., description="Analytical limitations list")
    safety_classification: Dict[str, Any] = Field(..., description="Defensive research classification metadata")

# Phase 6.2: MISP Threat Intelligence Feed Models

class MISPStatusResponse(BaseModel):
    configured: bool = Field(..., description="Whether MISP URL and API key are configured")
    base_url: Optional[str] = Field(default=None, description="Sanitized base URL of MISP instance (no secrets)")
    mode: str = Field(..., description="Operating mode: OFFLINE_DEMO_MODE or AUTHORIZED_LIVE_FEED")
    message: str = Field(..., description="Status summary and safety notice")

class MISPPreviewRequest(BaseModel):
    query: Optional[str] = Field(default=None, description="Optional search term for MISP restSearch")
    limit: int = Field(default=50, ge=1, le=200, description="Max attributes/events to preview")
    mock_event: Optional[Dict[str, Any]] = Field(default=None, description="Optional offline mock MISP event payload")

class MISPPreviewResponse(BaseModel):
    mode: str = Field(..., description="Operating mode used for preview")
    events_count: int = Field(..., description="Number of MISP events parsed")
    attributes_count: int = Field(..., description="Number of normalized evidence attributes")
    evidence_items: List[Evidence] = Field(default_factory=list, description="Transformed SHADOWTRACE evidence items")

class MISPImportRequest(BaseModel):
    case_id: str = Field(..., description="Target synthetic case ID to scope imported evidence")
    misp_event: Optional[Dict[str, Any]] = Field(default=None, description="Optional explicit MISP event payload to import")
    limit: Optional[int] = Field(default=None, description="Optional maximum items to import")

class MISPImportResponse(BaseModel):
    case_id: str = Field(..., description="Target synthetic case identifier")
    mode: str = Field(..., description="Operating mode used for import")
    imported_count: int = Field(..., description="Total evidence records imported")
    evidence_records: List[Evidence] = Field(default_factory=list, description="Normalized evidence records")
    provenance_records: List[EvidenceProvenanceRecord] = Field(default_factory=list, description="Cryptographic provenance and integrity records")

class MISPConnectionTestResponse(BaseModel):
    connected: bool = Field(..., description="Whether connection to authorized MISP instance succeeded")
    base_url: Optional[str] = Field(default=None, description="Target base URL tested")
    status: str = Field(..., description="Connection status descriptor")
    message: str = Field(..., description="Details of connection test result")
    version: Optional[str] = Field(default=None, description="MISP server version if reported")

# Public CIRCL MISP OSINT Feed Models

class CIRCLManifestItem(BaseModel):
    uuid: str = Field(..., description="MISP Event UUID")
    info: str = Field(..., description="Event description / title")
    date: str = Field(..., description="Event publication date")
    threat_level: str = Field(..., description="Confidence rating: High, Medium, Low")
    threat_level_id: int = Field(default=3, description="MISP threat_level_id (1-3)")
    orgc: str = Field(default="CIRCL", description="Originating organization")

class CIRCLFeedStatusResponse(BaseModel):
    available: bool = Field(..., description="Whether public CIRCL feed is reachable")
    feed_url: str = Field(..., description="Public feed base URL")
    mode: str = Field(default="PUBLIC_CIRCL_OSINT_FEED", description="Feed access mode")
    message: str = Field(..., description="Status summary and safety notice")
    sample_manifest: List[CIRCLManifestItem] = Field(default_factory=list, description="Latest event summaries from manifest.json")

class CIRCLPreviewRequest(BaseModel):
    event_uuid: Optional[str] = Field(default=None, description="Specific event UUID to preview (if None, previews first event in manifest)")
    max_attributes: int = Field(default=15, ge=1, le=50, description="Max attributes to process from the event")

class CIRCLPreviewResponse(BaseModel):
    feed_url: str = Field(..., description="Public feed base URL")
    event_uuid: str = Field(..., description="UUID of previewed event")
    event_info: str = Field(..., description="Title/info of previewed event")
    threat_level: str = Field(..., description="Confidence rating: High, Medium, Low")
    attributes_count: int = Field(..., description="Extracted evidence count")
    evidence_items: List[Evidence] = Field(default_factory=list, description="Normalized evidence records")

class CIRCLImportRequest(BaseModel):
    event_uuid: Optional[str] = Field(default=None, description="Specific event UUID to import (if None, imports first event in manifest)")
    max_attributes: int = Field(default=15, ge=1, le=50, description="Max attributes to import")
    case_id: str = Field(default="CASE-AUTH-MISP", description="Target case ID (strictly CASE-AUTH-MISP)")

class CIRCLImportResponse(BaseModel):
    case_id: str = Field(..., description="Target case identifier")
    mode: str = Field(default="PUBLIC_CIRCL_OSINT_FEED", description="Feed mode")
    imported_count: int = Field(..., description="Number of imported records")
    event_uuid: str = Field(..., description="UUID of imported event")
    evidence_records: List[Evidence] = Field(default_factory=list, description="Normalized evidence records")
    provenance_records: List[EvidenceProvenanceRecord] = Field(default_factory=list, description="Cryptographic provenance records")

class CIRCLPollRequest(BaseModel):
    max_events: int = Field(default=3, ge=1, le=10, description="Max newly detected events to process per poll cycle")
    max_attributes: int = Field(default=15, ge=1, le=50, description="Max attributes to process per event")
    force_refresh: bool = Field(default=False, description="Whether to re-evaluate manifest without skipping previously tracked UUIDs")
    mock_manifest: Optional[Dict[str, Any]] = Field(default=None, description="Optional controlled mock manifest for offline testing")
    mock_event: Optional[Dict[str, Any]] = Field(default=None, description="Optional controlled mock event payload for offline testing")

class CIRCLPollResponse(BaseModel):
    status: str = Field(..., description="Poll result: SUCCESS, SKIPPED_NO_NEW, PARTIAL, FAILURE")
    polled_at: str = Field(..., description="ISO 8601 timestamp of poll completion")
    manifest_total_events: int = Field(..., description="Total events available in manifest.json")
    new_events_detected: int = Field(..., description="Number of previously unseen events detected")
    processed_event_uuids: List[str] = Field(default_factory=list, description="UUIDs of events processed during this cycle")
    imported_evidence_count: int = Field(..., description="Total evidence records imported into CASE-AUTH-MISP")
    skipped_count: int = Field(default=0, description="Number of events skipped")
    failed_count: int = Field(default=0, description="Number of events that failed to process")
    errors: List[str] = Field(default_factory=list, description="Non-fatal error messages encountered")

class CIRCLSyncStatusResponse(BaseModel):
    feed_url: str = Field(..., description="Public CIRCL feed URL")
    last_poll_timestamp: Optional[str] = Field(default=None, description="Timestamp of the most recent poll")
    last_poll_status: str = Field(default="UNINITIALIZED", description="Status of the most recent poll")
    total_tracked_uuids: int = Field(..., description="Total unique event UUIDs tracked by sync engine")
    total_events_processed: int = Field(..., description="Cumulative events processed across all polls")
    total_evidence_imported: int = Field(..., description="Cumulative evidence records imported into CASE-AUTH-MISP")


