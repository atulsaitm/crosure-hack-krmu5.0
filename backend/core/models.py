"""Pydantic schemas for API request/response models."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import uuid


# ── Enums ──────────────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackType(str, Enum):
    SQLI = "SQLi"
    XSS = "XSS"
    SSTI = "SSTI"
    CSTI = "CSTI"
    RCE = "RCE"
    SSRF = "SSRF"
    IDOR = "IDOR"
    BAC = "BAC"
    BOLA = "BOLA"
    AUTH_BYPASS = "Auth_Bypass"
    SESSION = "Session"
    MISCONFIG = "Misconfig"
    CORS = "CORS"
    OAST = "OAST"
    PROTOTYPE_POLLUTION = "Prototype_Pollution"
    GRAPHQL = "GraphQL"
    WEBSOCKET = "WebSocket"
    MASS_ASSIGNMENT = "Mass_Assignment"
    JWT = "JWT"
    DESERIALIZATION = "Deserialization"
    COMMAND_INJECTION = "Command_Injection"
    OTHER = "Other"


class ScanPhase(str, Enum):
    QUEUED = "queued"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    CHAINING = "chaining"
    AI_ANALYSIS = "ai_analysis"
    COMPLETE = "complete"
    FAILED = "failed"


class AttackPrimitive(str, Enum):
    INFO_DISCLOSURE = "info_disclosure"
    AUTH_BYPASS = "auth_bypass"
    SESSION_HIJACK = "session_hijack"
    CODE_EXEC = "code_exec"
    DATA_ACCESS = "data_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ChainType(str, Enum):
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_BREACH = "data_breach"
    FULL_COMPROMISE = "full_compromise"
    AUTH_BYPASS = "auth_bypass"
    LATERAL_MOVEMENT = "lateral_movement"


# ── Scan Models ────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str
    auth_cookie: Optional[str] = None
    max_pages: Optional[int] = None
    scan_scope: Optional[List[str]] = None  # Plugin names; None = all


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vuln_type: AttackType
    severity: SeverityLevel
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    cvss_score: float = 0.0
    owasp_category: Optional[str] = None
    primitive: Optional[AttackPrimitive] = None
    remediation: Optional[str] = None
    chain_ids: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    # AI Triage fields
    ai_confidence: Optional[float] = None
    ai_verdict: Optional[str] = None  # true_positive | false_positive | needs_review
    ai_reasoning: Optional[str] = None


class VulnNode(BaseModel):
    finding_id: str
    step: int = 1
    vuln_type: AttackType
    primitive: Optional[AttackPrimitive] = None
    cvss: float = 0.0
    url: str = ""


class EnablesEdge(BaseModel):
    from_id: str
    to_id: str
    condition: str = "enables"
    boost: float = 1.0


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nodes: List[VulnNode] = Field(default_factory=list)
    edges: List[EnablesEdge] = Field(default_factory=list)
    total_score: float = 0.0
    chain_type: ChainType = ChainType.FULL_COMPROMISE
    description: str = ""
    kb_matched: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    findings: List[Finding] = Field(default_factory=list)
    chains: List[AttackChain] = Field(default_factory=list)
    endpoints_crawled: int = 0
    scan_duration: float = 0.0
    tech_stack: Optional[List[str]] = None
    errors: Optional[List[str]] = None


# ── Knowledge Base Models ──────────────────────────────────────────────────────

class ExploitCreate(BaseModel):
    title: str
    description: Optional[str] = None
    attack_type: str = "other"
    severity: str = "medium"
    cve_id: Optional[str] = None
    prerequisites: Optional[List[str]] = None
    steps: Optional[List[Dict[str, Any]]] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None


class ExploitResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    attack_type: str = "other"
    severity: str = "medium"
    cve_id: Optional[str] = None
    tags: Optional[List[str]] = None

    class Config:
        from_attributes = True


class ChainStepCreate(BaseModel):
    vuln_type: str
    description: str = ""
    primitive: Optional[str] = None


class ChainCreate(BaseModel):
    name: str
    description: Optional[str] = None
    chain_type: str = "full_compromise"
    total_score: float = 0.0
    steps: List[ChainStepCreate] = Field(default_factory=list)


class ChainResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    chain_type: str = "full_compromise"

    class Config:
        from_attributes = True


class RemediationRequest(BaseModel):
    finding: dict


class RemediationResponse(BaseModel):
    remediation: str


class TriageResponse(BaseModel):
    verdict: str = "needs_review"
    confidence: float = 0.5
    reasoning: str = ""


# ── Crawler Models ─────────────────────────────────────────────────────────────

class CrawledEndpoint(BaseModel):
    url: str
    method: str = "GET"
    params: Optional[Dict[str, str]] = None
    form_data: Optional[Dict[str, str]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    content_type: Optional[str] = None
    requires_auth: bool = False
    depth: int = 0
    parent_url: Optional[str] = None
    framework: Optional[str] = None


# ── WebSocket Events ───────────────────────────────────────────────────────────

class WSEvent(BaseModel):
    scan_id: str = ""
    phase: ScanPhase = ScanPhase.QUEUED
    message: str = ""
    progress: float = 0.0
