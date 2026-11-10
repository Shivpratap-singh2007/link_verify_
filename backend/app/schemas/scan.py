import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, description="HTTP or HTTPS URL to analyze statically.")


class DetectionIndicatorSchema(BaseModel):
    code: str
    title: str
    severity: str
    contribution: float
    description: str
    evidence: str


class ExtractedFeatureSchema(BaseModel):
    feature_name: str
    feature_value: str
    risk_contribution: float


class ThreatIntelEntrySchema(BaseModel):
    provider: str
    detection_status: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class EvidenceBreakdownSchema(BaseModel):
    source: str
    raw_score: Optional[float] = None
    effective_weight: float
    status: str
    summary: str


class MLDetailsSchema(BaseModel):
    model_loaded: bool
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    phishing_probability: Optional[float] = None
    model_confidence: Optional[float] = None
    predicted_label: Optional[str] = None
    status_message: str


class ScanReportResponse(BaseModel):
    id: Optional[uuid.UUID] = None
    persisted: bool = False
    submitted_url: str
    normalized_domain: str
    registered_domain: str
    scheme: str
    is_https: bool
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    verdict: str
    model_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    threat_intel_status: str
    scan_status: str = "completed"
    ml_details: MLDetailsSchema
    detection_indicators: List[DetectionIndicatorSchema]
    extracted_features: List[ExtractedFeatureSchema]
    threat_intelligence: List[ThreatIntelEntrySchema]
    evidence_breakdown: List[EvidenceBreakdownSchema]
    recommendations: List[str]
    safety_disclaimer: str
    scanned_at: datetime


class ScanSummarySchema(BaseModel):
    id: uuid.UUID
    original_url: str
    normalized_domain: str
    risk_score: int
    risk_level: RiskLevel
    model_confidence: Optional[float] = None
    verdict: str
    scan_status: str
    created_at: datetime


class PaginatedScansResponse(BaseModel):
    items: List[ScanSummarySchema]
    total: int
    page: int
    page_size: int
    total_pages: int


class DeleteScanResponse(BaseModel):
    deleted: bool
    id: uuid.UUID

