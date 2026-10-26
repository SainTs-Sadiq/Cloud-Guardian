"""
Pydantic request/response models for the Cloud Guardian REST API.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, Enum):
    detected = "detected"
    dry_run = "dry_run"
    pending_approval = "pending_approval"
    remediating = "remediating"
    remediated = "remediated"
    remediation_failed = "remediation_failed"
    notified = "notified"


class AlertSummary(BaseModel):
    event_id: str
    source: str
    event_name: str
    event_time: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: int = Field(ge=0, le=100)
    risk_tier: str
    actor_arn: str
    region: str
    status: str
    remediation_action: Optional[str] = None


class AlertDetail(AlertSummary):
    description: str
    account_id: str
    source_ip: Optional[str] = None
    modifiers: list[str] = []
    stored_at: Optional[str] = None
    updated_at: Optional[str] = None


class AlertListResponse(BaseModel):
    alerts: list[AlertSummary]
    total: int
    filters_applied: dict


class ScanRequest(BaseModel):
    minutes: int = Field(default=15, ge=1, le=1440)
    use_ml: bool = Field(default=True)


class ScanResponse(BaseModel):
    alerts_found: int
    scan_duration_seconds: float
    lookback_minutes: int
    message: str


class ApproveRequest(BaseModel):
    confirmed: bool = Field(..., description="Must be true to execute")


class RemediationResponse(BaseModel):
    event_id: str
    decision: str
    action: Optional[str]
    action_risk_tier: Optional[str]
    detail: str
    executed_at: str


class HealthResponse(BaseModel):
    """Public liveness response. Intentionally minimal: no AWS detail."""
    status: str


class DeepHealthResponse(BaseModel):
    status: str
    aws_account: Optional[str] = None
    aws_arn: Optional[str] = None
    region: str
    guardduty_enabled: bool
    cloudtrail_accessible: bool
    model_loaded: bool
    remediation_enabled: bool
    storage_backend: str


class TacticCoverage(BaseModel):
    tactic: str
    technique_count: int
    active_alerts: int


class CoverageResponse(BaseModel):
    total_techniques_mapped: int
    tactics: list[TacticCoverage]
    active_alert_count: int
