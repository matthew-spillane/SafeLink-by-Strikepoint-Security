from pydantic import BaseModel, HttpUrl
from typing import Optional, Any
from datetime import datetime


class ScanRequest(BaseModel):
    url: str
    session_id: Optional[str] = None


class CheckResult(BaseModel):
    name: str
    status: str  # "pass", "warning", "fail", "skipped"
    severity: str  # "low", "medium", "high", "info"
    summary: str
    details: Optional[Any] = None


class AIVerdict(BaseModel):
    verdict: str
    confidence: str
    explanation: str


class URLScanResult(BaseModel):
    screenshot_url: Optional[str] = None
    verdict: Optional[str] = None
    report_url: Optional[str] = None
    urlscan_uuid: Optional[str] = None
    available: bool = True


class ScanResponse(BaseModel):
    id: str
    url: str
    risk_score: int
    verdict: str
    verdict_color: str
    checks: list[CheckResult]
    redirect_chain: list[str]
    ai_verdict: Optional[AIVerdict] = None
    urlscan: Optional[URLScanResult] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    risk_score: int
    verdict: str
    verdict_color: str
    created_at: datetime

    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
