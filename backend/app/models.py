from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class UrlAnalyzeRequest(BaseModel):
    url: str


class UrlAnalyzeResponse(BaseModel):
    url: str
    trust_score: int
    level: Literal["SAFE", "MEDIUM", "HIGH"]
    main_reason: str
    findings: list[str]
    recommendation: str
    provider: str
    provider_used: bool


class ShareCreateResponse(BaseModel):
    share_id: str
    file_name: str
    secure_url: str
    expires_at: str
    view_only: bool
    otp_enabled: bool
    revoked: bool = False


class ShareMetadata(BaseModel):
    share_id: str = Field(default_factory=lambda: uuid4().hex)
    file_name: str
    stored_name: str
    content_type: str
    size_bytes: int
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str
    view_only: bool = True
    otp_enabled: bool = True
    revoked: bool = False
    access_code: str | None = None

    @classmethod
    def from_upload(
        cls,
        file_name: str,
        stored_name: str,
        content_type: str,
        size_bytes: int,
        expires_hours: int,
        view_only: bool,
        otp_enabled: bool,
        access_code: str | None,
    ) -> "ShareMetadata":
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        return cls(
            file_name=file_name,
            stored_name=stored_name,
            content_type=content_type,
            size_bytes=size_bytes,
            expires_at=expires_at.isoformat(),
            view_only=view_only,
            otp_enabled=otp_enabled,
            access_code=access_code,
        )


class ShareAccessEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    share_id: str
    action: Literal["opened", "download_attempted", "otp_verified", "revoked"]
    platform: str = "android"
    detail: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ShareAccessLogRequest(BaseModel):
    action: Literal["opened", "download_attempted", "otp_verified", "revoked"]
    platform: str = "android"
    detail: str


class RevokeShareResponse(BaseModel):
    share_id: str
    revoked: bool


class ShareAccessResponse(BaseModel):
    share: ShareMetadata
    events: list[ShareAccessEvent]


class OtpVerifyRequest(BaseModel):
    code: str


class OtpVerifyResponse(BaseModel):
    share_id: str
    verified: bool


# File Analysis Models
class FileAnalysisRequest(BaseModel):
    """Request model for file analysis (metadata only)."""
    filename: str
    file_size: int
    mime_type: str
    sha256: str


class VirusTotalStats(BaseModel):
    """VirusTotal detection statistics."""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    total_engines: int = 0


class ApkPermissionInfo(BaseModel):
    """Information about a dangerous APK permission."""
    name: str
    risk_level: str  # "HIGH", "MEDIUM", "LOW"
    description: str


class FileAnalysisResponse(BaseModel):
    """Complete file analysis response."""
    # File metadata
    filename: str
    file_type: str
    file_size: int
    sha256: str

    # Analysis results
    trust_score: int
    level: Literal["SAFE", "MEDIUM", "HIGH"]

    # VirusTotal intelligence
    virustotal_stats: VirusTotalStats | None = None
    malware_family: str | None = None
    threat_labels: list[str] = []

    # APK-specific analysis
    permissions: list[ApkPermissionInfo] = []
    is_apk: bool = False

    # Behavioral analysis
    behavioral_findings: list[str] = []
    phishing_indicators: list[str] = []

    # AI explanation and recommendations
    ai_explanation: str = ""
    recommendations: list[str] = []

    # Provider info
    provider: str = "backend-heuristics"
    analysis_timestamp: str = ""
