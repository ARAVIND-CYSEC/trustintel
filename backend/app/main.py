from __future__ import annotations

import logging
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from .models import (
    FileAnalysisResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    RevokeShareResponse,
    ShareAccessEvent,
    ShareAccessLogRequest,
    ShareAccessResponse,
    ShareCreateResponse,
    ShareMetadata,
    UrlAnalyzeRequest,
    UrlAnalyzeResponse,
)
from .repository import InMemoryShareRepository
from .storage import LocalStorage
from .file_analysis import analyze_file
from .threat_intel import analyze_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("trustintel-backend")

app = FastAPI(title="TrustIntel Secure Share API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    client_host = request.client.host if request.client else "unknown"
    logger.info(f"Incoming request: {request.method} {request.url.path} from {client_host}")
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"Response: {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.3f}s")
    
    return response

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception in {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error_type": type(exc).__name__,
            "path": str(request.url.path)
        }
    )

repo = InMemoryShareRepository()
storage = LocalStorage(Path(__file__).resolve().parent.parent / "storage")


@app.get("/health")
def health() -> dict[str, str]:
    """Health check endpoint for monitoring and load balancers."""
    logger.info("Health check requested")
    return {
        "status": "ok",
        "timestamp": time.time(),
        "version": "0.1.0",
        "service": "TrustIntel Secure Share API"
    }


@app.post("/analyze/url", response_model=UrlAnalyzeResponse)
async def analyze_url_endpoint(payload: UrlAnalyzeRequest) -> UrlAnalyzeResponse:
    return await analyze_url(payload.url)


@app.post("/analyze/file", response_model=FileAnalysisResponse)
async def analyze_file_endpoint(file: UploadFile = File(...)) -> FileAnalysisResponse:
    """
    Analyze an uploaded file for malware and security threats.
    
    - Uploads file to backend
    - Computes SHA-256 hash
    - Queries VirusTotal API for reputation data
    - For APK files: extracts and analyzes permissions
    - Generates risk score and threat report
    
    Returns comprehensive threat intelligence report.
    """
    logger.info(f"File upload received for analysis: {file.filename} ({file.content_type})")
    
    try:
        # Read file content
        content = await file.read()
        
        if not content:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        # File size limit (100MB for analysis)
        max_size = 100 * 1024 * 1024
        if len(content) > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"File too large for analysis. Maximum size is {max_size // (1024*1024)}MB"
            )
        
        # Perform analysis
        result = await analyze_file(
            filename=file.filename or "uploaded_file",
            file_content=content,
            mime_type=file.content_type,
        )
        
        logger.info(f"File analysis completed for {file.filename}: Level={result.level}, Score={result.trust_score}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing file {file.filename}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze file: {str(e)}"
        )


@app.post("/shares", response_model=ShareCreateResponse)
async def create_share(
    file: UploadFile = File(...),
    expires_hours: int = Form(24),
    view_only: bool = Form(True),
    otp_enabled: bool = Form(True),
) -> ShareCreateResponse:
    stored_name = f"{uuid4().hex}_{file.filename or 'upload.bin'}"
    saved_path = storage.save_upload(file.file, stored_name)
    access_code = f"{secrets.randbelow(900000) + 100000}" if otp_enabled else None
    share = ShareMetadata.from_upload(
        file_name=file.filename or "upload.bin",
        stored_name=stored_name,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=saved_path.stat().st_size,
        expires_hours=expires_hours,
        view_only=view_only,
        otp_enabled=otp_enabled,
        access_code=access_code,
    )
    repo.put_share(share)
    repo.add_event(
        ShareAccessEvent(
            share_id=share.share_id,
            action="opened",
            detail="Share created and ready for access.",
        )
    )
    return ShareCreateResponse(
        share_id=share.share_id,
        file_name=share.file_name,
        secure_url=f"/shares/{share.share_id}",
        expires_at=share.expires_at,
        view_only=share.view_only,
        otp_enabled=share.otp_enabled,
        revoked=share.revoked,
    )


@app.get("/shares/{share_id}", response_model=ShareAccessResponse)
def get_share(share_id: str) -> ShareAccessResponse:
    share = repo.get_share(share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    return ShareAccessResponse(share=share, events=repo.get_events(share_id))


@app.post("/shares/{share_id}/events", response_model=ShareAccessEvent)
def create_access_event(share_id: str, payload: ShareAccessLogRequest) -> ShareAccessEvent:
    share = repo.get_share(share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    event = ShareAccessEvent(
        share_id=share_id,
        action=payload.action,
        platform=payload.platform,
        detail=payload.detail,
    )
    repo.add_event(event)
    return event


@app.post("/shares/{share_id}/revoke", response_model=RevokeShareResponse)
def revoke_share(share_id: str) -> RevokeShareResponse:
    share = repo.get_share(share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    share.revoked = True
    repo.update_share(share)
    repo.add_event(
        ShareAccessEvent(
            share_id=share_id,
            action="revoked",
            detail="Access revoked by owner.",
        )
    )
    return RevokeShareResponse(share_id=share_id, revoked=True)


@app.post("/shares/{share_id}/otp/verify", response_model=OtpVerifyResponse)
def verify_otp(share_id: str, payload: OtpVerifyRequest) -> OtpVerifyResponse:
    share = repo.get_share(share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    verified = not share.otp_enabled or share.access_code == payload.code
    if verified:
        repo.add_event(
            ShareAccessEvent(
                share_id=share_id,
                action="otp_verified",
                detail="OTP verified successfully.",
            )
        )
    return OtpVerifyResponse(share_id=share_id, verified=verified)


def _is_share_expired(share: ShareMetadata) -> bool:
    """Check if a share has expired based on its expires_at timestamp."""
    try:
        expires_at = datetime.fromisoformat(share.expires_at)
        # Handle timezone-aware and naive datetimes
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at
    except (ValueError, TypeError):
        # If we can't parse the date, consider it not expired to be safe
        return False


@app.get("/shares/{share_id}/download")
def download_share(share_id: str):
    """
    Download a shared file. Validates that the share exists, is not expired,
    and is not revoked before returning the file.
    """
    share = repo.get_share(share_id)
    if not share:
        raise HTTPException(status_code=404, detail="Share not found")
    
    if share.revoked:
        raise HTTPException(status_code=403, detail="Share has been revoked")
    
    if _is_share_expired(share):
        raise HTTPException(status_code=410, detail="Share has expired")
    
    file_path = storage.root / share.stored_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found on server")
    
    repo.add_event(
        ShareAccessEvent(
            share_id=share_id,
            action="download_attempted",
            detail="File download initiated.",
        )
    )
    
    return FileResponse(
        path=file_path,
        filename=share.file_name,
        media_type=share.content_type,
    )
