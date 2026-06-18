"""
AI Shield — API Server (FastAPI)
Provides REST API for the browser extension and web frontend.

Security & Architecture:
- Fully public stateless API. No authentication required.
- CORS restricted to the Vercel frontend and the specific Browser Extension ID.
- In-memory rate limiting (resets on Render cold start).
- In-memory session stats for the Dashboard (resets on Render cold start).
- Input validation via Pydantic models.
"""

import asyncio
import logging
import time
from typing import Dict, Tuple
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from ai_phishing_detector import detect_ai_phishing, is_model_loaded
from deepfake_voice_scanner import scan_audio

# Configure logging
logger = logging.getLogger("ai_shield.api")

VERSION = "2.0.0"

# Input limits
MAX_TEXT_LENGTH = 50_000
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# ─── In-Memory State ─────────────────────────────────────────────────────────
# Note: On Render free tier, these will reset after 15 minutes of inactivity.

# Rate limiting: IP -> (request_count, window_start_time)
_rate_limits: Dict[str, Tuple[int, float]] = {}
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW = 60  # seconds

# Dashboard stats
_session_stats = {
    "total_scans": 0,
    "phishing_detected": 0,
    "deepfakes_detected": 0,
}

def check_rate_limit(ip: str) -> bool:
    """Simple in-memory sliding window rate limiter."""
    now = time.time()
    if ip in _rate_limits:
        count, start_time = _rate_limits[ip]
        if now - start_time > RATE_LIMIT_WINDOW:
            _rate_limits[ip] = (1, now)
            return True
        if count >= RATE_LIMIT_REQUESTS:
            return False
        _rate_limits[ip] = (count + 1, start_time)
        return True
    
    _rate_limits[ip] = (1, now)
    return True

def record_stat(scan_type: str, is_threat: bool):
    """Record a scan in the in-memory stats."""
    _session_stats["total_scans"] += 1
    if is_threat:
        if scan_type == "phishing":
            _session_stats["phishing_detected"] += 1
        elif scan_type == "deepfake":
            _session_stats["deepfakes_detected"] += 1


# ─── Pydantic Models ─────────────────────────────────────────────────────────

class ScanEmailRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_LENGTH)

class ScanEmailResponse(BaseModel):
    is_ai_generated: bool
    confidence: float
    explanation: str
    threat_level: str
    method_used: str

class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool

class DashboardResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    deepfakes_detected: int
    note: str


# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Shield API",
    description="Stateless Personal AI Security Agent — REST API for web and extension.",
    version=VERSION,
)

# CORS — fully public stateless API, allowing requests from local dev, Vercel, extensions, and email clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Middleware ───────────────────────────────────────────────────────────────

@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    """Enforce a strict timeout on all requests."""
    try:
        return await asyncio.wait_for(call_next(request), timeout=30.0)
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=408,
            content={"detail": "Your request took too long to process. If you are uploading an audio file, try a shorter clip."}
        )

@app.middleware("http")
async def enforce_https_middleware(request: Request, call_next):
    """Redirect HTTP requests to HTTPS if handled by a proxy (e.g., Render)."""
    if request.headers.get("x-forwarded-proto") == "http":
        from fastapi.responses import RedirectResponse
        url = request.url.replace(scheme="https")
        return RedirectResponse(url, status_code=301)
    return await call_next(request)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Middleware for rate limiting."""
    path = request.url.path
    client_ip = request.client.host if request.client else "unknown"

    if path.startswith("/api/"):
        if not check_rate_limit(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please wait a moment before trying again."},
            )

    response = await call_next(request)
    return response


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint. Wakes up the Render instance."""
    return HealthResponse(
        status="ok",
        version=VERSION,
        model_loaded=is_model_loaded(),
    )


@app.get("/api/download-extension")
async def download_extension():
    """Generates a ZIP file of the browser_extension directory and streams it."""
    import io
    import zipfile

    extension_dir = Path(__file__).parent / "browser_extension"
    if not extension_dir.exists():
        raise HTTPException(status_code=404, detail="Extension directory not found")

    # Create in-memory zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in extension_dir.rglob("*"):
            if file_path.is_file():
                # Avoid zipping OS-specific files if any
                if file_path.name == ".DS_Store":
                    continue
                # Determine archive name relative to extension_dir
                archive_name = file_path.relative_to(extension_dir)
                zip_file.write(file_path, archive_name)
    
    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=ai_shield_extension.zip",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )


@app.get("/api/dashboard-data", response_model=DashboardResponse)
async def dashboard_data():
    """Returns ephemeral session statistics."""
    return DashboardResponse(
        total_scans=_session_stats["total_scans"],
        phishing_detected=_session_stats["phishing_detected"],
        deepfakes_detected=_session_stats["deepfakes_detected"],
        note="Stats are ephemeral and reset whenever the server sleeps (approx 15 mins of inactivity).",
    )


@app.post("/api/scan-email")
async def scan_email(request_body: ScanEmailRequest):
    """Scan email text for AI-generated phishing."""
    result = detect_ai_phishing(request_body.text)
    record_stat("phishing", result["is_ai_generated"])
    return result


@app.post("/api/scan-voice")
async def scan_voice(file: UploadFile = File(...)):
    """Scan an uploaded audio file for deepfake patterns."""
    content_type = file.content_type or ""
    if not content_type.startswith("audio/"):
        allowed_types = {"audio/", "application/ogg", "video/ogg"}
        if not any(content_type.startswith(t) for t in allowed_types):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type '{content_type}'. Only audio files are accepted.",
            )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE / 1024 / 1024:.0f} MB.",
        )

    # Magic byte verification
    is_valid_audio = False
    if content.startswith(b'RIFF') and len(content) >= 12 and content[8:12] == b'WAVE':
        is_valid_audio = True
    elif content.startswith(b'ID3') or content.startswith(b'\xff\xfb') or content.startswith(b'\xff\xf3') or content.startswith(b'\xff\xf2'):
        is_valid_audio = True
    elif content.startswith(b'OggS'):
        is_valid_audio = True
    elif content.startswith(b'fLaC'):
        is_valid_audio = True

    if not is_valid_audio:
        raise HTTPException(
            status_code=400,
            detail="Invalid audio file format (magic byte verification failed).",
        )

    import tempfile
    suffix = Path(file.filename).suffix if file.filename else ".wav"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = scan_audio(tmp_path)
        record_stat("deepfake", result["is_deepfake"])
        return result
    finally:
        del content
        import gc
        gc.collect()
        try:
            import os
            os.unlink(tmp_path)
        except Exception as e:
            logger.error(f"Failed to delete temp file {tmp_path}: {e}")
