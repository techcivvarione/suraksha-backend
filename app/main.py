import logging
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.logging_setup import configure_logging
from app.core.monitoring import init_sentry
from app.db import engine
from app.middleware.security import SecurityLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.services.firebase_service import send_push_notification

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
configure_logging()
init_sentry()
logger = logging.getLogger(__name__)


def run_startup_migrations() -> None:
    command = [sys.executable, "-m", "alembic", "upgrade", "head"]
    result = subprocess.run(command, cwd=str(BASE_DIR), capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("startup_migrations_failed", extra={"stderr": result.stderr[-1000:]})
        raise RuntimeError("Database migrations failed")
    logger.info("startup_migrations_applied")



def ensure_token_version_column() -> bool:
    with engine.begin() as connection:
        exists = connection.execute(
            text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name='users'
                  AND column_name='token_version'
                """
            )
        ).first()
        if exists:
            return False
        connection.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0 NOT NULL"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS idx_users_token_version ON users(token_version)"))
    logger.info("schema_repair_token_version_applied")
    return True


def _is_scan_path(path: str) -> bool:
    return path.startswith("/scan")


def _http_error_payload(exc: HTTPException) -> dict:
    if isinstance(exc.detail, dict):
        return exc.detail

    message = str(exc.detail)
    if exc.status_code == 401:
        return {"error": "INVALID_TOKEN", "message": message}
    if exc.status_code == 403:
        return {"error": "FORBIDDEN", "message": message}
    if exc.status_code == 409:
        return {"error": "CONFLICT", "message": message}
    if exc.status_code >= 500:
        return {"error": "INTERNAL_ERROR", "message": "Something went wrong"}
    return {"error": "REQUEST_ERROR", "message": message}


def _scan_error_payload(exc: HTTPException) -> dict:
    if isinstance(exc.detail, dict):
        return exc.detail
    message = str(exc.detail)
    if exc.status_code == 401:
        return {"success": False, "error": "INVALID_TOKEN", "message": message}
    if exc.status_code == 429:
        return {"success": False, "error": "SCAN_LIMIT_REACHED", "message": message}
    if exc.status_code >= 500:
        return {"success": False, "error": "SCAN_PROCESSING_ERROR", "message": "Something went wrong"}
    return {"success": False, "error": "SCAN_BAD_REQUEST", "message": message}


app = FastAPI(
    title="GO Suraksha API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.get("/test-push")
def test_push(token: str = Query(..., min_length=20)):
    if (os.getenv("ENABLE_TEST_PUSH") or "false").strip().lower() != "true":
        raise HTTPException(status_code=404, detail="Not found")
    try:
        message_id = send_push_notification(token=token, title="GO Suraksha Test", body="Push notifications working")
        return {"status": "push_sent", "message_id": message_id}
    except Exception:
        logger.exception("test_push_failed")
        return {"status": "error", "error": "INTERNAL_ERROR", "message": "Something went wrong"}


@app.exception_handler(HTTPException)
async def scan_http_exception_handler(request: Request, exc: HTTPException):
    payload = _scan_error_payload(exc) if _is_scan_path(request.url.path) else _http_error_payload(exc)
    if exc.status_code >= 500:
        logger.error("api_http_error", extra={"path": request.url.path, "status_code": exc.status_code, "error": payload.get("error")})
    elif exc.status_code == 401:
        logger.warning("authentication_failure", extra={"path": request.url.path, "error": payload.get("error")})
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def scan_validation_exception_handler(request: Request, exc: RequestValidationError):
    if _is_scan_path(request.url.path):
        return JSONResponse(status_code=400, content={"success": False, "error": "SCAN_BAD_REQUEST", "message": "Invalid scan request."})
    return JSONResponse(
        status_code=422,
        content={"error": "VALIDATION_ERROR", "message": "Invalid request", "details": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("api_unhandled_exception", extra={"path": request.url.path})
    if _is_scan_path(request.url.path):
        return JSONResponse(status_code=500, content={"success": False, "error": "SCAN_PROCESSING_ERROR", "message": "Something went wrong"})
    return JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR", "message": "Something went wrong"})


app.add_middleware(SecurityLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

configured_origins = os.getenv("CORS_ORIGINS", "").strip()
allow_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()] if configured_origins else ["http://localhost:3000", "http://127.0.0.1:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "User-Agent"],
)


@app.on_event("startup")
def startup():
    logger.info("startup_begin")

    from app.services.cyber_card import ensure_cyber_card_indexes
    from app.services.device_service import ensure_user_devices_table
    from app.services.reality_detection.engine import validate_runtime_dependencies
    from app.services.scan_jobs import ensure_scan_jobs_table

    run_startup_migrations()
    ensure_token_version_column()
    validate_runtime_dependencies()
    ensure_cyber_card_indexes()
    ensure_scan_jobs_table()
    ensure_user_devices_table()

    try:
        from app.services.news_ingestor import ingest_rss

        ingest_rss()
        logger.info("rss_ingestion_completed")
    except Exception:
        logger.exception("rss_ingestion_skipped")

    logger.info("startup_complete")


from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router
from app.routes.news import router as news_router
from app.routes.home import router as home_router
from app.routes.history import router as history_router
from app.routes.analyze_ocr import router as analyze_ocr_router
from app.routes.security import router as security_router
from app.routes.trusted_contacts import router as trusted_contacts_router, legacy_router as trusted_contacts_legacy_router
from app.routes.trusted import router as trusted_router
from app.routes.alerts import router as alerts_router
from app.routes.ai import router as ai_router
from app.routes.risk import router as risk_router
from app.routes.risk_timeline import router as risk_timeline_router
from app.routes.risk_insights import router as risk_insights_router
from app.routes.ai_explanations import router as ai_explanations_router
from app.routes.family import router as family_router
from app.routes import trusted_alerts
from app.routes.cyber_card import router as cyber_card_router
from app.routes.scam_confirmation import router as scam_confirmation_router
from app.routes.scam_network import router as scam_network_router
from app.routes.scam_heatmap import router as scam_heatmap_router
from app.routes.scam_radar import router as radar_router
from app.routes.ai_image_router import router as ai_image_router
from app.routes.qr_secure import router as qr_secure_router
from app.routes.media import router as media_router
from app.routes.scan_password import router as scan_password_router
from app.routes.scan_email import router as scan_email_router
from app.routes.scan_qr import router as scan_qr_router
from app.routes.scan_threat import router as scan_threat_router
from app.routes.scan_reality_image import router as scan_reality_image_router
from app.routes.scan_reality_video import router as scan_reality_video_router
from app.routes.scan_reality_audio import router as scan_reality_audio_router
from app.routes.scan_results import router as scan_results_router
from app.routes.devices import router as devices_router
from app.routes.billing import router as billing_router
from app.routes.webhooks import router as webhooks_router

app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(news_router)
app.include_router(home_router)
app.include_router(history_router)
app.include_router(analyze_ocr_router)
app.include_router(security_router)
app.include_router(trusted_contacts_router)
app.include_router(trusted_contacts_legacy_router)
app.include_router(trusted_router)
app.include_router(alerts_router)
app.include_router(ai_router)
app.include_router(risk_router)
app.include_router(risk_timeline_router)
app.include_router(risk_insights_router)
app.include_router(ai_explanations_router)
app.include_router(family_router)
app.include_router(trusted_alerts.router)
app.include_router(cyber_card_router)
app.include_router(scam_confirmation_router)
app.include_router(scam_network_router)
app.include_router(scam_heatmap_router)
app.include_router(radar_router)
app.include_router(ai_image_router)
app.include_router(qr_secure_router)
app.include_router(media_router)
app.include_router(scan_password_router)
app.include_router(scan_email_router)
app.include_router(scan_qr_router)
app.include_router(scan_threat_router)
app.include_router(scan_reality_image_router)
app.include_router(scan_reality_video_router)
app.include_router(scan_reality_audio_router)
app.include_router(scan_results_router)
app.include_router(devices_router)
app.include_router(billing_router)
app.include_router(webhooks_router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "go-suraksha-backend", "version": "1.0.0"}
