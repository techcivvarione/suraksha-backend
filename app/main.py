import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from app.core.logging_setup import configure_logging
from app.core.monitoring import init_sentry
from app.middleware.security import SecurityLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.services.firebase_service import send_push_notification

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
configure_logging()
init_sentry()
logger = logging.getLogger(__name__)
_DOC_PATH_PREFIXES = ("/docs", "/openapi.json", "/redoc")


def _is_scan_path(path: str) -> bool:
    return path.startswith("/scan")


def _error_payload(*, error_code: str, message: str) -> dict:
    return {
        "status": "error",
        "error_code": error_code,
        "message": message,
    }


def _normalize_error_detail(detail, *, default_code: str, default_message: str) -> dict:
    if isinstance(detail, dict):
        error_code = detail.get("error_code") or detail.get("error") or default_code
        message = detail.get("message") or detail.get("detail") or default_message
        return _error_payload(error_code=str(error_code), message=str(message))
    return _error_payload(error_code=default_code, message=str(detail or default_message))


def _http_error_payload(exc: HTTPException) -> dict:
    if exc.status_code == 401:
        return _normalize_error_detail(exc.detail, default_code="INVALID_TOKEN", default_message="Unauthorized")
    if exc.status_code == 403:
        return _normalize_error_detail(exc.detail, default_code="FORBIDDEN", default_message="Forbidden")
    if exc.status_code == 409:
        return _normalize_error_detail(exc.detail, default_code="CONFLICT", default_message="Conflict")
    if exc.status_code >= 500:
        return _error_payload(error_code="INTERNAL_ERROR", message="Something went wrong")
    return _normalize_error_detail(exc.detail, default_code="REQUEST_ERROR", default_message="Request failed")


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
        return {"message_id": message_id}
    except Exception:
        logger.exception("test_push_failed")
        raise HTTPException(status_code=500, detail=_error_payload(error_code="INTERNAL_ERROR", message="Something went wrong"))


@app.exception_handler(HTTPException)
async def scan_http_exception_handler(request: Request, exc: HTTPException):
    payload = _http_error_payload(exc)
    if exc.status_code >= 500:
        logger.error("api_http_error", extra={"path": request.url.path, "status_code": exc.status_code, "error_code": payload.get("error_code")})
    elif exc.status_code == 401:
        logger.warning("authentication_failure", extra={"path": request.url.path, "error_code": payload.get("error_code")})
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def scan_validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error_code": "VALIDATION_ERROR",
            "message": "Invalid request",
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("api_unhandled_exception", extra={"path": request.url.path})
    return JSONResponse(status_code=500, content=_error_payload(error_code="INTERNAL_ERROR", message="Something went wrong"))


app.add_middleware(SecurityLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

configured_origins = os.getenv("CORS_ORIGINS", "").strip()
allow_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()] if configured_origins else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "User-Agent"],
)


async def _read_response_body(response: Response) -> bytes:
    body = getattr(response, "body", None)
    if body is not None:
        return body

    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    return b"".join(chunks)


@app.middleware("http")
async def success_response_envelope(request: Request, call_next):
    response = await call_next(request)

    if request.url.path.startswith(_DOC_PATH_PREFIXES):
        return response
    if request.url.path == "/scan/threat":
        return response
    if response.status_code < 200 or response.status_code >= 300 or response.status_code == 204:
        return response

    content_type = (response.headers.get("content-type") or "").lower()
    if "application/json" not in content_type:
        return response

    body = await _read_response_body(response)
    if not body:
        return response

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return Response(
            content=body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )

    if isinstance(payload, dict) and payload.get("status") == "success" and "data" in payload:
        wrapped = payload
    elif isinstance(payload, dict) and "data" in payload:
        wrapped = {
            "status": "success",
            "data": payload["data"],
        }
    else:
        wrapped = {
            "status": "success",
            "data": payload,
        }

    headers = dict(response.headers)
    headers.pop("content-length", None)
    return JSONResponse(
        status_code=response.status_code,
        content=wrapped,
        headers=headers,
        background=response.background,
    )


@app.on_event("startup")
def startup():
    import threading

    logger.info("startup_begin")

    from app.services.reality_detection.engine import validate_runtime_dependencies

    validate_runtime_dependencies()

    try:
        from app.services.news_ingestor import ingest_rss

        ingest_rss()
        logger.info("rss_ingestion_completed")
    except Exception:
        logger.exception("rss_ingestion_skipped")

    # Start the scan-job worker as a daemon background thread so reality scans
    # (image / video / audio) transition from "pending" → "completed" without
    # requiring a separately launched worker_runner.py process.
    # The thread is a daemon so it is automatically killed when the main process exits.
    # ScanWorker.run_forever() creates its own SQLAlchemy sessions and uses
    # asyncio.run() internally, which is safe from a plain non-async thread.
    try:
        from app.workers.scan_worker import ScanWorker

        _worker_thread = threading.Thread(
            target=ScanWorker().run_forever,
            name="scan-job-worker",
            daemon=True,
        )
        _worker_thread.start()
        logger.info("scan_worker_thread_started", extra={"thread": _worker_thread.name})
    except Exception:
        logger.exception("scan_worker_thread_start_failed")

    logger.info("startup_complete")


from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router
from app.routes.news import router as news_router
from app.routes.home import router as home_router
from app.routes.history import router as history_router
from app.routes.analyze_ocr import router as analyze_ocr_router
from app.routes.security import router as security_router
from app.routes.trusted_contacts import router as trusted_contacts_router, legacy_router as trusted_contacts_legacy_router
from app.routes.alerts import router as alerts_router
from app.routes.ai import router as ai_router
from app.routes.risk import router as risk_router
from app.routes.risk_timeline import router as risk_timeline_router
from app.routes.risk_insights import router as risk_insights_router
from app.routes.ai_explanations import router as ai_explanations_router
from app.routes.family import router as family_router
from app.routes.trusted_alerts import router as trusted_alerts_router
from app.routes.cyber_card import router as cyber_card_router
from app.routes.scam_confirmation import router as scam_confirmation_router
from app.routes.scam_network import router as scam_network_router
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
app.include_router(alerts_router)
app.include_router(ai_router)
app.include_router(risk_router)
app.include_router(risk_timeline_router)
app.include_router(risk_insights_router)
app.include_router(ai_explanations_router)
app.include_router(family_router)
app.include_router(trusted_alerts_router)
app.include_router(cyber_card_router)
app.include_router(scam_confirmation_router)
app.include_router(scam_network_router)
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
    return {"service": "go-suraksha-backend", "version": "1.0.0"}

