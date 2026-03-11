import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

print("========== DB DEBUG ==========")
print("DATABASE_URL:", os.getenv("DATABASE_URL"))
print("================================")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


def _is_scan_path(path: str) -> bool:
    return path.startswith("/scan")


def _scan_error_payload(exc: HTTPException) -> dict:
    if isinstance(exc.detail, dict):
        return exc.detail
    message = str(exc.detail)
    if exc.status_code == 429:
        return {"success": False, "error": "SCAN_LIMIT_REACHED", "message": message}
    if exc.status_code >= 500:
        return {"success": False, "error": "SCAN_PROCESSING_ERROR", "message": message}
    return {"success": False, "error": "SCAN_BAD_REQUEST", "message": message}

app = FastAPI(
    title="GO Suraksha API",
    version="1.0.0",
)


@app.exception_handler(HTTPException)
async def scan_http_exception_handler(request: Request, exc: HTTPException):
    if _is_scan_path(request.url.path):
        return JSONResponse(status_code=exc.status_code, content=_scan_error_payload(exc))
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def scan_validation_exception_handler(request: Request, exc: RequestValidationError):
    if _is_scan_path(request.url.path):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "SCAN_BAD_REQUEST",
                "message": "Invalid scan request.",
            },
        )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

from app.middleware.security import SecurityLoggingMiddleware
app.add_middleware(SecurityLoggingMiddleware)

configured_origins = os.getenv("CORS_ORIGINS", "").strip()
if configured_origins:
    allow_origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
else:
    allow_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    logger.info("GO Suraksha API starting up")

    try:
        from app.services.news_ingestor import ingest_rss
        ingest_rss()
        logger.info("RSS ingestion completed")
    except Exception as exc:
        logger.error("RSS ingestion skipped: %s", exc)

    logger.info("Startup completed")


from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router

from app.routes.news import router as news_router
from app.routes.home import router as home_router
from app.routes.history import router as history_router

from app.routes.analyze_ocr import router as analyze_ocr_router

from app.routes.security import router as security_router
from app.routes.trusted_contacts import router as trusted_contacts_router
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
from app.routes.ai_image_router import router as ai_image_router
from app.routes.qr_secure import router as qr_secure_router
from app.routes.media import router as media_router
from app.routes.alerts import router as alerts_router
from app.routes.scan_password import router as scan_password_router
from app.routes.scan_email import router as scan_email_router
from app.routes.scan_qr import router as scan_qr_router
from app.routes.scan_threat import router as scan_threat_router
from app.routes.scan_reality_image import router as scan_reality_image_router
from app.routes.scan_reality_video import router as scan_reality_video_router
from app.routes.scan_reality_audio import router as scan_reality_audio_router
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
app.include_router(ai_image_router)
app.include_router(qr_secure_router)
app.include_router(media_router)
app.include_router(alerts_router)
app.include_router(scan_password_router)
app.include_router(scan_email_router)
app.include_router(scan_qr_router)
app.include_router(scan_threat_router)
app.include_router(scan_reality_image_router)
app.include_router(scan_reality_video_router)
app.include_router(scan_reality_audio_router)
app.include_router(billing_router)
app.include_router(webhooks_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "go-suraksha-backend",
        "version": "1.0.0",
    }


@app.on_event("startup")
def show_routes():
    print("\n=== REGISTERED ROUTES ===")
    for route in app.routes:
        print(route.path)
    print("=========================\n")
