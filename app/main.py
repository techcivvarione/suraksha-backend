from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from dotenv import load_dotenv
from pathlib import Path
import logging

# -------------------------------------------------
# ENV & LOGGING
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

# -------------------------------------------------
# APP INIT
# -------------------------------------------------

app = FastAPI(
    title="GO Suraksha API",
    version="1.0.0",
)

# -------------------------------------------------
# SAFE STARTUP HOOK (NEVER BLOCK APP)
# -------------------------------------------------

@app.on_event("startup")
def startup():
    logger.info("🚀 GO Suraksha API starting up")

    # RSS ingestion (non-critical)
    try:
        from app.services.news_ingestor import ingest_rss
        ingest_rss()
        logger.info("📰 RSS ingestion completed")
    except Exception as e:
        logger.error(f"RSS ingestion skipped: {e}")

    logger.info("✅ Startup completed")

# -------------------------------------------------
# ROUTES (ORDER MATTERS: SIMPLE → COMPLEX)
# -------------------------------------------------

from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router

from app.routes.news import router as news_router
from app.routes.home import router as home_router
from app.routes.history import router as history_router

from app.routes.analyze import router as analyze_router
from app.routes.analyze_ocr import router as analyze_ocr_router

from app.routes.security import router as security_router
from app.routes.trusted_contacts import router as trusted_contacts_router
from app.routes.trusted import router as trusted_router

from app.routes.alerts import router as alerts_router
from app.routes.ai import router as ai_router
from app.routes.risk import router as risk_router

# -------------------------------------------------
# REGISTER ROUTERS
# -------------------------------------------------

app.include_router(auth_router)
app.include_router(profile_router)

app.include_router(news_router)
app.include_router(home_router)
app.include_router(history_router)

app.include_router(analyze_router)
app.include_router(analyze_ocr_router)

app.include_router(security_router)
app.include_router(trusted_contacts_router)
app.include_router(trusted_router)

app.include_router(alerts_router)
app.include_router(ai_router)
app.include_router(risk_router)

# -------------------------------------------------
# CORS (OPEN FOR NOW — LOCK LATER)
# -------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# HEALTH CHECK (OPTIONAL BUT RECOMMENDED)
# -------------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "go-suraksha-backend",
        "version": "1.0.0",
    }
