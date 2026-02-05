from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path
import logging

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app = FastAPI(
    title="GO Suraksha API",
    version="1.0.0",
)

# ✅ SAFE STARTUP HOOK (MUST NEVER CRASH APP)
@app.on_event("startup")
def startup():
    try:
        from app.services.news_ingestor import ingest_rss
        ingest_rss()
    except Exception as e:
        logging.error(f"RSS ingestion failed during startup: {e}")

# -------- ROUTES --------
from app.routes.news import router as news_router
from app.routes.analyze import router as analyze_router
from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router
from app.routes.history import router as history_router
from app.routes.alerts import router as alerts_router
from app.routes.ai import router as ai_router
from app.routes.risk import router as risk_router
from app.routes.security import router as security_router
from app.routes.home import router as home_router

app.include_router(news_router)
app.include_router(analyze_router)
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(history_router)
app.include_router(alerts_router)
app.include_router(ai_router)
app.include_router(risk_router)
app.include_router(security_router)
app.include_router(home_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
