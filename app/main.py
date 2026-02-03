from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.analyze import router as analyze_router
from app.routes.news import router as news_router
from app.routes.auth import router as auth_router
from app.routes.profile import router as profile_router
from app.routes.history import router as history_router
from app.routes.alerts import router as alerts_router
from app.routes.ai import router as ai_router
from app.routes.risk import router as risk_router
from app.routes.security import router as security_router
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(
    title="GO Suraksha API",
    description="Rule-based digital safety, scam detection, alerts, and account security",
    version="1.0.0"
)

@app.get("/")
def root():
    return {"status": "GO Suraksha backend is running"}

app.include_router(analyze_router)
app.include_router(news_router)
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(history_router)
app.include_router(ai_router)       # rule-based insights
app.include_router(alerts_router)
app.include_router(risk_router)
app.include_router(security_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)