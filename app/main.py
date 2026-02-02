from fastapi import FastAPI
from app.routes.analyze import router as analyze_router
from app.routes.news import router as news_router

app = FastAPI(title="GO Suraksha API")

@app.get("/")
def root():
    return {"status": "GO Suraksha backend is running"}

app.include_router(analyze_router)
app.include_router(news_router)
