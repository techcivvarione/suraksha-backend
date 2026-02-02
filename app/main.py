from fastapi import FastAPI
from app.routes.analyze import router as analyze_router

app = FastAPI(title="GO Suraksha API")

@app.get("/")
def root():
    return {"status": "GO Suraksha backend is running"}

app.include_router(analyze_router)
