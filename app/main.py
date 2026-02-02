from fastapi import FastAPI
from app.routes.analyze import router as analyze_router

app = FastAPI(title="GO Suraksha API")

app.include_router(analyze_router)

@app.get("/")
def health():
    return {"status": "GO Suraksha backend is running"}
