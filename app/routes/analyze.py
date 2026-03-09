from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/analyze", tags=["Analyzer (Deprecated)"])


@router.post("/", status_code=410)
def analyze_input(*args, **kwargs):
    raise HTTPException(
        status_code=410,
        detail="Legacy analyzer deprecated. Use /scan endpoints.",
    )
