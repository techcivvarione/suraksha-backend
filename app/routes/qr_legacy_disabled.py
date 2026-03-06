from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/qr", tags=["QR Deprecated"])

# SECURE QR MIGRATION: legacy endpoints disabled


@router.post("/pro/upi/analyze")
def deprecated_analyze():
    raise HTTPException(status_code=410, detail="Deprecated endpoint. Use /qr/analyze")


@router.post("/pro/report")
def deprecated_report():
    raise HTTPException(status_code=410, detail="Deprecated endpoint. Use /qr/analyze")
