import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.routes.scan_base import require_user
from app.services.scan_jobs import get_scan_job_for_user

router = APIRouter(prefix="/scan", tags=["Scan"])


@router.get("/result/{job_id}")
def get_scan_result(
    job_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_user),
):
    job = get_scan_job_for_user(
        db,
        job_id=job_id,
        user_id=current_user.id,
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    result = None
    if job.result_json:
        try:
            result = json.loads(job.result_json)
        except json.JSONDecodeError:
            result = {"raw": job.result_json}

    return {
        "status": job.status,
        "result": result,
    }
