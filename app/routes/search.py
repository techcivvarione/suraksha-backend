import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routes.auth import get_current_user

router = APIRouter(prefix="/search", tags=["Search"])
logger = logging.getLogger(__name__)

_TYPE_LABEL: dict[str, str] = {
    "EMAIL":    "Email Breach Check",
    "PASSWORD": "Password Strength Check",
    "THREAT":   "Threat / Link Scan",
    "IMAGE":    "Image Reality Scan",
    "QR":       "QR Code Scan",
    "SMS":      "SMS / Message Scan",
    "TEXT":     "Text Scan",
}

_TYPE_ICON: dict[str, str] = {
    "EMAIL":    "email",
    "PASSWORD": "lock",
    "THREAT":   "link",
    "IMAGE":    "image",
    "QR":       "qr_code",
    "SMS":      "message",
    "TEXT":     "message",
}

_RISK_SUBTITLE: dict[str, str] = {
    "LOW":     "No significant threats detected",
    "MEDIUM":  "Some risk indicators found",
    "HIGH":    "Threat detected — take action",
    "UNKNOWN": "Analysis completed",
}


class SearchResultItem(BaseModel):
    id: str
    type: str
    title: str
    subtitle: str
    risk: str
    score: int
    icon: str
    created_at: str


class SearchResponse(BaseModel):
    query: str
    results: List[SearchResultItem]
    total: int


def _build_title(scan_type: str, input_text: str) -> str:
    label = _TYPE_LABEL.get(scan_type.upper(), "Scan")
    preview = (input_text or "").strip()
    if len(preview) > 40:
        preview = preview[:37] + "…"
    return f"{label}: {preview}" if preview else label


def _build_subtitle(risk: str, reasons: Optional[dict]) -> str:
    base = _RISK_SUBTITLE.get((risk or "UNKNOWN").upper(), "Analysis completed")
    if reasons and isinstance(reasons, dict):
        # Try to extract a readable reason from the reasons dict
        reason_list = reasons.get("reasons") or reasons.get("highlights") or []
        if isinstance(reason_list, list) and reason_list:
            first = str(reason_list[0]).strip()
            if first:
                return first[:80]
    return base


@router.get("", response_model=SearchResponse)
def search(
    q: str = Query(..., min_length=1, max_length=200, description="Search query"),
    filter: Optional[str] = Query(None, description="Filter by scan type: EMAIL, PASSWORD, THREAT, IMAGE, QR, SMS"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Search across the user's scan history.
    Matches against input_text (case-insensitive ILIKE).
    Optional ?filter= to narrow by scan type.
    """
    clean_q = q.strip()
    like_pattern = f"%{clean_q}%"

    type_filter_clause = ""
    params: dict = {
        "user_id": str(current_user.id),
        "pattern": like_pattern,
        "limit": limit,
    }

    if filter:
        type_upper = filter.upper()
        # Support "ALL" or empty meaning no filter
        if type_upper not in ("", "ALL"):
            type_filter_clause = "AND UPPER(type) = :scan_type"
            params["scan_type"] = type_upper

    rows = db.execute(
        text(f"""
            SELECT
                id::text,
                COALESCE(type, 'TEXT') AS type,
                input_text,
                COALESCE(risk, 'UNKNOWN') AS risk,
                COALESCE(score, 0) AS score,
                reasons,
                created_at
            FROM scan_history
            WHERE user_id = CAST(:user_id AS uuid)
              AND input_text ILIKE :pattern
              {type_filter_clause}
            ORDER BY created_at DESC
            LIMIT :limit
        """),
        params,
    ).mappings().all()

    items: List[SearchResultItem] = []
    for row in rows:
        scan_type = str(row["type"]).upper()
        risk = str(row["risk"]).upper()
        items.append(
            SearchResultItem(
                id=str(row["id"]),
                type=scan_type,
                title=_build_title(scan_type, row["input_text"] or ""),
                subtitle=_build_subtitle(risk, row["reasons"]),
                risk=risk,
                score=int(row["score"] or 0),
                icon=_TYPE_ICON.get(scan_type, "search"),
                created_at=row["created_at"].isoformat() if row["created_at"] else "",
            )
        )

    logger.info(
        "search_executed",
        extra={
            "user_id": str(current_user.id),
            "query_len": len(clean_q),
            "filter": filter,
            "result_count": len(items),
        },
    )

    return SearchResponse(query=clean_q, results=items, total=len(items))
