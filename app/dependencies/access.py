from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.features import Feature, has_feature, normalize_plan
from app.db import get_db
from app.routes.auth import get_current_user
from app.services.upgrade import build_upgrade_response

logger = logging.getLogger(__name__)


def require_feature(feature: Feature | str, detail: Any = None):
    feature_name = feature.value if isinstance(feature, Feature) else str(feature)

    def _dependency(
        request: Request,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        if not has_feature(current_user, feature):
            logger.warning(
                "feature_access_denied user_id=%s plan=%s feature=%s path=%s method=%s",
                getattr(current_user, "id", None),
                normalize_plan(getattr(current_user, "plan", None)),
                feature_name,
                request.url.path,
                request.method,
            )
            structured = build_upgrade_response(
                user=current_user,
                reason="feature_not_in_plan",
                feature=feature_name,
                db=db,
                endpoint=request.url.path,
            )
            if detail is not None:
                structured["error"]["legacy_detail"] = detail
            raise HTTPException(
                status_code=403,
                detail=structured,
            )
        return current_user

    return _dependency
