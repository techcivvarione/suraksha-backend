from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import PaginationResponse


class LearningArticleSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    title: str
    description: str
    category: str
    read_time: int
    image_url: str | None = None
    is_featured: bool
    created_at: datetime


class LearningArticleDetail(LearningArticleSummary):
    content: str


class LearningArticlesListResponse(PaginationResponse[LearningArticleSummary]):
    model_config = ConfigDict(extra="forbid")

    category: str | None = None


class LearningRecommendationMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["history_match", "featured_fallback"]
    matched_categories: list[str] = Field(default_factory=list)


class LearningRecommendedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[LearningArticleSummary]
    meta: LearningRecommendationMeta
