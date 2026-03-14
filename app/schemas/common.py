from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class BaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = "success"
    message: str | None = None


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool = False
    error: str
    message: str


class PaginationResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")

    total: int
    limit: int
    offset: int
    items: list[T]
