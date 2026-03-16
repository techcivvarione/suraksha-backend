from __future__ import annotations

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class BaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = "success"
    message: str | None = None


class SuccessResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")

    status: Literal["success"] = "success"
    data: T


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["error"] = "error"
    error_code: str
    message: str


class EnvelopeDataResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: Literal["success"] = "success"
    data: dict[str, Any]


class PaginationResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")

    total: int
    limit: int
    offset: int
    items: list[T]
