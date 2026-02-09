import time
import uuid
import logging
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)


class SecurityLoggingMiddleware(BaseHTTPMiddleware):
    """
    Global security + audit middleware.

    - Adds request_id
    - Logs method, path, status, latency
    - Extracts user_id safely (if authenticated)
    - Captures IP & User-Agent
    - Never crashes the app
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Attach request_id to request state
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            status_code = 500
            logger.exception(
                "request_failed",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            raise exc

        duration_ms = int((time.time() - start_time) * 1000)

        # Extract user_id safely (never assume)
        user_id = None
        try:
            user = getattr(request.state, "user", None)
            if user and hasattr(user, "id"):
                user_id = str(user.id)
        except Exception:
            user_id = None

        # Client info
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        logger.info(
            "request_completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "user_id": user_id,
                "ip": client_ip,
                "user_agent": user_agent,
            },
        )

        # Expose request id to client (VERY useful for support/debug)
        response.headers["X-Request-ID"] = request_id
        return response
