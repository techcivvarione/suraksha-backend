from __future__ import annotations

import os

try:
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration
except ImportError:  # pragma: no cover
    sentry_sdk = None
    FastApiIntegration = None
    LoggingIntegration = None



def init_sentry() -> None:
    if sentry_sdk is None:
        return

    dsn = (os.getenv("SENTRY_DSN") or "").strip()
    if not dsn or sentry_sdk.Hub.current.client is not None:
        return

    sentry_sdk.init(
        dsn=dsn,
        integrations=[FastApiIntegration(), LoggingIntegration(level=None, event_level=None)],
        environment=os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("APP_ENV") or "development",
        traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE") or "0.0"),
        send_default_pii=False,
    )
