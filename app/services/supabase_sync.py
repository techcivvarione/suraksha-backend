"""Supabase auth mirror.

Keeps Supabase auth.users in sync with the backend users table.
This is a best-effort, fire-and-forget sync layer — errors are logged
and swallowed so Supabase issues NEVER block the primary auth flow.

Public API
----------
    ensure_supabase_user(db, user)
        Synchronous, idempotent sync.  Used by the migration script.

    ensure_supabase_user_async(user_id)
        Fire-and-forget: spawns a daemon thread that opens its own DB
        session and calls ensure_supabase_user().  Use this in auth routes
        so the login/signup response is never delayed by Supabase latency.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.user import User
from app.services.supabase_client import get_supabase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal: HTTP helpers for Supabase Admin REST API
# ---------------------------------------------------------------------------

def _supabase_url() -> str:
    return (os.getenv("SUPABASE_URL") or "").rstrip("/")


def _service_role_key() -> str:
    return os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or ""


def _admin_headers() -> dict[str, str]:
    key = _service_role_key()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
    }


def _http_admin_users(params: dict) -> list[dict]:
    """GET /auth/v1/admin/users with the given query params; returns user list."""
    url = _supabase_url() + "/auth/v1/admin/users"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_admin_headers())
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        return data.get("users") or []


# ---------------------------------------------------------------------------
# Internal: lookup existing Supabase users
# ---------------------------------------------------------------------------

def _find_supabase_id_by_email(email: str) -> Optional[str]:
    """Return the Supabase UUID for a user with the given email, or None."""
    try:
        # Supabase GoTrue /admin/users accepts ?filter=<text> for a fuzzy search
        users = _http_admin_users({"filter": email, "page": 1, "per_page": 50})
        for u in users:
            if (u.get("email") or "").lower() == email.lower():
                return str(u["id"])
    except Exception:
        logger.exception("supabase_sync.find_by_email_failed")
    return None


def _find_supabase_id_by_phone(phone: str) -> Optional[str]:
    """Return the Supabase UUID for a user with the given phone, or None."""
    try:
        users = _http_admin_users({"filter": phone, "page": 1, "per_page": 50})
        for u in users:
            if u.get("phone") == phone:
                return str(u["id"])
    except Exception:
        logger.exception("supabase_sync.find_by_phone_failed")
    return None


# ---------------------------------------------------------------------------
# Internal: create user via Supabase Admin client
# ---------------------------------------------------------------------------

def _create_in_supabase(user: User) -> Optional[str]:
    """
    Create the backend user in Supabase auth.users via the Admin API.

    Returns the Supabase UUID on success.
    On "already registered" error, resolves and returns the existing UUID.
    Returns None on unrecoverable failure.
    """
    if not user.email and not user.phone:
        logger.warning(
            "supabase_sync.no_identifier",
            extra={"user_id": str(user.id)},
        )
        return None

    try:
        client = get_supabase()

        attrs: dict = {
            # Store the backend UUID in Supabase user_metadata for cross-reference
            "user_metadata": {"backend_user_id": str(user.id)},
        }
        if user.email:
            attrs["email"] = user.email
            attrs["email_confirm"] = True          # skip email confirmation flow
        if user.phone:
            attrs["phone"] = user.phone
            attrs["phone_confirm"] = True          # skip phone confirmation flow

        result = client.auth.admin.create_user(attrs)
        return str(result.user.id)

    except Exception as exc:
        msg = str(exc).lower()
        # Supabase returns a 422 / "already registered" when the identifier exists
        if any(s in msg for s in (
            "already registered",
            "already exists",
            "user already",
            "email address is already",
        )):
            logger.info(
                "supabase_sync.already_exists_resolving",
                extra={"user_id": str(user.id)},
            )
            if user.email:
                return _find_supabase_id_by_email(user.email)
            if user.phone:
                return _find_supabase_id_by_phone(user.phone)

        logger.exception(
            "supabase_sync.create_failed",
            extra={"user_id": str(user.id)},
        )
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ensure_supabase_user(db: Session, user: User) -> None:
    """
    Idempotent: ensure this backend user exists in Supabase auth.users and
    that ``supabase_user_id`` is persisted in the backend DB.

    Safe to call on every login — returns immediately if already synced.
    Never raises; all errors are logged and swallowed so callers are unaffected.

    Parameters
    ----------
    db:   SQLAlchemy session (used to persist supabase_user_id if newly obtained)
    user: the backend User ORM instance (mutated in-place on first sync)
    """
    try:
        if getattr(user, "supabase_user_id", None):
            return  # already synced — fast path, no network call

        supabase_id = _create_in_supabase(user)

        if not supabase_id:
            logger.warning(
                "supabase_sync.sync_skipped",
                extra={
                    "user_id": str(user.id),
                    "reason": "could_not_obtain_supabase_id",
                },
            )
            return

        user.supabase_user_id = supabase_id
        db.add(user)
        db.commit()
        logger.info(
            "supabase_sync.synced",
            extra={"user_id": str(user.id), "supabase_id": supabase_id},
        )

    except Exception:
        logger.exception(
            "supabase_sync.ensure_failed",
            extra={"user_id": str(user.id)},
        )
        try:
            db.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Background (async) variant — for use in auth routes
# ---------------------------------------------------------------------------

def _bg_worker(user_id: str) -> None:
    """
    Thread target.  Opens its own DB session so it is fully isolated from
    the request-scoped session that was already committed and closed by the
    time the thread may execute.
    """
    # Import here to avoid circular imports; SessionLocal is cheap to import.
    from app.db import SessionLocal  # noqa: PLC0415

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            logger.warning(
                "supabase_sync.bg_worker.user_not_found",
                extra={"user_id": user_id},
            )
            return
        ensure_supabase_user(db, user)
    except Exception:
        logger.exception(
            "supabase_sync.bg_worker.failed",
            extra={"user_id": user_id},
        )
    finally:
        db.close()


def ensure_supabase_user_async(user_id: str | UUID) -> None:
    """
    Fire-and-forget Supabase sync for use inside auth route handlers.

    Spawns a daemon thread so the HTTP response is returned to the client
    immediately — Supabase API latency (typically 200–600 ms) is completely
    hidden from the user.

    The thread:
    - Opens its own SQLAlchemy session (thread-safe, independent of the
      request session which is already closed by this point)
    - Re-fetches the user from the DB by primary key
    - Calls ensure_supabase_user() — idempotent, returns instantly if the
      user was already synced on a previous login

    Parameters
    ----------
    user_id : str or UUID
        The backend user's primary key.  Converted to str internally.
    """
    threading.Thread(
        target=_bg_worker,
        args=(str(user_id),),
        daemon=True,          # thread does not block process shutdown
    ).start()
