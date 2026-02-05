# app/services/supabase_client.py

import os
from supabase import create_client, Client

_supabase: Client | None = None


def get_supabase() -> Client:
    """
    Lazy Supabase client initializer.
    Safe for:
    - FastAPI startup
    - Railway deployments
    - Cron jobs
    """

    global _supabase

    if _supabase is not None:
        return _supabase

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Supabase configuration missing.\n"
            "Required env vars:\n"
            "- SUPABASE_URL\n"
            "- SUPABASE_KEY\n"
            "Check Railway → Service → Variables."
        )

    _supabase = create_client(url, key)
    return _supabase
