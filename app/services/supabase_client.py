# app/services/supabase_client.py

import os
from supabase import create_client, Client

# Global client (kept for backward compatibility)
supabase: Client | None = None


def get_supabase() -> Client:
    """
    Lazy Supabase client initializer.
    Compatible with:
    - Existing code using `from supabase_client import supabase`
    - New code using `get_supabase()`
    """

    global supabase

    if supabase is not None:
        return supabase

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Supabase configuration missing.\n"
            "Required env vars:\n"
            "- SUPABASE_URL\n"
            "- SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY"
        )

    supabase = create_client(url, key)
    return supabase
