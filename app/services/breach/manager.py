from copy import deepcopy

from redis.exceptions import RedisError

from app.core.features import Limit, get_global_limit, normalize_plan
from app.services.breach.hibp_provider import HIBPProvider
from app.services.redis_store import get_json, set_json


def get_breach_provider(user_plan: str):
    """
    Returns a new provider instance per request.
    """
    return HIBPProvider(user_plan=user_plan)


def _email_cache_key(email: str, user_plan: str) -> str:
    tier = normalize_plan(user_plan)
    return f"scan:{email.lower()}:{tier}"


def check_email_breach(email: str, user_plan: str) -> dict:
    cache_key = _email_cache_key(email=email, user_plan=user_plan)

    try:
        cached = get_json("cache:breach:email", cache_key)
        if cached:
            return deepcopy(cached)
    except RedisError:
        cached = None

    provider = get_breach_provider(user_plan)
    result = provider.check_email(email)

    try:
        ttl = get_global_limit(Limit.BREACH_EMAIL_CACHE_TTL_SECONDS)
        set_json("cache:breach:email", deepcopy(result), ttl, cache_key)
    except RedisError:
        pass
    return result
