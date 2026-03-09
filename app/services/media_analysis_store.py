from typing import Optional

from redis.exceptions import RedisError

from app.services.redis_store import get_redis, build_hashed_key

TTL_SECONDS = 600  # 10 minutes


def store_recent_analysis(user_id: str, media_hash: str, analysis_type: str, risk_score: int, risk_level: str):
    try:
        redis = get_redis()
        key = build_hashed_key("media:analysis", user_id, media_hash)
        redis.hmset(
            key,
            {
                "user_id": user_id,
                "media_hash": media_hash,
                "analysis_type": analysis_type,
                "risk_score": str(risk_score),
                "risk_level": risk_level,
            },
        )
        redis.expire(key, TTL_SECONDS)
    except RedisError:
        # Fail open here; analysis can still proceed, but alert path will fail closed if missing.
        return


def fetch_recent_analysis(user_id: str, media_hash: str) -> Optional[dict]:
    try:
        redis = get_redis()
        key = build_hashed_key("media:analysis", user_id, media_hash)
        data = redis.hgetall(key)
        if not data:
            return None
        return {
            "user_id": data.get("user_id"),
            "media_hash": data.get("media_hash"),
            "analysis_type": data.get("analysis_type"),
            "risk_score": int(data.get("risk_score", 0)),
            "risk_level": data.get("risk_level"),
        }
    except RedisError:
        return None
