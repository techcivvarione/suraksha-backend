from app.services.breach.hibp_provider import HIBPProvider


def get_breach_provider(user_plan: str):
    """
    Returns a new provider instance per request.
    We do NOT cache globally because plan-based access
    control depends on the current user.
    """
    return HIBPProvider(user_plan=user_plan)
