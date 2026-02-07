from app.services.breach.hibp_provider import HIBPProvider

_provider = None

def get_breach_provider():
    global _provider
    if _provider is None:
        _provider = HIBPProvider()
    return _provider
