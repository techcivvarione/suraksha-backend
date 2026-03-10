from typing import Dict, Any

from app.services.breach.manager import check_email_breach

from .base import EmailBreachProvider


class ExistingBreachManagerProvider(EmailBreachProvider):
    def __init__(self, user_plan: str = "FREE"):
        self.user_plan = user_plan

    def lookup(self, email: str) -> Dict[str, Any]:
        res = check_email_breach(email, self.user_plan)
        breaches = res.get("breaches") or []
        count = res.get("count", len(breaches) if res.get("breached") else 0)
        latest_year = None
        sources = []
        for breach in breaches:
            date = breach.get("breach_date") or breach.get("BreachDate")
            if date:
                try:
                    yr = int(str(date)[:4])
                    latest_year = max(latest_year or yr, yr)
                except Exception:
                    pass
            name = breach.get("name") or breach.get("Name")
            if name:
                sources.append(name)
        return {
            "breach_count": count,
            "latest_year": latest_year,
            "sources": sources or None,
        }
