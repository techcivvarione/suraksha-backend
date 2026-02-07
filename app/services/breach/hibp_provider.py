import hashlib
import os
import requests
from typing import Optional

from app.services.breach.base import BreachProvider

HIBP_EMAIL_API = "https://haveibeenpwned.com/api/v3/breachedaccount"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range"


class HIBPProvider(BreachProvider):
    """
    Have I Been Pwned provider
    Access control (FREE vs PAID) is enforced HERE only.
    """

    def __init__(self, user_plan: str = "FREE"):
        self.api_key = os.getenv("HIBP_API_KEY")
        if not self.api_key:
            raise RuntimeError("HIBP_API_KEY not set")

        self.user_plan = user_plan.upper()

        self.headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "GO-SURAKSHA",
        }

    # ==================================================
    # EMAIL BREACH CHECK (LIVE)
    # ==================================================
    def check_email(self, email: str) -> dict:
        url = f"{HIBP_EMAIL_API}/{email}"

        resp = requests.get(
            url,
            headers=self.headers,
            timeout=8,
        )

        # ---------- NO BREACH ----------
        if resp.status_code == 404:
            return {
                "breached": False,
                "risk": "low",
                "score": 0,
                "count": 0,
                "reasons": ["No known data breaches found for this email"],
            }

        # ---------- RATE LIMITED ----------
        if resp.status_code == 429:
            return {
                "breached": False,
                "risk": "medium",
                "score": 0,
                "count": 0,
                "reasons": ["Breach service temporarily busy. Try again later."],
            }

        if resp.status_code != 200:
            raise RuntimeError("Email breach service unavailable")

        breaches = resp.json()
        count = len(breaches)

        # Extract details (PAID only)
        sites = [b["Name"] for b in breaches]
        domains = [b.get("Domain") for b in breaches if b.get("Domain")]

        response = {
            "breached": True,
            "risk": "high",
            "score": min(100, 40 + count * 10),
            "count": count,
            "reasons": [
                f"Email appeared in {count} known data breaches"
            ],
        }

        # 🔐 ACCESS CONTROL
        if self.user_plan == "PAID":
            response.update({
                "sites": sites,
                "domains": domains,
            })

        return response

    # ==================================================
    # PASSWORD BREACH CHECK (LIVE, K-ANONYMITY)
    # ==================================================
    def check_password(self, password: str) -> dict:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        resp = requests.get(
            f"{HIBP_PASSWORD_API}/{prefix}",
            headers={"user-agent": "GO-SURAKSHA"},
            timeout=8,
        )

        if resp.status_code != 200:
            raise RuntimeError("Password breach service unavailable")

        for line in resp.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return {
                    "breached": True,
                    "risk": "high",
                    "score": 90,
                    "count": int(count),
                    "reasons": [
                        f"Password found in breaches ({count} times)"
                    ],
                }

        return {
            "breached": False,
            "risk": "low",
            "score": 0,
            "count": 0,
            "reasons": ["Password not found in known breaches"],
        }
