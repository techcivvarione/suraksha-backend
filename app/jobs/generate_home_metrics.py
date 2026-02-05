"""
Background job to generate Home intelligence:
- Global / India / State-level Threat Pulse
- Global / India Financial Impact

SAFE DESIGN:
- No FastAPI imports
- No startup hooks
- One failure ≠ total failure
- Inserts only validated JSON
"""

import os
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from dotenv import load_dotenv
from pathlib import Path

from supabase import create_client
from openai import OpenAI


# ------------------------
# ENV & LOGGING
# ------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Supabase env vars missing")

if not OPENAI_API_KEY:
    raise RuntimeError("OpenAI API key missing")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
openai = OpenAI(api_key=OPENAI_API_KEY)


# ------------------------
# CONFIG
# ------------------------

INDIAN_STATES = [
    "IN-TG",  # Telangana
    "IN-KA",  # Karnataka
    "IN-MH",  # Maharashtra
    "IN-TN",  # Tamil Nadu
    "IN-DL",  # Delhi
]

THREAT_VALIDITY = {
    "global": timedelta(hours=12),
    "india": timedelta(hours=6),
    "region": timedelta(hours=24),
}

FINANCIAL_VALIDITY = timedelta(days=30)


# ------------------------
# AI HELPERS
# ------------------------

def call_ai(prompt: str) -> Optional[Dict[str, Any]]:
    try:
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity intelligence analyst. "
                        "Be conservative, factual, and avoid exaggeration. "
                        "If data is insufficient, say so explicitly. "
                        "Output STRICT JSON only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        content = resp.choices[0].message.content
        return json.loads(content)

    except Exception as e:
        logging.error(f"AI call failed: {e}")
        return None


# ------------------------
# METRIC GENERATORS
# ------------------------

def generate_threat_pulse(scope: str, region_code: Optional[str]) -> Optional[Dict[str, Any]]:
    if scope == "global":
        sources = [
            "IBM X-Force",
            "Verizon DBIR",
            "Microsoft Digital Defense",
            "ENISA",
            "Kaspersky",
            "WEF",
        ]
        context = "global"

    elif scope == "india":
        sources = [
            "CERT-In",
            "RBI",
            "NPCI",
            "UIDAI",
            "NCRB",
            "IBM X-Force",
        ]
        context = "India-wide"

    else:
        sources = [
            "CERT-In",
            "State Police Advisories",
            "RBI Fraud Alerts",
        ]
        context = f"Indian state {region_code}"

    prompt = f"""
Based on authoritative cybersecurity sources: {", ".join(sources)}

Generate a {context} cyber threat pulse for the last 24 hours.

Rules:
- Do NOT invent numbers
- Use conservative estimates
- If exact data is unavailable, use null
- Output STRICT JSON

JSON format:
{{
  "threat_level": "Low | Medium | High",
  "estimated_incidents_last_24h": number or null,
  "top_attack_vectors": [string],
  "summary": string
}}
"""

    payload = call_ai(prompt)
    if not payload:
        return None

    return {
        "scope": scope,
        "region_code": region_code,
        "metric_type": "threat_pulse",
        "payload": payload,
        "sources": sources,
        "confidence": "medium",
        "valid_until": datetime.now(tz=timezone.utc) + THREAT_VALIDITY[scope],
    }


def generate_financial_impact(scope: str) -> Optional[Dict[str, Any]]:
    if scope == "global":
        sources = [
            "Cybersecurity Ventures",
            "IBM Cost of Data Breach",
            "Accenture",
            "WEF",
            "Verizon DBIR",
        ]
        context = "global"

    else:
        sources = [
            "RBI",
            "CERT-In",
            "NCRB",
            "Cybersecurity Ventures",
            "Accenture",
        ]
        context = "India"

    prompt = f"""
Based on cybersecurity economic reports from: {", ".join(sources)}

Generate a {context} financial impact summary for cybercrime.

Rules:
- Use existing industry projections
- Do NOT exaggerate
- Output STRICT JSON

JSON format:
{{
  "year": number,
  "estimated_loss_usd": number,
  "display_text": string,
  "trend": "Increasing | Stable | Decreasing"
}}
"""

    payload = call_ai(prompt)
    if not payload:
        return None

    return {
        "scope": scope,
        "region_code": "IN" if scope == "india" else None,
        "metric_type": "financial_impact",
        "payload": payload,
        "sources": sources,
        "confidence": "high",
        "valid_until": datetime.now(tz=timezone.utc) + FINANCIAL_VALIDITY,
    }


# ------------------------
# DB INSERT
# ------------------------

def insert_metric(row: Dict[str, Any]):
    try:
        supabase.table("home_metrics").insert({
            "scope": row["scope"],
            "region_code": row["region_code"],
            "metric_type": row["metric_type"],
            "payload": row["payload"],
            "sources": row["sources"],
            "confidence": row["confidence"],
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "valid_until": row["valid_until"].isoformat(),
        }).execute()

        logging.info(
            f"Inserted {row['metric_type']} | scope={row['scope']} | region={row['region_code']}"
        )

    except Exception as e:
        logging.error(f"DB insert failed: {e}")


# ------------------------
# MAIN EXECUTION
# ------------------------

def main():
    logging.info("🚀 Home metrics generation started")

    # --- Threat Pulse ---
    for scope, region in [
        ("global", None),
        ("india", "IN"),
    ]:
        row = generate_threat_pulse(scope, region)
        if row:
            insert_metric(row)

    for state in INDIAN_STATES:
        row = generate_threat_pulse("region", state)
        if row:
            insert_metric(row)

    # --- Financial Impact ---
    for scope in ["global", "india"]:
        row = generate_financial_impact(scope)
        if row:
            insert_metric(row)

    logging.info("✅ Home metrics generation completed")


if __name__ == "__main__":
    main()
