"""
Batch job: Generate ~400 character security-focused summaries (English only)

- NO FastAPI imports
- SAFE to run via cron
- CHEAP (batch AI calls)
- Idempotent (can rerun safely)
"""

import os
import json
from pathlib import Path
from typing import List, Dict
from dotenv import load_dotenv
from openai import OpenAI

from app.services.supabase_client import supabase

# ------------------------
# ENV
# ------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

BATCH_SIZE = 5  # keep small for safety & cost


# ------------------------
# DB HELPERS
# ------------------------

def fetch_without_summary() -> List[Dict]:
    res = (
        supabase.table("news")
        .select("id, headline, matter")
        .is_("summary_400", None)
        .limit(BATCH_SIZE)
        .execute()
    )
    return res.data or []


def update_summary(rows: List[Dict]):
    for row in rows:
        supabase.table("news") \
            .update({"summary_400": row["summary_400"]}) \
            .eq("id", row["id"]) \
            .execute()


# ------------------------
# AI SUMMARIZATION
# ------------------------

def summarize_batch(items: List[Dict]) -> List[Dict]:
    if not items:
        return []

    payload = [
        {
            "id": i["id"],
            "headline": i["headline"],
            "matter": i["matter"],
        }
        for i in items
    ]

    prompt = f"""
You are a cybersecurity analyst.

Task:
Summarize each news item into a concise, security-focused summary.

Rules:
- Focus on risk, impact, and why it matters
- Neutral professional tone
- Maximum ~400 characters
- No HTML
- No links
- No emojis
- Output STRICT JSON ARRAY ONLY

Expected JSON format:
[
  {{
    "id": "string",
    "summary_400": "string"
  }}
]

Input:
{json.dumps(payload, ensure_ascii=False)}
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You write concise cybersecurity risk summaries."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )

    raw = resp.choices[0].message.content.strip()

    # ---- robust JSON extraction ----
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == -1:
        raise ValueError("Invalid JSON from model")

    return json.loads(raw[start:end])


# ------------------------
# MAIN
# ------------------------

def run():
    print("🚀 Summary_400 batch started")

    rows = fetch_without_summary()
    if not rows:
        print("ℹ️ No rows pending summary")
        return

    summarized = summarize_batch(rows)

    if summarized:
        update_summary(summarized)
        print(f"✅ Summarized {len(summarized)} items")

    print("🎉 Summary_400 batch completed")


if __name__ == "__main__":
    run()
