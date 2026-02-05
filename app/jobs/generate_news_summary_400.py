"""
Batch job: Generate ~400 character security-focused summaries (English only)

- SAFE to run via cron
- Idempotent
- Handles NULL + empty summaries
"""

import os
import json
from pathlib import Path
from typing import List, Dict

from dotenv import load_dotenv
from openai import OpenAI

from app.services.supabase_client import get_supabase

# ------------------------
# ENV
# ------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

BATCH_SIZE = 5

supabase = get_supabase()

# ------------------------
# DB HELPERS
# ------------------------

def fetch_without_summary() -> List[Dict]:
    """
    Fetch rows where summary_400 is NULL OR empty string
    """
    res = (
        supabase
        .table("news")
        .select("id, headline, matter")
        .or_("summary_400.is.null,summary_400.eq.")
        .limit(BATCH_SIZE)
        .execute()
    )
    return res.data or []


def update_summary(rows: List[Dict]):
    for row in rows:
        summary = row.get("summary_400", "").strip()
        if not row.get("id") or not summary:
            continue

        supabase.table("news") \
            .update({"summary_400": summary}) \
            .eq("id", row["id"]) \
            .execute()


# ------------------------
# AI SUMMARIZATION
# ------------------------

def summarize_batch(items: List[Dict]) -> List[Dict]:
    if not items:
        return []

    payload = []

    for i in items:
        text = (i.get("matter") or i.get("headline") or "").strip()
        if not text:
            continue

        payload.append({
            "id": i["id"],
            "text": text
        })

    if not payload:
        return []

    prompt = f"""
You are a cybersecurity analyst.

Task:
Summarize each item into a concise security-focused summary.

Rules:
- Focus on risk, impact, and why it matters
- Neutral professional tone
- Max ~400 characters
- No HTML, no links, no emojis
- Output STRICT JSON ARRAY ONLY

Format:
[
  {{
    "id": "string",
    "summary_400": "string"
  }}
]

Input:
{json.dumps(payload, ensure_ascii=False)}
"""

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You write concise cybersecurity risk summaries."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        raw = resp.choices[0].message.content.strip()

        start = raw.find("[")
        end = raw.rfind("]") + 1

        if start == -1 or end == -1:
            raise ValueError("No JSON array found")

        parsed = json.loads(raw[start:end])

        if not isinstance(parsed, list):
            raise ValueError("Output is not a list")

        return parsed

    except Exception as e:
        print(f"❌ Summary generation failed: {e}")
        return []


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
