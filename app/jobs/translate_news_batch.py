"""
Batch translation job for news.
- NO API calls in request path
- NO FastAPI imports
- SAFE to run via cron
"""

from dotenv import load_dotenv
from pathlib import Path
from typing import List

from app.services.supabase_client import supabase
from app.services.news_translator import translate_batch

# ------------------------
# ENV
# ------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

BATCH_SIZE = 10


# ------------------------
# DB HELPERS
# ------------------------

def fetch_untranslated(lang_code: str) -> List[dict]:
    column = "headline_te" if lang_code == "te" else "headline_hi"

    res = (
        supabase.table("news")
        .select("id, headline, matter")
        .or_(f"{column}.is.null,{column}.eq.")
        .limit(BATCH_SIZE)
        .execute()
    )

    return res.data or []



def update_translations(lang_code: str, translated_rows: List[dict]):
    for row in translated_rows:
        news_id = row.get("id")
        headline = row.get("headline")
        matter = row.get("matter")

        if not news_id or not headline:
            print("⚠️ Skipping invalid translation row:", row)
            continue

        if lang_code == "te":
            updates = {
                "headline_te": headline,
                "matter_te": matter,
            }
        else:
            updates = {
                "headline_hi": headline,
                "matter_hi": matter,
            }

        resp = (
            supabase.table("news")
            .update(updates)
            .eq("id", news_id)
            .execute()
        )

        if not resp.data:
            print(f"⚠️ Update affected 0 rows for id={news_id}")
        else:
            print(f"✅ Updated news id={news_id}")


# ------------------------
# MAIN
# ------------------------

def run():
    print("🚀 News translation batch started")

    for lang in ["te", "hi"]:
        rows = fetch_untranslated(lang)
        if not rows:
            print(f"ℹ️ No untranslated rows for {lang}")
            continue

        translated = translate_batch(rows, lang)

        print(f"DEBUG: translated output ({lang}) =", translated)

        if translated:
            update_translations(lang, translated)
            print(f"✅ {lang.upper()} translated: {len(translated)} items")

    print("🎉 Translation batch completed")


if __name__ == "__main__":
    run()
