import os
import time
import feedparser
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI
from app.db import supabase

# ------------------------------------------------------------------
# ENV
# ------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ------------------------------------------------------------------
# CACHE (translations)
# ------------------------------------------------------------------
_TRANSLATION_CACHE = {}
_CACHE_TTL = 60 * 60  # 1 hour


def _cache_key(lang: str):
    return f"news::{lang}"


def _is_cache_valid(entry):
    return entry and (time.time() - entry["ts"] < _CACHE_TTL)


# ------------------------------------------------------------------
# FEED PRIORITY & CAPS
# ------------------------------------------------------------------

# Tier-1 = highest trust / importance
TIER_1_FEEDS = {
    "The Hacker News",
    "BleepingComputer",
    "Krebs on Security",
    "CISA Advisories",
    "CERT-In",
    "Google Online Security",
}

# Tier-2 = strong signal
TIER_2_FEEDS = {
    "Dark Reading",
    "SecurityWeek",
    "Help Net Security",
    "Security Affairs",
    "The Register - Security",
    "Sophos News",
    "WeLiveSecurity",
}

# Tier-3 = awareness / AI / builders
TIER_3_FEEDS = {
    "OpenAI Blog",
    "Google DeepMind",
    "Microsoft AI Blog",
    "Anthropic",
    "Meta AI",
    "Hugging Face",
    "Y Combinator",
    "Indie Hackers",
    "HackerNoon",
    "Stripe Blog",
    "GitHub Engineering",
    "MeitY India",
    "RBI Press Releases",
    "PIB India Tech",
}

# Per-source caps
SOURCE_CAPS = {
    "DEFAULT": 2,
    "The Hacker News": 5,
    "BleepingComputer": 4,
    "CISA Advisories": 5,
    "CERT-In": 5,
}

# ------------------------------------------------------------------
# RSS SOURCES
# ------------------------------------------------------------------
RSS_SOURCES = {
    # Security
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss_simple.asp",
    "SecurityWeek": "https://www.securityweek.com/rss",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",
    "Security Affairs": "https://securityaffairs.com/feed",
    "The Register - Security": "https://www.theregister.com/security/headlines.atom",
    "WeLiveSecurity": "https://www.welivesecurity.com/en/rss/feed/",
    "Sophos News": "https://news.sophos.com/en-us/feed/",
    "Google Online Security": "http://feeds.feedburner.com/GoogleOnlineSecurityBlog",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",

    # AI / Builders / India
    "OpenAI Blog": "https://openai.com/blog/rss/",
    "Google DeepMind": "https://deepmind.google/blog/rss.xml",
    "Microsoft AI Blog": "https://www.microsoft.com/en-us/ai/blog/feed/",
    "Anthropic": "https://www.anthropic.com/rss.xml",
    "Meta AI": "https://ai.facebook.com/blog/rss/",
    "Hugging Face": "https://huggingface.co/blog/feed.xml",
    "Y Combinator": "https://www.ycombinator.com/blog/rss",
    "Indie Hackers": "https://www.indiehackers.com/feed.xml",
    "HackerNoon": "https://hackernoon.com/feed",
    "Stripe Blog": "https://stripe.com/blog/feed.rss",
    "GitHub Engineering": "https://github.blog/engineering/feed/",
    "MeitY India": "https://www.meity.gov.in/rss.xml",
    "CERT-In": "https://www.cert-in.org.in/Feeds/rss.xml",
    "RBI Press Releases": "https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=RSS",
    "PIB India Tech": "https://pib.gov.in/rssfeed.aspx?catid=108",
}

# ------------------------------------------------------------------
# CLASSIFICATION
# ------------------------------------------------------------------
def categorize(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["scam", "fraud", "phishing", "upi"]):
        return "Scam"
    if any(k in t for k in ["malware", "ransomware", "trojan"]):
        return "Malware"
    if any(k in t for k in ["breach", "leak", "exposed"]):
        return "Data Breach"
    if any(k in t for k in ["cert", "cisa", "alert", "advisory"]):
        return "Government Alert"
    if "ai" in t or "artificial intelligence" in t:
        return "AI"
    return "Awareness"


def impact_level(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["bank", "upi", "credential", "password"]):
        return "HIGH"
    if any(k in t for k in ["patch", "update", "advisory"]):
        return "MEDIUM"
    return "LOW"


ACTIONS = {
    "Scam": ["Do not click unknown links", "Report to 1930"],
    "Malware": ["Update device", "Run antivirus"],
    "Data Breach": ["Change passwords", "Enable 2FA"],
    "Government Alert": ["Follow official advisory"],
    "AI": ["Verify AI tools before use"],
    "Awareness": ["Stay alert online"],
}

# ------------------------------------------------------------------
# INGEST (PRIORITY + CAPS)
# ------------------------------------------------------------------
def ingest_news():
    ordered_sources = (
        [s for s in RSS_SOURCES if s in TIER_1_FEEDS] +
        [s for s in RSS_SOURCES if s in TIER_2_FEEDS] +
        [s for s in RSS_SOURCES if s in TIER_3_FEEDS]
    )

    for source in ordered_sources:
        url = RSS_SOURCES[source]
        feed = feedparser.parse(url)

        cap = SOURCE_CAPS.get(source, SOURCE_CAPS["DEFAULT"])
        count = 0

        for entry in feed.entries:
            if count >= cap:
                break

            link = entry.get("link")
            if not link:
                continue

            exists = supabase.table("raw_news") \
                .select("id") \
                .eq("link", link) \
                .execute()

            if exists.data:
                continue

            title = entry.get("title", "").strip()
            summary = entry.get("summary", "").strip()
            published = entry.get("published_parsed")

            published_at = (
                datetime(*published[:6]).isoformat()
                if published else None
            )

            text = f"{title} {summary}"
            category = categorize(text)
            impact = impact_level(text)

            supabase.table("news").insert({
                "headline": title,
                "matter": summary[:500],
                "category": category,
                "impact": impact,
                "actions": ACTIONS.get(category, ACTIONS["Awareness"]),
                "source": source,
                "published_at": published_at
            }).execute()

            count += 1

# ------------------------------------------------------------------
# READ API (FEATURED / TRENDING)
# ------------------------------------------------------------------
def get_news_with_language(lang: str = "en"):
    base_news = _fetch_news()
    if lang == "en":
        return base_news
    return _translate_with_cache(base_news, lang)


def _fetch_news():
    resp = supabase.table("news") \
        .select("*") \
        .order("published_at", desc=True) \
        .limit(60) \
        .execute()

    now = datetime.utcnow()
    items = []

    for n in resp.data or []:
        published = (
            datetime.fromisoformat(n["published_at"])
            if n.get("published_at") else None
        )

        is_trending = (
            published and
            now - published < timedelta(hours=24) and
            n["impact"] in ["HIGH", "MEDIUM"]
        )

        is_featured = (
            n["impact"] == "HIGH" or
            n["category"] == "Government Alert" or
            n["source"] in TIER_1_FEEDS
        )

        items.append({
            "source": n["source"],
            "category": n["category"],
            "title": n["headline"],
            "summary": n["matter"],
            "published_at": n["published_at"],
            "point_to_note": n["actions"][0] if n.get("actions") else "",
            "is_trending": is_trending,
            "is_featured": is_featured,
            "link": ""
        })

    return items


def _translate_with_cache(news_items, lang):
    cache = _TRANSLATION_CACHE.get(_cache_key(lang))
    if _is_cache_valid(cache):
        return cache["data"]

    translated = []
    for item in news_items:
        t = item.copy()
        t["title"] = _translate_text(item["title"], lang)
        t["summary"] = _translate_text(item["summary"], lang)
        t["point_to_note"] = _translate_text(item["point_to_note"], lang)
        translated.append(t)

    _TRANSLATION_CACHE[_cache_key(lang)] = {
        "data": translated,
        "ts": time.time()
    }
    return translated


def _translate_text(text: str, lang: str) -> str:
    if not text.strip():
        return text
    try:
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": f"Translate to {lang}. Keep it simple."},
                {"role": "user", "content": text},
            ],
            temperature=0.2,
        )
        return res.choices[0].message.content.strip()
    except Exception:
        return text
