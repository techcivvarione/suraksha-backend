import feedparser
import re
from datetime import datetime, timedelta

# In-memory cache
NEWS_CACHE = []
LAST_FETCHED = None

# RSS sources (Phase 2 – stable only)
RSS_SOURCES = [
    {
        "source": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "source": "Google News - Cybersecurity",
        "url": "https://news.google.com/rss/search?q=cybersecurity",
    },
    {
        "source": "Google News - AI",
        "url": "https://news.google.com/rss/search?q=artificial+intelligence",
    }
]

# ---------- helpers ----------

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<.*?>", "", text)   # remove HTML tags
    return text.strip()


def categorize(text: str) -> str:
    text = text.lower()

    if any(k in text for k in ["phishing", "fraud", "scam"]):
        return "Cyber Crime"
    if any(k in text for k in ["malware", "ransomware", "breach"]):
        return "Cyber"
    if any(k in text for k in ["ai", "artificial intelligence", "llm"]):
        return "AI"

    return "Technology"


def point_to_note(category: str) -> str:
    mapping = {
        "Cyber Crime": "Never click unknown links or share OTPs.",
        "Cyber": "Avoid cracked software and untrusted downloads.",
        "AI": "Verify AI tools before installing or granting permissions.",
        "Technology": "Stay updated with trusted technology sources."
    }
    return mapping.get(category, "Stay cautious online.")

# ---------- core ----------

def fetch_news(force: bool = False):
    global NEWS_CACHE, LAST_FETCHED

    # Cache validity: 30 minutes
    if NEWS_CACHE and LAST_FETCHED and not force:
        if datetime.utcnow() - LAST_FETCHED < timedelta(minutes=30):
            return NEWS_CACHE

    news_items = []

    for src in RSS_SOURCES:
        try:
            feed = feedparser.parse(src["url"])

            for entry in feed.entries[:5]:  # limit per source
                title = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                text_blob = f"{title} {summary}"

                category = categorize(text_blob)

                image = None
                if "media_thumbnail" in entry:
                    image = entry.media_thumbnail[0].get("url")

                news_items.append({
                    "source": src["source"],
                    "category": category,
                    "title": title,
                    "summary": summary,
                    "image": image,
                    "published_at": entry.get("published", ""),
                    "point_to_note": point_to_note(category),
                    "link": entry.get("link")
                })

        except Exception:
            # Never crash because of a bad feed
            continue

    NEWS_CACHE = news_items
    LAST_FETCHED = datetime.utcnow()

    return NEWS_CACHE
