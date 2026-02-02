import feedparser
from datetime import datetime

NEWS_CACHE = []
LAST_FETCHED = None


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


def fetch_news():
    global NEWS_CACHE, LAST_FETCHED

    news_items = []

    for src in RSS_SOURCES:
        feed = feedparser.parse(src["url"])

        for entry in feed.entries[:10]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            text_blob = f"{title} {summary}"

            category = categorize(text_blob)

            news_items.append({
                "source": src["source"],
                "category": category,
                "title": title,
                "summary": summary,
                "image": entry.get("media_thumbnail", [{}])[0].get("url"),
                "published_at": entry.get("published", ""),
                "point_to_note": point_to_note(category),
                "link": entry.get("link")
            })

    NEWS_CACHE = news_items
    LAST_FETCHED = datetime.utcnow()

    return NEWS_CACHE
