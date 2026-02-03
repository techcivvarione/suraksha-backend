import feedparser
from datetime import datetime
from app.db import supabase

RSS_SOURCES = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss_simple.asp",
}

def categorize(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["scam", "fraud", "phishing", "upi"]):
        return "Scam"
    if any(k in t for k in ["malware", "ransomware", "trojan"]):
        return "Malware"
    if any(k in t for k in ["breach", "leak", "exposed"]):
        return "Data Breach"
    if any(k in t for k in ["alert", "advisory", "cert"]):
        return "Government Alert"
    return "Awareness"

def impact_level(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["bank", "upi", "credential", "password"]):
        return "HIGH"
    if any(k in t for k in ["update", "patch"]):
        return "MEDIUM"
    return "LOW"

ACTIONS = {
    "Scam": [
        "Do not click unknown links",
        "Block the sender",
        "Report to 1930 or cybercrime.gov.in"
    ],
    "Malware": [
        "Update your device",
        "Run antivirus scan",
        "Avoid unknown downloads"
    ],
    "Data Breach": [
        "Change passwords immediately",
        "Enable 2FA",
        "Monitor account activity"
    ],
    "Government Alert": [
        "Follow official advisory",
        "Apply recommended actions"
    ],
    "Awareness": [
        "Stay alert online",
        "Follow cyber safety best practices"
    ]
}

def ingest_news():
    for source, url in RSS_SOURCES.items():
        feed = feedparser.parse(url)

        for entry in feed.entries[:10]:
            link = entry.get("link")
            if not link:
                continue

            # Skip duplicates
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

            # Insert raw news
            supabase.table("raw_news").insert({
                "source": source,
                "title": title,
                "summary": summary,
                "link": link,
                "published_at": published_at
            }).execute()

            text = f"{title} {summary}"
            category = categorize(text)
            impact = impact_level(text)

            # Insert processed news
            supabase.table("news").insert({
                "headline": title,
                "matter": summary[:500],
                "category": category,
                "impact": impact,
                "actions": ACTIONS[category],
                "source": source,
                "published_at": published_at
            }).execute()
