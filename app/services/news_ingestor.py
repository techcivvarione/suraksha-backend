import logging
import feedparser
import hashlib
from datetime import datetime

from app.services.supabase_client import get_supabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def ingest_rss():
    logging.info("🚀 RSS ingestion started")

    # ✅ FIX 1: define supabase at FUNCTION LEVEL
    supabase = None

    try:
        supabase = get_supabase()
    except Exception as e:
        logging.error(f"Supabase init failed: {e}")
        return

    if supabase is None:
        logging.error("Supabase client is None")
        return

    RSS_SOURCES = {
        "The Hacker News": ("https://feeds.feedburner.com/TheHackersNews", "Cyber"),
        "SecurityWeek": ("https://www.securityweek.com/rss", "Cyber"),
        "Help Net Security": ("https://www.helpnetsecurity.com/feed/", "Cyber"),
        "Security Affairs": ("https://securityaffairs.com/feed", "Cyber"),
        "WeLiveSecurity": ("https://www.welivesecurity.com/en/rss/feed/", "Cyber"),
        "Sophos News": ("https://news.sophos.com/en-us/feed/", "Cyber"),
        "Google Online Security": ("http://feeds.feedburner.com/GoogleOnlineSecurityBlog", "Cyber"),

        "MIT Technology Review": ("https://www.technologyreview.com/feed/", "AI"),
        "OpenAI Blog": ("https://openai.com/blog/rss/", "AI"),
        "The Register Security": ("https://www.theregister.com/security/headlines.atom", "Tech"),

        "CERT-In Advisories": ("https://www.cert-in.org.in/rss/all.xml", "Govt"),
        "CISA Advisories": ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "Govt"),
        "MeitY Press Releases": ("https://www.meity.gov.in/press-releases/rss.xml", "Govt"),
        "UIDAI Updates": ("https://uidai.gov.in/rss.xml", "Govt"),
        "RBI Press Releases": ("https://rbi.org.in/Scripts/Rss.aspx", "Govt"),
        "PIB Digital India": ("https://pib.gov.in/rss.aspx?ministry_id=31", "Govt"),
    }

    inserted = 0

    for source, (url, category) in RSS_SOURCES.items():
        try:
            feed = feedparser.parse(url)

            if not feed.entries:
                logging.warning(f"No entries from {source}")
                continue

            for entry in feed.entries[:10]:
                title = entry.get("title", "").strip()
                summary = (
                    entry.get("summary")
                    or entry.get("description")
                    or ""
                ).strip()
                link = entry.get("link", "")

                if not title:
                    continue

                fingerprint = hashlib.sha256(
                    (title + link).encode("utf-8")
                ).hexdigest()

                exists = (
                    supabase
                    .table("news")
                    .select("id")
                    .eq("fingerprint", fingerprint)
                    .execute()
                )

                if exists.data:
                    continue

                impact = "HIGH" if category in ["Cyber", "Govt"] else "MEDIUM"
                actions = "Stay alert. Follow official advisories. Do not click unknown links."

                supabase.table("news").insert({
                    "source": source,
                    "category": category,
                    "headline": title,
                    "matter": summary,
                    "impact": impact,
                    "actions": actions,
                    "fingerprint": fingerprint,
                    "published_at": datetime.utcnow().isoformat(),
                }).execute()

                inserted += 1

        except Exception as e:
            logging.error(f"RSS failed for {source}: {e}")
            continue

    logging.info(f"✅ RSS ingestion completed | inserted={inserted}")
