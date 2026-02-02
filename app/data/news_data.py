from datetime import datetime

CYBER_NEWS = [
    {
        "id": 1,
        "title": "Fake SBI KYC Messages Circulating",
        "summary": "Messages claiming SBI account will be blocked and asking users to update KYC via links are circulating.",
        "affected_users": "SBI customers",
        "what_to_do": [
            "Do not click any links",
            "SBI never sends KYC links via WhatsApp or SMS",
            "Report such messages to 1930"
        ],
        "severity": "high",
        "date": datetime.utcnow().isoformat()
    },
    {
        "id": 2,
        "title": "Fake Delivery SMS Scam",
        "summary": "Scammers are sending SMS claiming undelivered parcels with malicious links.",
        "affected_users": "Online shoppers",
        "what_to_do": [
            "Do not click unknown delivery links",
            "Check order status only in official apps",
            "Block and report the sender"
        ],
        "severity": "medium",
        "date": datetime.utcnow().isoformat()
    }
]
