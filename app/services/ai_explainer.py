from __future__ import annotations

import json
import re
from collections.abc import Iterable

SUPPORTED_LANGUAGES = {"en", "hi", "te", "ta"}

EXPLANATION_TEMPLATES: dict[str, dict[str, str]] = {
    "en": {
        "HIGH_VERDICT": "⚠️ This is likely a scam. Do not trust this.",
        "MOD_VERDICT": "⚠️ This looks suspicious. Be careful.",
        "LOW_VERDICT": "✅ This looks safe.",
        "ACTION_HIGH": "Do not click, pay, reply, or share details.",
        "ACTION_MOD": "Check with the sender before taking action.",
        "ACTION_LOW": "Still stay alert for anything unusual.",
        "DEFAULT_HIGH_WHY": "It can steal your money or personal details.",
        "DEFAULT_MOD_WHY": "Something does not look right here.",
        "DEFAULT_LOW_WHY": "No major risk was found.",
    },
    "hi": {
        "HIGH_VERDICT": "⚠️ यह धोखाधड़ी हो सकती है। इस पर भरोसा न करें।",
        "MOD_VERDICT": "⚠️ यह संदिग्ध लगता है। सावधान रहें।",
        "LOW_VERDICT": "✅ यह सुरक्षित लगता है।",
        "ACTION_HIGH": "कोई लिंक न खोलें, पैसे न भेजें, जानकारी साझा न करें।",
        "ACTION_MOD": "पहले जांच करें, फिर आगे बढ़ें।",
        "ACTION_LOW": "फिर भी किसी भी अजीब चीज़ पर ध्यान रखें।",
        "DEFAULT_HIGH_WHY": "यह आपका पैसा या निजी जानकारी ले सकता है।",
        "DEFAULT_MOD_WHY": "इस संदेश में कुछ ठीक नहीं लगता।",
        "DEFAULT_LOW_WHY": "कोई बड़ा खतरा नहीं मिला।",
    },
    "te": {
        "HIGH_VERDICT": "⚠️ ఇది మోసం అయ్యే అవకాశం ఉంది. దీనిని నమ్మవద్దు.",
        "MOD_VERDICT": "⚠️ ఇది అనుమానాస్పదంగా ఉంది. జాగ్రత్తగా ఉండండి.",
        "LOW_VERDICT": "✅ ఇది సురక్షితంగా కనిపిస్తోంది.",
        "ACTION_HIGH": "లింక్ నొక్కవద్దు, డబ్బు పంపవద్దు, వివరాలు పంచవద్దు.",
        "ACTION_MOD": "ముందు నిజమా చూడండి. తర్వాత మాత్రమే చర్య తీసుకోండి.",
        "ACTION_LOW": "అయినా కూడా ఏదైనా వింతగా ఉంటే జాగ్రత్తగా ఉండండి.",
        "DEFAULT_HIGH_WHY": "ఇది మీ డబ్బు లేదా వ్యక్తిగత వివరాలు తీసుకోవచ్చు.",
        "DEFAULT_MOD_WHY": "ఈ సందేశంలో ఏదో సరిగా లేదు.",
        "DEFAULT_LOW_WHY": "పెద్ద ప్రమాదం కనిపించలేదు.",
    },
    "ta": {
        "HIGH_VERDICT": "⚠️ இது மோசடியாக இருக்கலாம். இதை நம்பாதீர்கள்.",
        "MOD_VERDICT": "⚠️ இது சந்தேகமாக தெரிகிறது. கவனமாக இருங்கள்.",
        "LOW_VERDICT": "✅ இது பாதுகாப்பாக தெரிகிறது.",
        "ACTION_HIGH": "எந்த இணைப்பையும் திறக்காதீர்கள், பணம் அனுப்பாதீர்கள், தகவல் பகிராதீர்கள்.",
        "ACTION_MOD": "முதலில் சரிபார்க்கவும். பிறகு மட்டும் செயல்படவும்.",
        "ACTION_LOW": "இருந்தாலும் ஏதாவது வித்தியாசமாக இருந்தால் கவனமாக இருங்கள்.",
        "DEFAULT_HIGH_WHY": "இது உங்கள் பணத்தையோ தனிப்பட்ட தகவலையோ திருடலாம்.",
        "DEFAULT_MOD_WHY": "இந்த செய்தியில் ஏதோ சரியாக இல்லை.",
        "DEFAULT_LOW_WHY": "பெரிய ஆபத்து எதுவும் தெரியவில்லை.",
    },
}

SIGNAL_MAP: dict[str, dict[str, str]] = {
    "apk": {
        "en": "It asks you to install an app from a link.",
        "hi": "यह आपको लिंक से ऐप इंस्टॉल करने के लिए कहता है।",
        "te": "ఇది లింక్ నుండి యాప్ ఇన్‌స్టాల్ చేయమని చెబుతోంది.",
        "ta": "இது இணைப்பில் இருந்து செயலியை நிறுவச் சொல்கிறது.",
    },
    "remote_access": {
        "en": "It asks for remote control of your phone.",
        "hi": "यह आपके फोन का दूर से कंट्रोल मांगता है।",
        "te": "ఇది మీ ఫోన్‌ను దూరం నుంచి నియంత్రించమని అడుగుతోంది.",
        "ta": "இது உங்கள் தொலைபேசியை தொலைவிலிருந்து கட்டுப்படுத்தச் சொல்கிறது.",
    },
    "urgency": {
        "en": "It tries to rush you.",
        "hi": "यह आपको जल्दी करने के लिए दबाव डालता है।",
        "te": "ఇది మిమ్మల్ని త్వరపడమని ఒత్తిడి చేస్తోంది.",
        "ta": "இது உங்களை அவசரப்படுத்துகிறது.",
    },
    "bank": {
        "en": "It pretends to be a bank or trusted service.",
        "hi": "यह बैंक या भरोसेमंद सेवा होने का दिखावा करता है।",
        "te": "ఇది బ్యాంక్ లేదా నమ్మకమైన సేవలా నటిస్తోంది.",
        "ta": "இது வங்கி அல்லது நம்பகமான சேவையாக நடிக்கிறது.",
    },
    "otp": {
        "en": "It asks for private details like OTP or PIN.",
        "hi": "यह OTP या PIN जैसी निजी जानकारी मांगता है।",
        "te": "ఇది OTP లేదా PIN వంటి వ్యక్తిగత వివరాలు అడుగుతోంది.",
        "ta": "இது OTP அல்லது PIN போன்ற தனிப்பட்ட தகவலை கேட்கிறது.",
    },
    "kyc": {
        "en": "It uses a fake update request.",
        "hi": "यह नकली अपडेट या सत्यापन मांगता है।",
        "te": "ఇది నకిలీ అప్డేట్ లేదా ధృవీకరణ కోరుతోంది.",
        "ta": "இது போலியான புதுப்பிப்பு அல்லது சரிபார்ப்பை கேட்கிறது.",
    },
    "upi": {
        "en": "It tries to trick a payment approval.",
        "hi": "यह आपसे गलत तरीके से भुगतान मंजूर करवाना चाहता है।",
        "te": "ఇది మీతో తప్పుడు చెల్లింపు ఆమోదం పొందాలని చూస్తోంది.",
        "ta": "இது தவறான பணம் ஒப்புதலைப் பெற முயல்கிறது.",
    },
    "money_panic": {
        "en": "It tries to scare you about money.",
        "hi": "यह पैसे के बारे में डराता है।",
        "te": "ఇది డబ్బు గురించి భయపెడుతోంది.",
        "ta": "இது பணம் பற்றி பயமுறுத்துகிறது.",
    },
    "job": {
        "en": "It looks like a fake job message.",
        "hi": "यह नकली नौकरी वाला संदेश लगता है।",
        "te": "ఇది నకిలీ ఉద్యోగ సందేశంలా ఉంది.",
        "ta": "இது போலியான வேலை செய்தி போல தெரிகிறது.",
    },
    "delivery": {
        "en": "It uses a fake delivery story.",
        "hi": "यह नकली डिलीवरी का बहाना बनाता है।",
        "te": "ఇది నకిలీ డెలివరీ కథను ఉపయోగిస్తోంది.",
        "ta": "இது போலியான டெலிவரி கதையை பயன்படுத்துகிறது.",
    },
    "reward": {
        "en": "It promises money or rewards.",
        "hi": "यह इनाम या पैसे का लालच देता है।",
        "te": "ఇది బహుమతి లేదా డబ్బు ఇస్తామని చెబుతోంది.",
        "ta": "இது பரிசு அல்லது பணம் தருவதாக சொல்லுகிறது.",
    },
    "link": {
        "en": "It pushes you to open a suspicious link.",
        "hi": "यह आपको संदिग्ध लिंक खोलने के लिए कहता है।",
        "te": "ఇది అనుమానాస్పద లింక్ తెరవమని చెబుతోంది.",
        "ta": "இது சந்தேகமான இணைப்பைத் திறக்கச் சொல்கிறது.",
    },
    "generic": {
        "en": "It uses a mass message style.",
        "hi": "यह आम लोगों को भेजे जाने वाले संदेश जैसा है।",
        "te": "ఇది అందరికీ పంపే సాధారణ సందేశంలా ఉంది.",
        "ta": "இது பலருக்கும் அனுப்பும் பொதுவான செய்தி போல உள்ளது.",
    },
}

SIGNAL_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("apk", ("apk", "install app", "install anything", ".apk")),
    ("remote_access", ("remote access", "anydesk", "teamviewer", "rustdesk")),
    ("urgency", ("rush", "urgent", "immediately", "blocked today", "deadline", "update immediately")),
    ("bank", ("bank", "account warning", "card warning", "brand mismatch")),
    ("otp", ("otp", "upi pin", "pin", "sensitive information")),
    ("kyc", ("kyc", "aadhaar", "aadhar", "pan", "update request")),
    ("upi", ("upi", "collect request", "approve payment", "payment approval")),
    ("money_panic", ("payment panic", "money debited", "refund")),
    ("job", ("telegram", "whatsapp", "job")),
    ("delivery", ("delivery", "parcel", "courier")),
    ("reward", ("reward", "prize", "cashback", "lottery")),
    ("link", ("link", "domain", "website")),
    ("generic", ("generic greeting", "dear customer", "mass message")),
)


def generate_simple_explanation(
    risk_level: str,
    signals: list[str],
    language: str = "en",
) -> str:
    language_code = _normalize_language(language)
    templates = EXPLANATION_TEMPLATES[language_code]
    normalized_level = _normalize_risk_level(risk_level)
    simple_reasons = _map_signals_to_simple_lines(signals, language_code)

    if normalized_level == "HIGH":
        verdict = templates["HIGH_VERDICT"]
        why_lines = simple_reasons[:2] or [templates["DEFAULT_HIGH_WHY"]]
        action = templates["ACTION_HIGH"]
    elif normalized_level == "MEDIUM":
        verdict = templates["MOD_VERDICT"]
        why_lines = simple_reasons[:2] or [templates["DEFAULT_MOD_WHY"]]
        action = templates["ACTION_MOD"]
    else:
        verdict = templates["LOW_VERDICT"]
        why_lines = simple_reasons[:1] or [templates["DEFAULT_LOW_WHY"]]
        action = templates["ACTION_LOW"]

    return "\n\n".join([verdict, " ".join(why_lines), action])


def generate_ai_explanation(
    scan_type: str,
    risk: str | None,
    score: int | None,
    reasons: list[str] | str | None,
    text: str | None = None,
    language: str = "en",
) -> str:
    del scan_type, score, text
    return generate_simple_explanation(
        risk_level=risk or "LOW",
        signals=_coerce_signals(reasons),
        language=language,
    )


def _normalize_language(language: str | None) -> str:
    normalized = (language or "en").strip().lower()
    return normalized if normalized in SUPPORTED_LANGUAGES else "en"


def _normalize_risk_level(risk_level: str | None) -> str:
    normalized = (risk_level or "").strip().upper()
    if normalized in {"HIGH", "VERY_HIGH", "CRITICAL"}:
        return "HIGH"
    if normalized in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    return "LOW"


def _coerce_signals(reasons: list[str] | str | None) -> list[str]:
    if reasons is None:
        return []
    if isinstance(reasons, list):
        return [str(item).strip() for item in reasons if str(item).strip()]
    if isinstance(reasons, str):
        raw = reasons.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
        return [raw]
    if isinstance(reasons, Iterable):
        return [str(item).strip() for item in reasons if str(item).strip()]
    return []


def _map_signals_to_simple_lines(signals: list[str], language: str) -> list[str]:
    simple_lines: list[str] = []
    seen: set[str] = set()

    for signal in signals:
        lowered = signal.lower()
        mapped_key = None
        for signal_key, keywords in SIGNAL_PATTERNS:
            if any(_keyword_matches(lowered, keyword) for keyword in keywords):
                mapped_key = signal_key
                break
        sentence = SIGNAL_MAP.get(mapped_key or "", {}).get(language)
        if sentence is None:
            sentence = _fallback_simple_line(lowered, language)
        if sentence and sentence not in seen:
            seen.add(sentence)
            simple_lines.append(sentence)

    return simple_lines


def _fallback_simple_line(lowered_signal: str, language: str) -> str:
    templates = EXPLANATION_TEMPLATES[language]
    if "safe" in lowered_signal or "no major" in lowered_signal:
        return templates["DEFAULT_LOW_WHY"]
    if "suspicious" in lowered_signal or "danger" in lowered_signal:
        return templates["DEFAULT_MOD_WHY"]
    return ""


def _keyword_matches(signal_text: str, keyword: str) -> bool:
    normalized_keyword = keyword.strip().lower()
    if " " in normalized_keyword or "." in normalized_keyword:
        return normalized_keyword in signal_text
    return re.search(rf"\b{re.escape(normalized_keyword)}\b", signal_text) is not None
