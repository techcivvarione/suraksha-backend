import json
import os
from typing import List, Dict
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SUPPORTED_LANGS = {
    "te": "Telugu",
    "hi": "Hindi",
}


def translate_batch(
    items: List[Dict[str, str]],
    lang_code: str,
) -> List[Dict[str, str]]:
    """
    items = [
        {"id": "...", "headline": "...", "matter": "..."},
        ...
    ]

    returns:
    [
        {"id": "...", "headline": "...", "matter": "..."},
        ...
    ]
    """

    if not items:
        return []

    language = SUPPORTED_LANGS.get(lang_code)
    if not language:
        raise ValueError(f"Unsupported language: {lang_code}")

    payload = [
        {
            "id": item["id"],
            "headline": item["headline"],
            "matter": item["matter"],
        }
        for item in items
    ]

    prompt = f"""
Translate the following news items into {language}.

Rules:
- Keep meaning accurate
- Natural {language}
- Do NOT add explanations
- Do NOT add extra text
- Do NOT change keys or structure
- Output STRICT JSON ARRAY only

Expected JSON format:
[
  {{
    "id": "string",
    "headline": "string",
    "matter": "string"
  }}
]

Input:
{json.dumps(payload, ensure_ascii=False)}
"""

    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a professional news translator."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        raw = resp.choices[0].message.content.strip()

        # 🔒 ROBUST JSON EXTRACTION (CRITICAL FIX)
        start = raw.find("[")
        end = raw.rfind("]") + 1

        if start == -1 or end == -1:
            raise ValueError("No valid JSON array found in model response")

        clean_json = raw[start:end]

        parsed = json.loads(clean_json)

        # 🔒 SAFETY CHECK
        if not isinstance(parsed, list):
            raise ValueError("Parsed JSON is not a list")

        return parsed

    except Exception as e:
        print(f"❌ Translation failed for {lang_code}: {e}")
        return []
