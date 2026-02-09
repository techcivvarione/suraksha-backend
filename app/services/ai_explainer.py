import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def generate_ai_explanation(scan_type: str, risk: str, score: int, reasons: list[str]):
    prompt = f"""
You are a cybersecurity assistant.

Explain the scan result clearly for a normal user.

Scan Type: {scan_type}
Risk Level: {risk}
Risk Score: {score}

Detected Signals:
{chr(10).join("- " + r for r in reasons)}

Respond with:
1. What this means
2. What attackers are likely attempting
3. What the user should do next

Keep it concise and practical.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You explain cybersecurity risks clearly without fear-mongering."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content.strip()
