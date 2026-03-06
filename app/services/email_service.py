import logging
import os

import resend

logger = logging.getLogger(__name__)

resend.api_key = os.getenv("RESEND_API_KEY")


def send_email(to_email: str, subject: str, html_body: str):
    """
    Send email via Resend. Fails closed to logs without exposing OTP content.
    """
    if not resend.api_key:
        logger.error("RESEND_API_KEY not configured; email not sent.")
        return

    try:
        resend.Emails.send(
            {
                "from": "GoSuraksha <noreply@gosuraksha.com>",
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            }
        )
    except Exception as exc:
        logger.error("Email send failed for %s: %s", to_email, exc)
