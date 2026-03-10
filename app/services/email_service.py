import logging
import os

import resend
from textwrap import dedent

logger = logging.getLogger(__name__)

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL", "GoSuraksha <noreply@gosuraksha.com>")

resend.api_key = RESEND_API_KEY


def send_email(to_email: str, subject: str, html_body: str):
    """
    Send email via Resend. Fails closed to logs without exposing OTP content.
    """
    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not configured; email not sent.")
        return

    try:
        resend.Emails.send(
            {
                "from": RESEND_FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            }
        )
    except Exception as exc:
        logger.error("Email send failed for %s: %s", to_email, exc)


def send_otp_email(email: str, otp: str):
    """
    Send a branded OTP email. Does not log OTP value.
    """
    html = dedent(
        f"""
        <div style="font-family: Arial, sans-serif; background:#f7f9fb; padding:24px;">
          <div style="max-width:480px; margin:0 auto; background:#ffffff; border-radius:12px; padding:24px; box-shadow:0 8px 24px rgba(0,0,0,0.06);">
            <h2 style="margin:0 0 12px; color:#0f172a;">GO Suraksha Security</h2>
            <p style="margin:0 0 16px; color:#334155; font-size:15px;">Your verification code is:</p>
            <div style="font-size:28px; font-weight:700; letter-spacing:6px; color:#0f172a; text-align:center; padding:16px 0; background:#f1f5f9; border-radius:10px;">{otp}</div>
            <p style="margin:16px 0 8px; color:#334155; font-size:14px;">This code expires in 10 minutes.</p>
            <p style="margin:0 0 12px; color:#ef4444; font-size:13px; font-weight:600;">Never share this code with anyone.</p>
            <p style="margin:0 0 8px; color:#94a3b8; font-size:12px;">This email was sent by GO Suraksha Security System.</p>
            <p style="margin:0; color:#94a3b8; font-size:12px;">If you did not request this code, ignore this email.</p>
          </div>
        </div>
        """
    )
    send_email(email, "Your GO Suraksha verification code", html)
