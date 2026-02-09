import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging

logger = logging.getLogger(__name__)


def send_email(to_email: str, subject: str, html_body: str):
    """
    Send an HTML email using Gmail SMTP (TLS).
    This function MUST NOT crash the app.
    """

    try:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", 587))
        smtp_user = os.getenv("SMTP_USERNAME")
        smtp_pass = os.getenv("SMTP_PASSWORD")

        from_name = os.getenv("EMAIL_FROM_NAME")
        from_email = os.getenv("EMAIL_FROM_ADDRESS")

        if not all([smtp_host, smtp_user, smtp_pass, from_email]):
            logger.error("SMTP configuration incomplete. Email not sent.")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to_email

        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, to_email, msg.as_string())

        logger.info(f"Email sent to {to_email}")

    except Exception as e:
        logger.error(f"Email send failed to {to_email}: {e}")
