from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import engine
from app.models.attack_location import AttackLocation
from app.models.phishing_link import PhishingLink
from app.models.scam_category import ScamCategory
from app.models.scam_number import ScamNumber

logger = logging.getLogger(__name__)


CATEGORY_SEEDS = [
    ("11111111-1111-1111-1111-111111111111", "otp_fraud", "OTP Fraud", "Suspicious OTP or verification request patterns"),
    ("22222222-2222-2222-2222-222222222222", "fake_bank_kyc", "Fake Bank KYC", "Bank impersonation and fake KYC update requests"),
    ("33333333-3333-3333-3333-333333333333", "courier_scam", "Courier Scam", "Fake courier, parcel, and customs scam requests"),
    ("44444444-4444-4444-4444-444444444444", "loan_scam", "Loan Scam", "Fraudulent instant loan and credit app campaigns"),
    ("55555555-5555-5555-5555-555555555555", "job_scam", "Job Scam", "Fake job offer and employment scams"),
    ("66666666-6666-6666-6666-666666666666", "upi_payment_request", "UPI Payment Request", "Suspicious collect request or payment approval scams"),
    ("77777777-7777-7777-7777-777777777777", "phishing_link", "Phishing Link", "Reported suspicious links and fake login pages"),
]


def ensure_scam_network_tables() -> None:
    try:
        with engine.begin() as conn:
            for statement in [
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS report_type TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS category TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS scam_phone_number TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS normalized_phone_number TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS phishing_url TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS normalized_url TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS payment_handle TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS payment_provider TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS scam_description TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS report_hash TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS city TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS state TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS country TEXT",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'REPORTED'",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS visibility_status TEXT DEFAULT 'SUSPICIOUS'",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now()",
                "ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now()",
            ]:
                conn.execute(text(statement))
            conn.execute(text("UPDATE scam_reports SET created_at = COALESCE(created_at, reported_at, now()), updated_at = COALESCE(updated_at, reported_at, now()), scam_description = COALESCE(scam_description, description), status = COALESCE(status, 'REPORTED'), visibility_status = COALESCE(visibility_status, 'SUSPICIOUS')"))

        ScamNumber.__table__.create(bind=engine, checkfirst=True)
        PhishingLink.__table__.create(bind=engine, checkfirst=True)
        AttackLocation.__table__.create(bind=engine, checkfirst=True)
        ScamCategory.__table__.create(bind=engine, checkfirst=True)
        with engine.begin() as conn:
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_scam_reports_phone_created ON scam_reports (normalized_phone_number, created_at)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_scam_reports_url_created ON scam_reports (normalized_url, created_at)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_scam_reports_state_country_created ON scam_reports (state, country, created_at)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS ix_attack_locations_window_geohash ON attack_locations (time_window, geohash)'))
            for category_id, slug, name, description in CATEGORY_SEEDS:
                conn.execute(
                    text(
                        "INSERT INTO scam_categories (id, slug, name, description) VALUES (CAST(:id AS uuid), :slug, :name, :description) ON CONFLICT (slug) DO NOTHING"
                    ),
                    {'id': category_id, 'slug': slug, 'name': name, 'description': description},
                )
    except SQLAlchemyError:
        logger.exception('scam_network_schema_ensure_failed')
