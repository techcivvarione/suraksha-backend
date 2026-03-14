from __future__ import annotations

import logging

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
    logger.info("scam_network_schema_managed_by_migrations")
