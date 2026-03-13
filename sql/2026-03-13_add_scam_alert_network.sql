ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS report_type TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS category TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS scam_phone_number TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS normalized_phone_number TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS phishing_url TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS normalized_url TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS payment_handle TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS payment_provider TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS scam_description TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS report_hash TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS state TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'REPORTED';
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS visibility_status TEXT DEFAULT 'SUSPICIOUS';
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();
ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

UPDATE scam_reports
SET report_type = COALESCE(report_type, LOWER(COALESCE(scam_type, 'link'))),
    category = COALESCE(category, LOWER(REPLACE(COALESCE(scam_type, 'unknown'), ' ', '_'))),
    scam_description = COALESCE(scam_description, description),
    created_at = COALESCE(created_at, reported_at, now()),
    updated_at = COALESCE(updated_at, reported_at, now()),
    status = COALESCE(status, 'REPORTED'),
    visibility_status = COALESCE(visibility_status, 'SUSPICIOUS');

CREATE TABLE IF NOT EXISTS scam_numbers (
    id UUID PRIMARY KEY,
    normalized_phone_number TEXT UNIQUE NOT NULL,
    display_phone_number TEXT,
    report_count_24h INTEGER NOT NULL DEFAULT 0,
    report_count_7d INTEGER NOT NULL DEFAULT 0,
    report_count_30d INTEGER NOT NULL DEFAULT 0,
    first_reported_at TIMESTAMPTZ,
    last_reported_at TIMESTAMPTZ,
    risk_level TEXT NOT NULL DEFAULT 'low',
    status TEXT NOT NULL DEFAULT 'REPORTED_PATTERN',
    top_category TEXT,
    top_regions JSONB,
    latest_alert_event_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS phishing_links (
    id UUID PRIMARY KEY,
    normalized_url TEXT UNIQUE NOT NULL,
    domain TEXT NOT NULL,
    report_count_24h INTEGER NOT NULL DEFAULT 0,
    report_count_7d INTEGER NOT NULL DEFAULT 0,
    report_count_30d INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'REPORTED_PATTERN',
    risk_level TEXT NOT NULL DEFAULT 'low',
    first_reported_at TIMESTAMPTZ,
    last_reported_at TIMESTAMPTZ,
    latest_alert_event_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_locations (
    id UUID PRIMARY KEY,
    geohash TEXT NOT NULL,
    latitude_center DOUBLE PRECISION NOT NULL,
    longitude_center DOUBLE PRECISION NOT NULL,
    city TEXT,
    state TEXT,
    country TEXT,
    time_window TEXT NOT NULL,
    report_count INTEGER NOT NULL DEFAULT 0,
    last_aggregated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scam_categories (
    id UUID PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scam_reports_phone_created ON scam_reports(normalized_phone_number, created_at);
CREATE INDEX IF NOT EXISTS ix_scam_reports_url_created ON scam_reports(normalized_url, created_at);
CREATE INDEX IF NOT EXISTS ix_scam_reports_state_country_created ON scam_reports(state, country, created_at);
CREATE INDEX IF NOT EXISTS ix_scam_numbers_phone ON scam_numbers(normalized_phone_number);
CREATE INDEX IF NOT EXISTS ix_phishing_links_url ON phishing_links(normalized_url);
CREATE INDEX IF NOT EXISTS ix_attack_locations_window_geohash ON attack_locations(time_window, geohash);

INSERT INTO scam_categories (id, slug, name, description) VALUES
('11111111-1111-1111-1111-111111111111', 'otp_fraud', 'OTP Fraud', 'Suspicious OTP or verification request patterns'),
('22222222-2222-2222-2222-222222222222', 'fake_bank_kyc', 'Fake Bank KYC', 'Bank impersonation and fake KYC update requests'),
('33333333-3333-3333-3333-333333333333', 'courier_scam', 'Courier Scam', 'Fake courier, parcel, and customs scam requests'),
('44444444-4444-4444-4444-444444444444', 'loan_scam', 'Loan Scam', 'Fraudulent instant loan and credit app campaigns'),
('55555555-5555-5555-5555-555555555555', 'job_scam', 'Job Scam', 'Fake job offer and employment scams'),
('66666666-6666-6666-6666-666666666666', 'upi_payment_request', 'UPI Payment Request', 'Suspicious collect request or payment approval scams'),
('77777777-7777-7777-7777-777777777777', 'phishing_link', 'Phishing Link', 'Reported suspicious links and fake login pages')
ON CONFLICT (slug) DO NOTHING;
