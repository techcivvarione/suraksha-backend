-- SCAN REPUTATION TABLES
CREATE TABLE IF NOT EXISTS scan_reputation (
    id BIGSERIAL PRIMARY KEY,
    hash_value CHAR(64) NOT NULL,
    hash_type VARCHAR(16) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_count INTEGER NOT NULL DEFAULT 0,
    report_count INTEGER NOT NULL DEFAULT 0,
    is_flagged BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hash_value, hash_type)
);

CREATE INDEX IF NOT EXISTS idx_scan_reputation_hash ON scan_reputation (hash_value, hash_type);

CREATE TABLE IF NOT EXISTS scan_reports (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    hash_value CHAR(64) NOT NULL,
    hash_type VARCHAR(16) NOT NULL,
    reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_reports_hash ON scan_reports (hash_value, hash_type);
