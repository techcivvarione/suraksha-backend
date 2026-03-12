CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    file_path TEXT NOT NULL,
    scan_type VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    result_json TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scan_jobs_user_id ON scan_jobs (user_id);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_scan_type ON scan_jobs (scan_type);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_status ON scan_jobs (status);
