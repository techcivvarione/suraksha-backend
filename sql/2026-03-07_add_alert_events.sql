-- SECURE ALERT EVENTS START
CREATE TABLE IF NOT EXISTS alert_events (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    media_hash CHAR(64) NOT NULL,
    analysis_type VARCHAR(10) NOT NULL,
    risk_score INTEGER NOT NULL,
    notified_contact_id UUID NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'SENT',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_alert_events_user_media_time
    ON alert_events (user_id, media_hash, created_at);
-- SECURE ALERT EVENTS END
