-- STEP 6: Add scan_type, risk_level, and extra_signals to alert_events
-- These columns store the richer context produced at alert-creation time
-- so that family-feed and debug endpoints can return meaningful data
-- without re-joining scan_history.

ALTER TABLE alert_events
    ADD COLUMN IF NOT EXISTS scan_type     VARCHAR(20) NULL,
    ADD COLUMN IF NOT EXISTS risk_level    VARCHAR(10) NULL,
    ADD COLUMN IF NOT EXISTS extra_signals JSONB       NULL;

-- Backfill risk_level for existing rows from risk_score
UPDATE alert_events
SET risk_level = CASE
    WHEN risk_score >= 70 THEN 'high'
    WHEN risk_score >= 40 THEN 'medium'
    ELSE 'low'
END
WHERE risk_level IS NULL;

CREATE INDEX IF NOT EXISTS ix_alert_events_scan_type
    ON alert_events (scan_type);

CREATE INDEX IF NOT EXISTS ix_alert_events_risk_level
    ON alert_events (risk_level);
