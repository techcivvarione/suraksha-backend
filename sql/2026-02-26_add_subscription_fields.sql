ALTER TABLE users
ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE';

ALTER TABLE users
ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ NULL;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS last_subscription_event_at TIMESTAMPTZ NULL;

CREATE TABLE IF NOT EXISTS subscription_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID NULL,
    event_type VARCHAR(64) NOT NULL,
    event_at TIMESTAMPTZ NULL,
    processing_status VARCHAR(32) NOT NULL DEFAULT 'RECEIVED',
    payload TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_subscription_events_user_id
ON subscription_events(user_id);

-- Normalize legacy plan values for consistency.
UPDATE users
SET plan = 'GO_FREE'
WHERE UPPER(COALESCE(plan, '')) IN ('FREE', 'GO FREE', 'GOFREE');
