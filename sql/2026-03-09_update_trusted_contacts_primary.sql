-- TRUSTED CONTACT PRIMARY SUPPORT START
ALTER TABLE trusted_contacts
    ADD COLUMN IF NOT EXISTS name TEXT,
    ADD COLUMN IF NOT EXISTS phone TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS relationship TEXT,
    ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- backfill from legacy columns if present
UPDATE trusted_contacts
SET name = COALESCE(name, contact_name),
    email = COALESCE(email, contact_email),
    phone = COALESCE(phone, contact_phone)
WHERE TRUE;

ALTER TABLE trusted_contacts
    ADD CONSTRAINT fk_trusted_contacts_user
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_trusted_primary
    ON trusted_contacts (owner_user_id) WHERE is_primary = true;

CREATE INDEX IF NOT EXISTS ix_trusted_primary
    ON trusted_contacts (owner_user_id, is_primary);
-- TRUSTED CONTACT PRIMARY SUPPORT END
