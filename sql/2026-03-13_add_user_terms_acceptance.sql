ALTER TABLE users
ADD COLUMN IF NOT EXISTS accepted_terms BOOLEAN DEFAULT FALSE;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS accepted_terms_at TIMESTAMP NULL;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS terms_version TEXT;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS privacy_version TEXT;

UPDATE users
SET accepted_terms = FALSE
WHERE accepted_terms IS NULL;

UPDATE users
SET terms_version = 'v1'
WHERE terms_version IS NULL;

UPDATE users
SET privacy_version = 'v1'
WHERE privacy_version IS NULL;

ALTER TABLE users
ALTER COLUMN accepted_terms SET DEFAULT FALSE;
