ALTER TABLE users
ADD COLUMN IF NOT EXISTS preferred_language VARCHAR(10);

UPDATE users
SET preferred_language = 'en'
WHERE preferred_language IS NULL OR BTRIM(preferred_language) = '';

ALTER TABLE users
ALTER COLUMN preferred_language SET DEFAULT 'en';

ALTER TABLE users
ALTER COLUMN preferred_language SET NOT NULL;
