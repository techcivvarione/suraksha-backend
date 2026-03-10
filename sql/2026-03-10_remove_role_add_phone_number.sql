ALTER TABLE users
DROP COLUMN IF EXISTS role;

ALTER TABLE users
ADD COLUMN IF NOT EXISTS phone_number VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_users_phone_number ON users(phone_number);
