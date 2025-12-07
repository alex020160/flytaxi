-- 003_create_password_reset_tokens.sql

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    -- шестизначный код (как строка)
    code TEXT NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id
    ON password_reset_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_code_valid
    ON password_reset_tokens(code, expires_at)
    WHERE used_at IS NULL;
