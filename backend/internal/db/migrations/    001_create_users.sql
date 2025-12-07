-- 001_create_users.sql

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,

    -- роль пользователя: клиент, водитель, админ (на будущее)
    role TEXT NOT NULL CHECK (role IN ('client', 'driver', 'admin')),

    first_name  TEXT NOT NULL,
    last_name   TEXT NOT NULL,
    middle_name TEXT,

    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL UNIQUE,

    -- bcrypt-хэш пароля
    password_hash TEXT NOT NULL,

    -- класс автомобиля для водителя (econom|business|comfort|kids)
    driver_class TEXT,

    -- флаг активности аккаунта
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
