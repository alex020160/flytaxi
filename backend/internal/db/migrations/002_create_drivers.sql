-- 002_create_drivers.sql

CREATE TABLE IF NOT EXISTS drivers (
    id BIGSERIAL PRIMARY KEY,

    -- ссылка на запись в users
    user_id BIGINT NOT NULL UNIQUE
        REFERENCES users(id) ON DELETE CASCADE,

    car_make         TEXT NOT NULL,
    car_model        TEXT NOT NULL,
    car_color        TEXT NOT NULL,
    car_plate_number TEXT NOT NULL UNIQUE,

    driver_license_num  TEXT NOT NULL UNIQUE,
    license_expires_at  DATE NOT NULL,
    experience_years    INT  NOT NULL,

    -- одобрен администратором или нет
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_drivers_user_id ON drivers(user_id);
