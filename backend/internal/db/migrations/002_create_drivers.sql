CREATE TABLE IF NOT EXISTS drivers (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            BIGINT       NOT NULL REFERENCES users(id),
    car_make           VARCHAR(100),   -- марка: Toyota
    car_model          VARCHAR(100),   -- модель: Camry
    car_color          VARCHAR(50),
    car_plate_number   VARCHAR(32),    -- номер авто
    driver_license_num VARCHAR(64),    -- номер водительских прав
    license_expires_at DATE,           -- срок действия прав
    experience_years   INT,            -- стаж вождения
    is_approved        BOOLEAN      NOT NULL DEFAULT FALSE,   -- модерация
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
