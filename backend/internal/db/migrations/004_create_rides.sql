-- 004_create_rides.sql

CREATE TABLE IF NOT EXISTS rides (
    id BIGSERIAL PRIMARY KEY,

    -- клиент, который создал заказ
    client_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    -- водитель, который выполняет заказ (может быть NULL, пока не назначен)
    driver_id BIGINT
        REFERENCES users(id) ON DELETE SET NULL,

    from_address TEXT NOT NULL,
    to_address   TEXT NOT NULL,

    -- класс автомобиля (должен совпадать с driver_class в users)
    car_class TEXT NOT NULL
        CHECK (car_class IN ('econom', 'business', 'comfort', 'kids')),

    with_pet     BOOLEAN NOT NULL DEFAULT FALSE,
    with_booster BOOLEAN NOT NULL DEFAULT FALSE,

    comment TEXT,

    -- цена и ETA могут быть NULL, пока не посчитаны
    price       INT,
    eta_minutes INT,

    -- статус заказа
    status TEXT NOT NULL CHECK (
        status IN (
            'new',         -- создан, ищем водителя
            'assigned',    -- водитель принял
            'in_progress', -- в пути
            'finished',    -- завершено
            'cancelled',   -- отменено
            'archived'     -- скрыто из списка, но хранится для статистики
        )
    ),

    -- кто отменил поездку (client|driver), если status = 'cancelled'
    cancelled_by TEXT
        CHECK (cancelled_by IN ('client', 'driver')),

    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    rating     SMALLINT,  -- 0..5
    tip_amount INT,
    client_note TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rides_client_id ON rides(client_id);
CREATE INDEX IF NOT EXISTS idx_rides_driver_id ON rides(driver_id);
CREATE INDEX IF NOT EXISTS idx_rides_status ON rides(status);
