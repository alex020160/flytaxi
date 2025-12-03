SET search_path = public;

ALTER TABLE drivers
    ADD COLUMN IF NOT EXISTS is_rejected BOOLEAN NOT NULL DEFAULT FALSE;
