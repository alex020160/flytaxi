package db

import (
    "context"
    "log"

    "github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(connStr string) *pgxpool.Pool {
    pool, err := pgxpool.New(context.Background(), connStr)
    if err != nil {
        log.Fatalf("failed to connect db: %v", err)
    }

    // ВАЖНО: запуск миграций
    if err := RunMigrations(pool); err != nil {
        log.Fatalf("failed to run migrations: %v", err)
    }

    return pool
}
