package db

import (
    "context"
    "log"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(connStr string) *pgxpool.Pool {
    ctx := context.Background()

    pool, err := pgxpool.New(ctx, connStr)
    if err != nil {
        log.Fatalf("failed to init db pool: %v", err)
    }

    // 🔁 Ждём, пока Postgres реально начнёт принимать подключения
    for i := 0; i < 30; i++ { // максимум ~30 секунд
        if err := pool.Ping(ctx); err == nil {
            log.Println("[DB] connection established")
            break
        } else {
            log.Printf("[DB] waiting for postgres... (%d/30): %v", i+1, err)
            time.Sleep(1 * time.Second)
        }
    }

    // 🔥 Запускаем миграции
    if err := RunMigrations(pool); err != nil {
        log.Fatalf("Failed to apply migrations: %v", err)
    }

    return pool
}
