package db

import (
    "context"
    "embed"
    "fmt"
    "log"
    "sort"
    "strings"

    "github.com/jackc/pgx/v5/pgxpool"
)

var (
    //go:embed migrations/*.sql
    migrationFiles embed.FS
)

func RunMigrations(pool *pgxpool.Pool) error {
    ctx := context.Background()

    entries, err := migrationFiles.ReadDir("migrations")
    if err != nil {
        return fmt.Errorf("read migrations dir: %w", err)
    }

    // сортируем файлы: 001_..., 002_...
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].Name() < entries[j].Name()
    })

    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
            continue
        }

        name := e.Name()

        data, err := migrationFiles.ReadFile("migrations/" + name)
        if err != nil {
            return fmt.Errorf("read migration %s: %w", name, err)
        }

        sql := string(data)
        log.Printf("[MIGRATION] applying: %s", name)

        _, err = pool.Exec(ctx, sql)
        if err != nil {
            return fmt.Errorf("exec migration %s: %w", name, err)
        }
    }

    log.Printf("[MIGRATION] all migrations applied successfully")
    return nil
}
