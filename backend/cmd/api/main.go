package main

import (
    "log"
    "time"
    "github.com/joho/godotenv"
    "taxi-project/internal/auth"
    "taxi-project/internal/config"
    "taxi-project/internal/db"
    httpServer "taxi-project/internal/http"
)

func main() {

    if err := godotenv.Load(); err != nil {
            log.Println("No .env file found (skipping)")
    }
    cfg := config.Load()

    pool := db.NewPool(cfg.DBURL)
    defer pool.Close()

    jwtMgr := auth.NewJWTManager(cfg.JWTSecret, 24*time.Hour)

    r := httpServer.NewRouter(pool, jwtMgr)

    log.Printf("Starting API on :%s", cfg.HTTPPort)
    if err := r.Run(":" + cfg.HTTPPort); err != nil {
        log.Fatal(err)
    }
}

