package config

import (
    "log"
    "os"

    "github.com/joho/godotenv"
)

type Config struct {
    HTTPPort    string
    DBURL       string
    JWTSecret   string
    SMTPHost  string
    SMTPPort  string
    SMTPUser  string
    SMTPPass  string
    SMTPFrom  string
}

func Load() *Config {
    _ = godotenv.Load()

    cfg := &Config{
        HTTPPort:  getenv("HTTP_PORT", "8080"),
        DBURL:     getenv("DB_URL", "postgres://postgres:postgres@localhost:5432/taxi?sslmode=disable"),
        JWTSecret: getenv("JWT_SECRET", "supersecret"),
        SMTPHost: getenv("SMTP_HOST", ""),
        SMTPPort: getenv("SMTP_PORT", ""),
        SMTPUser: getenv("SMTP_USERNAME", ""),
        SMTPPass: getenv("SMTP_PASSWORD", ""),
        SMTPFrom: getenv("SMTP_FROM", ""),
    }

    if cfg.JWTSecret == "" {
        log.Fatal("JWT_SECRET is required")
    }

    return cfg
}

func getenv(key, def string) string {
    v := os.Getenv(key)
    if v == "" {
        return def
    }
    return v
}


