package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPPort  string
	DBURL     string
	JWTSecret string

	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		HTTPPort:  getenv("HTTP_PORT", "8080"),

		// Default must match docker-compose configuration!
		DBURL: getenv("DB_URL", "postgres://flytaxi:flytaxi@db:5432/flytaxi?sslmode=disable"),

		JWTSecret: getenv("JWT_SECRET", ""),

		SMTPHost: getenv("SMTP_HOST", ""),
		SMTPPort: getenv("SMTP_PORT", ""),
		SMTPUser: getenv("SMTP_USERNAME", ""),
		SMTPPass: getenv("SMTP_PASSWORD", ""),
		SMTPFrom: getenv("SMTP_FROM", ""),
	}

	// --- Validate required variables ---
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET is required (not provided)")
	}

	if cfg.DBURL == "" {
		log.Fatal("DB_URL is required (not provided)")
	}

	return cfg
}

// getenv returns value or default
func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
