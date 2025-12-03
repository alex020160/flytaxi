package auth

import (
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
    secretKey     string
    tokenDuration time.Duration
}

type UserClaims struct {
    UserID int64  `json:"user_id"`
    Role   string `json:"role"`
    jwt.RegisteredClaims
}

// ВАЖНО: второй аргумент — time.Duration, а не int
func NewJWTManager(secret string, duration time.Duration) *JWTManager {
    return &JWTManager{
        secretKey:     secret,
        tokenDuration: duration,
    }
}

func (m *JWTManager) Generate(userID int64, role string) (string, error) {
    claims := &UserClaims{
        UserID: userID,
        Role:   role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.tokenDuration)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(m.secretKey))
}
