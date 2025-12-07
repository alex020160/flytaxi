// internal/auth/jwt.go
package auth

import (
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
    secretKey string
}

func NewJWTManager(secret string) *JWTManager {
    return &JWTManager{secretKey: secret}
}

func (m *JWTManager) Generate(userID int64, role string) (string, error) {
    claims := jwt.MapClaims{
        "user_id": userID,
        "role": role,
        "exp": time.Now().Add(7 * 24 * time.Hour).Unix(),  // 7 суток
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(m.secretKey))
}

func (m *JWTManager) Parse(tokenString string) (int64, string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(m.secretKey), nil
    })
    if err != nil || !token.Valid {
        return 0, "", err
    }

    claims := token.Claims.(jwt.MapClaims)

    userID, ok1 := claims["user_id"].(float64)
    role, ok2 := claims["role"].(string)
    if !ok1 || !ok2 {
        return 0, "", jwt.ErrInvalidKey
    }

    return int64(userID), role, nil
}
