// internal/auth/middleware.go
package auth

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

// AuthMiddleware проверяет JWT только для защищённых API-эндпоинтов.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "нет токена"})
            return
        }

        tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

        userID, role, err := h.jwt.Parse(tokenStr)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "неверный токен"})
            return
        }

        c.Set("userID", userID)
        c.Set("role", role)

        c.Next()
    }
}

