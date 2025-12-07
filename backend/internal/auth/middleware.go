// internal/auth/middleware.go
package auth

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

// AuthMiddleware проверяет JWT только для защищённых API-эндпоинтов.
// Статика (/, /assets, /client, /driver, /admin и т.п.) не трогается.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        path := c.Request.URL.Path

        // 1. Всё, что НЕ начинается с /api/ — пропускаем без проверки
        if !strings.HasPrefix(path, "/api/") {
            c.Next()
            return
        }

        // 2. Публичные API-эндпоинты (логин/регистрация/восстановление пароля)
        switch path {
        case "/api/auth/login",
            "/api/client/register",
            "/api/driver/register",
            "/api/auth/forgot-password",
            "/api/auth/reset-password":
            c.Next()
            return
        }

        // 3. Все остальные /api/... — требуют токен
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "нет токена"})
            return
        }

        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || strings.TrimSpace(parts[1]) == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "неверный формат токена"})
            return
        }

        tokenString := strings.TrimSpace(parts[1])

        userID, role, err := h.jwt.Parse(tokenString)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "некорректный токен"})
            return
        }

        // кладём данные пользователя в контекст
        c.Set("userID", userID)
        c.Set("role", role)

        c.Next()
    }
}
