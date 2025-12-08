package http

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"

    "taxi-project/internal/auth"
)

func NewRouter(db *pgxpool.Pool, jwtMgr *auth.JWTManager) *gin.Engine {
    r := gin.Default()

    authHandler := auth.NewHandler(db, jwtMgr)

    api := r.Group("/api")
    {
        // ===== ПУБЛИЧНЫЕ маршруты (БЕЗ JWT) =====
        authGroup := api.Group("/auth")
        {
            authGroup.POST("/client/register", authHandler.RegisterClient)
            authGroup.POST("/driver/register", authHandler.RegisterDriver)
            authGroup.POST("/login", authHandler.Login)
            authGroup.POST("/forgot-password", authHandler.ForgotPassword)
            authGroup.POST("/reset-password", authHandler.ResetPassword)
        }

        api.GET("/ping", func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{"message": "pong"})
        })

        // admin login – тоже публичный (логин по константам)
        adminPublic := api.Group("/admin")
        {
            adminPublic.POST("/login", authHandler.AdminLogin)
        }

        // ===== ДАЛЬШЕ – ТОЛЬКО С JWT =====
        protected := api.Group("")
        protected.Use(authHandler.AuthMiddleware())
        {
            // админские ручки, которые требуют авторизации
            adminGroup := protected.Group("/admin")
            {
                adminGroup.GET("/drivers/pending", authHandler.ListPendingDrivers)
                adminGroup.GET("/drivers/:id", authHandler.GetDriverApplication)
                adminGroup.POST("/drivers/:id/approve", authHandler.ApproveDriver)
                adminGroup.POST("/drivers/:id/reject", authHandler.RejectDriver)
            }

            ridesGroup := protected.Group("/rides")
            {
                ridesGroup.POST("/create", authHandler.CreateRide)
                ridesGroup.GET("/active", authHandler.GetClientActiveRide)     // клиент
                ridesGroup.POST("/:id/cancel", authHandler.CancelRide)         // клиент
                ridesGroup.POST("/:id/rate", authHandler.RateRide)             // клиент
            }

            driverAPI := protected.Group("/driver")
            {
                driverAPI.GET("/orders", authHandler.ListAvailableOrders)
                driverAPI.POST("/orders/:id/accept", authHandler.AcceptOrder)
                driverAPI.POST("/orders/:id/reject", authHandler.RejectOrder)
                driverAPI.POST("/orders/:id/start", authHandler.StartRide)
                driverAPI.POST("/orders/:id/finish", authHandler.FinishRide)
                driverAPI.POST("/orders/:id/close", authHandler.CloseRideForDriver)
                driverAPI.GET("/me", authHandler.DriverProfile)
            }

            clientAPI := protected.Group("/client")
            {
                clientAPI.GET("/me", authHandler.ClientProfile)
                clientAPI.GET("/rides", authHandler.ClientRides)
            }
        }
    }

    // ====== frontend ======
    staticRoot := "../frontend"

    r.Static("/assets", staticRoot+"/assets")
    r.Static("/client", staticRoot+"/client")
    r.Static("/driver", staticRoot+"/driver")
    r.Static("/admin", staticRoot+"/admin")

    // главная
    r.GET("/", func(c *gin.Context) {
        c.File(staticRoot + "/index.html")
    })

    return r
}
