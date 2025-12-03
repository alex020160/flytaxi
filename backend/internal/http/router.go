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
        authGroup := api.Group("/auth")
        {
            authGroup.POST("/client/register", authHandler.RegisterClient)
            authGroup.POST("/driver/register", authHandler.RegisterDriver)
            authGroup.POST("/login", authHandler.Login)
            authGroup.POST("/forgot-password", authHandler.ForgotPassword)
            authGroup.POST("/reset-password",  authHandler.ResetPassword)
        }

        api.GET("/ping", func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{"message": "pong"})
        })

        adminGroup := api.Group("/admin")
        {
            adminGroup.POST("/login", authHandler.AdminLogin)
            adminGroup.GET("/drivers/pending", authHandler.ListPendingDrivers)
            adminGroup.GET("/drivers/:id",      authHandler.GetDriverApplication)
            adminGroup.POST("/drivers/:id/approve", authHandler.ApproveDriver)
            adminGroup.POST("/drivers/:id/reject",  authHandler.RejectDriver)
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