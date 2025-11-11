package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/morodik/pp/db"
	"github.com/morodik/pp/handlers"
)

func main() {
	router := gin.Default()

	router.SetTrustedProxies(nil)

	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * 3600,
	}))

	router.OPTIONS("/*path", func(c *gin.Context) {
		c.Status(204)
	})

	db.Init()

	router.POST("/register", handlers.Register)
	router.POST("/login", handlers.Login)
	router.POST("/logout", handlers.Logout)

	protected := router.Group("/api")
	protected.Use(handlers.AuthMiddleware())
	{
		protected.GET("/user", handlers.GetUser)
	}

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "aboba"})
	})

	router.Run(":8080")
}
