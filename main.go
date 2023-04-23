package main

import (
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/initializers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/routes"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.Use(gin.Logger())

	routes.UserAuthRoutes(r)

	routes.AdminAuthRoutes(r)

	// r.POST("/signup", controllers.Signup)
	// r.POST("/login", controllers.Login)
	// r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	r.Run()
}
