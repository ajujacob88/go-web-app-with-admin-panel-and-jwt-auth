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

// https://www.youtube.com/watch?v=ma7rUS_vW9M&t=1342s
// https://www.youtube.com/watch?v=7Q17ubqLfaM
// https://www.youtube.com/watch?v=hWmR8YtlFlE
//https://jwt.io/
////https://www.youtube.com/watch?v=bj77B59nkTQ
