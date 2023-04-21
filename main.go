package main

import (
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/controllers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/initializers"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.Run()
}
