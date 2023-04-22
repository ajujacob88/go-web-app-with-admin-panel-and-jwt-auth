package routes

import (
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/controllers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/middleware"
	"github.com/gin-gonic/gin"
)

func UserAuthRoutes(r *gin.Engine) {
	r.LoadHTMLGlob("template/*.html")

	r.Static("/template", "./template")

	r.GET("/userSignup", controllers.UserSignup)
	r.POST("/Signup", controllers.Signup)
	r.GET("/userLogin", controllers.UserLogin)
	r.POST("/userPostLogin", controllers.Login)
	r.GET("/userProfile", middleware.RequireAuth, controllers.UserLogged, controllers.UserProfile)
	r.GET("/userLogout", controllers.UserLogout)
}
