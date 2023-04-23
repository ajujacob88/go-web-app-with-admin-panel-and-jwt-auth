package routes

import (
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/controllers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/middleware"
	"github.com/gin-gonic/gin"
)

func AdminAuthRoutes(r *gin.Engine) {

	r.LoadHTMLGlob("template/*.html")

	//r.Static("/template", "./template") //to load the bootstrap css files,, mention the folder/template or /assets where static css and other files are located

	r.GET("/adminLogin", controllers.AdminLogin)
	r.POST("/adminPostLogin", controllers.AdminPostLogin)
	r.GET("/adminProfile", middleware.RequireAuthAdmin, controllers.AdminLogged, controllers.AdminProfile)
	r.GET("/logoutadmin", controllers.AdminLogout)
	r.POST("/createUser", controllers.CreateUser)
	r.GET("/deleteUser/:id", controllers.DeleteUser)
	r.POST("/updateUser/:name", controllers.UpdateUser)

}
