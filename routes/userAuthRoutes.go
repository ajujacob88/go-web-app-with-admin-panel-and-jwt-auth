package routes

import (
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/controllers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/middleware"

	"net/http"

	"github.com/gin-gonic/gin"
)

func UserAuthRoutes(r *gin.Engine) {
	r.LoadHTMLGlob("template/*.html")

	r.Static("/template", "./template") //to load the bootstrap css files,, mention the folder/template or /assets where static css and other files are located

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/userLogin") //redirect the index to /userlogin. http://localhost:4000/ to http://localhost:4000/userLogin
	})

	r.GET("/userSignup", controllers.UserSignup)
	r.POST("/userPostSignup", controllers.UserPostSignup)
	r.GET("/userLogin", controllers.UserLogin)
	r.POST("/userPostLogin", controllers.UserPostLogin)
	r.GET("/userProfile", middleware.RequireAuth, controllers.UserLogged, controllers.UserProfile)
	r.GET("/userLogout", controllers.UserLogout)
}
