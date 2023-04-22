package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/initializers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// ===================================================USER ROUTES===========================================

// ===================USER SIGNUP=====================
func UserSignup(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok := userLoggedStatus
	if ok {
		c.Redirect(303, "/userProfile")
		return
	}

	c.HTML(http.StatusOK, "usersignup.html", nil)
}

//===================POST SIGNUP=====================

func Signup(c *gin.Context) {
	usernameFromForm := c.Request.FormValue("email")
	passwordFromForm := c.Request.FormValue("password")

	// get the email/password of req body, first create a body to store the data that is coming in
	var body struct {
		Email    string
		Password string
		Name     string
	}

	body.Email = usernameFromForm
	body.Password = passwordFromForm
	//populate the variable with the data that came in
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//hash the password, use the bcrypt library
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		c.Redirect(303, "/usersignup")
		return
	}

	//save the user in database
	user := models.User{Email: body.Email, Password: string(hash), Name: body.Name}

	result := initializers.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		c.Redirect(303, "/userSignup")
		return
	}
	//respond
	c.HTML(http.StatusOK, "userlogin.html", nil)
}

//===================USER LOGIN=====================

func UserLogin(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok := userLoggedStatus
	if ok {
		c.Redirect(303, "/main")
		return
	}
	c.HTML(http.StatusOK, "userlogin.html", nil)
}

//===================POST LOIGN=====================

func Login(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	//GEt name and password from request body

	usernameFromForm := c.Request.FormValue("username")
	passwordFromForm := c.Request.FormValue("password")

	// Get the email and password of req body
	var body struct {
		Email    string
		Password string
	}
	body.Email = usernameFromForm
	body.Password = passwordFromForm

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email) //db.First(&user, "id = ?", "1b74413f-f3b8-409f-ac47-e8c062e3472a"),, SELECT * FROM users WHERE id = "1b74413f-f3b8-409f-ac47-e8c062e3472a";

	if user.ID == 0 {
		userLoggedStatus = false
		c.Redirect(303, "/userLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email id or password",
		})
		return
	}

	//compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		userLoggedStatus = false
		c.Redirect(303, "/userLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email id or password",
		})
		return
	}
	//generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create the token",
		})
		return
	}

	//send it back
	// c.JSON(http.StatusOK, gin.H{
	// 	"token": tokenString,
	// })

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	userLoggedStatus = true
	c.HTML(http.StatusOK, "userprofile.html", nil)
}

//===================LOGOUT=====================

func UserLogout(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", "", -1, "", "", false, true)
	c.HTML(http.StatusOK, "userlogin.html", nil)
	userLoggedStatus = false

}

//===================HOME PAGE=====================

var userLoggedStatus = false

func UserLogged(c *gin.Context) {

	fmt.Println("useerLOgged function called and userLoggedStatus is: set to true")
	userLoggedStatus = true
}

//===================USER PROFILE=====================

func UserProfile(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok := userLoggedStatus
	if ok {
		c.HTML(http.StatusOK, "home.html", nil)
		return
	}
	c.Redirect(303, "/userLogin")
}

// authorisation middle wares for securing routes
func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		//"message": "I am logged in",
		"message": user,
	})
}
