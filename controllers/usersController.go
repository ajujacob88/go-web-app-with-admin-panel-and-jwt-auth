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

func UserPostSignup(c *gin.Context) {
	fmt.Println("debug check")
	fullnameFromForm := c.Request.FormValue("fullname")
	emailFromForm := c.Request.FormValue("email")
	passwordFromForm := c.Request.FormValue("password")

	// get the email/password of req body, first create a body to store the data that is coming in
	var body struct {
		Email    string
		Password string
		Name     string
	}

	body.Name = fullnameFromForm
	body.Email = emailFromForm
	body.Password = passwordFromForm

	fmt.Println("debug check body name is ", body.Name)
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
		c.Redirect(303, "/userProfile")
		return
	}
	c.HTML(http.StatusOK, "userlogin.html", nil)
}

//===================POST LOGIN=====================

func UserPostLogin(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	//GEt name and password from request body

	emailFromForm := c.Request.FormValue("email")
	passwordFromForm := c.Request.FormValue("password")

	// Get the email and password of req body
	var body struct {
		Email    string
		Password string
	}
	body.Email = emailFromForm
	body.Password = passwordFromForm

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//look up requested user
	//Check if the user exists in the database
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email) //db.First(&user, "id = ?", "1b74413f-f3b8-409f-ac47-e8c062e3472a"),, SELECT * FROM users WHERE id = "1b74413f-f3b8-409f-ac47-e8c062e3472a";

	if user.ID == 0 {
		userLoggedStatus = false
		c.Redirect(303, "/userLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email id or passwordd",
		})
		return
	}

	//compare sent in pass with saved user pass hash
	//Check if the password is correct
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)) //CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent. Returns nil on success, or an error on failure.

	if err != nil {
		userLoggedStatus = false
		c.Redirect(303, "/userLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email id or password",
		})
		return
	}
	//generate a jwt token
	// Create a new token object, specifying signing method and the claims you would like it to contain.
	//This creates a new JWT (JSON Web Token) with the specified claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	//This signs the token using the specified secret key and returns a string representation of the complete, signed token.
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
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

	//respond
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	userLoggedStatus = true
	c.HTML(http.StatusOK, "userprofile.html", user.Name)
	//c.Redirect(303, "/userProfile")
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
	// fmt.Println("in user profile")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok := userLoggedStatus
	if ok {
		c.HTML(http.StatusOK, "userprofile.html", nil)
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
