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

// ===================================================ADMIN ROUTES===========================================

//===================ADMIN LOGIN=====================

func AdminLogin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	//ok := adminLoggedStatus

	// if ok {
	// 	c.Redirect(303, "/adminProfile")
	// 	return
	// }
	c.HTML(http.StatusOK, "adminlogin.html", nil)
}

//===================POST LOGIN=====================

type User struct {
	ID       int
	UserName string
	Password string
}

func AdminPostLogin(c *gin.Context) {
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	//GEt name and password from request body

	adminNameFromForm := c.Request.FormValue("adminName")
	adminPasswordFromForm := c.Request.FormValue("password")

	var form struct {
		Name     string
		Password string
	}

	form.Name = adminNameFromForm
	form.Password = adminPasswordFromForm

	//Check if the admin exists in the database
	var admin models.Admin

	initializers.DB.First(&admin, "name = ?", form.Name)

	if admin.ID == 0 {
		c.Redirect(303, "/adminLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid Admin Name or password",
		})
		return
	}

	//Check if the password is correct , no need to bcrypt since admin password is not hashed/encrypted in db, so just compare with if

	if admin.Password != form.Password {
		// Passwords do not match
		userLoggedStatus = false
		c.Redirect(303, "/userLogin")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email id or password",
		})
		return
	} else {
		// Passwords match

		//generate a jwt token
		// Create a new token object, specifying signing method and the claims you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": admin.ID,
			"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		})

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to create the token",
			})
			return
		}

		//respond
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie("admintoken", tokenString, 3600, "", "", false, true)
		c.Redirect(303, "/adminProfile")
		adminLoggedStatus = true
		fmt.Println("admin logged in")

		c.HTML(http.StatusOK, "adminprofile.html", nil)
	}

}

// ===================ADMIN LOGOUT=====================
func AdminLogout(c *gin.Context) {

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("admintoken", "", -1, "", "", false, true)
	adminLoggedStatus = false
	c.Redirect(303, "/adminLogin")

}

// ===================ADMIN Status=====================
var adminLoggedStatus = false

func AdminLogged(c *gin.Context) {

	fmt.Println("admin logged status set to true")
	adminLoggedStatus = true
}

func AdminProfile(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	ok := adminLoggedStatus
	fmt.Println("admin logged status is ", ok)

	if ok {
		var user []models.User

		var id [60]uint
		var name [60]string
		var email [60]string

		initializers.DB.Raw("SELECT id,name,email FROM users").Scan(&user)
		for index, val := range user {
			id[index], name[index], email[index] = val.ID, val.Name, val.Email
		}
		c.HTML(http.StatusOK, "adminprofile.html", gin.H{
			"id":    id,
			"name":  name,
			"email": email,
		})
		fmt.Println("fetching users")
		return
	}
	c.Redirect(303, "/adminLogin")
}

// ===================CREATE USER FROM ADMIN PANEL=====================

func CreateUser(c *gin.Context) {

	fullnameFromForm := c.Request.FormValue("fullname")
	emailFromForm := c.Request.FormValue("email")
	passwordFromForm := c.Request.FormValue("password")

	//GEt email and password from the form
	var form struct {
		Email    string
		Password string
		Name     string
	}

	form.Name = fullnameFromForm
	form.Email = emailFromForm
	form.Password = passwordFromForm
	//hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(form.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		c.Redirect(303, "/adminProfile")
		return
	}

	//Save the user in the database
	user := models.User{Email: form.Email, Password: string(hashedPassword), Name: form.Name}

	result := initializers.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user/email already exist",
		})
		c.Redirect(303, "/adminProfile")

		return
	}

	//respond
	c.Redirect(303, "/adminProfile")

}

// ===================DELETE USER FROM ADMIN PANEL=====================

func DeleteUser(c *gin.Context) {

	var user models.User
	name := c.Param("name")
	email := c.Param("email")

	initializers.DB.Where("name=?", name).Delete(&user)
	initializers.DB.Where("email=?", email).Delete(&user)
	c.Redirect(303, "/adminProfile")
	fmt.Println("user deleted")

}

// ===================Update USER FROM ADMIN PANEL=====================

func UpdateUser(c *gin.Context) {
	fmt.Println("updating user")

	updateData := c.Request.FormValue("updatedName")
	var user models.User
	name := c.Param("name")

	initializers.DB.Model(&user).Where("name=?", name).Update("name", updateData)
	fmt.Println("user updated")
	c.Redirect(303, "/adminProfile")
}
