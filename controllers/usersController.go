package controllers

import (
	"net/http"

	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/initializers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	// get the email/password of req body, first create a body to store the data that is coming in
	var body struct {
		Email    string
		Password string
		Name     string
	}
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
		return
	}

	//create the user
	user := models.User{Email: body.Email, Password: string(hash), Name: body.Name}

	result := initializers.DB.Create(&user) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}
	//respond
	c.JSON(http.StatusOK, gin.H{})
}
