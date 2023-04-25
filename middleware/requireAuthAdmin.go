package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/initializers"
	"github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func RequireAuthAdmin(c *gin.Context) {
	// Get the cookie off request
	tokenString, err := c.Cookie("admintoken")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Decode / validate it

	// Parse takes the token string and a function for looking up the key. The latter is especially
	//This block of code parses and validates the token extracted from the cookie.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		// it allow you to extract the correct expiration and not-before times from the token claims.
		expTime := int64(0)
		if exp, ok := claims["exp"].(float64); ok {
			expTime = int64(exp)
		}
		nbfTime := int64(0)
		if nbf, ok := claims["nbf"].(float64); ok {
			nbfTime = int64(nbf)
		}
		if time.Now().Unix() > expTime || time.Now().Unix() < nbfTime {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// Find the user with token sub
		// This block of code retrieves the sub claim from the token, which is the ID of the admin user who generated the token, and uses it to retrieve the corresponding admin object from the database. If no admin object is found with the given ID, the function returns an error response with HTTP status

		var admin models.Admin
		initializers.DB.First(&admin, claims["sub"])

		if admin.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// Attach user to request context
		c.Set("admin", admin)

		// Continue with the request
		c.Next()

	} else {

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
}
