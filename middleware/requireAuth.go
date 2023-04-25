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

func RequireAuth(c *gin.Context) {
	// Get the cookie off request
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Decode / validate it

	// Parse takes the token string and a function for looking up the key. The latter is especially
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

		// Check the expiration and not before time
		// expTime := int64(claims["exp"].(float64))
		// nbfTime := int64(claims["nbf"].(float64))
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
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		// Attach user to request context
		c.Set("user", user)

		// Continue with the request
		c.Next()

	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
}

/*
func RequireAuth(c *gin.Context) {
	fmt.Println("In middleware")

	// Get the cookie off request
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	//Decode /validate it

	// Parse takes the token string and a function for looking up the key. The latter is especially
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		//check the expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			fmt.Println("Token tampered")
		}

		//find the user with token sub
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)

		}

		//attach to request
		c.Set("user", user)

		//continue
		c.Next()
		fmt.Println("middlewarec.next:", claims["foo"], claims["nbf"])

	} else {
		c.HTML(http.StatusOK, "userlogin.html", gin.H{})
		//c.AbortWithStatus(http.StatusUnauthorized)
	}

}

*/
