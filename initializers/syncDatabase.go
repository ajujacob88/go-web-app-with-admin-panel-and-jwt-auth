package initializers

import "github.com/ajujacob88/go-web-app-with-admin-panel-and-jwt-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.Admin{})

}
