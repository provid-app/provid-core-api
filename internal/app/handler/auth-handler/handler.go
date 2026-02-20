package auth_handler

import "github.com/gin-gonic/gin"

type AuthHandler interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	LoginPIN(c *gin.Context)
	SendOTP(c *gin.Context)
	Logout(c *gin.Context)
	ChangePassword(c *gin.Context)
	ValidateOTP(c *gin.Context)
	RegisterPIN(c *gin.Context)
	GetUserProfile(c *gin.Context)
	RefreshToken(c *gin.Context)
}
