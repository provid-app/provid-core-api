package auth_service

import (
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"

	"github.com/gin-gonic/gin"
)

type AuthService interface {
	SendOTP(c *gin.Context, request webrequest.OTPRequest) (webresponse.JSONResponse, int)
	LoginPassword(c *gin.Context, request webrequest.LoginRequest) (webresponse.JSONResponse, int)
	LoginPIN(c *gin.Context, request webrequest.LoginPINRequest) (webresponse.JSONResponse, int)
	Register(c *gin.Context, request webrequest.RegisterRequest) (webresponse.JSONResponse, int)
	Logout(c *gin.Context) (webresponse.JSONResponse, int)
	ChangePassword(c *gin.Context, request webrequest.ChangePasswordRequest) (webresponse.JSONResponse, int)
	ValidateOTP(c *gin.Context, request webrequest.ValidateOTPRequest) (webresponse.JSONResponse, int)
	RegisterPIN(c *gin.Context, request webrequest.RegisterPINRequest) (webresponse.JSONResponse, int)
	GetUserProfile(c *gin.Context) (webresponse.JSONResponse, int)
	RefreshToken(c *gin.Context) (webresponse.JSONResponse, int)
}
