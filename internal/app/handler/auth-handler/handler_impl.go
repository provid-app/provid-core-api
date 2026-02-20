package auth_handler

import (
	"net/http"
	auth_service "provid-backend/internal/app/service/auth-service"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/webrequest"

	"github.com/gin-gonic/gin"
)

type AuthHandlerImpl struct {
	authService auth_service.AuthService
}

func (a *AuthHandlerImpl) Logout(c *gin.Context) {
	response, statusCode := a.authService.Logout(c)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) ChangePassword(c *gin.Context) {
	var request webrequest.ChangePasswordRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.ChangePassword(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) ValidateOTP(c *gin.Context) {
	var request webrequest.ValidateOTPRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.ValidateOTP(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) Register(c *gin.Context) {
	var request webrequest.RegisterRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	response, statusCode := a.authService.Register(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) Login(c *gin.Context) {
	var request webrequest.LoginRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.LoginPassword(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) LoginPIN(c *gin.Context) {
	var request webrequest.LoginPINRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.LoginPIN(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) RegisterPIN(c *gin.Context) {
	var request webrequest.RegisterPINRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.RegisterPIN(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) SendOTP(c *gin.Context) {
	var request webrequest.OTPRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := a.authService.SendOTP(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) GetUserProfile(c *gin.Context) {
	response, statusCode := a.authService.GetUserProfile(c)

	helper.WriteJSON(c, statusCode, response)
}

func (a *AuthHandlerImpl) RefreshToken(c *gin.Context) {
	response, statusCode := a.authService.RefreshToken(c)

	helper.WriteJSON(c, statusCode, response)
}

func NewAuthHandler(authService auth_service.AuthService) AuthHandler {
	return &AuthHandlerImpl{
		authService: authService,
	}
}
