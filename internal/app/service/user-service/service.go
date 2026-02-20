package user_service

import (
	"provid-backend/internal/model/webresponse"

	"github.com/gin-gonic/gin"
)

type UserService interface {
	GetUserProfile(c *gin.Context) (webresponse.JSONResponse, int)
}
