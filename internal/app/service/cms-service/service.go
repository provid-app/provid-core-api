package cms_service

import (
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"

	"github.com/gin-gonic/gin"
)

type CMSService interface {
	Login(c *gin.Context, request webrequest.LoginRequest) (webresponse.JSONResponse, int)
	Logout(c *gin.Context) (webresponse.JSONResponse, int)
	RefreshToken(c *gin.Context) (webresponse.JSONResponse, int)

	ListMissions(c *gin.Context) (webresponse.JSONResponse, int)
	ListCategories(c *gin.Context) (webresponse.JSONResponse, int)
	ListSegments(c *gin.Context) (webresponse.JSONResponse, int)

	CreateSegmen(c *gin.Context, request webrequest.CreateSegmenRequest) (webresponse.JSONResponse, int)
	UpdateSegmen(c *gin.Context, request webrequest.UpdateSegmenRequest) (webresponse.JSONResponse, int)
	DeleteSegmen(c *gin.Context, request webrequest.DeleteBulkRequest) (webresponse.JSONResponse, int)

	CreateCategory(c *gin.Context, request webrequest.CreateCategoryRequest) (webresponse.JSONResponse, int)
	UpdateCategory(c *gin.Context, request webrequest.UpdateCategoryRequest) (webresponse.JSONResponse, int)
	DeleteCategory(c *gin.Context, request webrequest.DeleteBulkRequest) (webresponse.JSONResponse, int)

	CreateMission(c *gin.Context, request webrequest.CreateMissionRequest) (webresponse.JSONResponse, int)
	UpdateMission(c *gin.Context, request webrequest.UpdateMissionRequest) (webresponse.JSONResponse, int)

	//Create
}
