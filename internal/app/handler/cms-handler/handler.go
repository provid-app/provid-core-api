package cms_handler

import "github.com/gin-gonic/gin"

type CMSHandler interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	RefreshToken(c *gin.Context)

	GetMissionList(c *gin.Context)
	GetSegmenList(c *gin.Context)
	GetCategoryList(c *gin.Context)

	CreateMission(c *gin.Context)
	UpdateMission(c *gin.Context)

	CreateSegmen(c *gin.Context)
	UpdateSegmen(c *gin.Context)
	DeleteSegmen(c *gin.Context)

	CreateCategory(c *gin.Context)
	UpdateCategory(c *gin.Context)
	DeleteCategory(c *gin.Context)
}
