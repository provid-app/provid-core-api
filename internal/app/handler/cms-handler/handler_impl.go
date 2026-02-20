package cms_handler

import (
	"net/http"
	cms_service "provid-backend/internal/app/service/cms-service"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/webrequest"

	"github.com/gin-gonic/gin"
)

type CMSHandlerImpl struct {
	CMSService cms_service.CMSService
}

func (C *CMSHandlerImpl) Login(c *gin.Context) {
	var request webrequest.LoginRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, statusCode := C.CMSService.Login(c, request)

	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) Logout(c *gin.Context) {
	response, statusCode := C.CMSService.Logout(c)

	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) RefreshToken(c *gin.Context) {
	response, statusCode := C.CMSService.RefreshToken(c)

	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) GetMissionList(c *gin.Context) {
	response, statusCode := C.CMSService.ListMissions(c)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) CreateMission(c *gin.Context) {
	var request webrequest.CreateMissionRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.CreateMission(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) UpdateMission(c *gin.Context) {
	var request webrequest.UpdateMissionRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.UpdateMission(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) GetSegmenList(c *gin.Context) {
	response, statusCode := C.CMSService.ListSegments(c)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) GetCategoryList(c *gin.Context) {
	response, statusCode := C.CMSService.ListCategories(c)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) CreateSegmen(c *gin.Context) {
	var request webrequest.CreateSegmenRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.CreateSegmen(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) UpdateSegmen(c *gin.Context) {
	var request webrequest.UpdateSegmenRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.UpdateSegmen(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) DeleteSegmen(c *gin.Context) {
	var request webrequest.DeleteBulkRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.DeleteSegmen(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) CreateCategory(c *gin.Context) {
	var request webrequest.CreateCategoryRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.CreateCategory(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) UpdateCategory(c *gin.Context) {
	var request webrequest.UpdateCategoryRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.UpdateCategory(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func (C *CMSHandlerImpl) DeleteCategory(c *gin.Context) {
	var request webrequest.DeleteBulkRequest
	if err := helper.ReadJSON(c, &request); err != nil {
		helper.WriteJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, statusCode := C.CMSService.DeleteCategory(c, request)
	helper.WriteJSON(c, statusCode, response)
}

func NewCMSHandler(service cms_service.CMSService) CMSHandler {
	return &CMSHandlerImpl{
		CMSService: service,
	}
}
