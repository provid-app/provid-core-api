package user_service

import (
	model2 "provid-backend/gen/core/query"
	userRepository "provid-backend/internal/app/repository/user-repository"
	"provid-backend/internal/model/data"
	"provid-backend/internal/model/webresponse"

	"github.com/gin-gonic/gin"
)

type UserServiceImpl struct {
	AuthRepository userRepository.AuthRepository
	Query          *model2.Query
	PasetoData     data.PasetoItemData
}

func (u *UserServiceImpl) GetUserProfile(c *gin.Context) (webresponse.JSONResponse, int) {

	panic("implement me")
}

func NewUserServiceImpl(authRepository userRepository.AuthRepository, query *model2.Query, pasetoData data.PasetoItemData) UserService {
	return &UserServiceImpl{
		AuthRepository: authRepository,
		Query:          query,
		PasetoData:     pasetoData,
	}
}
