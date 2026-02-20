package route

import (
	_ "net/http"
	modelcms "provid-backend/gen/cms/query"
	model "provid-backend/gen/core/query"
	auth_handler "provid-backend/internal/app/handler/auth-handler"
	cms_handler "provid-backend/internal/app/handler/cms-handler"
	category_repository "provid-backend/internal/app/repository/category-repository"
	cms_repository "provid-backend/internal/app/repository/cms-repository"
	mission_repository "provid-backend/internal/app/repository/mission-repository"
	segmen_repository "provid-backend/internal/app/repository/segmen-repository"
	user_repository "provid-backend/internal/app/repository/user-repository"
	auth_service "provid-backend/internal/app/service/auth-service"
	cms_service "provid-backend/internal/app/service/cms-service"
	"provid-backend/internal/emailclient"
	"provid-backend/internal/middleware"
	"provid-backend/internal/model/data"

	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func InitRoutes(pgClient *gorm.DB, cmsClient *gorm.DB, pasetoData data.PasetoItemData, emailClient *emailclient.Client) *gin.Engine {

	router := gin.New()

	router.Use(
		gin.Recovery(),
		middleware.HTTPLogger(),
	)

	router.Use(cors.New(cors.Config{
		AllowOriginFunc:  addAllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization", "", "API-Key", "App-Key", "X-Access-Token", "X-Refresh-Token", "Device-Id", "X-API-Language", "Accept-Language"},
		ExposeHeaders:    []string{"Content-Length", "X-Access-Token", "X-Refresh-Token", "Device-Id"},
		AllowCredentials: true,
		MaxAge:           1 * time.Hour,
	}))

	Q := model.Use(pgClient)
	QCMS := modelcms.Use(cmsClient)
	// Auth route
	authRepo := user_repository.NewAuthRepository(Q)
	authService := auth_service.NewAuthService(authRepo, emailClient, Q, pasetoData)
	authHandler := auth_handler.NewAuthHandler(authService)

	authRoute := router.Group("/auth")
	{
		authRoute.POST("/register", authHandler.Register)
		authRoute.POST("/login", authHandler.Login)
		authRoute.POST("/login-pin", authHandler.LoginPIN)
		authRoute.POST("/send-otp", authHandler.SendOTP)
		authRoute.POST("/validate-otp", authHandler.ValidateOTP)
		authRoute.POST("/logout", authHandler.Logout)
		authRoute.POST("/change-password", authHandler.ChangePassword)
		authRoute.POST("/register-pin", authHandler.RegisterPIN)
		authRoute.POST("/refresh", authHandler.RefreshToken)
	}

	// Protected routes (require authentication)
	userRoute := router.Group("/user")
	userRoute.Use(middleware.AuthMiddleware(Q, pasetoData))
	{
		userRoute.GET("/profile", authHandler.GetUserProfile)
	}

	// CMS route
	missionRepo := mission_repository.NewMissionRepository(Q)
	segmenRepo := segmen_repository.NewSegmenRepository(Q)
	categoryRepo := category_repository.NewCategoryRepository(Q)

	cmsRepo := cms_repository.NewCMSRepository(QCMS)
	cmsService := cms_service.NewCMSService(cmsRepo, missionRepo, segmenRepo, categoryRepo, QCMS, pasetoData)
	cmsHandler := cms_handler.NewCMSHandler(cmsService)

	cmsRoute := router.Group("/cms")
	{
		cmsRoute.POST("/login", cmsHandler.Login)
		cmsRoute.POST("/logout", cmsHandler.Logout)
		cmsRoute.POST("/refresh", cmsHandler.RefreshToken)
	}

	cmsMissionRoute := router.Group("/cms/mission")
	cmsMissionRoute.Use(middleware.AuthMiddlewareCMS(QCMS, pasetoData))
	{
		cmsMissionRoute.GET("/list", cmsHandler.GetMissionList)
		//cmsMissionRoute.GET("/detail/:id", cmsHandler.GetMissionDetail)
		cmsMissionRoute.POST("/create", cmsHandler.CreateMission)
		cmsMissionRoute.POST("/update", cmsHandler.UpdateMission)
		//cmsMissionRoute.DELETE("/delete/:id", cmsHandler.DeleteMission)
	}

	cmsSegmenRoute := router.Group("/cms/segmen")
	cmsSegmenRoute.Use(middleware.AuthMiddlewareCMS(QCMS, pasetoData))
	{
		cmsSegmenRoute.GET("/list", cmsHandler.GetSegmenList)
		cmsSegmenRoute.POST("/create", cmsHandler.CreateSegmen)
		cmsSegmenRoute.POST("/update", cmsHandler.UpdateSegmen)
		cmsSegmenRoute.POST("/delete", cmsHandler.DeleteSegmen)
	}

	cmsCategoryRoute := router.Group("/cms/category")
	cmsCategoryRoute.Use(middleware.AuthMiddlewareCMS(QCMS, pasetoData))
	{
		cmsCategoryRoute.GET("/list", cmsHandler.GetCategoryList)
		cmsCategoryRoute.POST("/create", cmsHandler.CreateCategory)
		cmsCategoryRoute.POST("/update", cmsHandler.UpdateCategory)
		cmsCategoryRoute.POST("/delete", cmsHandler.DeleteCategory)
	}

	return router
}

func addAllowedOrigins(origin string) bool {
	env := os.Getenv("APP_ENV")
	// Allow development tio (any port)
	if env == "development" {
		if strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "https://cms.provid.id") ||
			strings.HasPrefix(origin, "https://localhost:") {
			return true
		}
	}

	// Allow specific production domains
	allowedDomains := []string{
		//"https://pharmacin.id",
		//"https://dev.pharmacin.id",
		//"https://test.pharmacin.id",
	}
	for _, domain := range allowedDomains {
		if origin == domain {
			return true
		}
	}

	return false
}
