package cms_service

import (
	"errors"
	"net/http"
	"provid-backend/gen/cms/model"
	modelcms "provid-backend/gen/cms/query"
	coremodel "provid-backend/gen/core/model"
	category_repository "provid-backend/internal/app/repository/category-repository"
	cms_repository "provid-backend/internal/app/repository/cms-repository"
	mission_repository "provid-backend/internal/app/repository/mission-repository"
	segmen_repository "provid-backend/internal/app/repository/segmen-repository"
	"provid-backend/internal/helper"
	"provid-backend/internal/logger"
	"provid-backend/internal/model/data"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gen/field"
	"gorm.io/gorm"
)

const missionDateLayout = "02-01-2006"

func parseMissionDate(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, errors.New("tanggal kosong")
	}
	return time.ParseInLocation(missionDateLayout, trimmed, time.Local)
}

type CMSServiceImpl struct {
	CMSRepository      cms_repository.CMSRepository
	MissionRepository  mission_repository.MissionRepository
	SegmenRepository   segmen_repository.SegmenRepository
	CategoryRepository category_repository.CategoryRepository
	Query              *modelcms.Query
	PasetoData         data.PasetoItemData
}

func (C *CMSServiceImpl) ListSegments(c *gin.Context) (webresponse.JSONResponse, int) {
	// Read metadata from query params to support GET /cms/segmen/list
	// Defaults (when empty): page=1, limit=10, offset=0, sort_order=desc

	req := webrequest.MetadataRequest{
		SearchParam: strings.TrimSpace(c.Query("search")),
		SortBy:      strings.TrimSpace(c.Query("sort_by")),
		SortOrder:   strings.TrimSpace(c.Query("sort_order")),
		Filters:     map[string]any{},
	}

	// Defaults: apply when param is empty or not parseable
	req.Page = 1
	req.Limit = 10
	req.Offset = 0
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	if v := strings.TrimSpace(c.Query("page")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Page = i
		}
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Limit = i
		}
	}
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Offset = i
		}
	}

	for key, vals := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filters_") || len(vals) == 0 {
			continue
		}
		filterKey := strings.TrimPrefix(key, "filters_")

		switch filterKey {
		case "is_active":
			// Boolean filters - take first value only
			val := strings.TrimSpace(vals[0])
			if val == "" {
				continue
			}
			b, err := strconv.ParseBool(val)
			if err == nil {
				req.Filters[filterKey] = b
			}
		default:
			// String filters - support multiple values
			var allValues []string
			for _, v := range vals {
				parts := strings.Split(v, ",")
				for _, part := range parts {
					trimmed := strings.TrimSpace(part)
					if trimmed != "" {
						allValues = append(allValues, trimmed)
					}
				}
			}
			if len(allValues) == 1 {
				req.Filters[filterKey] = allValues[0]
			} else if len(allValues) > 1 {
				req.Filters[filterKey] = allValues
			}
		}
	}

	if len(req.Filters) == 0 {
		req.Filters = nil
	}

	items, metadata, err := C.SegmenRepository.ListSegments(c.Request.Context(), req)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Berhasil mengambil data segmen",
		Data: map[string]any{
			"items":    items,
			"metadata": metadata,
		},
	}, http.StatusOK
}

//func (C *CMSServiceImpl) GetMissionDetail(c *gin.Context, missionID string) (webresponse.JSONResponse, int) {
//	//TODO implement me
//	panic("implement me")
//}

func (C *CMSServiceImpl) ListMissions(c *gin.Context) (webresponse.JSONResponse, int) {
	// Read metadata from query params to support GET /cms/mission/list
	// Defaults (when empty): page=1, limit=10, offset=0, sort_order=desc

	req := webrequest.MetadataRequest{
		SearchParam: strings.TrimSpace(c.Query("search")),
		SortBy:      strings.TrimSpace(c.Query("sort_by")),
		SortOrder:   strings.TrimSpace(c.Query("sort_order")),
		Filters:     map[string]any{},
	}

	// Defaults: apply when param is empty or not parseable
	req.Page = 1
	req.Limit = 10
	req.Offset = 0
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	if v := strings.TrimSpace(c.Query("page")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Page = i
		}
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Limit = i
		}
	}
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Offset = i
		}
	}

	for key, vals := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filters_") || len(vals) == 0 {
			continue
		}
		filterKey := strings.TrimPrefix(key, "filters_")

		// Keep typing minimal and explicit for known filters used by repository.
		switch filterKey {
		case "is_active", "is_scheduled":
			// Boolean filters - take first value only
			val := strings.TrimSpace(vals[0])
			if val == "" {
				continue
			}
			b, err := strconv.ParseBool(val)
			if err == nil {
				req.Filters[filterKey] = b
			}
		default:
			// String filters - support multiple values
			// Collect all values from multiple params and comma-separated values
			var allValues []string
			for _, v := range vals {
				// Split by comma for comma-separated values
				parts := strings.Split(v, ",")
				for _, part := range parts {
					trimmed := strings.TrimSpace(part)
					if trimmed != "" {
						allValues = append(allValues, trimmed)
					}
				}
			}
			if len(allValues) == 1 {
				// Single value - store as string for backward compatibility
				req.Filters[filterKey] = allValues[0]
			} else if len(allValues) > 1 {
				// Multiple values - store as []string
				req.Filters[filterKey] = allValues
			}
		}
	}

	if len(req.Filters) == 0 {
		req.Filters = nil
	}

	missions, metadata, err := C.MissionRepository.ListMissions(c.Request.Context(), req)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Berhasil mengambil data misi",
		Data: map[string]any{
			"items":    missions,
			"metadata": metadata,
		},
	}, http.StatusOK
}

func (C *CMSServiceImpl) CreateMission(c *gin.Context, request webrequest.CreateMissionRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	if request.ScheduledAt != nil && request.PublishedAt != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "scheduled_at dan published_at tidak boleh diisi bersamaan",
		}, http.StatusUnprocessableEntity
	}

	status := "draf"
	isActive := false
	isScheduled := false
	var scheduledAt time.Time
	var publishedAt time.Time

	if request.PublishedAt != nil {
		dateOnly, err := parseMissionDate(*request.PublishedAt)
		if err != nil {
			return webresponse.JSONResponse{Error: true, Message: "Format published_at harus DD-MM-YYYY"}, http.StatusUnprocessableEntity
		}

		now := time.Now().In(dateOnly.Location())
		publishedAt = time.Date(dateOnly.Year(), dateOnly.Month(), dateOnly.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), dateOnly.Location())
		status = "diterbitkan"
		isActive = true
	} else if request.ScheduledAt != nil {
		dateOnly, err := parseMissionDate(*request.ScheduledAt)
		if err != nil {
			return webresponse.JSONResponse{Error: true, Message: "Format scheduled_at harus DD-MM-YYYY"}, http.StatusUnprocessableEntity
		}

		scheduledAt = time.Date(dateOnly.Year(), dateOnly.Month(), dateOnly.Day(), 0, 0, 1, 0, dateOnly.Location())
		status = "terjadwal"
		isScheduled = true
	}

	mission := &coremodel.MMission{
		ID:           helper.GenerateUID(),
		MissionName:  strings.TrimSpace(request.MissionName),
		Status:       status,
		Instruction:  strings.TrimSpace(request.Instruction),
		RewardPoints: request.RewardPoints,
		IsActive:     isActive,
		IsScheduled:  isScheduled,
		MissionValue: request.MissionValue,
		MissionType:  strings.TrimSpace(request.MissionType),
		ScheduledAt:  scheduledAt,
		PublishedAt:  publishedAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := C.MissionRepository.CreateMission(c.Request.Context(), mission); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil membuat misi", Data: mission}, http.StatusOK
}

func (C *CMSServiceImpl) UpdateMission(c *gin.Context, request webrequest.UpdateMissionRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	mission, err := C.MissionRepository.GetMissionByID(c.Request.Context(), request.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return webresponse.JSONResponse{Error: true, Message: "Misi tidak ditemukan"}, http.StatusNotFound
		}
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	mission.MissionName = strings.TrimSpace(request.MissionName)
	mission.MissionType = strings.TrimSpace(request.MissionType)
	if request.Instruction != nil {
		mission.Instruction = strings.TrimSpace(*request.Instruction)
	}
	if request.RewardPoints != nil {
		mission.RewardPoints = *request.RewardPoints
	}
	if request.MissionValue != nil {
		mission.MissionValue = *request.MissionValue
	}
	mission.UpdatedAt = time.Now()

	if err := C.MissionRepository.UpdateMission(c.Request.Context(), mission); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil memperbarui misi", Data: mission}, http.StatusOK
}

func (C *CMSServiceImpl) ListCategories(c *gin.Context) (webresponse.JSONResponse, int) {
	// Read metadata from query params to support GET /cms/category/list
	// Defaults (when empty): page=1, limit=10, offset=0, sort_order=desc

	req := webrequest.MetadataRequest{
		SearchParam: strings.TrimSpace(c.Query("search")),
		SortBy:      strings.TrimSpace(c.Query("sort_by")),
		SortOrder:   strings.TrimSpace(c.Query("sort_order")),
		Filters:     map[string]any{},
	}

	// Defaults: apply when param is empty or not parseable
	req.Page = 1
	req.Limit = 10
	req.Offset = 0
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	if v := strings.TrimSpace(c.Query("page")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Page = i
		}
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Limit = i
		}
	}
	if v := strings.TrimSpace(c.Query("offset")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			req.Offset = i
		}
	}

	for key, vals := range c.Request.URL.Query() {
		if !strings.HasPrefix(key, "filters_") || len(vals) == 0 {
			continue
		}
		filterKey := strings.TrimPrefix(key, "filters_")

		switch filterKey {
		case "is_active":
			// Boolean filters - take first value only
			val := strings.TrimSpace(vals[0])
			if val == "" {
				continue
			}
			b, err := strconv.ParseBool(val)
			if err == nil {
				req.Filters[filterKey] = b
			}
		default:
			// String filters - support multiple values
			var allValues []string
			for _, v := range vals {
				parts := strings.Split(v, ",")
				for _, part := range parts {
					trimmed := strings.TrimSpace(part)
					if trimmed != "" {
						allValues = append(allValues, trimmed)
					}
				}
			}
			if len(allValues) == 1 {
				req.Filters[filterKey] = allValues[0]
			} else if len(allValues) > 1 {
				req.Filters[filterKey] = allValues
			}
		}
	}

	if len(req.Filters) == 0 {
		req.Filters = nil
	}

	items, metadata, err := C.CategoryRepository.ListCategories(c.Request.Context(), req)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Berhasil mengambil data kategori",
		Data: map[string]any{
			"items":    items,
			"metadata": metadata,
		},
	}, http.StatusOK
}

func (C *CMSServiceImpl) Login(c *gin.Context, request webrequest.LoginRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	userData, err := C.CMSRepository.GetUserByEmail(c.Request.Context(), request.Email)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email atau password salah",
		}, http.StatusUnauthorized
	}

	if !userData.LockedUntil.IsZero() && userData.LockedUntil.After(time.Now()) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Akun Anda terkunci sementara karena terlalu banyak percobaan login yang gagal. Silakan coba lagi nanti.",
		}, http.StatusUnauthorized
	}

	err = helper.CheckHashArgon2id(userData.PasswordHash, request.Password)
	if err != nil {
		tx := C.Query.Begin()

		userData.FailedLoginCount += 1
		if userData.FailedLoginCount >= 5 {
			userData.LockedUntil = time.Now().Add(time.Minute * 30)
		}

		err = C.CMSRepository.UpdateUser(c.Request.Context(), userData, nil, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Terjadi kesalahan pada server",
			}, http.StatusInternalServerError
		}

		tx.Commit()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email atau password salah",
		}, http.StatusUnauthorized
	}

	userData.FailedLoginCount = 0
	userData.LockedUntil = time.Time{}
	userData.LastLoginAt = time.Now()
	tx := C.Query.Begin()

	err = C.CMSRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
		C.Query.User.LockedUntil,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	uuid := helper.GenerateUID()

	err = C.CMSRepository.RevokeUserSessionsByUserID(c.Request.Context(), userData.ID, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	jti := helper.GenerateLoginJTI()

	// Generate access token
	accessToken, _ := helper.GenerateAccessToken(userData.ID, userData.Email, C.PasetoData)

	// Generate refresh token
	refreshToken, _, absoluteExp := helper.GenerateRefreshToken(userData.ID, jti, C.PasetoData)

	// Hash refresh token for storage
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)

	// Get client info
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := c.GetHeader("X-Device-ID")

	err = C.CMSRepository.CreateUserSession(c.Request.Context(), &model.UserSession{
		ID:           uuid,
		UserID:       userData.ID,
		SessionToken: refreshTokenHash,
		ExpiresAt:    absoluteExp,
		DeviceID:     deviceID,
		IP:           clientIP,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}, []field.Expr{}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Login berhasil",
		Data: map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	}, http.StatusOK
}

func (C *CMSServiceImpl) Logout(c *gin.Context) (webresponse.JSONResponse, int) {
	refreshToken := c.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		// Try to get from Authorization header
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			refreshToken = authHeader[7:]
		}
	}

	if refreshToken == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Refresh token tidak ditemukan",
		}, http.StatusBadRequest
	}

	// Decode the refresh token to get user info
	decodedToken, err := helper.DecodePasetoToken(refreshToken, C.PasetoData)
	if err != nil {
		// Even if token is invalid/expired, we consider logout successful
		// (user is already effectively logged out)
		return webresponse.JSONResponse{
			Error:   false,
			Message: "Logout berhasil",
		}, http.StatusOK
	}

	// Verify token type
	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "refresh" {
		return webresponse.JSONResponse{
			Error:   false,
			Message: "Logout berhasil",
		}, http.StatusOK
	}

	// Get user ID from token
	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return webresponse.JSONResponse{
			Error:   false,
			Message: "Logout berhasil",
		}, http.StatusOK
	}

	// Find the session by refresh token hash
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)
	session, err := C.CMSRepository.GetSessionByRefreshTokenHash(c.Request.Context(), refreshTokenHash)
	if err != nil || session == nil {
		// Session not found or already revoked, consider logout successful
		return webresponse.JSONResponse{
			Error:   false,
			Message: "Logout berhasil",
		}, http.StatusOK
	}

	// Revoke the session
	tx := C.Query.Begin()
	err = C.CMSRepository.RevokeUserSessionsByUserID(c.Request.Context(), userID, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada server",
		}, http.StatusInternalServerError
	}
	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Logout berhasil",
	}, http.StatusOK
}

func (C *CMSServiceImpl) RefreshToken(c *gin.Context) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	refreshToken := c.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Refresh token tidak ditemukan",
		}, http.StatusBadRequest
	}

	decodedToken, err := helper.DecodePasetoToken(refreshToken, C.PasetoData)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Refresh token tidak valid atau sudah kadaluarsa",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "refresh" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)
	session, err := C.CMSRepository.GetSessionByRefreshTokenHash(c.Request.Context(), refreshTokenHash)
	if err != nil || session == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi tidak ditemukan atau sudah berakhir",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	if session.UserID != userID {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi telah berakhir, silakan login ulang",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	userQuery := C.Query.User
	userData, err := userQuery.WithContext(c.Request.Context()).Where(userQuery.ID.Eq(userID)).First()
	if err != nil || userData == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Pengguna tidak ditemukan",
		}, http.StatusUnauthorized
	}

	newJti := helper.GenerateLoginJTI()
	newAccessToken, _ := helper.GenerateAccessToken(userData.ID, userData.Email, C.PasetoData)
	newRefreshToken, _, newAbsoluteExp := helper.GenerateRefreshToken(userData.ID, newJti, C.PasetoData)
	newRefreshTokenHash := helper.GenerateHMACSHA256(newRefreshToken)

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := c.GetHeader("X-Device-ID")

	tx := C.Query.Begin()
	if err = C.CMSRepository.RevokeUserSessionsByUserID(c.Request.Context(), userID, tx); err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal memperbarui token",
		}, http.StatusInternalServerError
	}

	newSession := &model.UserSession{
		ID:           helper.GenerateUID(),
		UserID:       userData.ID,
		SessionToken: newRefreshTokenHash,
		ExpiresAt:    newAbsoluteExp,
		DeviceID:     deviceID,
		IP:           clientIP,
		UserAgent:    userAgent,
		CreatedAt:    now,
	}
	if err = C.CMSRepository.CreateUserSession(c.Request.Context(), newSession, []field.Expr{}, tx); err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal memperbarui token",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Token berhasil diperbarui",
		Data: webresponse.TokenResponse{
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
		},
	}, http.StatusOK
}

func (C *CMSServiceImpl) CreateSegmen(c *gin.Context, request webrequest.CreateSegmenRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	isActive := request.GetIsActiveOrDefault(true)
	logger.AppLogger.Info().
		Str("is_active_raw", string(request.IsActiveRaw)).
		Bool("is_active_parsed", isActive).
		Msg("create_segmen_is_active")

	segmen := &coremodel.MSegman{
		ID:          helper.GenerateUID(),
		SegmenName:  strings.TrimSpace(request.SegmenName),
		Description: strings.TrimSpace(request.Description),
		IsActive:    isActive,
		Symbol:      strings.TrimSpace(request.Symbol),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := C.SegmenRepository.CreateSegmen(c.Request.Context(), segmen); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil membuat segmen", Data: segmen}, http.StatusOK
}

func (C *CMSServiceImpl) UpdateSegmen(c *gin.Context, request webrequest.UpdateSegmenRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	segmen, err := C.SegmenRepository.GetSegmenByID(c.Request.Context(), request.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return webresponse.JSONResponse{Error: true, Message: "Segmen tidak ditemukan"}, http.StatusNotFound
		}
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	segmen.SegmenName = strings.TrimSpace(request.SegmenName)
	segmen.Description = strings.TrimSpace(request.Description)
	segmen.Symbol = strings.TrimSpace(request.Symbol)
	if b := request.GetIsActiveOrNil(); b != nil {
		segmen.IsActive = *b
	}
	segmen.UpdatedAt = time.Now()

	if err := C.SegmenRepository.UpdateSegmen(c.Request.Context(), segmen); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil memperbarui segmen", Data: segmen}, http.StatusOK
}

func (C *CMSServiceImpl) DeleteSegmen(c *gin.Context, request webrequest.DeleteBulkRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{Error: true, Message: "Pastikan semua data terisi dengan benar", ErrorList: validate}, http.StatusUnprocessableEntity
	}

	type deleteLog struct {
		ID      string `json:"id"`
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}

	logs := make([]deleteLog, 0, len(request.IDs))
	errCount := 0

	for _, rawID := range request.IDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			errCount++
			logs = append(logs, deleteLog{ID: rawID, Success: false, Error: "id kosong"})
			continue
		}

		err := C.SegmenRepository.DeleteSegmenByID(c.Request.Context(), id)
		if err != nil {
			errCount++
			logs = append(logs, deleteLog{ID: id, Success: false, Error: err.Error()})
			logger.AppLogger.Error().Err(err).Str("segmen_id", id).Msg("delete_segmen_failed")
			continue
		}
		logs = append(logs, deleteLog{ID: id, Success: true})
	}

	msg := "Delete successful"
	if errCount > 0 {
		msg = "delete successful with " + strconv.Itoa(errCount) + " error"
	}

	return webresponse.JSONResponse{Error: false, Message: msg, LogList: logs}, http.StatusOK
}

func (C *CMSServiceImpl) CreateCategory(c *gin.Context, request webrequest.CreateCategoryRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{Error: true, Message: "Pastikan semua data terisi dengan benar", ErrorList: validate}, http.StatusUnprocessableEntity
	}

	isActive := true
	if request.IsActive != nil {
		isActive = *request.IsActive
	}

	category := &coremodel.MCategory{
		ID:               helper.GenerateUID(),
		CategoryName:     strings.TrimSpace(request.CategoryName),
		GoogleCategoryID: strings.TrimSpace(request.GoogleCategoryID),
		Description:      strings.TrimSpace(request.Description),
		IsActive:         isActive,
		Symbol:           strings.TrimSpace(request.Symbol),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := C.CategoryRepository.CreateCategory(c.Request.Context(), category); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil membuat kategori", Data: category}, http.StatusOK
}

func (C *CMSServiceImpl) UpdateCategory(c *gin.Context, request webrequest.UpdateCategoryRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{Error: true, Message: "Pastikan semua data terisi dengan benar", ErrorList: validate}, http.StatusUnprocessableEntity
	}

	category, err := C.CategoryRepository.GetCategoryByID(c.Request.Context(), request.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return webresponse.JSONResponse{Error: true, Message: "Kategori tidak ditemukan"}, http.StatusNotFound
		}
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	category.CategoryName = strings.TrimSpace(request.CategoryName)
	category.GoogleCategoryID = strings.TrimSpace(request.GoogleCategoryID)
	category.Description = strings.TrimSpace(request.Description)
	category.Symbol = strings.TrimSpace(request.Symbol)
	if request.IsActive != nil {
		category.IsActive = *request.IsActive
	}
	category.UpdatedAt = time.Now()

	if err := C.CategoryRepository.UpdateCategory(c.Request.Context(), category); err != nil {
		return webresponse.JSONResponse{Error: true, Message: "Terjadi kesalahan pada server"}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{Error: false, Message: "Berhasil memperbarui kategori", Data: category}, http.StatusOK
}

func (C *CMSServiceImpl) DeleteCategory(c *gin.Context, request webrequest.DeleteBulkRequest) (webresponse.JSONResponse, int) {
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{Error: true, Message: "Pastikan semua data terisi dengan benar", ErrorList: validate}, http.StatusUnprocessableEntity
	}

	type deleteLog struct {
		ID      string `json:"id"`
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}

	logs := make([]deleteLog, 0, len(request.IDs))
	errCount := 0

	for _, rawID := range request.IDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			errCount++
			logs = append(logs, deleteLog{ID: rawID, Success: false, Error: "id kosong"})
			continue
		}

		err := C.CategoryRepository.DeleteCategoryByID(c.Request.Context(), id)
		if err != nil {
			errCount++
			logs = append(logs, deleteLog{ID: id, Success: false, Error: err.Error()})
			logger.AppLogger.Error().Err(err).Str("category_id", id).Msg("delete_category_failed")
			continue
		}
		logs = append(logs, deleteLog{ID: id, Success: true})
	}

	msg := "Delete successful"
	if errCount > 0 {
		msg = "delete successful with " + strconv.Itoa(errCount) + " error"
	}

	return webresponse.JSONResponse{Error: false, Message: msg, LogList: logs}, http.StatusOK
}

func NewCMSService(repository cms_repository.CMSRepository, missionRepository mission_repository.MissionRepository, segmenRepository segmen_repository.SegmenRepository, categoryRepository category_repository.CategoryRepository, query *modelcms.Query, itemData data.PasetoItemData) CMSService {
	// NOTE: CMS uses cms DB (query) for auth. Missions live in core DB (gen/core).
	// Route.InitRoutes already has core query (Q) available; if needed we can
	// refactor constructor to accept it. For now we keep existing signature.
	return &CMSServiceImpl{
		CMSRepository:      repository,
		MissionRepository:  missionRepository,
		SegmenRepository:   segmenRepository,
		CategoryRepository: categoryRepository,
		Query:              query,
		PasetoData:         itemData,
	}
}
