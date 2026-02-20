package auth_service

import (
	"context"
	"errors"
	"net/http"
	"provid-backend/gen/core/model"
	model2 "provid-backend/gen/core/query"
	userRepository "provid-backend/internal/app/repository/user-repository"
	"provid-backend/internal/emailclient"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gen/field"
)

type AuthServiceImpl struct {
	EmailClient    *emailclient.Client
	AuthRepository userRepository.AuthRepository
	Query          *model2.Query
	PasetoData     data.PasetoItemData
}

const resendLimitCount = 5
const timeLimitCooldown = time.Minute * 15

func (a *AuthServiceImpl) Logout(c *gin.Context) (webresponse.JSONResponse, int) {
	// Get refresh token from header or request body
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
	decodedToken, err := helper.DecodePasetoToken(refreshToken, a.PasetoData)
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
	session, err := a.AuthRepository.GetSessionByRefreshTokenHash(c.Request.Context(), refreshTokenHash)
	if err != nil || session == nil {
		// Session not found or already revoked, consider logout successful
		return webresponse.JSONResponse{
			Error:   false,
			Message: "Logout berhasil",
		}, http.StatusOK
	}

	// Revoke the session
	tx := a.Query.Begin()
	now := helper.GetCurrentTime()

	session.RevokedAt = now
	session.RevokeReason = "user_logout"

	err = a.AuthRepository.UpdateUserSession(c.Request.Context(), session, []field.Expr{
		a.Query.UserSession.CreatedAt,
		a.Query.UserSession.RefreshTokenHash,
		a.Query.UserSession.DeviceID,
		a.Query.UserSession.IP,
		a.Query.UserSession.UserAgent,
		a.Query.UserSession.IdleExpiresAt,
		a.Query.UserSession.ExpiresAt,
		a.Query.UserSession.RotatedFromSessionID,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan logout",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Logout berhasil",
	}, http.StatusOK
}

func (a *AuthServiceImpl) ChangePassword(c *gin.Context, request webrequest.ChangePasswordRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Validate input
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	// Verify the token from password reset flow
	hashedToken := helper.GenerateHMACSHA256(request.Token)
	otpRecord, err := a.AuthRepository.GetOTPRequestByTokenAndPurpose(c.Request.Context(), hashedToken, "change_password")
	if err != nil || otpRecord == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid atau sudah kadaluarsa",
		}, http.StatusBadRequest
	}

	// Check if token is expired
	if otpRecord.ExpiresAt.Before(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token sudah kadaluarsa",
		}, http.StatusBadRequest
	}

	// Check if token was already consumed
	if !otpRecord.ConsumedAt.IsZero() {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token sudah digunakan",
		}, http.StatusBadRequest
	}

	// Get user data
	userData, err := a.AuthRepository.GetUserByUID(c.Request.Context(), otpRecord.UserID)
	if err != nil || userData == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "User tidak ditemukan",
		}, http.StatusNotFound
	}

	// Get current password credentials
	passwordCreds, err := a.AuthRepository.GetPasswordCredentialsByUserID(c.Request.Context(), userData.ID)
	if err != nil || passwordCreds == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengubah password",
		}, http.StatusInternalServerError
	}

	// Hash new password using Argon2id
	hashedPassword, err := helper.GenerateHashArgon2id(request.Password)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengubah password",
		}, http.StatusInternalServerError
	}

	tx := a.Query.Begin()

	// Update password credentials
	passwordCreds.PasswordHash = hashedPassword
	passwordCreds.PasswordUpdatedAt = now
	passwordCreds.MustChangePassword = false

	err = a.AuthRepository.UpdatePasswordCredentials(c.Request.Context(), passwordCreds, []field.Expr{
		a.Query.UserPasswordCredential.CreatedAt,
		a.Query.UserPasswordCredential.UpdatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengubah password",
		}, http.StatusInternalServerError
	}

	// Mark the OTP token as consumed
	otpRecord.ConsumedAt = now
	err = a.AuthRepository.UpdateOTPRequest(c.Request.Context(), otpRecord, []field.Expr{
		a.Query.OtpRequest.CreatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengubah password",
		}, http.StatusInternalServerError
	}

	// Revoke all existing sessions for security (force re-login with new password)
	err = a.AuthRepository.RevokeUserSessionsByUserID(c.Request.Context(), userData.ID, "password_changed", tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengubah password",
		}, http.StatusInternalServerError
	}

	// Reset any account lockout
	if userData.LockedUntil.After(time.Time{}) || userData.FailedLoginCount > 0 {
		userData.LockedUntil = time.Time{}
		userData.FailedLoginCount = 0
		err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
			a.Query.User.UpdatedAt,
			a.Query.User.PinSetAt,
			a.Query.User.OnboardingCompletedAt,
			a.Query.User.EmailVerifiedAt,
			a.Query.User.LastLoginAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal mengubah password",
			}, http.StatusInternalServerError
		}
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Password berhasil diubah, silakan login kembali",
	}, http.StatusOK
}

func (a *AuthServiceImpl) ValidateOTP(c *gin.Context, request webrequest.ValidateOTPRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Validate input
	if request.OTP == "" || request.Email == "" || request.Purpose == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "OTP, email, dan purpose harus diisi",
		}, http.StatusBadRequest
	}

	// Validate purpose
	if request.Purpose != "verify_email" && request.Purpose != "password_reset" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Purpose tidak valid",
		}, http.StatusBadRequest
	}

	tx := a.Query.Begin()
	otpRecord, err := a.AuthRepository.GetOTPRequestByEmailAndPurpose(c.Request.Context(), request.Email, request.Purpose)
	if err != nil || otpRecord == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "OTP tidak valid",
		}, http.StatusBadRequest
	}

	// Check if OTP was already consumed
	if !otpRecord.ConsumedAt.IsZero() {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "OTP sudah digunakan",
		}, http.StatusBadRequest
	}

	if otpRecord.ExpiresAt.Before(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "OTP sudah kadaluarsa",
		}, http.StatusBadRequest
	}

	if otpRecord.Attempts >= otpRecord.MaxAttempts {
		go func() {
			// wait for 15 minute
			time.Sleep(timeLimitCooldown)

			tx := a.Query.Begin()
			_, err := a.AuthRepository.DeleteOTPRequestByID(context.Background(), otpRecord.ID, request.Purpose)
			if err != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "Batas percobaan OTP telah terlampaui",
		}, http.StatusTooManyRequests
	}

	isValidOTP := helper.VerifyHMACSHA256(request.OTP, otpRecord.OtpHash)
	otpRecord.Attempts += 1
	otpRecord.LastAttemptAt = now
	if !isValidOTP {
		err = a.AuthRepository.UpdateOTPRequest(c.Request.Context(), otpRecord, []field.Expr{
			a.Query.OtpRequest.CreatedAt,
		}, tx)
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
			Message: "OTP tidak valid",
		}, http.StatusBadRequest
	}

	otpRecord.ConsumedAt = now

	//var tokenNew string
	var webRes webresponse.JSONResponse

	if request.Purpose == "verify_email" {
		err = a.AuthRepository.UpdateOTPRequest(c.Request.Context(), otpRecord, []field.Expr{
			a.Query.OtpRequest.CreatedAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		// update email verified
		userData, err := a.AuthRepository.GetUserByEmail(c.Request.Context(), request.Email)
		if err != nil || userData == nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		userData.EmailVerifiedAt = now
		//userData.Status = "active"
		err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
			a.Query.User.UpdatedAt,
			a.Query.User.PinSetAt,
			a.Query.User.OnboardingCompletedAt,
			a.Query.User.LockedUntil,
			a.Query.User.LastLoginAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		// Clean up any expired challenges for this user
		_ = a.AuthRepository.DeleteExpiredAuthChallenges(c.Request.Context(), userData.ID)

		// Generate JTI for challenge token
		jti := helper.GenerateLoginJTI()
		jtiHash := helper.GenerateHMACSHA256(jti)

		// Generate challenge token for PIN registration
		challengeToken, challengeExp := helper.GenerateChallengeToken(userData.ID, jti, "register_pin", a.PasetoData)

		// Get client info
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Create auth challenge record
		err = a.AuthRepository.CreateAuthChallenge(c.Request.Context(), &model.AuthChallenge{
			ID:         "",
			UserID:     userData.ID,
			Purpose:    "register_pin",
			JtiHash:    jtiHash,
			ExpiresAt:  challengeExp,
			ConsumedAt: time.Time{},
			IP:         clientIP,
			UserAgent:  userAgent,
			CreatedAt:  now,
		}, []field.Expr{
			a.Query.AuthChallenge.ID,
			a.Query.AuthChallenge.ConsumedAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		webRes = webresponse.JSONResponse{
			Error:   false,
			Message: "Email berhasil diverifikasi",
			Data: map[string]interface{}{
				"challenge_token": challengeToken,
				"expires_in":      int(helper.ChallengeTokenDuration.Seconds()),
			},
		}
	} else if request.Purpose == "password_reset" {
		err = a.AuthRepository.UpdateOTPRequest(c.Request.Context(), otpRecord, []field.Expr{
			a.Query.OtpRequest.CreatedAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		userData, err := a.AuthRepository.GetUserByEmail(c.Request.Context(), request.Email)
		if err != nil || userData == nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		oneTimeCode, err := helper.GenerateToken(24)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		hashedOTP := helper.GenerateHMACSHA256(oneTimeCode)

		otpModel := model.OtpRequest{
			ID:            "",
			UserID:        userData.ID,
			Email:         userData.Email,
			Purpose:       "change_password",
			OtpHash:       hashedOTP,
			ExpiresAt:     now.Add(time.Minute * 15),
			ConsumedAt:    time.Time{},
			Attempts:      0,
			MaxAttempts:   5,
			LastAttemptAt: time.Time{},
			SendCount:     0,
			IP:            clientIP,
			UserAgent:     userAgent,
			CreatedAt:     now,
		}
		err = a.AuthRepository.CreateOTPRequest(context.Background(), &otpModel, []field.Expr{
			a.Query.OtpRequest.ConsumedAt,
			a.Query.OtpRequest.LastAttemptAt,
			a.Query.OtpRequest.ID,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal memvalidasi OTP",
			}, http.StatusInternalServerError
		}

		webRes = webresponse.JSONResponse{
			Error:   false,
			Message: "OTP berhasil divalidasi",
			Data: map[string]interface{}{
				"token": oneTimeCode,
			},
		}
	}

	tx.Commit()

	return webRes, http.StatusOK
}

func (a *AuthServiceImpl) SendOTP(c *gin.Context, request webrequest.OTPRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()
	if request.Purpose != "verify_email" && request.Purpose != "password_reset" && request.Purpose != "change_email" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengirim OTP",
		}, http.StatusInternalServerError
	}

	oldRec, err := a.AuthRepository.GetOTPRequestByEmailAndPurpose(c.Request.Context(), request.Mail, request.Purpose)
	if err == nil && oldRec != nil {
		// Check if OTP was already consumed
		if !oldRec.ConsumedAt.IsZero() {
			// OTP already used, delete and allow creating new one
			_, _ = a.AuthRepository.DeleteOTPRequestByID(c.Request.Context(), oldRec.ID, request.Purpose)
			oldRec = nil
		} else if oldRec.SendCount >= resendLimitCount {
			// Rate limit exceeded - schedule cleanup and return error
			go func() {
				// wait for cooldown period before allowing new OTP
				time.Sleep(timeLimitCooldown)

				_, _ = a.AuthRepository.DeleteOTPRequestByID(context.Background(), oldRec.ID, request.Purpose)
			}()

			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal mengirim OTP, batas pengiriman OTP telah tercapai",
			}, http.StatusTooManyRequests
		}
	}

	otpArr, err := helper.GenerateOTP(6)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengirim OTP",
		}, http.StatusInternalServerError
	}

	otp := otpArr[6]
	hashedOTP := helper.GenerateHMACSHA256(otp)

	userData, err := a.AuthRepository.GetUserByEmail(context.Background(), request.Mail)
	if err != nil || userData == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengirim OTP",
		}, http.StatusInternalServerError
	}

	userProfile, err := a.AuthRepository.GetUserProfileByUserID(context.Background(), userData.ID)
	if err != nil || userProfile == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengirim OTP",
		}, http.StatusInternalServerError
	}

	tx := a.Query.Begin()

	// Get client IP and UserAgent
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	var otpModel model.OtpRequest

	if oldRec == nil || oldRec.ExpiresAt.Before(now) {
		if oldRec != nil {
			res, err := a.AuthRepository.DeleteOTPRequestByID(c.Request.Context(), oldRec.ID, request.Purpose)
			if err != nil || res.RowsAffected == 0 {
				tx.Rollback()
				return webresponse.JSONResponse{
					Error:   true,
					Message: "Gagal mengirim OTP",
				}, http.StatusInternalServerError
			}
		}

		otpModel = model.OtpRequest{
			ID:            "",
			UserID:        userData.ID,
			Email:         request.Mail,
			Purpose:       request.Purpose,
			OtpHash:       hashedOTP,
			ExpiresAt:     now.Add(time.Minute * 15),
			ConsumedAt:    time.Time{},
			Attempts:      0,
			MaxAttempts:   5,
			LastAttemptAt: time.Time{},
			SendCount:     1, // First send
			IP:            clientIP,
			UserAgent:     userAgent,
			CreatedAt:     now,
		}
		err = a.AuthRepository.CreateOTPRequest(context.Background(), &otpModel, []field.Expr{
			a.Query.OtpRequest.ConsumedAt,
			a.Query.OtpRequest.LastAttemptAt,
			a.Query.OtpRequest.ID,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal mengirim OTP",
			}, http.StatusInternalServerError
		}
	} else {
		otpModel = model.OtpRequest{
			ID:            oldRec.ID,
			UserID:        oldRec.UserID,
			Email:         request.Mail,
			Purpose:       request.Purpose,
			OtpHash:       hashedOTP,
			ExpiresAt:     now.Add(time.Minute * 15),
			ConsumedAt:    oldRec.ConsumedAt,
			Attempts:      0,
			MaxAttempts:   5,
			LastAttemptAt: oldRec.LastAttemptAt,
			SendCount:     oldRec.SendCount + 1,
			IP:            clientIP,
			UserAgent:     userAgent,
			CreatedAt:     oldRec.CreatedAt,
		}
		err = a.AuthRepository.UpdateOTPRequest(c.Request.Context(), &otpModel, []field.Expr{
			a.Query.OtpRequest.CreatedAt,
			a.Query.OtpRequest.ConsumedAt,
			a.Query.OtpRequest.LastAttemptAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal mengirim OTP",
			}, http.StatusInternalServerError
		}
	}

	tx.Commit()

	// Determine template name based on purpose
	templateName := "verify_email_otp"
	if request.Purpose == "password_reset" {
		templateName = "forgot_otp"
	}

	title := "Verifikasi Email"
	if request.Purpose == "password_reset" {
		title = "Reset Password"
	}

	// Send email using external email service
	_, err = a.EmailClient.SendEmail(c.Request.Context(), emailclient.SendEmailRequest{
		TemplateName: templateName,
		Email:        request.Mail,
		Data: map[string]interface{}{
			"FullName": userProfile.FullName,
			"Otp":      otp,
			"Email":    request.Mail,
			"Title":    title,
		},
	})
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal mengirim OTP",
		}, http.StatusInternalServerError
	}

	return webresponse.JSONResponse{
		Error:   false,
		Message: "OTP berhasil dikirim",
	}, http.StatusOK
}

func (a *AuthServiceImpl) LoginPassword(c *gin.Context, request webrequest.LoginRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Validate input
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	// Get user by email
	userData, err := a.AuthRepository.GetUserByEmail(c.Request.Context(), request.Email)
	if err != nil || userData == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email atau password salah",
		}, http.StatusUnauthorized
	}

	// Check if user is locked out
	if !userData.LockedUntil.IsZero() && userData.LockedUntil.After(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Akun Anda terkunci sementara. Silakan coba lagi nanti",
		}, http.StatusTooManyRequests
	}

	// Get password credentials
	passwordCreds, err := a.AuthRepository.GetPasswordCredentialsByUserID(c.Request.Context(), userData.ID)
	if err != nil || passwordCreds == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email atau password salah",
		}, http.StatusUnauthorized
	}

	// Verify password using Argon2id
	err = helper.CheckHashArgon2id(passwordCreds.PasswordHash, request.Password)
	if err != nil {
		// Increment failed login count
		tx := a.Query.Begin()
		userData.FailedLoginCount += 1

		// Lock account after 5 failed attempts for 15 minutes
		if userData.FailedLoginCount >= 5 {
			userData.LockedUntil = now.Add(timeLimitCooldown)
		}

		_ = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
			a.Query.User.UpdatedAt,
			a.Query.User.Status,
			a.Query.User.PinSetAt,
			a.Query.User.OnboardingCompletedAt,
			a.Query.User.LastLoginAt,
			a.Query.User.EmailVerifiedAt,
		}, tx)
		tx.Commit()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email atau password salah",
		}, http.StatusUnauthorized
	}

	// Check if email is verified
	if userData.EmailVerifiedAt.IsZero() {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email belum terverifikasi harap verifikasi email terlebih dahulu",
			Data: map[string]interface{}{
				"type": "verify_email",
			},
		}, http.StatusForbidden
	}

	// Check if PIN is registered
	userPin, _ := a.AuthRepository.GetUserPinByUserID(c.Request.Context(), userData.ID)
	if userPin == nil {
		// PIN not registered - generate challenge token for PIN registration
		tx := a.Query.Begin()

		// Clean up any expired challenges for this user
		_ = a.AuthRepository.DeleteExpiredAuthChallenges(c.Request.Context(), userData.ID)

		// Invalidate any existing register_pin challenges for this user
		_ = a.AuthRepository.InvalidateAuthChallengesByUserAndPurpose(c.Request.Context(), userData.ID, "register_pin", tx)

		// Generate JTI for challenge token
		jti := helper.GenerateLoginJTI()
		jtiHash := helper.GenerateHMACSHA256(jti)

		// Generate challenge token for PIN registration
		challengeToken, challengeExp := helper.GenerateChallengeToken(userData.ID, jti, "register_pin", a.PasetoData)

		// Get client info
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Create auth challenge record
		err = a.AuthRepository.CreateAuthChallenge(c.Request.Context(), &model.AuthChallenge{
			ID:         "",
			UserID:     userData.ID,
			Purpose:    "register_pin",
			JtiHash:    jtiHash,
			ExpiresAt:  challengeExp,
			ConsumedAt: time.Time{},
			IP:         clientIP,
			UserAgent:  userAgent,
			CreatedAt:  now,
		}, []field.Expr{
			a.Query.AuthChallenge.ID,
			a.Query.AuthChallenge.ConsumedAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal melakukan login",
			}, http.StatusInternalServerError
		}

		// Reset failed login count (password was correct)
		userData.FailedLoginCount = 0
		userData.LockedUntil = time.Time{}

		err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
			a.Query.User.UpdatedAt,
			a.Query.User.PinSetAt,
			a.Query.User.Status,
			a.Query.User.OnboardingCompletedAt,
			a.Query.User.EmailVerifiedAt,
			a.Query.User.LastLoginAt,
		}, tx)
		if err != nil {
			tx.Rollback()
			return webresponse.JSONResponse{
				Error:   true,
				Message: "Gagal melakukan login",
			}, http.StatusInternalServerError
		}

		tx.Commit()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "PIN belum terdaftar, harap daftarkan PIN terlebih dahulu",
			Data: map[string]interface{}{
				"type":            "pin_registration",
				"challenge_token": challengeToken,
				"expires_in":      int(helper.ChallengeTokenDuration.Seconds()),
			},
		}, http.StatusForbidden
	}

	// Password verification passed - now generate challenge token for PIN verification
	tx := a.Query.Begin()

	// Clean up any expired challenges for this user
	_ = a.AuthRepository.DeleteExpiredAuthChallenges(c.Request.Context(), userData.ID)

	// Generate JTI for challenge token
	jti := helper.GenerateLoginJTI()
	jtiHash := helper.GenerateHMACSHA256(jti)

	// Generate challenge token
	challengeToken, challengeExp := helper.GenerateChallengeToken(userData.ID, jti, "login_pin", a.PasetoData)

	// Get client info
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	// Create auth challenge record
	err = a.AuthRepository.CreateAuthChallenge(c.Request.Context(), &model.AuthChallenge{
		ID:         "",
		UserID:     userData.ID,
		Purpose:    "login_pin",
		JtiHash:    jtiHash,
		ExpiresAt:  challengeExp,
		ConsumedAt: time.Time{},
		IP:         clientIP,
		UserAgent:  userAgent,
		CreatedAt:  now,
	}, []field.Expr{
		a.Query.AuthChallenge.ID,
		a.Query.AuthChallenge.ConsumedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan login",
		}, http.StatusInternalServerError
	}

	// Reset failed login count (password was correct)
	userData.FailedLoginCount = 0
	userData.LockedUntil = time.Time{}

	err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
		a.Query.User.UpdatedAt,
		a.Query.User.PinSetAt,
		a.Query.User.Status,
		a.Query.User.OnboardingCompletedAt,
		a.Query.User.EmailVerifiedAt,
		a.Query.User.LastLoginAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan login",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Verifikasi password berhasil, silakan masukkan PIN",
		Data: map[string]interface{}{
			"challenge_token": challengeToken,
			"expires_in":      int(helper.ChallengeTokenDuration.Seconds()),
		},
	}, http.StatusOK
}

func (a *AuthServiceImpl) Register(c *gin.Context, request webrequest.RegisterRequest) (webresponse.JSONResponse, int) {
	if request.Step == 1 {
		validate := request.ValidateStep1()

		user, err := a.AuthRepository.GetUserByEmail(c.Request.Context(), request.Email)
		if err == nil && user != nil {
			validate = append(validate, data.ValidationErrorData{
				Field:   "email",
				Message: "Email sudah terdaftar",
			})
		}

		if len(validate) != 0 {
			return webresponse.JSONResponse{
				Error:     true,
				Message:   "Pastikan semua data terisi dengan benar",
				ErrorList: validate,
			}, http.StatusUnprocessableEntity
		}

		return webresponse.JSONResponse{
			Error:   false,
			Message: "Registrasi tahap pertama berhasil",
		}, http.StatusOK
	} else if request.Step == 2 {
		validate := request.ValidateStep2()
		if len(validate) != 0 {
			return webresponse.JSONResponse{
				Error:     true,
				Message:   "Pastikan semua data terisi dengan benar",
				ErrorList: validate,
			}, http.StatusUnprocessableEntity
		}
	} else {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Terjadi kesalahan pada proses registrasi",
		}, http.StatusBadRequest
	}

	tx := a.Query.Begin()

	userId := helper.GenerateUID()
	err := a.AuthRepository.CreateUser(c.Request.Context(), &model.User{
		ID:                    userId,
		Email:                 request.Email,
		EmailVerifiedAt:       time.Time{},
		Status:                "pending",
		PasswordSetAt:         helper.GetCurrentTime(),
		PinSetAt:              time.Time{},
		OnboardingCompletedAt: time.Time{},
		FailedLoginCount:      0,
		LockedUntil:           time.Time{},
		LastLoginAt:           time.Time{},
		CreatedAt:             helper.GetCurrentTime(),
		UpdatedAt:             time.Time{},
	}, []field.Expr{
		a.Query.User.EmailVerifiedAt,
		a.Query.User.PinSetAt,
		a.Query.User.OnboardingCompletedAt,
		a.Query.User.FailedLoginCount,
		a.Query.User.LockedUntil,
		a.Query.User.LastLoginAt,
		a.Query.User.CreatedAt,
		a.Query.User.UpdatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat akun baru",
		}, http.StatusInternalServerError
	}

	err = a.AuthRepository.CreateUserIdentity(c.Request.Context(), &model.UserIdentity{
		ID:                    "",
		UserID:                userId,
		Provider:              "password",
		ProviderSubject:       "",
		ProviderEmail:         "",
		ProviderEmailVerified: false,
		CreatedAt:             helper.GetCurrentTime(),
	}, []field.Expr{
		a.Query.UserIdentity.ID,
		a.Query.UserIdentity.ProviderSubject,
		a.Query.UserIdentity.ProviderEmail,
		a.Query.UserIdentity.ProviderEmailVerified,
	}, tx)

	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat akun baru",
		}, http.StatusInternalServerError
	}

	// Create User Profile
	birthDate, _ := helper.ParseDateDefault(request.Date)
	err = a.AuthRepository.CreateUserProfile(c.Request.Context(), &model.UserProfile{
		UserID:    userId,
		FullName:  request.Fullname,
		Birthdate: birthDate,
		CreatedAt: helper.GetCurrentTime(),
		UpdatedAt: time.Time{},
	}, []field.Expr{
		a.Query.UserProfile.UpdatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat akun baru",
		}, http.StatusInternalServerError
	}

	hashedPassword, err := helper.GenerateHashArgon2id(request.Password)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat akun baru",
		}, http.StatusInternalServerError
	}
	err = a.AuthRepository.CreatePasswordCredentials(c.Request.Context(), &model.UserPasswordCredential{
		UserID:             userId,
		PasswordHash:       hashedPassword,
		PasswordAlgo:       "argon2id",
		PasswordUpdatedAt:  time.Time{},
		MustChangePassword: false,
		CreatedAt:          helper.GetCurrentTime(),
		UpdatedAt:          time.Time{},
	}, []field.Expr{
		a.Query.UserPasswordCredential.PasswordUpdatedAt,
		a.Query.UserPasswordCredential.UpdatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat akun baru",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	//go func(ctx *gin.Context, userId, purpose, mailTo string) {
	a.SendOTP(c, webrequest.OTPRequest{
		UserID:  userId,
		Purpose: "verify_email",
		Mail:    request.Email,
	})
	//}(c.Copy(), userId, "verify_email", request.Email)

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Registrasi berhasil",
	}, http.StatusOK
}

func NewAuthService(authRepo userRepository.AuthRepository, emailClient *emailclient.Client, query *model2.Query, pasetoData data.PasetoItemData) AuthService {
	return &AuthServiceImpl{
		EmailClient:    emailClient,
		AuthRepository: authRepo,
		Query:          query,
		PasetoData:     pasetoData,
	}
}

func (a *AuthServiceImpl) RegisterPIN(c *gin.Context, request webrequest.RegisterPINRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Validate input
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	// Validate the challenge token
	userData, err := a.validateRegisterPINChallengeToken(c, request.ChallengeToken, request.Email)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: err.Error(),
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Check if email is verified before allowing PIN registration
	if userData.EmailVerifiedAt.IsZero() {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Email harus diverifikasi terlebih dahulu",
		}, http.StatusBadRequest
	}

	// Check if PIN already exists
	existingPin, _ := a.AuthRepository.GetUserPinByUserID(c.Request.Context(), userData.ID)
	if existingPin != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "PIN sudah terdaftar",
		}, http.StatusConflict
	}

	// Hash PIN using argon2id
	hashedPin, err := helper.GenerateHashArgon2id(request.PIN)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat PIN",
		}, http.StatusInternalServerError
	}

	tx := a.Query.Begin()

	// Consume the challenge token
	decodedToken, _ := helper.DecodePasetoToken(request.ChallengeToken, a.PasetoData)
	if decodedToken != nil {
		jti, _ := decodedToken.GetJti()
		jtiHash := helper.GenerateHMACSHA256(jti)
		challenge, _ := a.AuthRepository.GetAuthChallengeByJTIHash(c.Request.Context(), jtiHash)
		if challenge != nil {
			_ = a.AuthRepository.ConsumeAuthChallenge(c.Request.Context(), challenge.ID, tx)
		}
	}

	// Create user PIN record
	err = a.AuthRepository.CreateUserPin(c.Request.Context(), &model.UserPin{
		UserID:         userData.ID,
		PinHash:        hashedPin,
		PinAlgo:        "argon2id",
		SetAt:          now,
		FailedPinCount: 0,
		PinLockedUntil: time.Time{},
		CreatedAt:      now,
		UpdatedAt:      time.Time{},
	}, []field.Expr{
		a.Query.UserPin.PinLockedUntil,
		a.Query.UserPin.UpdatedAt,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat PIN",
		}, http.StatusInternalServerError
	}

	// Update user's pin_set_at timestamp and last login
	userData.PinSetAt = now
	userData.LastLoginAt = now
	userData.OnboardingCompletedAt = now
	userData.Status = "active"
	err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
		a.Query.User.UpdatedAt,
		a.Query.User.LockedUntil,
		a.Query.User.FailedLoginCount,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat PIN",
		}, http.StatusInternalServerError
	}

	// Generate JTI for refresh token
	jti := helper.GenerateLoginJTI()

	// Generate access token
	accessToken, _ := helper.GenerateAccessToken(userData.ID, userData.Email, a.PasetoData)

	// Generate refresh token
	refreshToken, idleExp, absoluteExp := helper.GenerateRefreshToken(userData.ID, jti, a.PasetoData)

	// Hash refresh token for storage
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)

	// Get client info
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := c.GetHeader("X-Device-ID")

	// Create session record
	err = a.AuthRepository.CreateUserSession(c.Request.Context(), &model.UserSession{
		ID:                   "",
		UserID:               userData.ID,
		RefreshTokenHash:     refreshTokenHash,
		DeviceID:             deviceID,
		IP:                   clientIP,
		UserAgent:            userAgent,
		CreatedAt:            now,
		LastUsedAt:           now,
		IdleExpiresAt:        idleExp,
		ExpiresAt:            absoluteExp,
		RevokedAt:            time.Time{},
		RevokeReason:         "",
		RotatedFromSessionID: "",
	}, []field.Expr{
		a.Query.UserSession.ID,
		a.Query.UserSession.RevokedAt,
		a.Query.UserSession.RevokeReason,
		a.Query.UserSession.RotatedFromSessionID,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal membuat PIN",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "PIN berhasil didaftarkan",
		Data: webresponse.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, http.StatusOK
}

func (a *AuthServiceImpl) LoginPIN(c *gin.Context, request webrequest.LoginPINRequest) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Validate input
	validate := request.Validate()
	if len(validate) != 0 {
		return webresponse.JSONResponse{
			Error:     true,
			Message:   "Pastikan semua data terisi dengan benar",
			ErrorList: validate,
		}, http.StatusUnprocessableEntity
	}

	var userData *model.User
	var userPin *model.UserPin
	var err error

	// Determine flow based on which token is provided
	if request.ChallengeToken != "" {
		// Flow 1: Using challenge token (after LoginPassword)
		userData, userPin, err = a.validateChallengeToken(c, request.ChallengeToken)
		if err != nil {
			return webresponse.JSONResponse{
				Error:   true,
				Message: err.Error(),
				Data: map[string]interface{}{
					"type": "session_expired",
				},
			}, http.StatusUnauthorized
		}
	} else if request.RefreshToken != "" {
		// Flow 2: Using refresh token (quick unlock for returning users)
		userData, userPin, err = a.validateRefreshToken(c, request.RefreshToken)
		if err != nil {
			return webresponse.JSONResponse{
				Error:   true,
				Message: err.Error(),
				Data: map[string]interface{}{
					"type": "session_expired",
				},
			}, http.StatusUnauthorized
		}
	}

	// Check if PIN is locked
	if !userPin.PinLockedUntil.IsZero() && userPin.PinLockedUntil.After(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "PIN terkunci sementara. Silakan coba lagi nanti",
		}, http.StatusTooManyRequests
	}

	// Verify PIN using Argon2id
	err = helper.CheckHashArgon2id(userPin.PinHash, request.PIN)
	if err != nil {
		// Increment failed PIN count
		tx := a.Query.Begin()
		newFailedCount := userPin.FailedPinCount + 1

		updateData := map[string]interface{}{
			"failed_pin_count": newFailedCount,
		}

		// Lock PIN after 5 failed attempts for 15 minutes
		if newFailedCount >= 5 {
			updateData["pin_locked_until"] = now.Add(timeLimitCooldown)
		}

		p := tx.Query.UserPin
		_, _ = p.WithContext(c.Request.Context()).
			Where(p.UserID.Eq(userData.ID)).
			Updates(updateData)
		tx.Commit()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "PIN salah",
		}, http.StatusUnauthorized
	}

	// PIN verification passed - create session and generate tokens
	tx := a.Query.Begin()

	// Consume the challenge token if it was used
	if request.ChallengeToken != "" {
		decodedToken, _ := helper.DecodePasetoToken(request.ChallengeToken, a.PasetoData)
		if decodedToken != nil {
			jti, _ := decodedToken.GetJti()
			jtiHash := helper.GenerateHMACSHA256(jti)
			challenge, _ := a.AuthRepository.GetAuthChallengeByJTIHash(c.Request.Context(), jtiHash)
			if challenge != nil {
				_ = a.AuthRepository.ConsumeAuthChallenge(c.Request.Context(), challenge.ID, tx)
			}
		}
	}

	// Revoke any existing active sessions for this user (new login)
	err = a.AuthRepository.RevokeUserSessionsByUserID(c.Request.Context(), userData.ID, "new_login", tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan login",
		}, http.StatusInternalServerError
	}

	// Generate JTI for refresh token
	jti := helper.GenerateLoginJTI()

	// Generate access token
	accessToken, _ := helper.GenerateAccessToken(userData.ID, userData.Email, a.PasetoData)

	// Generate refresh token
	refreshToken, idleExp, absoluteExp := helper.GenerateRefreshToken(userData.ID, jti, a.PasetoData)

	// Hash refresh token for storage
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)

	// Get client info
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := c.GetHeader("X-Device-ID")

	// Create session record
	err = a.AuthRepository.CreateUserSession(c.Request.Context(), &model.UserSession{
		ID:                   "",
		UserID:               userData.ID,
		RefreshTokenHash:     refreshTokenHash,
		DeviceID:             deviceID,
		IP:                   clientIP,
		UserAgent:            userAgent,
		CreatedAt:            now,
		LastUsedAt:           now,
		IdleExpiresAt:        idleExp,
		ExpiresAt:            absoluteExp,
		RevokedAt:            time.Time{},
		RevokeReason:         "",
		RotatedFromSessionID: "",
	}, []field.Expr{
		a.Query.UserSession.ID,
		a.Query.UserSession.RevokedAt,
		a.Query.UserSession.RevokeReason,
		a.Query.UserSession.RotatedFromSessionID,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan login",
		}, http.StatusInternalServerError
	}

	// Reset failed PIN count and update last login time
	p := tx.Query.UserPin
	_, _ = p.WithContext(c.Request.Context()).
		Where(p.UserID.Eq(userData.ID)).
		Updates(map[string]interface{}{
			"failed_pin_count": 0,
			"pin_locked_until": nil,
		})

	userData.LastLoginAt = now
	err = a.AuthRepository.UpdateUser(c.Request.Context(), userData, []field.Expr{
		a.Query.User.UpdatedAt,
		a.Query.User.Status,
		a.Query.User.PinSetAt,
		a.Query.User.OnboardingCompletedAt,
		a.Query.User.EmailVerifiedAt,
		a.Query.User.FailedLoginCount,
		a.Query.User.LockedUntil,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal melakukan login",
		}, http.StatusInternalServerError
	}

	tx.Commit()

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Login berhasil",
		Data: webresponse.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, http.StatusOK
}

// validateChallengeToken validates the challenge token from LoginPassword
func (a *AuthServiceImpl) validateChallengeToken(c *gin.Context, challengeToken string) (*model.User, *model.UserPin, error) {
	// Decode and validate the challenge token
	decodedToken, err := helper.DecodePasetoToken(challengeToken, a.PasetoData)
	if err != nil {
		return nil, nil, errors.New("Sesi telah berakhir, silakan login ulang dengan password")
	}

	// Verify token type
	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "challenge" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Verify purpose
	purpose, err := decodedToken.GetString("purpose")
	if err != nil || purpose != "login_pin" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get user ID from token
	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get JTI and verify challenge exists in database
	jti, err := decodedToken.GetJti()
	if err != nil || jti == "" {
		return nil, nil, errors.New("Token tidak valid")
	}

	jtiHash := helper.GenerateHMACSHA256(jti)
	challenge, err := a.AuthRepository.GetAuthChallengeByJTIHash(c.Request.Context(), jtiHash)
	if err != nil || challenge == nil {
		return nil, nil, errors.New("Sesi telah berakhir, silakan login ulang dengan password")
	}

	// Verify challenge is for the same user
	if challenge.UserID != userID {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get user data
	userData, err := a.AuthRepository.GetUserByUID(c.Request.Context(), userID)
	if err != nil || userData == nil {
		return nil, nil, errors.New("User tidak ditemukan")
	}

	// Get user PIN
	userPin, err := a.AuthRepository.GetUserPinByUserID(c.Request.Context(), userID)
	if err != nil || userPin == nil {
		return nil, nil, errors.New("PIN tidak ditemukan")
	}

	return userData, userPin, nil
}

// validateRefreshToken validates the refresh token for quick unlock
func (a *AuthServiceImpl) validateRefreshToken(c *gin.Context, refreshToken string) (*model.User, *model.UserPin, error) {
	// Decode and validate the refresh token
	decodedToken, err := helper.DecodePasetoToken(refreshToken, a.PasetoData)
	if err != nil {
		return nil, nil, errors.New("Sesi telah berakhir, silakan login ulang dengan password")
	}

	// Verify token type
	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "refresh" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get user ID from token
	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get JTI to verify session
	jti, err := decodedToken.GetJti()
	if err != nil || jti == "" {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Verify session exists and is valid in database
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)
	session, err := a.AuthRepository.GetSessionByRefreshTokenHash(c.Request.Context(), refreshTokenHash)
	if err != nil || session == nil {
		return nil, nil, errors.New("Sesi telah berakhir, silakan login ulang dengan password")
	}

	// Verify session belongs to the same user
	if session.UserID != userID {
		return nil, nil, errors.New("Token tidak valid")
	}

	// Get user data
	userData, err := a.AuthRepository.GetUserByUID(c.Request.Context(), userID)
	if err != nil || userData == nil {
		return nil, nil, errors.New("User tidak ditemukan")
	}

	// Get user PIN
	userPin, err := a.AuthRepository.GetUserPinByUserID(c.Request.Context(), userID)
	if err != nil || userPin == nil {
		return nil, nil, errors.New("PIN tidak ditemukan")
	}

	return userData, userPin, nil
}

// validateRegisterPINChallengeToken validates the challenge token for PIN registration
func (a *AuthServiceImpl) validateRegisterPINChallengeToken(c *gin.Context, challengeToken string, email string) (*model.User, error) {
	// Decode and validate the challenge token
	decodedToken, err := helper.DecodePasetoToken(challengeToken, a.PasetoData)
	if err != nil {
		return nil, errors.New("Sesi telah berakhir, silakan verifikasi email atau login ulang")
	}

	// Verify token type
	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "challenge" {
		return nil, errors.New("Token tidak valid")
	}

	// Verify purpose is for PIN registration
	purpose, err := decodedToken.GetString("purpose")
	if err != nil || purpose != "register_pin" {
		return nil, errors.New("Token tidak valid untuk registrasi PIN")
	}

	// Get user ID from token
	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return nil, errors.New("Token tidak valid")
	}

	// Get JTI and verify challenge exists in database
	jti, err := decodedToken.GetJti()
	if err != nil || jti == "" {
		return nil, errors.New("Token tidak valid")
	}

	jtiHash := helper.GenerateHMACSHA256(jti)
	challenge, err := a.AuthRepository.GetAuthChallengeByJTIHash(c.Request.Context(), jtiHash)
	if err != nil || challenge == nil {
		return nil, errors.New("Sesi telah berakhir, silakan verifikasi email atau login ulang")
	}

	// Verify challenge is for the same user
	if challenge.UserID != userID {
		return nil, errors.New("Token tidak valid")
	}

	// Verify challenge purpose matches
	if challenge.Purpose != "register_pin" {
		return nil, errors.New("Token tidak valid untuk registrasi PIN")
	}

	// Get user data by email and verify it matches the token's user
	userData, err := a.AuthRepository.GetUserByEmail(c.Request.Context(), email)
	if err != nil || userData == nil {
		return nil, errors.New("User tidak ditemukan")
	}

	// Verify the email matches the user in the token
	if userData.ID != userID {
		return nil, errors.New("Email tidak sesuai dengan token")
	}

	return userData, nil
}

// GetUserProfile retrieves the current user's profile information
func (a *AuthServiceImpl) GetUserProfile(c *gin.Context) (webresponse.JSONResponse, int) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Unauthorized",
		}, http.StatusUnauthorized
	}

	userIDStr, ok := userID.(string)
	if !ok || userIDStr == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Unauthorized",
		}, http.StatusUnauthorized
	}

	// Get user data
	userData, err := a.AuthRepository.GetUserByUID(c.Request.Context(), userIDStr)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Pengguna tidak ditemukan",
		}, http.StatusNotFound
	}

	// Get user profile
	userProfile, err := a.AuthRepository.GetUserProfileByUserID(c.Request.Context(), userIDStr)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Profil pengguna tidak ditemukan",
		}, http.StatusNotFound
	}

	// Build response data
	profileData := map[string]interface{}{
		"user_id":    userData.ID,
		"email":      userData.Email,
		"status":     userData.Status,
		"full_name":  userProfile.FullName,
		"last_login": userData.LastLoginAt,
		"created_at": userData.CreatedAt,
	}

	// Add birthdate if set
	if !userProfile.Birthdate.IsZero() {
		profileData["birthdate"] = userProfile.Birthdate.Format("2006-01-02")
	}

	return webresponse.JSONResponse{
		Error:   false,
		Message: "Berhasil mengambil profil pengguna",
		Data:    profileData,
	}, http.StatusOK
}

// RefreshToken generates a new access token using a valid refresh token
// It also implements token rotation for security
func (a *AuthServiceImpl) RefreshToken(c *gin.Context) (webresponse.JSONResponse, int) {
	now := helper.GetCurrentTime()

	// Get refresh token from header
	refreshToken := c.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Refresh token tidak ditemukan",
		}, http.StatusBadRequest
	}

	// Decode and validate the refresh token
	decodedToken, err := helper.DecodePasetoToken(refreshToken, a.PasetoData)
	if err != nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Refresh token tidak valid atau sudah kadaluarsa",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Verify token type
	tokenType, err := decodedToken.GetString("type")
	if err != nil || tokenType != "refresh" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	// Get user ID from token
	userID, err := decodedToken.GetSubject()
	if err != nil || userID == "" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	// Find the session by refresh token hash
	refreshTokenHash := helper.GenerateHMACSHA256(refreshToken)
	session, err := a.AuthRepository.GetSessionByRefreshTokenHash(c.Request.Context(), refreshTokenHash)
	if err != nil || session == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi tidak ditemukan atau sudah berakhir",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Verify session belongs to the user in the token
	if session.UserID != userID {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Token tidak valid",
		}, http.StatusUnauthorized
	}

	// Check if session is revoked
	if !session.RevokedAt.IsZero() {
		// Potential token reuse attack - revoke all sessions for this user
		tx := a.Query.Begin()
		_ = a.AuthRepository.RevokeUserSessionsByUserID(c.Request.Context(), userID, "potential_token_reuse", tx)
		tx.Commit()

		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi telah dicabut, silakan login ulang",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Check if session has expired (absolute expiry)
	if session.ExpiresAt.Before(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi telah berakhir, silakan login ulang",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Check if session has idle expired
	if session.IdleExpiresAt.Before(now) {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Sesi tidak aktif terlalu lama, silakan login ulang",
			Data: map[string]interface{}{
				"type": "session_expired",
			},
		}, http.StatusUnauthorized
	}

	// Get user data
	userData, err := a.AuthRepository.GetUserByUID(c.Request.Context(), userID)
	if err != nil || userData == nil {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Pengguna tidak ditemukan",
		}, http.StatusUnauthorized
	}

	// Check if user is still active
	if userData.Status != "active" {
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Akun tidak aktif",
		}, http.StatusForbidden
	}

	tx := a.Query.Begin()

	// Generate new JTI for new refresh token
	newJti := helper.GenerateLoginJTI()

	// Generate new access token
	newAccessToken, _ := helper.GenerateAccessToken(userData.ID, userData.Email, a.PasetoData)

	// Generate new refresh token (token rotation)
	newRefreshToken, newIdleExp, newAbsoluteExp := helper.GenerateRefreshToken(userData.ID, newJti, a.PasetoData)

	// Hash new refresh token for storage
	newRefreshTokenHash := helper.GenerateHMACSHA256(newRefreshToken)

	// Get client info
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := c.GetHeader("X-Device-ID")

	// Revoke old session (mark as rotated)
	session.RevokedAt = now
	session.RevokeReason = "token_rotated"
	err = a.AuthRepository.UpdateUserSession(c.Request.Context(), session, []field.Expr{
		a.Query.UserSession.CreatedAt,
		a.Query.UserSession.RefreshTokenHash,
		a.Query.UserSession.DeviceID,
		a.Query.UserSession.IP,
		a.Query.UserSession.UserAgent,
		a.Query.UserSession.IdleExpiresAt,
		a.Query.UserSession.ExpiresAt,
		a.Query.UserSession.RotatedFromSessionID,
	}, tx)
	if err != nil {
		tx.Rollback()
		return webresponse.JSONResponse{
			Error:   true,
			Message: "Gagal memperbarui token",
		}, http.StatusInternalServerError
	}

	// Create new session with rotated token
	err = a.AuthRepository.CreateUserSession(c.Request.Context(), &model.UserSession{
		ID:                   "",
		UserID:               userData.ID,
		RefreshTokenHash:     newRefreshTokenHash,
		DeviceID:             deviceID,
		IP:                   clientIP,
		UserAgent:            userAgent,
		CreatedAt:            now,
		LastUsedAt:           now,
		IdleExpiresAt:        newIdleExp,
		ExpiresAt:            newAbsoluteExp,
		RevokedAt:            time.Time{},
		RevokeReason:         "",
		RotatedFromSessionID: session.ID,
	}, []field.Expr{
		a.Query.UserSession.ID,
		a.Query.UserSession.RevokedAt,
		a.Query.UserSession.RevokeReason,
	}, tx)
	if err != nil {
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
