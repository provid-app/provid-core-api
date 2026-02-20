package middleware

import (
	"net/http"
	query2 "provid-backend/gen/cms/query"
	"provid-backend/gen/core/model"
	query "provid-backend/gen/core/query"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"
	"provid-backend/internal/model/webresponse"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Context keys for storing user data
const (
	ContextKeyUserID  = "user_id"
	ContextKeyEmail   = "email"
	ContextKeyUser    = "user"
	ContextKeySession = "session"
)

// AuthMiddleware validates the access token and checks if user has a valid session
func AuthMiddleware(q *query.Query, pasetoData data.PasetoItemData) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token akses tidak ditemukan",
			})
			return
		}

		// Check Bearer prefix
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Format token tidak valid",
			})
			return
		}

		// Extract token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token akses tidak ditemukan",
			})
			return
		}

		// Decode and validate PASETO token
		token, err := helper.DecodePasetoToken(tokenString, pasetoData)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid atau sudah kadaluarsa",
			})
			return
		}

		// Validate token type
		tokenType, err := token.GetString("type")
		if err != nil || tokenType != "access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Tipe token tidak valid",
			})
			return
		}

		// Get user ID from token subject
		userID, err := token.GetSubject()
		if err != nil || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid",
			})
			return
		}

		// Get email from token
		email, err := token.GetString("email")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid",
			})
			return
		}

		ctx := c.Request.Context()

		// Verify user exists and is active
		u := q.User
		user, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Pengguna tidak ditemukan",
			})
			return
		}

		// Check if user is active
		if user.Status != "active" {
			c.AbortWithStatusJSON(http.StatusForbidden, webresponse.JSONResponse{
				Error:   true,
				Message: "Akun tidak aktif",
			})
			return
		}

		// Verify user has an active session (not revoked and not expired)
		s := q.UserSession
		now := time.Now()
		session, err := s.WithContext(ctx).
			Where(
				s.UserID.Eq(userID),
				s.RevokedAt.IsNull(),
				s.ExpiresAt.Gt(now),
				s.IdleExpiresAt.Gt(now),
			).
			Order(s.CreatedAt.Desc()).
			First()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Sesi tidak valid atau sudah berakhir",
			})
			return
		}

		// Store user info in context for downstream handlers
		c.Set(ContextKeyUserID, userID)
		c.Set(ContextKeyEmail, email)
		c.Set(ContextKeyUser, user)
		c.Set(ContextKeySession, session)

		c.Next()
	}
}

// AuthMiddlewareCMS validates the access token and checks if user has a valid session
func AuthMiddlewareCMS(q *query2.Query, pasetoData data.PasetoItemData) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token akses tidak ditemukan",
			})
			return
		}

		// Check Bearer prefix
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Format token tidak valid",
			})
			return
		}

		// Extract token
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token akses tidak ditemukan",
			})
			return
		}

		// Decode and validate PASETO token
		token, err := helper.DecodePasetoToken(tokenString, pasetoData)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid atau sudah kadaluarsa",
			})
			return
		}

		// Validate token type
		tokenType, err := token.GetString("type")
		if err != nil || tokenType != "access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Tipe token tidak valid",
			})
			return
		}

		// Get user ID from token subject
		userID, err := token.GetSubject()
		if err != nil || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid",
			})
			return
		}

		// Get email from token
		email, err := token.GetString("email")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Token tidak valid",
			})
			return
		}

		ctx := c.Request.Context()

		// Verify user exists and is active
		u := q.User
		user, err := u.WithContext(ctx).Where(u.ID.Eq(userID)).First()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Pengguna tidak ditemukan",
			})
			return
		}

		// Check if user is active
		//if user.Status != "active" {
		//	c.AbortWithStatusJSON(http.StatusForbidden, webresponse.JSONResponse{
		//		Error:   true,
		//		Message: "Akun tidak aktif",
		//	})
		//	return
		//}

		// Verify user has an active session (not revoked and not expired)
		s := q.UserSession
		now := time.Now()
		session, err := s.WithContext(ctx).
			Where(
				s.UserID.Eq(userID),
				s.ExpiresAt.Gt(now),
			).
			Order(s.CreatedAt.Desc()).
			First()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, webresponse.JSONResponse{
				Error:   true,
				Message: "Sesi tidak valid atau sudah berakhir",
			})
			return
		}

		// Store user info in context for downstream handlers
		c.Set(ContextKeyUserID, userID)
		c.Set(ContextKeyEmail, email)
		c.Set(ContextKeyUser, user)
		c.Set(ContextKeySession, session)

		c.Next()
	}
}

// GetUserFromContext retrieves the user from gin context
func GetUserFromContext(c *gin.Context) (*model.User, bool) {
	user, exists := c.Get(ContextKeyUser)
	if !exists {
		return nil, false
	}
	u, ok := user.(*model.User)
	return u, ok
}

// GetUserIDFromContext retrieves the user ID from gin context
func GetUserIDFromContext(c *gin.Context) (string, bool) {
	userID, exists := c.Get(ContextKeyUserID)
	if !exists {
		return "", false
	}
	id, ok := userID.(string)
	return id, ok
}

// GetSessionFromContext retrieves the session from gin context
func GetSessionFromContext(c *gin.Context) (*model.UserSession, bool) {
	session, exists := c.Get(ContextKeySession)
	if !exists {
		return nil, false
	}
	s, ok := session.(*model.UserSession)
	return s, ok
}
