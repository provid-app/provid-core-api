package user_repository

import (
	"context"
	"provid-backend/gen/core/model"
	model2 "provid-backend/gen/core/query"

	"gorm.io/gen"
	"gorm.io/gen/field"
)

type AuthRepository interface {
	GetOTPRequestByEmailAndPurpose(ctx context.Context, email string, purpose string) (*model.OtpRequest, error)
	UpdateOTPRequest(ctx context.Context, otp *model.OtpRequest, omit []field.Expr, tx *model2.QueryTx) error
	DeleteOTPRequestByID(ctx context.Context, id string, purpose string) (*gen.ResultInfo, error)
	GetOTPRequestByTokenAndPurpose(ctx context.Context, token []byte, purpose string) (*model.OtpRequest, error)

	CreateOTPRequest(ctx context.Context, otp *model.OtpRequest, omit []field.Expr, tx *model2.QueryTx) error
	CreateUserIdentity(ctx context.Context, identity *model.UserIdentity, omit []field.Expr, tx *model2.QueryTx) error
	CreatePasswordCredentials(ctx context.Context, password *model.UserPasswordCredential, omit []field.Expr, tx *model2.QueryTx) error
	CreateUserProfile(context context.Context, profile *model.UserProfile, omit []field.Expr, tx *model2.QueryTx) error
	CreateUser(context context.Context, user *model.User, omit []field.Expr, tx *model2.QueryTx) error
	UpdateUser(context context.Context, user *model.User, omit []field.Expr, tx *model2.QueryTx) error
	GetUserByEmail(context context.Context, email string) (*model.User, error)
	GetUserProfileByUserID(context context.Context, userID string) (*model.UserProfile, error)
	GetUserByUID(context context.Context, uid string) (*model.User, error)

	CreateUserPin(ctx context.Context, pin *model.UserPin, omit []field.Expr, tx *model2.QueryTx) error
	GetUserPinByUserID(ctx context.Context, userID string) (*model.UserPin, error)

	GetPasswordCredentialsByUserID(ctx context.Context, userID string) (*model.UserPasswordCredential, error)
	UpdatePasswordCredentials(ctx context.Context, creds *model.UserPasswordCredential, omit []field.Expr, tx *model2.QueryTx) error
	CreateUserSession(ctx context.Context, session *model.UserSession, omit []field.Expr, tx *model2.QueryTx) error
	RevokeUserSessionsByUserID(ctx context.Context, userID string, reason string, tx *model2.QueryTx) error
	GetActiveSessionByUserID(ctx context.Context, userID string) (*model.UserSession, error)
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash []byte) (*model.UserSession, error)
	UpdateUserSession(ctx context.Context, session *model.UserSession, omit []field.Expr, tx *model2.QueryTx) error

	CreateAuthChallenge(ctx context.Context, challenge *model.AuthChallenge, omit []field.Expr, tx *model2.QueryTx) error
	GetAuthChallengeByJTIHash(ctx context.Context, jtiHash []byte) (*model.AuthChallenge, error)
	ConsumeAuthChallenge(ctx context.Context, challengeID string, tx *model2.QueryTx) error
	DeleteExpiredAuthChallenges(ctx context.Context, userID string) error
	InvalidateAuthChallengesByUserAndPurpose(ctx context.Context, userID string, purpose string, tx *model2.QueryTx) error

	GetUserProfileByID(ctx context.Context, id string) (*model.UserProfile, error)
}
