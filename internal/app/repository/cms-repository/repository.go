package cms_repository

import (
	"context"
	"provid-backend/gen/cms/model"
	model2 "provid-backend/gen/cms/query"

	"gorm.io/gen/field"
)

type CMSRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	UpdateUser(ctx context.Context, user *model.User, omit []field.Expr, tx *model2.QueryTx) error

	CreateUserSession(ctx context.Context, session *model.UserSession, omit []field.Expr, tx *model2.QueryTx) error
	RevokeUserSessionsByUserID(ctx context.Context, userID string, tx *model2.QueryTx) error
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash []byte) (*model.UserSession, error)
}
