package cms_repository

import (
	"context"
	"database/sql/driver"
	"errors"
	"provid-backend/gen/cms/model"
	modelcms "provid-backend/gen/cms/query"

	"gorm.io/gen/field"
	"gorm.io/gorm"
)

type CMSRepositoryImpl struct {
	Query *modelcms.Query
}

type ByteValuer []byte

func (b ByteValuer) Value() (driver.Value, error) {
	return []byte(b), nil
}

func (C *CMSRepositoryImpl) GetSessionByRefreshTokenHash(ctx context.Context, tokenHash []byte) (*model.UserSession, error) {
	s := C.Query.UserSession

	session, err := s.WithContext(ctx).Where(s.SessionToken.Eq(ByteValuer(tokenHash))).First()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (C *CMSRepositoryImpl) RevokeUserSessionsByUserID(ctx context.Context, userID string, tx *modelcms.QueryTx) error {
	s := tx.Query.UserSession

	_, err := s.WithContext(ctx).Where(s.UserID.Eq(userID)).First()
	// return error kalo -> err tidak nil dan bukan record not found
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		s.WithContext(ctx).Where(s.UserID.Eq(userID)).Delete()
	}

	return nil
}

func (C *CMSRepositoryImpl) CreateUserSession(ctx context.Context, session *model.UserSession, omit []field.Expr, tx *modelcms.QueryTx) error {
	s := tx.Query.UserSession

	err := s.WithContext(ctx).Omit(omit...).Create(session)
	if err != nil {
		return err
	}
	return nil
}

func (C *CMSRepositoryImpl) UpdateUser(ctx context.Context, user *model.User, omit []field.Expr, tx *modelcms.QueryTx) error {

	u := tx.Query.User

	err := u.WithContext(ctx).Omit(omit...).Save(user)
	if err != nil {
		return err
	}
	return nil
}

func (C *CMSRepositoryImpl) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	U := C.Query.User

	user, err := U.WithContext(nil).Where(U.Email.Eq(email)).First()
	if err != nil {
		return nil, err
	}

	return user, nil
}

func NewCMSRepository(query *modelcms.Query) CMSRepository {
	return &CMSRepositoryImpl{
		Query: query,
	}
}
