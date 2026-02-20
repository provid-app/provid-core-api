package user_repository

import (
	"context"
	"database/sql/driver"
	"errors"
	data "provid-backend/gen/core/model"
	model "provid-backend/gen/core/query"
	"time"

	"gorm.io/gen"
	"gorm.io/gen/field"
)

type AuthRepositoryImpl struct {
	Query *model.Query
}

func (a *AuthRepositoryImpl) GetUserProfileByID(ctx context.Context, id string) (*data.UserProfile, error) {
	p := a.Query.UserProfile

	profile, err := p.WithContext(ctx).Where(p.UserID.Eq(id)).First()

	if err != nil {
		return nil, err
	}

	return profile, nil
}

type ByteValuer []byte

func (b ByteValuer) Value() (driver.Value, error) {
	return []byte(b), nil
}

func (a *AuthRepositoryImpl) GetOTPRequestByTokenAndPurpose(ctx context.Context, token []byte, purpose string) (*data.OtpRequest, error) {
	o := a.Query.OtpRequest

	otpRequest, err := o.WithContext(ctx).Where(o.OtpHash.Eq(ByteValuer(token)), o.Purpose.Eq(purpose)).First()

	if err != nil {
		return nil, err
	}

	return otpRequest, nil
}

func (a *AuthRepositoryImpl) UpdateUser(context context.Context, user *data.User, omit []field.Expr, tx *model.QueryTx) error {
	u := tx.Query.User

	err := u.WithContext(context).Omit(omit...).Save(user)
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthRepositoryImpl) DeleteOTPRequestByID(ctx context.Context, id string, purpose string) (*gen.ResultInfo, error) {
	o := a.Query.OtpRequest

	res, err := o.WithContext(ctx).Where(o.ID.Eq(id), o.Purpose.Eq(purpose)).Delete()
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (a *AuthRepositoryImpl) GetOTPRequestByEmailAndPurpose(ctx context.Context, email string, purpose string) (*data.OtpRequest, error) {
	o := a.Query.OtpRequest

	otpRequest, err := o.WithContext(ctx).Where(o.Email.Eq(email), o.Purpose.Eq(purpose)).First()
	if err != nil {
		return nil, err
	}

	return otpRequest, nil
}

func (a *AuthRepositoryImpl) UpdateOTPRequest(ctx context.Context, otp *data.OtpRequest, omit []field.Expr, tx *model.QueryTx) error {
	o := tx.Query.OtpRequest

	err := o.WithContext(ctx).Omit(omit...).Save(otp)

	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) CreateOTPRequest(ctx context.Context, otp *data.OtpRequest, omit []field.Expr, tx *model.QueryTx) error {
	o := tx.Query.OtpRequest

	err := o.WithContext(ctx).Omit(omit...).Create(otp)

	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) GetUserProfileByUserID(context context.Context, userID string) (*data.UserProfile, error) {
	p := a.Query.UserProfile

	profile, err := p.WithContext(context).Where(p.UserID.Eq(userID)).First()
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (a *AuthRepositoryImpl) CreateUserIdentity(ctx context.Context, identity *data.UserIdentity, omit []field.Expr, tx *model.QueryTx) error {
	i := tx.Query.UserIdentity

	err := i.WithContext(ctx).Omit(omit...).Create(identity)

	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) CreatePasswordCredentials(ctx context.Context, password *data.UserPasswordCredential, omit []field.Expr, tx *model.QueryTx) error {
	p := tx.Query.UserPasswordCredential

	err := p.WithContext(ctx).Omit(omit...).Create(password)

	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) CreateUserProfile(context context.Context, profile *data.UserProfile, omit []field.Expr, tx *model.QueryTx) error {
	u := tx.Query.UserProfile

	err := u.WithContext(context).Omit(omit...).Create(profile)

	if err != nil {
		return err
	}

	return nil

}

func (a *AuthRepositoryImpl) CreateUser(context context.Context, user *data.User, omit []field.Expr, tx *model.QueryTx) error {
	u := tx.Query.User

	err := u.WithContext(context).Omit(omit...).Create(user)

	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) GetUserByEmail(context context.Context, email string) (*data.User, error) {
	if email == "" {
		return nil, errors.New("email is empty")
	}

	u := a.Query.User
	user, err := u.WithContext(context).Where(u.Email.Eq(email)).First()
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *AuthRepositoryImpl) GetUserByUID(context context.Context, uid string) (*data.User, error) {
	if uid == "" {
		return nil, errors.New("uid is empty")
	}

	u := a.Query.User
	user, err := u.WithContext(context).Where(u.ID.Eq(uid)).First()
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *AuthRepositoryImpl) CreateUserPin(ctx context.Context, pin *data.UserPin, omit []field.Expr, tx *model.QueryTx) error {
	p := tx.Query.UserPin

	err := p.WithContext(ctx).Omit(omit...).Create(pin)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) GetUserPinByUserID(ctx context.Context, userID string) (*data.UserPin, error) {
	if userID == "" {
		return nil, errors.New("user_id is empty")
	}

	p := a.Query.UserPin
	pin, err := p.WithContext(ctx).Where(p.UserID.Eq(userID)).First()
	if err != nil {
		return nil, err
	}

	return pin, nil
}

func (a *AuthRepositoryImpl) GetPasswordCredentialsByUserID(ctx context.Context, userID string) (*data.UserPasswordCredential, error) {
	if userID == "" {
		return nil, errors.New("user_id is empty")
	}

	p := a.Query.UserPasswordCredential
	cred, err := p.WithContext(ctx).Where(p.UserID.Eq(userID)).First()
	if err != nil {
		return nil, err
	}

	return cred, nil
}

func (a *AuthRepositoryImpl) UpdatePasswordCredentials(ctx context.Context, creds *data.UserPasswordCredential, omit []field.Expr, tx *model.QueryTx) error {
	p := tx.Query.UserPasswordCredential

	err := p.WithContext(ctx).Omit(omit...).Save(creds)
	if err != nil {
		return err
	}
    
	return nil
}

func (a *AuthRepositoryImpl) CreateUserSession(ctx context.Context, session *data.UserSession, omit []field.Expr, tx *model.QueryTx) error {
	s := tx.Query.UserSession

	err := s.WithContext(ctx).Omit(omit...).Create(session)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) RevokeUserSessionsByUserID(ctx context.Context, userID string, reason string, tx *model.QueryTx) error {
	if userID == "" {
		return errors.New("user_id is empty")
	}

	s := tx.Query.UserSession
	now := time.Now()

	_, err := s.WithContext(ctx).
		Where(s.UserID.Eq(userID), s.RevokedAt.IsNull()).
		Updates(map[string]interface{}{
			"revoked_at":    now,
			"revoke_reason": reason,
		})
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) GetActiveSessionByUserID(ctx context.Context, userID string) (*data.UserSession, error) {
	if userID == "" {
		return nil, errors.New("user_id is empty")
	}

	s := a.Query.UserSession
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
		return nil, err
	}

	return session, nil
}

func (a *AuthRepositoryImpl) GetSessionByRefreshTokenHash(ctx context.Context, tokenHash []byte) (*data.UserSession, error) {
	s := a.Query.UserSession
	now := time.Now()

	session, err := s.WithContext(ctx).
		Where(
			s.RefreshTokenHash.Eq(ByteValuer(tokenHash)),
			s.RevokedAt.IsNull(),
			s.ExpiresAt.Gt(now),
			s.IdleExpiresAt.Gt(now),
		).
		First()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (a *AuthRepositoryImpl) UpdateUserSession(ctx context.Context, session *data.UserSession, omit []field.Expr, tx *model.QueryTx) error {
	s := tx.Query.UserSession

	err := s.WithContext(ctx).Omit(omit...).Save(session)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) CreateAuthChallenge(ctx context.Context, challenge *data.AuthChallenge, omit []field.Expr, tx *model.QueryTx) error {
	c := tx.Query.AuthChallenge

	err := c.WithContext(ctx).Omit(omit...).Create(challenge)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) GetAuthChallengeByJTIHash(ctx context.Context, jtiHash []byte) (*data.AuthChallenge, error) {
	c := a.Query.AuthChallenge
	now := time.Now()

	challenge, err := c.WithContext(ctx).
		Where(
			c.JtiHash.Eq(ByteValuer(jtiHash)),
			c.ConsumedAt.IsNull(),
			c.ExpiresAt.Gt(now),
		).
		First()
	if err != nil {
		return nil, err
	}

	return challenge, nil
}

func (a *AuthRepositoryImpl) ConsumeAuthChallenge(ctx context.Context, challengeID string, tx *model.QueryTx) error {
	c := tx.Query.AuthChallenge
	now := time.Now()

	_, err := c.WithContext(ctx).
		Where(c.ID.Eq(challengeID)).
		Update(c.ConsumedAt, now)
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) DeleteExpiredAuthChallenges(ctx context.Context, userID string) error {
	c := a.Query.AuthChallenge
	now := time.Now()

	_, err := c.WithContext(ctx).
		Where(c.UserID.Eq(userID), c.ExpiresAt.Lt(now)).
		Delete()
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthRepositoryImpl) InvalidateAuthChallengesByUserAndPurpose(ctx context.Context, userID string, purpose string, tx *model.QueryTx) error {
	c := tx.Query.AuthChallenge
	now := time.Now()

	_, err := c.WithContext(ctx).
		Where(c.UserID.Eq(userID), c.Purpose.Eq(purpose), c.ConsumedAt.IsNull()).
		Update(c.ConsumedAt, now)
	if err != nil {
		return err
	}

	return nil
}

func NewAuthRepository(query *model.Query) AuthRepository {
	return &AuthRepositoryImpl{
		Query: query,
	}
}
