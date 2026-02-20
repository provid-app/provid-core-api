package helper

import (
	"os"
	"provid-backend/internal/model/data"
	"time"

	"aidanwoods.dev/go-paseto"
)

// AccessTokenDuration is the duration for access tokens (15 minutes)
const AccessTokenDuration = 15 * time.Minute

// RefreshTokenIdleDuration is the idle timeout for refresh tokens (7 days)
const RefreshTokenIdleDuration = 7 * 24 * time.Hour

// RefreshTokenAbsoluteDuration is the absolute max lifetime for refresh tokens (30 days)
const RefreshTokenAbsoluteDuration = 30 * 24 * time.Hour

// ChallengeTokenDuration is the duration for challenge tokens (5 minutes - short-lived for PIN entry)
const ChallengeTokenDuration = 5 * time.Minute

func DecodePasetoToken(token string, pasetoCreds data.PasetoItemData) (*paseto.Token, error) {
	parser := paseto.NewParser()

	decodedToken, err := parser.ParseV4Public(*pasetoCreds.PasetoPublic, token, nil)
	if err != nil {
		return nil, err
	}

	return decodedToken, nil
}

func GenerateAccessToken(userID, email string, pasetoData data.PasetoItemData) (string, time.Time) {
	timeNow := time.Now()
	timeExp := timeNow.Add(AccessTokenDuration)

	token := paseto.NewToken()
	token.SetIssuedAt(timeNow)
	token.SetNotBefore(timeNow)
	token.SetIssuer(os.Getenv("APP_ID") + "-" + os.Getenv("APP_ENV") + "-API")
	token.SetExpiration(timeExp)
	token.SetSubject(userID)
	token.SetString("email", email)
	token.SetString("type", "access")

	signedToken := token.V4Sign(*pasetoData.PasetoSecret, nil)

	return signedToken, timeExp
}

func GenerateRefreshToken(userID, jti string, pasetoData data.PasetoItemData) (string, time.Time, time.Time) {
	timeNow := time.Now()
	idleExp := timeNow.Add(RefreshTokenIdleDuration)
	absoluteExp := timeNow.Add(RefreshTokenAbsoluteDuration)

	token := paseto.NewToken()
	token.SetIssuedAt(timeNow)
	token.SetNotBefore(timeNow)
	token.SetIssuer(os.Getenv("APP_ID") + "-" + os.Getenv("APP_ENV") + "-API")
	token.SetExpiration(absoluteExp)
	token.SetSubject(userID)
	token.SetJti(jti)
	token.SetString("type", "refresh")

	signedToken := token.V4Sign(*pasetoData.PasetoSecret, nil)

	return signedToken, idleExp, absoluteExp
}

// GenerateChallengeToken generates a short-lived challenge token for PIN verification
// This is used after password authentication to require PIN entry
func GenerateChallengeToken(userID, jti, purpose string, pasetoData data.PasetoItemData) (string, time.Time) {
	timeNow := time.Now()
	timeExp := timeNow.Add(ChallengeTokenDuration)

	token := paseto.NewToken()
	token.SetIssuedAt(timeNow)
	token.SetNotBefore(timeNow)
	token.SetIssuer(os.Getenv("APP_ID") + "-" + os.Getenv("APP_ENV") + "-API")
	token.SetExpiration(timeExp)
	token.SetSubject(userID)
	token.SetJti(jti)
	token.SetString("type", "challenge")
	token.SetString("purpose", purpose)

	signedToken := token.V4Sign(*pasetoData.PasetoSecret, nil)

	return signedToken, timeExp
}
