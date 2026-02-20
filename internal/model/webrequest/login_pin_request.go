package webrequest

import (
	"errors"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"
	"regexp"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type LoginPINRequest struct {
	ChallengeToken string `json:"challenge_token"`
	RefreshToken   string `json:"refresh_token"`
	PIN            string `json:"pin"`
}

var loginPINRequestDisplayNames = map[string]string{
	"challenge_token": "Challenge Token",
	"refresh_token":   "Refresh Token",
	"pin":             "PIN",
}

func (r LoginPINRequest) GetFieldDisplayName() map[string]string {
	return loginPINRequestDisplayNames
}

// ValidateWithChallenge validates when using challenge token (after LoginPassword)
func (r LoginPINRequest) ValidateWithChallenge() []data.ValidationErrorData {
	return helper.ValidateStruct(r.GetFieldDisplayName(), &r,
		helper.Field(&r.ChallengeToken, ozzo.Required),
		helper.Field(&r.PIN, ozzo.Required, ozzo.Length(6, 6), ozzo.By(func(value interface{}) error {
			pin, _ := value.(string)
			matched, _ := regexp.MatchString(`^\d{6}$`, pin)
			if !matched {
				return errors.New("PIN harus terdiri dari 6 digit angka")
			}
			return nil
		})),
	)
}

// ValidateWithRefreshToken validates when using refresh token (quick unlock)
func (r LoginPINRequest) ValidateWithRefreshToken() []data.ValidationErrorData {
	return helper.ValidateStruct(r.GetFieldDisplayName(), &r,
		helper.Field(&r.RefreshToken, ozzo.Required),
		helper.Field(&r.PIN, ozzo.Required, ozzo.Length(6, 6), ozzo.By(func(value interface{}) error {
			pin, _ := value.(string)
			matched, _ := regexp.MatchString(`^\d{6}$`, pin)
			if !matched {
				return errors.New("PIN harus terdiri dari 6 digit angka")
			}
			return nil
		})),
	)
}

// Validate basic validation - at least one token type must be provided
func (r LoginPINRequest) Validate() []data.ValidationErrorData {
	if r.ChallengeToken == "" && r.RefreshToken == "" {
		return []data.ValidationErrorData{
			{
				Field:   "token",
				Message: "Challenge token atau refresh token harus diisi",
			},
		}
	}

	// Validate based on which token is provided
	if r.ChallengeToken != "" {
		return r.ValidateWithChallenge()
	}
	return r.ValidateWithRefreshToken()
}
