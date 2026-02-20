package webrequest

import (
	"errors"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"
	"regexp"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type RegisterPINRequest struct {
	Email           string `json:"email"`
	ChallengeToken  string `json:"challenge_token"`
	PIN             string `json:"pin"`
	ConfirmationPIN string `json:"confirmation_pin"`
}

var registerPINRequestDisplayNames = map[string]string{
	"email":            "Email",
	"challenge_token":  "Challenge Token",
	"pin":              "PIN",
	"confirmation_pin": "Konfirmasi PIN",
}

func (r RegisterPINRequest) GetFieldDisplayName() map[string]string {
	return registerPINRequestDisplayNames
}

func (r RegisterPINRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(r.GetFieldDisplayName(), &r,
		helper.Field(&r.Email, ozzo.Required, ozzo.Match(regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`))),
		helper.Field(&r.ChallengeToken, ozzo.Required),
		helper.Field(&r.PIN, ozzo.Required, ozzo.Length(6, 6), ozzo.By(func(value interface{}) error {
			pin, _ := value.(string)
			// Validate PIN is numeric only
			matched, _ := regexp.MatchString(`^\d{6}$`, pin)
			if !matched {
				return errors.New("PIN harus terdiri dari 6 digit angka")
			}
			return nil
		})),
		helper.Field(&r.ConfirmationPIN, ozzo.Required, ozzo.By(func(value interface{}) error {
			if r.PIN != r.ConfirmationPIN {
				return errors.New("PIN dan Konfirmasi PIN tidak sama")
			}
			return nil
		})),
	)
}
