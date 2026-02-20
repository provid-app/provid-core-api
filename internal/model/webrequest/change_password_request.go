package webrequest

import (
	"errors"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type ChangePasswordRequest struct {
	Token                string `json:"token"`
	Password             string `json:"password"`
	ConfirmationPassword string `json:"confirmation_password"`
}

var changePasswordRequestDisplayNames = map[string]string{
	"password":              "Kata Sandi",
	"confirmation_password": "Konfirmasi Kata Sandi",
}

func (l ChangePasswordRequest) GetFieldDisplayName() map[string]string {
	return changePasswordRequestDisplayNames
}

func (l ChangePasswordRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(l.GetFieldDisplayName(), &l,
		helper.Field(&l.Password, ozzo.Required, ozzo.Length(8, 0)),
		helper.Field(&l.ConfirmationPassword, ozzo.Required, ozzo.By(func(value interface{}) error {
			if l.Password != l.ConfirmationPassword {
				return errors.New("password and confirm")
			}
			return nil
		})),
	)
}
