package webrequest

import (
	"errors"
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type RegisterRequest struct {
	Fullname             string `json:"fullname"`
	Email                string `json:"email"`
	Date                 string `json:"date_of_birth"`
	Password             string `json:"password"`
	ConfirmationPassword string `json:"confirmation_password"`
	Step                 int    `json:"step"`
}

var registerRequestDisplayNames = map[string]string{
	"fullname":              "Nama Lengkap",
	"email":                 "Email",
	"date_of_birth":         "Tanggal Lahir",
	"password":              "Kata Sandi",
	"confirmation_password": "Konfirmasi Kata Sandi",
}

func (l RegisterRequest) GetFieldDisplayName() map[string]string { return registerRequestDisplayNames }

func (l RegisterRequest) ValidateStep1() []data.ValidationErrorData {
	return helper.ValidateStruct(l.GetFieldDisplayName(), &l,
		helper.Field(&l.Fullname, ozzo.Required),
		helper.Field(&l.Email, ozzo.Required, is.Email),
		helper.Field(&l.Date, ozzo.Required),
	)
}

func (l RegisterRequest) ValidateStep2() []data.ValidationErrorData {
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
