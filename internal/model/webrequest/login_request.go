package webrequest

import (
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var loginRequestDisplayNames = map[string]string{
	"email":    "Email",
	"password": "Password",
}

func (l LoginRequest) GetFieldDisplayName() map[string]string { return loginRequestDisplayNames }

func (l LoginRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(l.GetFieldDisplayName(), &l,
		helper.Field(&l.Email, ozzo.Required, is.Email),
		helper.Field(&l.Password, ozzo.Required),
	)
}
