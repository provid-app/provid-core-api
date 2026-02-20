package webrequest

import (
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type CreateCategoryRequest struct {
	CategoryName     string `json:"category_name"`
	GoogleCategoryID string `json:"google_category_id"`
	Description      string `json:"description"`
	IsActive         *bool  `json:"is_active"`
	Symbol           string `json:"symbol"`
}

func (r CreateCategoryRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"category_name":      "Nama Kategori",
		"google_category_id": "Google Category ID",
	}, &r,
		helper.Field(&r.CategoryName, ozzo.Required),
		helper.Field(&r.GoogleCategoryID, ozzo.Required),
	)
}

type UpdateCategoryRequest struct {
	ID               string `json:"id"`
	CategoryName     string `json:"category_name"`
	GoogleCategoryID string `json:"google_category_id"`
	Description      string `json:"description"`
	IsActive         *bool  `json:"is_active"`
	Symbol           string `json:"symbol"`
}

func (r UpdateCategoryRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"id":                 "ID",
		"category_name":      "Nama Kategori",
		"google_category_id": "Google Category ID",
	}, &r,
		helper.Field(&r.ID, ozzo.Required),
		helper.Field(&r.CategoryName, ozzo.Required),
		helper.Field(&r.GoogleCategoryID, ozzo.Required),
	)
}
