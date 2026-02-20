package webrequest

import (
	"encoding/json"
	"strings"

	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type CreateSegmenRequest struct {
	SegmenName  string          `json:"segmen_name"`
	Description string          `json:"description"`
	IsActiveRaw json.RawMessage `json:"is_active"`
	Symbol      string          `json:"symbol"`
	TypeSegmen  string          `json:"type_segmen"`
}

func (r CreateSegmenRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"segmen_name": "Nama Segmen",
	}, &r,
		helper.Field(&r.SegmenName, ozzo.Required),
		helper.Field(&r.TypeSegmen, ozzo.Required),
	)
}

func (r CreateSegmenRequest) GetIsActiveOrDefault(defaultVal bool) bool {
	if len(r.IsActiveRaw) == 0 {
		return defaultVal
	}

	// Try bool first
	var b bool
	if err := json.Unmarshal(r.IsActiveRaw, &b); err == nil {
		return b
	}

	// Then try string ("true"/"false")
	var s string
	if err := json.Unmarshal(r.IsActiveRaw, &s); err == nil {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case "true", "1", "yes", "y":
			return true
		case "false", "0", "no", "n":
			return false
		}
	}

	// If invalid, keep default (we're not validating hard per your preference)
	return defaultVal
}

type UpdateSegmenRequest struct {
	ID          string          `json:"id"`
	SegmenName  string          `json:"segmen_name"`
	Description string          `json:"description"`
	IsActiveRaw json.RawMessage `json:"is_active"`
	Symbol      string          `json:"symbol"`
	TypeSegmen  string          `json:"type_segmen"`
}

func (r UpdateSegmenRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"id":          "ID",
		"segmen_name": "Nama Segmen",
	}, &r,
		helper.Field(&r.ID, ozzo.Required),
		helper.Field(&r.SegmenName, ozzo.Required),
		helper.Field(&r.TypeSegmen, ozzo.Required),
	)
}

func (r UpdateSegmenRequest) GetIsActiveOrNil() *bool {
	if len(r.IsActiveRaw) == 0 {
		return nil
	}

	var b bool
	if err := json.Unmarshal(r.IsActiveRaw, &b); err == nil {
		return &b
	}

	var s string
	if err := json.Unmarshal(r.IsActiveRaw, &s); err == nil {
		s = strings.TrimSpace(strings.ToLower(s))
		switch s {
		case "true", "1", "yes", "y":
			bb := true
			return &bb
		case "false", "0", "no", "n":
			bb := false
			return &bb
		}
	}

	return nil
}

type DeleteBulkRequest struct {
	IDs []string `json:"ids"`
}

func (r DeleteBulkRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"ids": "IDs",
	}, &r,
		helper.Field(&r.IDs, ozzo.Required, ozzo.Length(1, 0)),
	)
}
