package webrequest

import (
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type CreateMissionRequest struct {
	MissionName  string  `json:"mission_name"`
	Instruction  string  `json:"instruction"`
	RewardPoints float64 `json:"reward_points"`
	MissionValue float64 `json:"mission_value"`
	MissionType  string  `json:"mission_type"`
	ScheduledAt  *string `json:"scheduled_at"`
	PublishedAt  *string `json:"published_at"`
}

func (r CreateMissionRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"mission_name": "Nama Misi",
		"mission_type": "Tipe Misi",
	}, &r,
		helper.Field(&r.MissionName, ozzo.Required),
		helper.Field(&r.MissionType, ozzo.Required),
	)
}
