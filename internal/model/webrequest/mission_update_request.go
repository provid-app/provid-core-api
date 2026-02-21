package webrequest

import (
	"provid-backend/internal/helper"
	"provid-backend/internal/model/data"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

type UpdateMissionRequest struct {
	ID           string   `json:"id"`
	MissionName  string   `json:"mission_name"`
	Instruction  *string  `json:"instruction"`
	RewardPoints *float64 `json:"reward_points"`
	MissionValue *float64 `json:"mission_value"`
	MissionType  string   `json:"mission_type"`
	SegmentID    string   `json:"segment_id"`

	ScheduleAt *string `json:"schedule_at"`
	PublishAt  *string `json:"publish_at"`
}

func (r UpdateMissionRequest) Validate() []data.ValidationErrorData {
	return helper.ValidateStruct(map[string]string{
		"id":           "ID",
		"mission_name": "Nama Misi",
		"mission_type": "Tipe Misi",
		"segment_id":   "Segmen",
	}, &r,
		helper.Field(&r.ID, ozzo.Required),
		helper.Field(&r.MissionName, ozzo.Required),
		helper.Field(&r.MissionType, ozzo.Required),
		helper.Field(&r.SegmentID, ozzo.Required),
	)
}
