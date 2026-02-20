package mission_repository

import (
	"context"
	"provid-backend/gen/core/model"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
)

type MissionRepository interface {
	ListMissions(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MMission, webresponse.MetadataResponse, error)
	CreateMission(ctx context.Context, mission *model.MMission) error
	GetMissionByID(ctx context.Context, id string) (*model.MMission, error)
	UpdateMission(ctx context.Context, mission *model.MMission) error
}
