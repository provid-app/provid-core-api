package segmen_repository

import (
	"context"
	"provid-backend/gen/core/model"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
)

type SegmenRepository interface {
	ListSegments(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MSegman, webresponse.MetadataResponse, error)

	CreateSegmen(ctx context.Context, segmen *model.MSegman) error
	UpdateSegmen(ctx context.Context, segmen *model.MSegman) error
	GetSegmenByID(ctx context.Context, id string) (*model.MSegman, error)
	DeleteSegmenByID(ctx context.Context, id string) error
}
