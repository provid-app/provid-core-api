package category_repository

import (
	"context"
	"provid-backend/gen/core/model"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
)

type CategoryRepository interface {
	ListCategories(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MCategory, webresponse.MetadataResponse, error)

	CreateCategory(ctx context.Context, category *model.MCategory) error
	UpdateCategory(ctx context.Context, category *model.MCategory) error
	GetCategoryByID(ctx context.Context, id string) (*model.MCategory, error)
	DeleteCategoryByID(ctx context.Context, id string) error
}
