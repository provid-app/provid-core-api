package category_repository

import (
	"context"
	"strings"

	"provid-backend/gen/core/model"
	corequery "provid-backend/gen/core/query"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
)

type CategoryRepositoryImpl struct {
	Query *corequery.Query
}

func NewCategoryRepository(query *corequery.Query) CategoryRepository {
	return &CategoryRepositoryImpl{Query: query}
}

func (R *CategoryRepositoryImpl) ListCategories(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MCategory, webresponse.MetadataResponse, error) {
	q := R.Query.MCategory.WithContext(ctx)
	m := R.Query.MCategory

	// --- Pagination normalization (server-side) ---
	limit := req.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	page := req.Page
	offset := req.Offset
	if page > 0 {
		offset = (page - 1) * limit
	}
	if offset < 0 {
		offset = 0
	}
	if page <= 0 {
		page = (offset / limit) + 1
	}

	// --- Search (simple, safe LIKE) ---
	if sp := strings.TrimSpace(req.SearchParam); sp != "" {
		like := "%" + sp + "%"
		q = q.Where(
			m.CategoryName.Like(like),
		).Or(
			m.Description.Like(like),
		)
	}

	// --- Filters (limited to known safe fields) ---
	if req.Filters != nil {
		for k, v := range req.Filters {
			switch k {
			case "is_active":
				if b, ok := v.(bool); ok {
					q = q.Where(m.IsActive.Is(b))
				}
			case "google_category_id":
				switch val := v.(type) {
				case string:
					if strings.TrimSpace(val) != "" {
						q = q.Where(m.GoogleCategoryID.Eq(val))
					}
				case []string:
					if len(val) > 0 {
						q = q.Where(m.GoogleCategoryID.In(val...))
					}
				}
			case "symbol":
				switch val := v.(type) {
				case string:
					if strings.TrimSpace(val) != "" {
						q = q.Where(m.Symbol.Eq(val))
					}
				case []string:
					if len(val) > 0 {
						q = q.Where(m.Symbol.In(val...))
					}
				}
			}
		}
	}

	// --- Ordering (whitelist to prevent SQL injection) ---
	orderExpr := m.CreatedAt.Desc()
	if sortField := strings.TrimSpace(req.SortBy); sortField != "" {
		if f, ok := m.GetFieldByName(sortField); ok {
			switch strings.ToLower(strings.TrimSpace(req.SortOrder)) {
			case "asc":
				orderExpr = f.Asc()
			default:
				orderExpr = f.Desc()
			}
		}
	}
	q = q.Order(orderExpr)

	items, total, err := q.FindByPage(offset, limit)
	if err != nil {
		return nil, webresponse.MetadataResponse{}, err
	}

	totalPages := int((total + int64(limit) - 1) / int64(limit))

	meta := webresponse.MetadataResponse{
		Page:       page,
		Limit:      limit,
		Offset:     offset,
		Total:      total,
		TotalPages: totalPages,
	}
	return items, meta, nil
}

func (R *CategoryRepositoryImpl) CreateCategory(ctx context.Context, category *model.MCategory) error {
	return R.Query.MCategory.WithContext(ctx).Create(category)
}

func (R *CategoryRepositoryImpl) GetCategoryByID(ctx context.Context, id string) (*model.MCategory, error) {
	m := R.Query.MCategory
	return m.WithContext(ctx).Where(m.ID.Eq(id)).First()
}

func (R *CategoryRepositoryImpl) UpdateCategory(ctx context.Context, category *model.MCategory) error {
	return R.Query.MCategory.WithContext(ctx).Save(category)
}

func (R *CategoryRepositoryImpl) DeleteCategoryByID(ctx context.Context, id string) error {
	m := R.Query.MCategory
	_, err := m.WithContext(ctx).Where(m.ID.Eq(id)).Delete()
	return err
}
