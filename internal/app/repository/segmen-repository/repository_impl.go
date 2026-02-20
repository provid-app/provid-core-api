package segmen_repository

import (
	"context"
	"strings"

	"provid-backend/gen/core/model"
	corequery "provid-backend/gen/core/query"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"
)

type SegmenRepositoryImpl struct {
	Query *corequery.Query
}

func NewSegmenRepository(query *corequery.Query) SegmenRepository {
	return &SegmenRepositoryImpl{Query: query}
}

func (S *SegmenRepositoryImpl) ListSegments(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MSegman, webresponse.MetadataResponse, error) {
	q := S.Query.MSegman.WithContext(ctx)
	m := S.Query.MSegman

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
			m.SegmenName.Like(like),
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

func (S *SegmenRepositoryImpl) CreateSegmen(ctx context.Context, segmen *model.MSegman) error {
	// Use UnderlyingDB().Select() to ensure is_active is included even when false.
	// gorm-gen's Select() with Create() doesn't properly handle zero values,
	// so we fall back to standard GORM which respects the Select clause.
	m := S.Query.MSegman
	return m.WithContext(ctx).UnderlyingDB().
		Select("id", "segmen_name", "description", "is_active", "symbol", "type_segmen", "created_at", "updated_at").
		Create(segmen).Error
}

func (S *SegmenRepositoryImpl) GetSegmenByID(ctx context.Context, id string) (*model.MSegman, error) {
	m := S.Query.MSegman
	return m.WithContext(ctx).Where(m.ID.Eq(id)).First()
}

func (S *SegmenRepositoryImpl) UpdateSegmen(ctx context.Context, segmen *model.MSegman) error {
	return S.Query.MSegman.WithContext(ctx).Save(segmen)
}

func (S *SegmenRepositoryImpl) DeleteSegmenByID(ctx context.Context, id string) error {
	m := S.Query.MSegman
	// Delete expects model instance(s)
	_, err := m.WithContext(ctx).Where(m.ID.Eq(id)).Delete()
	return err
}
