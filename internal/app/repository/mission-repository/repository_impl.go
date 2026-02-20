package mission_repository

import (
	"context"
	"strings"

	"provid-backend/gen/core/model"
	corequery "provid-backend/gen/core/query"
	"provid-backend/internal/model/webrequest"
	"provid-backend/internal/model/webresponse"

	"gorm.io/gen/field"
)

type MissionRepositoryImpl struct {
	Query *corequery.Query
}

func NewMissionRepository(query *corequery.Query) MissionRepository {
	return &MissionRepositoryImpl{Query: query}
}

func (M *MissionRepositoryImpl) ListMissions(ctx context.Context, req webrequest.MetadataRequest) ([]*model.MMission, webresponse.MetadataResponse, error) {
	q := M.Query.MMission.WithContext(ctx)
	m := M.Query.MMission

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
		q = q.Where(m.MissionName.Like(like))
	}

	// --- Filters (limited to known safe fields) ---
	// If you need more filters later, add explicit cases here.
	if req.Filters != nil {
		for k, v := range req.Filters {
			switch k {
			case "status":
				switch val := v.(type) {
				case string:
					if strings.TrimSpace(val) != "" {
						q = q.Where(m.Status.Eq(val))
					}
				case []string:
					if len(val) > 0 {
						q = q.Where(m.Status.In(val...))
					}
				}
			case "is_active":
				if b, ok := v.(bool); ok {
					q = q.Where(m.IsActive.Is(b))
				}
			case "is_scheduled":
				if b, ok := v.(bool); ok {
					q = q.Where(m.IsScheduled.Is(b))
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

	missions, total, err := q.FindByPage(offset, limit)
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
	return missions, meta, nil
}

func (M *MissionRepositoryImpl) CreateMission(ctx context.Context, mission *model.MMission) error {
	m := M.Query.MMission
	omit := make([]field.Expr, 0, 2)
	if mission.ScheduledAt.IsZero() {
		omit = append(omit, m.ScheduledAt)
	}
	if mission.PublishedAt.IsZero() {
		omit = append(omit, m.PublishedAt)
	}
	return m.WithContext(ctx).Omit(omit...).Create(mission)
}

func (M *MissionRepositoryImpl) GetMissionByID(ctx context.Context, id string) (*model.MMission, error) {
	m := M.Query.MMission
	return m.WithContext(ctx).Where(m.ID.Eq(id)).First()
}

func (M *MissionRepositoryImpl) UpdateMission(ctx context.Context, mission *model.MMission) error {
	return M.Query.MMission.WithContext(ctx).Save(mission)
}
