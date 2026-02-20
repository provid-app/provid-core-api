package webrequest

type MetadataRequest struct {
	SearchParam string                 `json:"search_param"`
	Page        int                    `json:"page"`
	Limit       int                    `json:"limit"`
	Offset      int                    `json:"offset"`
	SortBy      string                 `json:"sort_by"`
	SortOrder   string                 `json:"sort_order"`
	Filters     map[string]interface{} `json:"filters"`
}
