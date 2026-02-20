package webresponse

type MetadataResponse struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Offset     int   `json:"offset"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}
