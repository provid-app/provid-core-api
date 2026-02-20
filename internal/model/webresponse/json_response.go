package webresponse

type JSONResponse struct {
	Error     bool   `json:"error"`
	NewToken  string `json:"new_token,omitempty"`
	LogList   any    `json:"log_list,omitempty"`
	ErrorList any    `json:"error_list,omitempty"`
	Message   string `json:"message"`
	Data      any    `json:"data,omitempty"`
}
