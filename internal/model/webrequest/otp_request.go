package webrequest

type OTPRequest struct {
	UserID  string `json:"user_id"`
	Purpose string `json:"purpose"`
	Mail    string `json:"email"`
}
