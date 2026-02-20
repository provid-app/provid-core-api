package webrequest

type ValidateOTPRequest struct {
	OTP     string `json:"otp"`
	Email   string `json:"email"`
	Purpose string `json:"purpose"`
}
