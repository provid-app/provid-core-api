package webresponse

type TokenResponse struct {
	AccessToken  string `json:"acc"`
	RefreshToken string `json:"ref"`
}
