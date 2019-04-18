package geetest

var (
	Version = "3.0.0"

	FnChallenge = "geetest_challenge"
	FnValidate  = "geetest_validate"
	FnSeccode   = "geetest_seccode"

	GTStatusSessionKey = "gt_server_status"

	APIURL          = "http://api.geetest.com"
	RegisterHandler = "/register.php"
	ValidateHandler = "/validate.php"
	JSONFormat      = false
)

type Geetest struct {
	PrivateKey  string
	CaptchaID   string
	SDKVersion  string
	responceStr string
}

func NewGeetest(captchaID, privateKey string) (*Geetest, error) {
	return &Geetest{
		PrivateKey:  privateKey,
		CaptchaID:   captchaID,
		SDKVersion:  Version,
		responceStr: "",
	}, nil
}
