package geetest

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

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

func (g *Geetest) PreProcess(userID string, newCaptcha uint8, jsonFormat uint8, clientType string, ipAddress string) (interface{}, error) {
	_, priResponse, err := g.register(userID, newCaptcha, jsonFormat, clientType, ipAddress)
	return priResponse, err
}

func (g *Geetest) register(userID string, newCaptcha uint8, jsonFormat uint8, clientType string, ipAddress string) (interface{}, string, error) {
	priResponse, err := g.registerChallenge(userID, newCaptcha, jsonFormat, clientType, ipAddress)
	return nil, priResponse, err
}

func (g *Geetest) registerChallenge(userID string, newCaptcha uint8, jsonFormat uint8, clientType string, ipAddress string) (string, error) {
	var registerURL string
	if userID != "" {
		registerURL = fmt.Sprintf("%s%s?gt=%s&user_id=%s&json_format=%v&client_type=%s&ip_address=%s",
			APIURL, RegisterHandler, g.CaptchaID, userID, jsonFormat, clientType, ipAddress)
	} else {
		registerURL = fmt.Sprintf("%s%s?gt=%s&json_format=%v&client_type=%s&ip_address=%s",
			APIURL, RegisterHandler, g.CaptchaID, jsonFormat, clientType, ipAddress)
	}

	fmt.Println(registerURL)
	res, err := http.Get(registerURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}
