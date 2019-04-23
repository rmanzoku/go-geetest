package geetest

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/go-querystring/query"
	"github.com/pkg/errors"
)

var (
	// DefaultGeetest is default Geetest
	DefaultGeetest = &Geetest{}

	sdk             = "github.com/rmanzoku/go-geetest"
	apiURL          = "https://api.geetest.com"
	registerHandler = "/register.php"
	validateHandler = "/validate.php"
	jsonFormat      = 1
)

// Geetest is base struct for connection information for geetest.
type Geetest struct {
	PrivateKey  string
	CaptchaID   string
	RegisterURL string
	ValidateURL string
	SDK         string
}

// ClientValidate is a captcha response from geetest server on a client.
type ClientValidate struct {
	GeetestChallenge string `json:"geetest_challenge"`
	GeetestValidate  string `json:"geetest_validate"`
	GeetestSeccode   string `json:"geetest_seccode"`
}

// RegisterResponse is challenge infomation using on a client.
type RegisterResponse struct {
	Success    uint8  `json:"success"`
	CaptchaID  string `json:"gt"`
	Challenge  string `json:"challenge"`
	NewCaptcha bool   `json:"new_captcha"`
}

type registerRequest struct {
	UserID     string `url:"user_id,omitempty"`
	CaptchaID  string `url:"gt"`
	ClientType string `url:"client_type"`
	IPAddress  string `url:"ip_address"`
	JSONFormat int    `url:"json_format"`
}

type validateRequest struct {
	Seccode    string `json:"seccode" url:"seccode"`
	SDK        string `json:"sdk" url:"sdk"`
	UserID     string `json:"user_id" url:"user_id"`
	Data       string `json:"data" url:"data"`
	Timestamp  int64  `json:"timestamp" url:"timestamp"`
	Challenge  string `json:"challege" url:"challenge"`
	UserInfo   string `json:"userinfo" url:"userinfo"`
	CaptchaID  string `json:"captchaid" url:"captchaid"`
	JSONFormat int    `json:"json_format" url:"json_format"`
}

type validateResponse struct {
	Seccode string `json:"seccode"`
}

func NewGeetest(captchaID, privateKey string) (*Geetest, error) {
	return &Geetest{
		PrivateKey:  privateKey,
		CaptchaID:   captchaID,
		RegisterURL: apiURL + registerHandler,
		ValidateURL: apiURL + validateHandler,
		SDK:         sdk,
	}, nil
}

func (g *Geetest) PreProcess(userID string, newCaptcha bool, clientType string, ipAddress string) (*RegisterResponse, error) {
	req := &registerRequest{
		UserID:     userID,
		ClientType: clientType,
		IPAddress:  ipAddress,
		CaptchaID:  g.CaptchaID,
		JSONFormat: jsonFormat,
	}
	res, err := g.registerChallenge(req)
	if err != nil {
		return nil, err
	}

	res.Success = 1
	res.CaptchaID = g.CaptchaID
	res.NewCaptcha = newCaptcha

	if len(res.Challenge) == 32 {
		res.Challenge = g.md5Encode(res.Challenge + g.PrivateKey)
	} else {
		res.Challenge = g.makeFailChallenge()
	}

	return res, nil
}

func (g *Geetest) makeFailChallenge() string {
	rand.Seed(time.Now().UnixNano())
	rnd1 := rand.Intn(100)
	rnd2 := rand.Intn(100)
	md5Str1 := g.md5Encode(fmt.Sprintf("%v", rnd1))
	md5Str2 := g.md5Encode(fmt.Sprintf("%v", rnd2))
	return md5Str1 + md5Str2[0:2]
}

func (g *Geetest) registerChallenge(req *registerRequest) (*RegisterResponse, error) {
	registerURL := g.RegisterURL + "?" + req.Query()

	res, err := http.Get(registerURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	ret := new(RegisterResponse)
	return ret, json.Unmarshal(body, ret)
}

func (g *Geetest) SuccessValidate(challenge string, validate string, seccode string, userID string, data string, userInfo string) (bool, error) {
	var err error
	if !g.checkPara(challenge, validate, seccode) {
		return false, errors.New("Invalid parameter")
	}

	req := &validateRequest{
		Seccode:    seccode,
		SDK:        g.SDK,
		UserID:     userID,
		Data:       data,
		Timestamp:  time.Now().Unix(),
		Challenge:  challenge,
		UserInfo:   userInfo,
		CaptchaID:  g.CaptchaID,
		JSONFormat: jsonFormat,
	}

	backinfo, err := g.validateChallenge(req)
	if err != nil {
		return false, err
	}

	if backinfo.Seccode != g.md5Encode(seccode) {
		return false, errors.New("Invalid seccode")
	}

	return true, nil

}

func (g *Geetest) validateChallenge(req *validateRequest) (*validateResponse, error) {
	validateURL := g.ValidateURL + "?" + req.Query()

	res, err := http.Post(validateURL, "", nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	ret := new(validateResponse)
	return ret, json.Unmarshal(body, ret)
}

func (g *Geetest) checkPara(challenge, validate, seccode string) bool {
	if challenge == "" {
		return false
	}
	if validate == "" {
		return false
	}
	if seccode == "" {
		return false
	}

	encodeStr := g.md5Encode(g.PrivateKey + "geetest" + challenge)
	if validate != encodeStr {
		return false
	}

	return true
}

func (r *registerRequest) Query() string {
	v, _ := query.Values(r)
	return v.Encode()
}

func (r *validateRequest) Query() string {
	v, _ := query.Values(r)
	return v.Encode()
}

func (g *Geetest) md5Encode(values string) string {
	ret := md5.Sum([]byte(values))
	return fmt.Sprintf("%x", ret)
}
