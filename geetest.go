package geetest

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
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

type response struct {
	Success    uint8  `json:"success"`
	CaptchaID  string `json:"gt"`
	Challenge  string `json:"challenge"`
	NewCaptcha bool   `json:"new_captcha"`
}

type request struct {
	Seccode    string `json:"seccode"`
	SDK        string `json:"sdk"`
	UserID     string `json:"user_id"`
	Data       string `json:"data"`
	Timestamp  int64  `json:"timestamp"`
	Challenge  string `json:"challenge"`
	UserInfo   string `json:"userinfo"`
	CaptchaID  string `json:"captchaid"`
	JSONFormat uint8  `json:"json_format"`
}

func NewGeetest(captchaID, privateKey string) (*Geetest, error) {
	return &Geetest{
		PrivateKey:  privateKey,
		CaptchaID:   captchaID,
		SDKVersion:  Version,
		responceStr: "",
	}, nil
}

func (g *Geetest) PreProcess(userID string, newCaptcha uint8, jsonFormat uint8, clientType string, ipAddress string) (uint8, error) {
	status, challege, err := g.register(userID, newCaptcha, jsonFormat, clientType, ipAddress)
	if err != nil {
		return status, err
	}
	g.responceStr, err = g.makeResponseFormat(status, challege, newCaptcha)
	return status, err
}

func (g *Geetest) register(userID string, newCaptcha uint8, jsonFormat uint8, clientType string, ipAddress string) (uint8, string, error) {
	status := uint8(0)
	var challenge string

	priResponceStr, err := g.registerChallenge(userID, newCaptcha, jsonFormat, clientType, ipAddress)
	if err != nil {
		return status, challenge, err
	}
	if priResponceStr != "" {
		if jsonFormat == 1 {
			res := new(response)
			err := json.Unmarshal([]byte(priResponceStr), res)
			if err != nil {
				return status, challenge, err
			}
			challenge = res.Challenge
		} else {
			challenge = priResponceStr
		}
	} else {
		challenge = " "
	}

	if len(challenge) == 32 {
		challenge = g.md5Encode(challenge)
		return 1, challenge, nil
	}

	return 0, g.makeFailChallenge(), nil
}

func (g *Geetest) GetResponseStr() string {
	return g.responceStr
}

func (g *Geetest) GetResponse() (*response, error) {
	r := new(response)
	return r, json.Unmarshal([]byte(g.responceStr), r)
}

func (g *Geetest) makeFailChallenge() string {
	rand.Seed(time.Now().UnixNano())
	rnd1 := rand.Intn(100)
	rnd2 := rand.Intn(100)
	md5Str1 := g.md5Encode(fmt.Sprintf("%v", rnd1))
	md5Str2 := g.md5Encode(fmt.Sprintf("%v", rnd2))
	return md5Str1 + md5Str2[0:2]
}

func (g *Geetest) makeResponseFormat(success uint8, challenge string, newCaptcha uint8) (string, error) {
	if challenge == "" {
		challenge = g.makeFailChallenge()
	}

	ret := &response{
		Success:   success,
		CaptchaID: g.CaptchaID,
		Challenge: challenge,
	}

	if newCaptcha != 0 {
		ret.NewCaptcha = true
	} else {
		ret.NewCaptcha = false
	}

	jsonByte, err := json.Marshal(ret)
	return string(jsonByte), err
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

	res, err := http.Get(registerURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}

func (g *Geetest) SuccessValidate(challenge string, validate string, seccode string, userID string, gt string, data string, userInfo string, jsonFormat uint8) (uint8, error) {
	var err error
	if !g.checkPara(challenge, validate, seccode) {
		return 0, errors.New("checkPara")
	}
	if !g.checkResult(challenge, validate) {
		return 0, nil
	}

	validateURL := fmt.Sprintf("%s%s", APIURL, ValidateHandler)
	req := &request{
		Seccode:    seccode,
		SDK:        "github.com/rmanzoku/gt3-go-sdk",
		UserID:     userID,
		Data:       data,
		Timestamp:  time.Now().Unix(),
		Challenge:  challenge,
		UserInfo:   userInfo,
		CaptchaID:  gt,
		JSONFormat: jsonFormat,
	}
	_, err = g.postValues(validateURL, req)
	if err != nil {
		return 0, err
	}

	// fmt.Println(backinfo)
	return 1, nil

}

func (g *Geetest) postValues(apiServer string, body *request) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	res, err := http.Post(apiServer, "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	ret, err := ioutil.ReadAll(res.Body)
	return string(ret), err
}

func (g *Geetest) checkResult(origin, validate string) bool {
	encodeStr := g.md5Encode(g.PrivateKey + "geetest" + origin)
	if validate == encodeStr {
		return true
	}
	return false
}

func (g *Geetest) checkPara(challenge string, validate string, seccode string) bool {
	if challenge == "" {
		return false
	}
	if validate == "" {
		return false
	}
	if seccode == "" {
		return false
	}

	return true
}

func (g *Geetest) md5Encode(values string) string {
	ret := md5.Sum([]byte(values))
	return fmt.Sprintf("%x", ret)
}

func strip(str string) string {
	return strings.Join(strings.Fields(str), "")
}
