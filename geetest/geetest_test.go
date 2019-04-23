package geetest

import (
	"os"
	"testing"

	"github.com/cheekybits/is"
)

var (
	privateKey = os.Getenv("KEY")
	captchaID  = os.Getenv("ID")
	err        error
	g          = &Geetest{}
	challenge  = ""
)

func TestNewGeetest(t *testing.T) {
	is := is.New(t)
	g, err = NewGeetest(privateKey, captchaID)
	is.NoErr(err)
}

func TestPreProcess(t *testing.T) {
	is := is.New(t)
	_, err = g.PreProcess(
		"",
		1,
		1,
		"web",
		"127.0.0.1",
	)
	is.NoErr(err)
}

// func TestSuccessValidate(t *testing.T) {
// 	is := is.New(t)

// 	fmt.Println(g.GetResponseStr())
// 	r, err := g.GetResponse()
// 	is.NoErr(err)

// 	fmt.Println(r)

// 	_, err = g.SuccessValidate()
// 	is.NoErr(err)
// }
