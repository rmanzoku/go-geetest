package geetest

import (
	"fmt"
	"os"
	"testing"

	"github.com/cheekybits/is"
)

var (
	privateKey = os.Getenv("KEY")
	captchaID  = os.Getenv("ID")
	err        error
)

func TestNewGeetest(t *testing.T) {
	is := is.New(t)
	g, err := NewGeetest(privateKey, captchaID)
	is.NoErr(err)
	fmt.Println(g)
}

func TestPreProcess(t *testing.T) {
	is := is.New(t)
	g, err := NewGeetest(privateKey, captchaID)
	is.NoErr(err)

	_, err = g.PreProcess(
		"",
		1,
		1,
		"web",
		"127.0.0.1",
	)
	is.NoErr(err)
}
