package geetest

import (
	"fmt"
	"testing"

	"github.com/cheekybits/is"
)

var (
	privateKey = "hoge"
	captchaID  = "fuga"
	err        error
)

func TestNewGeetest(t *testing.T) {
	is := is.New(t)
	g, err := NewGeetest(privateKey, captchaID)
	is.NoErr(err)
	fmt.Println(g)
}
