//go:build windows
// +build windows

package ss

import (
	cond "github.com/vela-security/vela-cond"
	vswitch "github.com/vela-security/vela-switch"
	"go.uber.org/ratelimit"
	"time"
)

type option struct {
	flag  *OptionFlag
	proto string
	rate  ratelimit.Limiter
	cnd   *cond.Cond
	vsh   *vswitch.Switch
	pid   []int
	inode interface{}
	hook  func(sock *Socket) (stop bool)
}

func newOption() *option {
	return &option{}
}

func oop(*option) {}

func Rate(n int, tv time.Duration) func(*option) {
	return func(o *option) {
		o.rate = ratelimit.New(n, ratelimit.Per(tv))
	}
}

func Hook(v func(*Socket) (stop bool)) func(*option) {
	return func(o *option) {
		o.hook = v
	}
}

func Limit(rate ratelimit.Limiter) func(*option) {
	return func(o *option) {
		o.rate = rate
	}
}

func Inode(v interface{}) func(*option) {
	return oop
}

func Pid(v []int) func(*option) {
	return oop
}

func State(v OptionFlagState) func(*option) {
	if len(v) == 0 {
		return oop
	}
	if v[0] == "*" || v[0] == "all" {
		return oop
	}

	cnd := cond.New("state = " + v.String())
	return Cnd(cnd)
}

func Switch(v *vswitch.Switch) func(*option) {
	return func(o *option) {
		o.vsh = v
	}
}

func Flag(of *OptionFlag) func(*option) {
	return func(opt *option) {
		opt.flag = of
	}
}

func Cnd(v *cond.Cond) func(*option) {
	return func(o *option) {
		if o.cnd != nil {
			o.cnd.Merge(v)
		} else {
			o.cnd = v
		}
	}
}
