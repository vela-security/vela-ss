//go:build linux
// +build linux

package ss

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-inode"
	vswitch "github.com/vela-security/vela-switch"
	"go.uber.org/ratelimit"
	"time"
)

const (
	SS_UNKNOWN uint32 = iota
	SS_ESTABLISHED
	SS_SYN_SENT
	SS_SYN_RECV
	SS_FIN_WAIT1
	SS_FIN_WAIT2
	SS_TIME_WAIT
	SS_CLOSE
	SS_CLOSE_WAIT
	SS_LAST_ACK
	SS_LISTEN
	SS_CLOSING
	SS_MAX
)

type option struct {
	flag     *OptionFlag
	rate     ratelimit.Limiter
	vsh      *vswitch.Switch
	cnd      *cond.Cond
	hook     func(sock *Socket) (stop bool)
	pid      []int
	inode    *inode.Inodes
	nlStates uint32 //netlink
	ntCnd    *cond.Cond
}

func newOption() *option {
	return &option{
		nlStates: uint32(1<<SS_MAX - 1),
	}
}

func Flag(f *OptionFlag) func(*option) {
	return func(o *option) {
		o.flag = f
	}
}

func Pid(v []int) func(*option) {
	return func(o *option) {
		o.pid = v
	}
}

func Rate(n int, tv time.Duration) func(*option) {
	return func(o *option) {
		o.rate = ratelimit.New(n, ratelimit.Per(tv))
	}
}

func Limit(rate ratelimit.Limiter) func(*option) {
	return func(o *option) {
		o.rate = rate
	}
}

func Switch(v *vswitch.Switch) func(*option) {
	return func(o *option) {
		o.vsh = v
	}
}

func Cnd(v *cond.Cond) func(*option) {
	return func(o *option) {
		if o.cnd == nil {
			o.cnd = v
		} else {
			o.cnd.Merge(v)
		}
	}
}

func Inode(v *inode.Inodes) func(*option) {
	return func(o *option) {
		o.inode = v
	}
}

func withNlState(v OptionFlagState) func(*option) {
	var state uint32
	for _, name := range v {
		switch name {
		case "LISTEN":
			state = state | uint32(1<<SS_LISTEN)
		case "SYN-SENT":
			state = state | uint32(1<<SS_SYN_SENT)
		case "SYN-RCVD":
			state = state | uint32(1<<SS_SYN_RECV)
		case "FIN-WAIT-1":
			state = state | uint32(1<<SS_FIN_WAIT1)
		case "FIN-WAIT-2":
			state = state | uint32(1<<SS_FIN_WAIT2)
		case "TIME-WAIT":
			state = state | uint32(1<<SS_TIME_WAIT)
		case "CLOSED":
			state = state | uint32(1<<SS_CLOSE)
		case "CLOSE-WAIT":
			state = state | uint32(1<<SS_CLOSE_WAIT)
		case "ESTAB":
			state = state | uint32(1<<SS_ESTABLISHED)
		case "CLOSING":
			state = state | uint32(1<<SS_CLOSING)

		case "*", "all":
			state = uint32(1<<SS_MAX - 1)
		}
	}

	return func(o *option) {
		o.nlStates = state
		o.cnd = cond.New()
	}
}

func State(v OptionFlagState) func(*option) {
	if len(v) == 0 {
		return func(_ *option) {}
	}

	if supportNetLink {
		return withNlState(v)
	}

	section := cond.NewSection()
	section.Keys("state")
	section.Method(cond.Eq)
	section.Value(v...)

	for _, name := range v {
		switch name {
		case "*", "all":
			return func(_ *option) {}
		default:
			section.Value(name)
		}
	}

	cnd := cond.New()
	return func(o *option) {
		cnd.Append(section)
		o.ntCnd = cnd
	}
}

func Hook(v func(*Socket) (stop bool)) func(*option) {
	return func(o *option) {
		o.hook = v
	}
}
