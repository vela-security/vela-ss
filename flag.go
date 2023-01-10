package ss

import (
	"flag"
	"github.com/vela-security/vela-public/lua"
	"strings"
)

//vela.ss("-t -a -p -s 123 -s 456" , "addr = 127.0.0.1")
/*
-4 : IPv4
-6 : IPv6
-t : tcp
-u : udp
-a : all state default:connect
-p : process
-l : state listen
-s : state -s LISTEN -s ETABLISH -s SYN
*/

type OptionFlagState []string

func (f *OptionFlagState) String() string {
	return strings.Join(*f, ",")
}

func (f *OptionFlagState) Set(value string) error {
	strings.Replace(value, "_", "-", -1)
	*f = append(*f, value)
	return nil
}

type OptionFlag struct {
	allFamily bool //地址类别
	v4        bool
	v6        bool

	state    OptionFlagState
	allState bool
	listen   bool

	allProto bool
	tcp      bool
	udp      bool
	unix     bool
	ref      bool
}

func (of *OptionFlag) Ref() bool {
	return of.ref
}

func (of *OptionFlag) NoRef() *OptionFlag {
	of.ref = false
	return of
}

func (of *OptionFlag) V4() bool {
	if of.allFamily {
		return true
	}

	return of.v4
}

func (of *OptionFlag) V6() bool {
	if of.allFamily {
		return true
	}
	return of.v6
}

func (of *OptionFlag) HaveTCP() bool {
	if of.allProto {
		return true
	}

	return of.tcp
}

func (of *OptionFlag) HaveUDP() bool {
	if of.allProto {
		return true
	}

	return of.udp
}

func (of *OptionFlag) prepare() {

	//关闭所有协议标签
	if of.tcp {
		of.allProto = false
	}

	if of.udp {
		of.allProto = false
	}

	//关闭所有状态
	if of.listen {
		of.state = []string{"LISTEN"}
	}

	//关闭所有地址类
	if of.v4 {
		of.allFamily = false
	}

	if of.v6 {
		of.allFamily = false
	}
}

func NewOptionFlag(v string) (*OptionFlag, error) {
	of := &OptionFlag{}

	var opt flag.FlagSet
	opt.BoolVar(&of.v4, "4", false, "ipv4")
	opt.BoolVar(&of.v6, "6", false, "ipv6")
	opt.BoolVar(&of.tcp, "t", false, "tcp")
	opt.BoolVar(&of.udp, "u", false, "udp")
	opt.BoolVar(&of.ref, "p", false, "process")
	opt.Var(&of.state, "s", "state")
	opt.BoolVar(&of.allState, "a", true, "state")
	opt.BoolVar(&of.listen, "l", false, "listen state")
	of.allState = true
	of.allProto = true
	of.allFamily = true

	args := strings.Split(v, " ")
	err := opt.Parse(args)
	if err != nil {
		return nil, err
	}

	of.prepare()
	return of, nil
}

func NewOptionFlagL(L *lua.LState, idx int) *OptionFlag {
	v := L.IsString(idx)
	of, err := NewOptionFlag(v)
	if err != nil {
		L.RaiseError("invalid option %v", err)
		return nil
	}
	of.prepare()
	return of
}
