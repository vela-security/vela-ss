package ss

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-process"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"syscall"
)

func (sock *Socket) Type() lua.LValueType                   { return lua.LTObject }
func (sock *Socket) AssertFloat64() (float64, bool)         { return 0, false }
func (sock *Socket) AssertString() (string, bool)           { return "", false }
func (sock *Socket) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sock *Socket) Peek() lua.LValue                       { return sock }

func (sock *Socket) Proto() string {
	switch sock.Protocol {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	default:
		return ""
	}
}

func (sock *Socket) P() string {
	if sock.Process != "" {
		return sock.Process
	}

	p, e := process.Pid(int(sock.Pid))
	if e != nil {
		return ""
	}

	sock.Process = p.Executable
	sock.Username = p.Username
	return p.Executable
}

func (sock *Socket) Compare(key, val string, cnd cond.Method) bool {
	switch key {
	case "pid":
		return cnd(auxlib.ToString(sock.Pid), val)
	case "local_addr":
		return cnd(sock.LocalIP, val)
	case "local_port":
		return cnd(auxlib.ToString(sock.LocalPort), val)
	case "Remote_addr":
		return cnd(sock.RemoteIP, val)
	case "Remote_port":
		return cnd(auxlib.ToString(sock.RemotePort), val)
	case "state":
		return cnd(sock.State, val)

	default:
		return cnd(sock.Index(nil, key).String(), val)
	}
}

func (sock *Socket) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "pid":
		return lua.LInt(sock.Pid)
	case "family":
		return lua.LInt(sock.Family)
	case "protocol":
		return lua.LString(sock.Proto())

	case "local_addr", "src":
		return lua.S2L(sock.LocalIP)
	case "local_port", "src_port":
		return lua.LInt(sock.LocalPort)
	case "remote_addr", "dst":
		return lua.S2L(sock.RemoteIP)
	case "remote_port", "dst_port":
		return lua.LInt(sock.RemotePort)

	case "path":
		return lua.S2L(sock.Path)

	case "state":
		return lua.S2L(sock.State)

	case "process":
		return lua.S2L(sock.P())

	case "user":
		return lua.S2L(sock.Username)
	case "inode":
		return lua.LInt(sock.Inode)
	}

	return lua.LNil

}
