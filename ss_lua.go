package ss

import (
	"github.com/vela-security/vela-inode"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	vswitch "github.com/vela-security/vela-switch"
)

func (s *ss) String() string                         { return lua.B2S(s.Byte()) }
func (s *ss) Type() lua.LValueType                   { return lua.LTObject }
func (s *ss) AssertFloat64() (float64, bool)         { return 0, false }
func (s *ss) AssertString() (string, bool)           { return "", false }
func (s *ss) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (s *ss) Peek() lua.LValue                       { return s }

func (s *ss) inodeL(L *lua.LState) int {
	Inode(inode.All())
	return 0
}

func (s *ss) switchL(L *lua.LState) int {
	n := len(s.Sockets)
	if n == 0 {
		return 0
	}

	vsh := vswitch.CheckSwitch(L, 1)
	if vsh == nil {
		return 0
	}

	for i := 0; i < n; i++ {
		vsh.Do(s.Sockets[i])
	}

	return 0
}

func (s *ss) findL(L *lua.LState) int {
	key := L.CheckString(1)
	val := L.Get(2)
	if val.Type() == lua.LTNil {
		L.Push(lua.LNil)
		return 1
	}

	if len(s.Sockets) == 0 {
		L.Push(lua.LNil)
		return 1
	}

	for _, sock := range s.Sockets {
		if sock.Compare(key, val.String(), func(a string, b string) bool {
			return a == b
		}) {
			L.Push(sock)
			return 1
		}
	}

	L.Push(lua.LNil)
	return 1

}
func (s *ss) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "closed":
		return lua.LInt(s.CLOSED)
	case "listen":
		return lua.LInt(s.LISTEN)
	case "syn_sent":
		return lua.LInt(s.SYN_SENT)
	case "syn_rcvd":
		return lua.LInt(s.SYN_RCVD)
	case "estab":
		return lua.LInt(s.ESTABLISHED)
	case "fin_wait_1":
		return lua.LInt(s.FIN_WAIT1)
	case "fin_wait_2":
		return lua.LInt(s.FIN_WAIT2)
	case "close_wait":
		return lua.LInt(s.CLOSE_WAIT)
	case "closing":
		return lua.LInt(s.CLOSING)
	case "last_ack":
		return lua.LInt(s.LAST_ACK)
	case "time_wait":
		return lua.LInt(s.TIME_WAIT)
	case "delete_tcb":
		return lua.LInt(s.DELETE_TCB)
	case "total":
		return lua.LInt(s.Total)

	case "err":
		if s.Err == nil {
			return lua.LNil
		}
		return lua.S2L(s.Err.Error())

	case "find":
		return lua.NewFunction(s.findL)

	case "pipe":
		return lua.NewFunction(s.pipeL)

	case "switch":
		return lua.NewFunction(s.switchL)

	}

	return lua.LNil
}

func (s *ss) pipeL(L *lua.LState) int {
	n := len(s.Sockets)
	if n == 0 {
		return 0
	}
	pp := pipe.NewByLua(L, pipe.Env(xEnv))
	for i := 0; i < n; i++ {
		pp.Do(s.Sockets[i], L, func(err error) {
			xEnv.Errorf("socket ss pipe call fail %v", err)
		})
	}
	return 0
}
