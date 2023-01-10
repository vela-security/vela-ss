package ss

import (
	"github.com/vela-security/vela-inode"
	"github.com/vela-security/vela-public/kind"
)

type ss struct {
	CLOSED      int       `json:"closed"`
	LISTEN      int       `json:"listen"`
	SYN_SENT    int       `json:"syn_sent"`
	SYN_RCVD    int       `json:"syn_rcvd"`
	ESTABLISHED int       `json:"established"`
	FIN_WAIT1   int       `json:"fin_wait1"`
	FIN_WAIT2   int       `json:"fin_wait2"`
	CLOSE_WAIT  int       `json:"close_wait"`
	CLOSING     int       `json:"closing"`
	LAST_ACK    int       `json:"last_ack"`
	TIME_WAIT   int       `json:"time_wait"`
	DELETE_TCB  int       `json:"delete_tcb, omitempty"`
	Total       int       `json:"total"`
	Sockets     []*Socket `json:"sockets"`
	Err         error     `json:"-"`
	over        bool      `json:"-"`
	ov          *option   `json:"-"`
}

func (s *ss) Break() {
	s.over = true
}

func (s *ss) append(v *Socket) {
	switch v.State {

	case "ESTAB":
		s.ESTABLISHED++
	case "SYN-SENT":
		s.SYN_SENT++
	case "SYN-RCVD":
		s.SYN_RCVD++
	case "FIN-WAIT-1":
		s.FIN_WAIT1++
	case "FIN-WAIT-2":
		s.FIN_WAIT2++
	case "TIME-WAIT":
		s.TIME_WAIT++
	case "CLOSED":
		s.CLOSED++
	case "CLOSE-WAIT":
		s.CLOSE_WAIT++
	case "LAST-ACK":
		s.LAST_ACK++
	case "LISTEN":
		s.LISTEN++
	case "CLOSING":
		s.CLOSING++

	}
	s.Total++
	s.Sockets = append(s.Sockets, v)
}

func (s *ss) Byte() []byte {
	buf := kind.NewJsonEncoder()
	buf.Tab("")
	buf.KV("closed", s.CLOSED)
	buf.KV("listen", s.LISTEN)
	buf.KV("syn_sent", s.SYN_SENT)
	buf.KV("syn_rcvd", s.SYN_RCVD)
	buf.KV("established", s.ESTABLISHED)
	buf.KV("fin_wait1", s.FIN_WAIT1)
	buf.KV("fin_wait2", s.FIN_WAIT2)
	buf.KV("close_wait", s.CLOSE_WAIT)
	buf.KV("closing", s.CLOSING)
	buf.KV("last_ack", s.LAST_ACK)
	buf.KV("time_wait", s.TIME_WAIT)
	buf.KV("delete_tcb", s.DELETE_TCB)
	buf.Arr("sockets")

	for _, item := range s.Sockets {
		item.Marshal(buf)
	}
	buf.End("]}")

	return buf.Bytes()
}

func (s *ss) match(v *Socket) bool {
	if s.ov.cnd == nil {
		return true
	}

	if s.ov.flag.listen && v.State != "LISTEN" {
		return false
	}

	return s.ov.cnd.Match(v)
}

func (s *ss) wait() {
	if s.ov.rate == nil {
		return
	}
	s.ov.rate.Take()
}

func (s *ss) V4() {
	if !s.ov.flag.V4() {
		return
	}

	if s.ov.flag.HaveTCP() {
		s.tcp4()
	}

	if s.ov.flag.HaveUDP() {
		s.udp4()
	}
}

func (s *ss) V6() {
	if !s.ov.flag.V6() {
		return
	}

	if s.ov.flag.HaveTCP() {
		s.tcp6()
	}

	if s.ov.flag.HaveUDP() {
		s.udp6()
	}
}

func (s *ss) prepare() {
	if s.ov.flag.Ref() {
		s.ov.inode = inode.New(s.ov.pid)
	}

	if s.ov.flag.listen {
		State(OptionFlagState{"LISTEN"})(s.ov)
		return
	}

	if s.ov.flag.allState {
		State(OptionFlagState{"*"})(s.ov)
		return
	}
	State(s.ov.flag.state)(s.ov) //设置状态
}

func ssByOption(ov *option) *ss {
	s := &ss{ov: ov}
	s.prepare()
	s.V4()
	s.V6()
	s.unix()
	return s
}

func By(opt ...func(*option)) *ss {
	ov := newOption()
	for _, fn := range opt {
		fn(ov)
	}
	return ssByOption(ov)
}
