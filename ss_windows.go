package ss

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-process"
	"strconv"
)

var notSupportNetlink uint32 = 0

func (s *ss) handle(sock *Socket) {
	//限速
	s.wait()

	if !s.match(sock) {
		return
	}

	if s.ov.hook != nil {
		s.ov.hook(sock)
	}

	if s.ov.vsh != nil {
		s.ov.vsh.Do(sock)
	}

	s.append(sock)
}

func ByPID(pid int, opt ...func(*option)) *ss {
	ov := newOption()
	ov.cnd = cond.New("pid = " + strconv.Itoa(pid))

	for _, fn := range opt {
		fn(ov)
	}

	return ssByOption(ov)
}

func ByProcess(p *process.Process, opt ...func(*option)) *ss {
	ov := newOption()
	ov.cnd = cond.New("pid = " + strconv.Itoa(p.Pid))
	for _, fn := range opt {
		fn(ov)
	}

	return ssByOption(ov)
}

func withKernel() {
}
