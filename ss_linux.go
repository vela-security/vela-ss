package ss

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-inode"
	"github.com/vela-security/vela-process"
	"golang.org/x/sys/unix"
	"strconv"
)

var notNetlinkSupport = false

func (s *ss) handle(sock *Socket) {
	//限速
	s.wait()

	if s.ov.inode != nil {
		sock.Pid = uint32(s.ov.inode.FindPid(sock.Inode))
	}

	if !s.match(sock) {
		return
	}

	if s.ov.flag.Ref() {
		sock.P()
	}

	if s.ov.hook != nil {
		if s.ov.hook(sock) {
			s.over = true
		}
	}

	if s.ov.vsh != nil {
		s.ov.vsh.Do(sock)
	}

	s.append(sock)
}

func (s *ss) do(family, protocol uint8) {
	if supportNetLink {
		err := s.netlink(family, protocol)
		if err != nil {
			xEnv.Infof("netlink fail %v", err)
		}
		return
	}

	err := s.proc(family, protocol)
	if err != nil {
		s.Err = err
		return
	}
	s.Err = nil
}

func (s *ss) tcp4() {
	s.do(unix.AF_INET, unix.IPPROTO_TCP)
}

func (s *ss) tcp6() {
	s.do(unix.AF_INET6, unix.IPPROTO_TCP)
}

func (s *ss) udp4() {
	s.do(unix.AF_INET, unix.IPPROTO_UDP)
}

func (s *ss) udp6() {
	s.do(unix.AF_INET6, unix.IPPROTO_UDP)
}

func ByPID(pid int, opt ...func(*option)) *ss {
	ov := newOption()
	ov.cnd = cond.New("pid = " + strconv.Itoa(pid))

	for _, fn := range opt {
		fn(ov)
	}

	ov.hook = func(s *Socket) (stop bool) {
		s.Pid = uint32(pid)
		s.P()
		return
	}

	return ssByOption(ov)
}

func ByProcess(p *process.Process, opt ...func(*option)) *ss {
	ov := newOption()
	for _, fn := range opt {
		fn(ov)
	}

	ov.inode = inode.New([]int{p.Pid})

	ov.hook = func(s *Socket) (stop bool) {
		s.Pid = uint32(p.Pid)
		s.Process = p.Executable
		return
	}

	return ssByOption(ov)

}

func withKernel() {
	info := xEnv.Kernel()
	if info == "" {
		supportNetLink = false
		return
	}

	n, _ := strconv.Atoi(string(info[0]))
	if n >= 3 {
		xEnv.Errorf("%s socket support netlink", info)
		supportNetLink = true
		return
	}

	supportNetLink = false
	xEnv.Errorf("%s socket not support netlink", info)
}
