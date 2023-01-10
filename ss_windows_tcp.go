//go:build windows
// +build windows

package ss

import (
	"syscall"
)

func (s *ss) tcp4() {
	tbl, err := GetTCPTable2(true)
	if err != nil {
		s.Err = err
		return
	}

	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		s.Err = err
		return
	}
	defer snp.Close()

	rows := tbl.Rows()
	for _, row := range rows {
		sock := toSocket(&row)
		sock.Protocol = syscall.IPPROTO_TCP
		sock.Family = syscall.IPPROTO_IP
		s.handle(sock)
	}
}

func (s *ss) tcp6() {
	tbl, err := GetTCP6Table2(true)
	if err != nil {
		s.Err = err
		return
	}

	snp, err := CreateToolhelp32Snapshot(Th32csSnapProcess, 0)
	if err != nil {
		s.Err = err
		return
	}
	defer snp.Close()

	rows := tbl.Rows()
	for _, row := range rows {
		sock := toSocket(&row)
		sock.Protocol = syscall.IPPROTO_TCP
		sock.Family = syscall.IPPROTO_IPV6
		s.handle(sock)
	}
}

func (s *ss) tcp() {
	s.tcp4()
	s.tcp6()
}
