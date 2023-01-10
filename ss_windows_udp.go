//go:build windows
// +build windows

package ss

import (
	"syscall"
)

func (s *ss) udp4() {
	tbl, err := GetUDPTableOwnerPID(true)
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
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IP
		s.handle(sock)
	}
}

func (s *ss) udp6() {
	tbl, err := GetUDP6TableOwnerPID(true)
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
		sock.Protocol = syscall.IPPROTO_UDP
		sock.Family = syscall.IPPROTO_IPV6
		s.handle(sock)
	}
}

func (s *ss) udp() {
	s.udp4()
	s.udp6()
}
