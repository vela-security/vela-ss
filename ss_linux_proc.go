//go:build linux
// +build linux

package ss

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func parseIP(hexIP string) (string, error) {
	var byteIP []byte
	byteIP, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", fmt.Errorf("cannot parse address field in socket line %q", hexIP)
	}
	switch len(byteIP) {
	case 4:
		return net.IP{byteIP[3], byteIP[2], byteIP[1], byteIP[0]}.String(), nil
	case 16:
		return net.IP{
			byteIP[3], byteIP[2], byteIP[1], byteIP[0],
			byteIP[7], byteIP[6], byteIP[5], byteIP[4],
			byteIP[11], byteIP[10], byteIP[9], byteIP[8],
			byteIP[15], byteIP[14], byteIP[13], byteIP[12],
		}.String(), nil

	default:
		return "", fmt.Errorf("unable to parse IP %s", hexIP)
	}
}

func (s *ss) ntCondMatch(sock *Socket) bool {
	if s.ov.ntCnd == nil {
		return true
	}

	return s.ov.ntCnd.Match(sock)
}

func readNt(family, protocol uint8, raw string, header map[int]string) (socket *Socket, droped bool, err error) {
	socket = &Socket{Family: family, Protocol: protocol}

	for index, key := range strings.Fields(raw) {
		switch header[index] {
		case "src":
			fields := strings.Split(key, ":")
			if len(fields) != 2 {
				droped = true
				break
			}
			socket.LocalIP, err = parseIP(fields[0])
			if err != nil {
				droped = true
				break
			}
			var port uint64
			port, err = strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				droped = true
				break
			}
			socket.LocalPort = int(port)
		case "dst":
			fields := strings.Split(key, ":")
			if len(fields) != 2 {
				droped = true
				break
			}
			socket.RemoteIP, err = parseIP(fields[0])
			if err != nil {
				droped = true
				break
			}
			var port uint64
			port, err = strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				droped = true
				break
			}
			socket.RemotePort = int(port)
		case "state":
			var st uint64
			st, err = strconv.ParseUint(key, 16, 64)
			if err != nil {
				continue
			}
			if (protocol == unix.IPPROTO_UDP && st != 7) || (protocol == unix.IPPROTO_TCP && st != 10) {
				droped = true
				break
			}
			socket.State = TCP2String(uint8(st))
		case "uid":
			uid, err := strconv.ParseUint(key, 0, 64)
			if err != nil {
				continue
			}
			socket.UID = uint32(uid)
			if user, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
				socket.Username = user.Name
			}
		case "inode":
			inode, err := strconv.ParseUint(key, 0, 64)
			if err != nil {
				continue
			}
			socket.Inode = uint32(inode)
		default:
		}
	}

	return
}

func readNtHeader(raw string) map[int]string {
	header := make(map[int]string)

	header[0] = "sl"
	header[1] = "src"
	header[2] = "dst"
	header[3] = "state"
	header[4] = "queue"
	header[5] = "t"
	header[6] = "retrnsmt"
	header[7] = "uid"
	for index, field := range strings.Fields(raw[strings.Index(raw, "uid")+3:]) {
		header[8+index] = field
	}

	return header
}

func (s *ss) netstat(family, protocol uint8, path string) (err error) {
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024*2))
	var header map[int]string
	for i := 0; r.Scan(); i++ {
		raw := r.Text()
		if i == 0 {
			header = readNtHeader(raw)
			continue
		}

		socket, droped, er := readNt(family, protocol, r.Text(), header)
		if er != nil {
			continue
		}

		if !droped &&
			socket != nil &&
			len(socket.RemoteIP) != 0 &&
			len(socket.LocalIP) != 0 &&
			socket.State != "" && s.ntCondMatch(socket) {
			s.handle(socket)
		}

		if s.over {
			return
		}
	}
	return
}

func generatePath(family, protocol uint8) string {

	parse := func(proto string) string {
		switch family {
		case unix.AF_INET:
			return fmt.Sprintf("/proc/net/%s", proto)
		case unix.AF_INET6:
			return fmt.Sprintf("/proc/net/%s6", proto)
		}
		return ""
	}

	switch protocol {
	case unix.IPPROTO_TCP:
		return parse("tcp")
	case unix.IPPROTO_UDP:
		return parse("udp")
	}

	return ""

}

func (s *ss) proc(family, protocol uint8) error {
	path := generatePath(family, protocol)
	if path == "" {
		return fmt.Errorf("not found proc net path")
	}

	return s.netstat(family, protocol, path)

}
