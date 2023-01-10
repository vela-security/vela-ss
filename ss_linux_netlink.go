//go:build linux
// +build linux

package ss

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/elastic/gosigar/sys"
	account "github.com/vela-security/vela-account"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"net"
	"sync/atomic"
	"syscall"
)

var (
	notSupportNetlink uint32 = 0
	supportNetLink           = true
)

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
)

const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
	INET_DIAG_DCTCPINFO
	INET_DIAG_PROTOCOL
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK
	INET_DIAG_BBRINFO
	INET_DIAG_CLASS_ID
	INET_DIAG_MD5SIG
	INET_DIAG_MAX
)

var (
	native = nl.NativeEndian()
	order  = binary.BigEndian
)

type NetlinkSocketID struct {
	sPort       uint16
	dPort       uint16
	source      net.IP
	destination net.IP
	iface       uint32
	cookie      [2]uint32
}

type NetlinkRequestData struct {
	family   uint8
	protocol uint8
	ext      uint8
	pad      uint8
	states   uint32
	id       NetlinkSocketID
}

type reply struct {
	family  uint8
	state   uint8
	timer   uint8
	retrans uint8
	id      NetlinkSocketID
	expires uint32
	rQueue  uint32
	wQueue  uint32
	uid     uint32
	inode   uint32
}

type buffer struct {
	Chunk []byte
	pos   int
}

const (
	ESTAB uint8 = iota + 1
	SynSent
	SynRcvd
	FinWait1
	FinWait2
	TimeWait
	Closed
	CloseWait
	LastAck
	Listen
	Closing
)

func TCP2String(v uint8) string {
	switch v {
	case ESTAB:
		return "ESTAB"
	case SynSent:
		return "SYN-SENT"
	case SynRcvd:
		return "SYN-RCVD"
	case FinWait1:
		return "FIN-WAIT-1"
	case FinWait2:
		return "FIN-WAIT-2"
	case TimeWait:
		return "TIME-WAIT"
	case Closed:
		return "CLOSED"
	case CloseWait:
		return "CLOSE-WAIT"
	case LastAck:
		return "LAST-ACK"

	case Listen:
		return "LISTEN"
	case Closing:
		return "CLOSING"
	}

	return ""

}

func (b *buffer) WriteByte(c byte) {
	b.Chunk[b.pos] = c
	b.pos++
}

func (b *buffer) Read() byte {
	c := b.Chunk[b.pos]
	b.pos++
	return c
}

func (b *buffer) Next(n int) []byte {
	s := b.Chunk[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (nlrd *NetlinkRequestData) Serialize() []byte {
	buff := buffer{Chunk: make([]byte, sizeofSocketRequest)}
	buff.WriteByte(nlrd.family)
	buff.WriteByte(nlrd.protocol)
	buff.WriteByte(nlrd.ext)
	buff.WriteByte(nlrd.pad)

	native.PutUint32(buff.Next(4), nlrd.states)
	order.PutUint16(buff.Next(2), nlrd.id.sPort)
	order.PutUint16(buff.Next(2), nlrd.id.dPort)
	if nlrd.family == unix.AF_INET6 {
		copy(buff.Next(16), nlrd.id.source)
		copy(buff.Next(16), nlrd.id.destination)
	} else {
		copy(buff.Next(4), nlrd.id.source.To4())
		buff.Next(12)
		copy(buff.Next(4), nlrd.id.destination.To4())
		buff.Next(12)
	}
	native.PutUint32(buff.Next(4), nlrd.id.iface)
	native.PutUint32(buff.Next(4), nlrd.id.cookie[0])
	native.PutUint32(buff.Next(4), nlrd.id.cookie[1])
	return buff.Chunk
}

func (nlrd *NetlinkRequestData) Len() int {
	return sizeofSocketRequest
}

func (r *reply) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := buffer{Chunk: b}
	r.family = rb.Read()
	r.state = rb.Read()
	r.timer = rb.Read()
	r.retrans = rb.Read()
	r.id.sPort = order.Uint16(rb.Next(2))
	r.id.dPort = order.Uint16(rb.Next(2))
	if r.family == unix.AF_INET6 {
		r.id.source = net.IP(rb.Next(16))
		r.id.destination = net.IP(rb.Next(16))
	} else {
		r.id.source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		r.id.destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
	r.id.iface = native.Uint32(rb.Next(4))
	r.id.cookie[0] = native.Uint32(rb.Next(4))
	r.id.cookie[1] = native.Uint32(rb.Next(4))
	r.expires = native.Uint32(rb.Next(4))
	r.rQueue = native.Uint32(rb.Next(4))
	r.wQueue = native.Uint32(rb.Next(4))
	r.uid = native.Uint32(rb.Next(4))
	r.inode = native.Uint32(rb.Next(4))
	return nil
}

func (s *ss) netLinkErrno(data []byte) error {
	if len(data) < 4 {
		return errors.New("received netlink error (data too short to read errno)")
	}
	errno := -sys.GetEndian().Uint32(data[:4])
	err := NetlinkErrno(errno)
	if err == NLE_MSGTYPE_NOSUPPORT {
		s.Err = err
		atomic.AddUint32(&notSupportNetlink, 1)
		xEnv.Infof("%v", err)
	}

	return err
}

func (s *ss) netlink(family, protocol uint8) error {
	sub, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return err
	}
	defer sub.Close()
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&NetlinkRequestData{
		family:   family,
		protocol: protocol,
		ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		states:   s.ov.nlStates,
	})

	err = sub.Send(req)
	if err != nil {
		return err
	}

loop:
	for {
		var msgs []syscall.NetlinkMessage
		var from *unix.SockaddrNetlink
		msgs, from, err = sub.Receive()
		if err != nil {
			return err
		}

		if from.Pid != nl.PidKernel {
			continue
		}

		if len(msgs) == 0 {
			break
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				err = s.netLinkErrno(m.Data)
				//not support
				break loop
			}
			r := &reply{}
			if err := r.deserialize(m.Data); err != nil {
				continue
			}

			s.handle(&Socket{
				LocalIP:    r.id.source.String(),
				RemoteIP:   r.id.destination.String(),
				LocalPort:  int(r.id.sPort),
				RemotePort: int(r.id.dPort),
				UID:        r.uid,
				IFace:      r.id.iface,
				Family:     r.family,
				State:      TCP2String(r.state),
				Inode:      r.inode,
				Protocol:   protocol,
				Username:   account.ByUid(r.uid),
			})

			if s.over {
				return err
			}

		}
	}

	return err
}
