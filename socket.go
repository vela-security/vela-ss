package ss

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
)

type Socket struct {
	Pid        uint32 `json:"pid"`
	Family     uint8  `json:"family"`
	Protocol   uint8  `json:"protocol"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Path       string `json:"path"`
	State      string `json:"state"`
	Process    string `json:"process"`
	UID        uint32 `json:"uid"`
	IFace      uint32 `json:"iface"`
	Inode      uint32 `json:"inode"`
	Username   string `json:"username"`
}

func (sock *Socket) Marshal(enc *kind.JsonEncoder) {
	enc.Tab("")

	enc.KV("state", sock.State)
	enc.KV("family", sock.Family)
	enc.KV("protocol", sock.Protocol)
	enc.KV("local_addr", sock.LocalIP)
	enc.KV("local_port", sock.LocalPort)
	enc.KV("remote_addr", sock.RemoteIP)
	enc.KV("remote_port", sock.RemotePort)
	enc.KV("pid", sock.Pid)
	enc.KV("inode", sock.Inode)
	enc.KV("process", sock.Process)
	enc.KV("username", sock.Username)

	enc.End("},")
}

func (sock *Socket) Byte() []byte {
	buf := kind.NewJsonEncoder()
	sock.Marshal(buf)
	buf.End("")
	return buf.Bytes()
}

func (sock *Socket) String() string {
	return lua.B2S(sock.Byte())
}
