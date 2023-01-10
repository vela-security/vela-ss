package ss

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/vela-security/vela-public/auxlib"
	"strconv"
)

const (
	Sync int = iota + 10
	Diff
)

type listen struct {
	RecordID  string `json:"record_id"`
	Pid       uint32 `json:"pid"`
	Family    uint8  `json:"family"`
	Protocol  uint8  `json:"protocol"`
	LocalIP   string `json:"local_ip"`
	LocalPort int    `json:"local_port"`
	Path      string `json:"path"`
	Process   string `json:"process"`
	Username  string `json:"username"`
	fd        int    `json:"fd"`
}

func (ln *listen) Proto() string {
	return strconv.Itoa(int(ln.Protocol))
}

func (ln *listen) Port2Str() string {
	return strconv.Itoa(ln.LocalPort)
}

func (ln *listen) md5() {
	h := md5.New()
	h.Write(auxlib.S2B(ln.Proto()))
	h.Write(auxlib.S2B(ln.LocalIP))
	h.Write(auxlib.S2B(ln.Port2Str()))
	h.Sum(nil)
	hash := hex.EncodeToString(h.Sum(nil))
	ln.RecordID = hash
}

func (ln *listen) equal(old *listen) bool {
	switch {
	case ln.Pid != old.Pid:
		return false
	case ln.Family != old.Family:
		return false
	case ln.Protocol != old.Protocol:
		return false
	case ln.LocalIP != old.LocalIP:
		return false
	case ln.LocalPort != old.LocalPort:
		return false
	case ln.Process != old.Process:
		return false
	case ln.Username != old.Username:
		return false
	case ln.Path != old.Path:
		return false
	}

	return true
}
