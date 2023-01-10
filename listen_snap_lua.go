package ss

import (
	"fmt"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"go.uber.org/ratelimit"
	"gopkg.in/tomb.v2"
	"reflect"
	"sync/atomic"
	"time"
)

var (
	lnTypeof         = reflect.TypeOf((*ListenSnap)(nil)).String()
	subscript uint32 = 0
)

func (snap *ListenSnap) runL(L *lua.LState) int {
	snap.do(Diff)
	return 0
}

func (snap *ListenSnap) pollL(L *lua.LState) int {
	n := L.IsInt(1)
	var interval time.Duration
	if n <= 5 {
		interval = 5 * time.Second
	} else {
		interval = time.Duration(n) * time.Second
	}

	snap.tomb = new(tomb.Tomb)
	xEnv.Spawn(0, func() {
		snap.poll(interval)
	})

	snap.V(lua.PTRun, time.Now())
	return 0
}

func (snap *ListenSnap) syncL(L *lua.LState) int {
	snap.do(Sync)
	return 0
}

func (snap *ListenSnap) onCreateL(L *lua.LState) int {
	snap.onCreate.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) onUpdateL(L *lua.LState) int {
	snap.onUpdate.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) onDeleteL(L *lua.LState) int {
	snap.onDelete.CheckMany(L, pipe.Env(xEnv), pipe.Seek(0))
	return 0
}

func (snap *ListenSnap) limitL(L *lua.LState) int {
	n := L.IsInt(1)
	if n <= 0 {
		return 0
	}

	var pre time.Duration

	tv := L.IsInt(2)
	if tv <= 0 {
		pre = time.Second
	} else {
		pre = time.Duration(tv) * time.Second
	}
	snap.rate = ratelimit.New(n, ratelimit.Per(pre))
	return 0
}

func (snap *ListenSnap) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "run":
		return lua.NewFunction(snap.runL)
	case "poll":
		return lua.NewFunction(snap.pollL)
	case "sync":
		return lua.NewFunction(snap.syncL)
	case "limit":
		return lua.NewFunction(snap.limitL)
	case "on_create":
		return lua.NewFunction(snap.onCreateL)
	case "on_update":
		return lua.NewFunction(snap.onUpdateL)
	case "on_delete":
		return lua.NewFunction(snap.onUpdateL)
	}

	return lua.LNil
}

func newListenSnapshot(L *lua.LState) *ListenSnap {
	name := fmt.Sprintf("listen.snapshot.%d", atomic.AddUint32(&subscript, 1))
	return &ListenSnap{
		name:     name,
		enable:   L.IsTrue(1),
		co:       xEnv.Clone(L),
		bkt:      []string{"vela", "listen", "snapshot"},
		onCreate: pipe.New(),
		onDelete: pipe.New(),
		onUpdate: pipe.New(),
		current:  make(map[string]*listen, 64),
		update:   make(map[string]*listen, 64),
		delete:   make(map[string]interface{}, 64),
		report:   &report{},
	}
}
