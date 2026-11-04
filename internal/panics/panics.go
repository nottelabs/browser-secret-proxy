// Package panics contains a panic on a goroutine the proxy runs for one
// connection, so that a bug one connection reaches ends that connection and
// not the process.
//
// A recovered panic keeps its value's type and where it happened, never the
// value itself: the value could hold anything a request or response carried,
// a real value included.
package panics

import (
	"fmt"
	"net"
	"path"
	"runtime"
	"strings"
)

// Error is a recovered panic, without its value.
type Error struct {
	// Type is the Go type of the panic value, such as runtime.boundsError.
	Type string
	// Site names the innermost functions that were running, innermost
	// first, with their file and line.
	Site string
}

func (e *Error) Error() string { return "panicked with a " + e.Type }

// Recover stops a panic of the goroutine it runs on and passes it to handle;
// without a panic it does nothing. It must be the deferred function itself,
// as in
//
//	defer panics.Recover(handle)
//
// for recover to see the panic.
func Recover(handle func(*Error)) {
	v := recover()
	if v == nil {
		return
	}
	handle(&Error{Type: fmt.Sprintf("%T", v), Site: site()})
}

// Abort closes connections a panic left in an unknown state. A TLS
// connection is not sent a close_notify: its transport is closed instead, so
// that nothing is written through state the panic may have broken, and the
// peer does not take what it received for a complete exchange.
func Abort(conns ...net.Conn) {
	for _, c := range conns {
		if t, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = t.NetConn()
		}
		_ = c.Close()
	}
}

// maxSiteFrames bounds the functions Site names.
const maxSiteFrames = 6

// site names the innermost functions of a panicking goroutine. Called while
// a deferred function runs, it skips the frames of the deferred calls and of
// the runtime.
func site() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs)])
	var sites []string
	panicking := false
	for len(sites) < maxSiteFrames {
		frame, more := frames.Next()
		if frame.Function == "runtime.gopanic" {
			panicking = true
		} else if panicking && !strings.HasPrefix(frame.Function, "runtime.") {
			sites = append(sites, fmt.Sprintf("%s (%s:%d)", frame.Function, path.Base(frame.File), frame.Line))
		}
		if !more {
			break
		}
	}
	return strings.Join(sites, " < ")
}
