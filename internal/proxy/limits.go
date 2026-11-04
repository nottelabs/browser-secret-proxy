package proxy

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// idleTimer closes a client connection and its destination connection once
// no bytes have moved either way for timeout. Reads and writes on the
// connections it wraps count as traffic, a long write each time a chunk of
// it is taken; a read or write that waits does not, so a peer that stops
// reading is cut off too.
type idleTimer struct {
	timeout time.Duration
	last    atomic.Int64 // when bytes last moved, in Unix nanoseconds

	mu    sync.Mutex
	timer *time.Timer
}

func newIdleTimer(timeout time.Duration) *idleTimer {
	t := &idleTimer{timeout: timeout}
	t.touch()
	return t
}

func (t *idleTimer) touch() { t.last.Store(time.Now().UnixNano()) }

// wrap returns c with its traffic counted.
func (t *idleTimer) wrap(c net.Conn) net.Conn { return &countedConn{Conn: c, idle: t} }

// start arms the timer, which then closes conns once they are idle. It does
// nothing when the timeout is zero.
func (t *idleTimer) start(log *slog.Logger, conns ...net.Conn) {
	if t.timeout <= 0 {
		return
	}
	t.touch()
	t.mu.Lock()
	defer t.mu.Unlock()
	check := func() {
		idle := time.Since(time.Unix(0, t.last.Load()))
		if idle < t.timeout {
			t.mu.Lock()
			if t.timer != nil {
				t.timer.Reset(t.timeout - idle)
			}
			t.mu.Unlock()
			return
		}
		log.Debug("closing an idle connection", "idle_timeout", t.timeout)
		for _, c := range conns {
			_ = c.Close()
		}
	}
	t.timer = time.AfterFunc(t.timeout, check)
}

// stop disarms the timer.
func (t *idleTimer) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}

// countedConn is a net.Conn whose reads and writes reset its idle timer.
type countedConn struct {
	net.Conn
	idle *idleTimer
}

func (c *countedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.idle.touch()
	}
	return n, err
}

// writeChunk is the most a write hands the connection at once, so a long
// write that a slow reader drains counts as traffic as it goes. It is
// io.Copy's buffer size: tunnels write as before, and TLS records are
// smaller.
const writeChunk = 32 << 10

func (c *countedConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(len(p), writeChunk)])
		if n > 0 {
			c.idle.touch()
		}
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// CloseWrite half-closes the connection when it can, as tunnels expect, and
// closes it otherwise.
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
