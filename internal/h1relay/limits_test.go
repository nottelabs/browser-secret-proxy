package h1relay

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A head that declares a large body reserves no memory for it: the body
// takes memory as it arrives.
func TestDeclaredBodyIsNotAllocatedUpFront(t *testing.T) {
	const relays = 8
	const declared = 32 << 20
	o := options(t)
	o.MaxBody = declared
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < relays; i++ {
		client, relayClient := net.Pipe()
		relayServer, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		go func() { _ = Serve(relayClient, relayServer, o) }()
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		send(t, client, "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: "+strconv.Itoa(declared)+"\r\n\r\nx")
		// A pipe write returns once the relay read it, and the relay reads
		// past what it buffered with the head only while reading the body.
		send(t, client, "y")
	}
	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if grew > relays*(1<<20) {
		t.Fatalf("%d relays waiting on a %d byte body each hold %d MiB of heap", relays, declared, grew>>20)
	}
}

// A body larger than the first buffer still arrives whole, swapped.
func TestLargeBodyIsReadWhole(t *testing.T) {
	client, _, _, serverReader := pipes(t)
	body := strings.Repeat("a", 300<<10) + "tok_standin" + strings.Repeat("b", 200<<10)
	go func() {
		_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}()
	want := strings.Replace(body, "tok_standin", "real", 1)
	if head := readHead(t, serverReader); !strings.Contains(head, "Content-Length: "+strconv.Itoa(len(want))+"\r\n") {
		t.Fatalf("server got %q", head)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverReader, got); err != nil || string(got) != want {
		t.Fatalf("server body of %d bytes differs (%v)", len(got), err)
	}
}

// A request head must arrive within HeadTimeout of its first byte, so a
// client that drips one cannot hold the connection.
func TestSlowRequestHeadEndsTheConnection(t *testing.T) {
	o := options(t)
	o.HeadTimeout = 200 * time.Millisecond
	client, _, _, serverReader, result := pipesWith(t, o)
	go func() {
		for _, c := range "GET / HTTP/1.1\r\nHost: allowed.test\r\nX-Slow: " + strings.Repeat("s", 100) {
			if _, err := io.WriteString(client, string(c)); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("relay error %v, want a deadline error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a dripped request head kept the connection open")
	}
	if b, err := serverReader.ReadByte(); err == nil {
		t.Fatalf("server received data starting with %q", b)
	}
}

// HeadTimeout counts from a head's first byte: a keep-alive connection may
// wait longer than that between requests.
func TestHeadTimeoutAllowsIdleKeepAlive(t *testing.T) {
	o := options(t)
	o.HeadTimeout = 100 * time.Millisecond
	client, clientReader, server, serverReader, _ := pipesWith(t, o)
	for i := 0; i < 2; i++ {
		send(t, client, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
		readHead(t, serverReader)
		send(t, server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		if head := readHead(t, clientReader); !strings.HasPrefix(head, "HTTP/1.1 200 ") {
			t.Fatalf("client got %q", head)
		}
		time.Sleep(3 * o.HeadTimeout)
	}
}
