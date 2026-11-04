package h2relay

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// logBuffer collects log output written from the relay's goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logTo sends the relay's log, without timestamps, to logs.
func logTo(logs *logBuffer) func(*Options) {
	return func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if len(groups) == 0 && a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		}))
	}
}

// A real value a destination echoes into content-encoding gets the response
// refused, and the refusal's log line does not quote it.
func TestRefusedCodingsAreNotLogged(t *testing.T) {
	for _, coding := range []string{realCard, "gzip, " + realCard} {
		t.Run(coding, func(t *testing.T) {
			logs := &logBuffer{}
			h := newHarness(t, func(o *Options) { masking(t, true)(o); logTo(logs)(o) })
			id := get(h, 1)
			h.serverSend(status(h, id, false, field(":status", "200"), field("content-encoding", coding)))
			h.expect(h.toClient, "client", isBadGateway(1))
			if !strings.Contains(logs.String(), "refusing a response that cannot be masked") {
				t.Fatalf("no log line:\n%s", logs)
			}
			if strings.Contains(logs.String(), realCard) {
				t.Fatalf("the log has the real value:\n%s", logs)
			}
		})
	}
}

// The log line of a body swap names the authority only: the body's sizes
// before and after would give away the length of the real value.
func TestBodySwapLogHasNoSizes(t *testing.T) {
	logs := &logBuffer{}
	h := newHarness(t, logTo(logs))
	h.clientSend(
		Frame{Type: FrameHeaders, Flags: FlagEndHeaders, Stream: 1, Payload: h.clientBlock(request("POST", hpack.HeaderField{Name: "content-type", Value: "text/plain"})...)},
		Frame{Type: FrameData, Flags: FlagEndStream, Stream: 1, Payload: []byte("k=tok_standin")},
	)
	h.expect(h.toServer, "server", isType(FrameHeaders))
	if f := h.expect(h.toServer, "server", isType(FrameData)); string(f.Payload) != "k=real_value" {
		t.Fatalf("server got %q", f.Payload)
	}
	want := `level=INFO msg="swapped stand-ins in a request body" authority=allowed.test` + "\n"
	for _, line := range strings.SplitAfter(logs.String(), "\n") {
		if strings.Contains(line, "request body") && line != want {
			t.Fatalf("log line %q, want %q", line, want)
		}
	}
	if !strings.Contains(logs.String(), want) {
		t.Fatalf("no log line:\n%s", logs)
	}
}
