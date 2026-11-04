package h1relay

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
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

// A real value a destination echoes into Content-Encoding or
// Transfer-Encoding gets the response refused, and the refusal's log line
// does not quote it.
func TestRefusedCodingsAreNotLogged(t *testing.T) {
	for _, header := range []string{
		"Content-Encoding: " + realCard,
		"Content-Encoding: gzip, " + realCard,
		"Transfer-Encoding: x" + realCard + ", chunked",
	} {
		t.Run(header, func(t *testing.T) {
			logs := &logBuffer{}
			o := maskedOptions(t, true)
			o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			got := rawRoundTrip(t, o, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
				"HTTP/1.1 200 OK\r\n"+header+"\r\nContent-Length: 2\r\n\r\nok")
			if !strings.HasPrefix(got, "HTTP/1.1 502 ") || strings.Contains(got, realCard) {
				t.Fatalf("client got %q", got)
			}
			if !strings.Contains(logs.String(), "refusing a response that cannot be masked") {
				t.Fatalf("no log line:\n%s", logs)
			}
			if strings.Contains(logs.String(), realCard) {
				t.Fatalf("the log has the real value:\n%s", logs)
			}
		})
	}
}
