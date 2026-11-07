package certs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// A CA that is not valid now is refused at start, with its date, instead of
// signing leaves that every client refuses.
func TestNewRefusesACAThatIsNotValidNow(t *testing.T) {
	key := ecKey(t)
	now := time.Now()
	cases := []struct {
		name                string
		notBefore, notAfter time.Time
		want                string
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), "CA certificate expired at " + now.Add(-time.Hour).UTC().Format(time.RFC3339)},
		{"not valid yet", now.Add(time.Hour), now.Add(48 * time.Hour), "CA certificate is not valid before " + now.Add(time.Hour).UTC().Format(time.RFC3339)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(testCAValid(t, key, c.notBefore, c.notAfter, true), pkcs8(t, key))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one with %q", err, c.want)
			}
		})
	}
	// Valid from and until the exact instants, as x509 verification counts
	// them.
	notBefore, notAfter := now.Add(-time.Hour).Truncate(time.Second), now.Add(time.Hour).Truncate(time.Second)
	caPEM := testCAValid(t, key, notBefore, notAfter, true)
	for _, at := range []time.Time{notBefore, notAfter} {
		if _, err := newAt(caPEM, pkcs8(t, key), at); err != nil {
			t.Errorf("at %v: %v", at, err)
		}
	}
	if _, err := newAt(caPEM, pkcs8(t, key), notAfter.Add(time.Nanosecond)); err == nil {
		t.Error("a CA just past its NotAfter was accepted")
	}
}

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

// Nothing is logged while the CA is more than ExpiryWarning from its end, a
// warning within it, an error once it has expired.
func TestExpiryIsLogged(t *testing.T) {
	a := authority(t) // valid for 30 days
	end := a.CA().NotAfter
	cases := []struct {
		at   time.Time
		want string
	}{
		{end.Add(-ExpiryWarning - time.Minute), ""},
		{end.Add(-ExpiryWarning), "level=WARN msg=\"the CA certificate expires soon"},
		{end.Add(-time.Hour), "expires_in=1h0m0s"},
		{end, "level=WARN"},
		{end.Add(time.Second), "level=ERROR msg=\"the CA certificate has expired"},
	}
	for _, c := range cases {
		var logs logBuffer
		a.logExpiry(logs.logger(), c.at)
		got := logs.String()
		if c.want == "" && got != "" || !strings.Contains(got, c.want) {
			t.Errorf("at %v before expiry: logged %q, want %q", end.Sub(c.at), got, c.want)
		}
		if c.want != "" && !strings.Contains(got, "not_after="+end.UTC().Format(time.RFC3339)) {
			t.Errorf("at %v before expiry: %q does not give the expiry", end.Sub(c.at), got)
		}
	}
}

// The watch checks once a day, and also at the start of the warning window
// and right after expiry.
func TestNextExpiryCheck(t *testing.T) {
	a := authority(t)
	end := a.CA().NotAfter
	cases := []struct {
		at   time.Time
		want time.Duration
	}{
		{end.Add(-20 * 24 * time.Hour), expiryCheckEvery},
		{end.Add(-ExpiryWarning - time.Hour), time.Hour},
		{end.Add(-ExpiryWarning), expiryCheckEvery},
		{end.Add(-time.Hour), time.Hour + time.Second},
		{end.Add(time.Second), expiryCheckEvery},
		{end.Add(time.Second - time.Millisecond), time.Second}, // never a busy loop
	}
	for _, c := range cases {
		if got := a.nextExpiryCheck(c.at); got != c.want {
			t.Errorf("at %v before expiry: next check in %v, want %v", end.Sub(c.at), got, c.want)
		}
	}
}

// A CA that expires within ExpiryWarning is reported as soon as the watch
// starts, and a CA that expires while the proxy runs is reported when it
// does; the watch ends with its context.
func TestWatchExpiry(t *testing.T) {
	key := ecKey(t)
	end := time.Now().Add(1500 * time.Millisecond)
	a, err := New(testCA(t, key, end, true), pkcs8(t, key))
	if err != nil {
		t.Fatal(err)
	}
	var logs logBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.WatchExpiry(ctx, logs.logger()); close(done) }()
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(logs.String(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("logs %q, want %q", logs.String(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("level=WARN")
	waitFor("level=ERROR")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchExpiry did not return when its context ended")
	}
}
