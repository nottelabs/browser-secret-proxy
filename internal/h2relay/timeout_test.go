package h2relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/scope/scopetest"
)

const stepTimeout = 200 * time.Millisecond

// timeouts sets every protocol-step timeout to an hour except the ones a
// test sets after it.
func timeouts(mutate ...func(*Options)) func(*Options) {
	return func(o *Options) {
		o.PrefaceTimeout, o.ClientPrefaceTimeout, o.SettingsTimeout, o.HeaderBlockTimeout = time.Hour, time.Hour, time.Hour, time.Hour
		for _, m := range mutate {
			m(o)
		}
	}
}

// checkEndedAfter checks that the relay ended with want no sooner than
// stepTimeout after start, and closed the client connection.
func checkEndedAfter(t *testing.T, h *harness, start time.Time, want error) {
	t.Helper()
	if err := h.result(); !errors.Is(err, want) {
		t.Fatalf("relay error %v, want %v", err, want)
	}
	if elapsed := time.Since(start); elapsed < stepTimeout {
		t.Fatalf("the relay ended after %v, before the %v timeout", elapsed, stepTimeout)
	}
	h.drainClient()
}

// A client that opens the connection (TLS done) and then sends no preface,
// or only part of it, is closed once the preface timeout passes. Before,
// the relay waited for it forever, holding the destination connection.
func TestSilentClientTimesOut(t *testing.T) {
	for name, sent := range map[string][]byte{
		"nothing":             nil,
		"only the magic":      []byte(Preface),
		"part of first frame": append([]byte(Preface), 0, 0, 0, FrameSettings),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			h := newSilentHarness(t, timeouts(func(o *Options) { o.ClientPrefaceTimeout = stepTimeout }), nil)
			h.serverSend(Frame{Type: FrameSettings})
			if len(sent) > 0 {
				h.write(h.client, sent)
			}
			checkEndedAfter(t, h, start, errClientPreface)
		})
	}
}

// A client that sends its preface in time is not held to the timeout
// afterwards: it may stay quiet between requests.
func TestClientPrefaceTimeoutEndsWithThePreface(t *testing.T) {
	h := newHarness(t, timeouts(func(o *Options) { o.ClientPrefaceTimeout = stepTimeout }))
	time.Sleep(3 * stepTimeout)
	h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)})
	h.expect(h.toServer, "server", isType(FrameHeaders))
}

// RFC 9113 6.5.3: a SETTINGS frame the client does not acknowledge in time
// is a connection error of type SETTINGS_TIMEOUT. Without it, a client that
// never acknowledges a lower SETTINGS_HEADER_TABLE_SIZE from the
// destination keeps a larger HPACK table than the relay's upstream encoder,
// and the relay's decoder must accept it.
func TestUnacknowledgedSettingsTimeOut(t *testing.T) {
	short := timeouts(func(o *Options) { o.SettingsTimeout = stepTimeout })
	t.Run("the first", func(t *testing.T) {
		h := newRawHarness(t, short, nil)
		h.clientSend(Frame{Type: FrameSettings})
		start := time.Now()
		h.serverSend(Frame{Type: FrameSettings})
		h.expect(h.toClient, "client", isGoAway(errCodeSettingsTimeout))
		checkEndedAfter(t, h, start, errSettingsTimeout)
	})
	t.Run("a later one", func(t *testing.T) {
		h := newHarness(t, short)
		start := time.Now()
		h.serverSend(settingsFrame(Setting{ID: SettingHeaderTableSize, Value: 0}))
		h.expect(h.toClient, "client", isGoAway(errCodeSettingsTimeout))
		checkEndedAfter(t, h, start, errSettingsTimeout)
	})
	t.Run("one of two", func(t *testing.T) {
		h := newHarness(t, short)
		start := time.Now()
		h.serverSend(settingsFrame(Setting{ID: SettingHeaderTableSize, Value: 0}), settingsFrame(Setting{ID: SettingHeaderTableSize, Value: 4096}))
		h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
		h.expect(h.toClient, "client", isGoAway(errCodeSettingsTimeout))
		checkEndedAfter(t, h, start, errSettingsTimeout)
	})
	t.Run("past the deadlines kept", func(t *testing.T) {
		// The relay keeps the deadlines of maxUnackedSettings frames; the
		// ones after them are still counted and timed.
		h := newHarness(t, short)
		var settings, acks []Frame
		for range maxUnackedSettings + 6 {
			settings = append(settings, Frame{Type: FrameSettings})
		}
		for range maxUnackedSettings {
			acks = append(acks, Frame{Type: FrameSettings, Flags: FlagAck})
		}
		start := time.Now()
		h.serverSend(settings...)
		h.clientSend(acks...)
		h.expect(h.toClient, "client", isGoAway(errCodeSettingsTimeout))
		checkEndedAfter(t, h, start, errSettingsTimeout)
	})
}

// A client that acknowledges every SETTINGS frame at once, as browsers do,
// keeps its connection however long it lasts, with or without masking. A
// response header block finished in time does not time the server out
// either, however long the response then waits.
func TestPromptPeersAreNotTimedOut(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"plain":  func(*Options) {},
		"masked": masking(t, true),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, func(o *Options) {
				mutate(o)
				o.ClientPrefaceTimeout, o.SettingsTimeout, o.HeaderBlockTimeout = stepTimeout, stepTimeout, stepTimeout
			})
			for range 3 {
				time.Sleep(stepTimeout / 2)
				h.serverSend(settingsFrame(Setting{ID: SettingMaxConcurrentStreams, Value: 100}))
				h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameSettings && f.Flags&FlagAck == 0 })
				h.clientSend(Frame{Type: FrameSettings, Flags: FlagAck})
				h.expect(h.toServer, "server", func(f Frame) bool { return f.Type == FrameSettings && f.Flags&FlagAck != 0 })
			}
			time.Sleep(2 * stepTimeout)
			h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)})
			id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
			status := h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})
			h.serverSend(Frame{Type: FrameHeaders, Stream: id})
			time.Sleep(stepTimeout / 2)
			h.serverSend(Frame{Type: FrameContinuation, Flags: FlagEndHeaders, Stream: id, Payload: status})
			time.Sleep(2 * stepTimeout)
			h.serverSend(Frame{Type: FrameData, Flags: FlagEndStream, Stream: id, Payload: []byte("ok")})
			f := h.expect(h.toClient, "client", func(f Frame) bool { return f.Type == FrameData || f.Type == FrameGoAway })
			if f.Type != FrameData || string(f.Payload) != "ok" {
				t.Fatalf("client got frame type %d (%q), want the response body", f.Type, f.Payload)
			}
			select {
			case err := <-h.done:
				t.Fatalf("the relay ended: %v", err)
			default:
			}
		})
	}
}

// A server that starts a response header block and never finishes it is
// timed out. Without masking the relay holds the client write lock while a
// block is open, so the whole connection would otherwise stall with it.
func TestUnfinishedServerHeaderBlockTimesOut(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"plain":  func(*Options) {},
		"masked": masking(t, true),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, timeouts(mutate, func(o *Options) { o.HeaderBlockTimeout = stepTimeout }))
			h.clientSend(Frame{Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: h.clientBlock(request("GET")...)})
			id := h.expect(h.toServer, "server", isType(FrameHeaders)).Stream
			start := time.Now()
			h.serverSend(Frame{Type: FrameHeaders, Stream: id, Payload: h.serverBlock(hpack.HeaderField{Name: ":status", Value: "200"})})
			checkEndedAfter(t, h, start, errHeaderBlockTimeout)
		})
	}
}

// tlsPipe is a TLS connection over a pipe with a throwaway certificate: the
// relay's end (the TLS server) and the test's.
func tlsPipe(t *testing.T) (relayEnd, testEnd net.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"allowed.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	server := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	client := tls.Client(b, &tls.Config{ServerName: "allowed.test", InsecureSkipVerify: true}) //nolint:gosec // throwaway certificate
	errs := make(chan error, 1)
	go func() { errs <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server, client
}

// The timeouts work on TLS connections, as the proxy gives the relay: a
// deadline that passes inside TLS is still told apart from other errors.
func TestTimeoutsOverTLS(t *testing.T) {
	hosts, err := hostmatch.New([]string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	opts := timeouts(func(o *Options) {
		o.Hosts = hosts
		o.Session = scopetest.Static(t, hosts, map[string]string{"tok_standin": "real_value"})
		o.ClientPrefaceTimeout, o.HeaderBlockTimeout = stepTimeout, stepTimeout
	})
	run := func(client, server net.Conn) <-chan error {
		var o Options
		opts(&o)
		done := make(chan error, 1)
		go func() { done <- newRelay(client, server, o).run() }()
		return done
	}
	wait := func(t *testing.T, done <-chan error, want error) {
		t.Helper()
		select {
		case err := <-done:
			if !errors.Is(err, want) {
				t.Fatalf("relay error %v, want %v", err, want)
			}
		case <-time.After(waitFor):
			t.Fatal("relay did not stop")
		}
	}
	t.Run("silent client", func(t *testing.T) {
		clientRelay, client := tlsPipe(t)
		serverRelay, server := tlsPipe(t)
		go func() { _, _ = io.Copy(io.Discard, client) }()
		go func() { _, _ = io.Copy(io.Discard, server) }()
		wait(t, run(clientRelay, serverRelay), errClientPreface)
	})
	t.Run("unfinished server header block", func(t *testing.T) {
		clientRelay, client := tlsPipe(t)
		serverRelay, server := tlsPipe(t)
		go func() { _, _ = io.Copy(io.Discard, client) }()
		done := run(clientRelay, serverRelay)
		var block bytes.Buffer
		enc := hpack.NewEncoder(&block)
		for _, f := range request("GET") {
			_ = enc.WriteField(f)
		}
		go func() {
			_, _ = client.Write(append([]byte(Preface), encodeFrames([]Frame{{Type: FrameSettings}, {Type: FrameHeaders, Flags: FlagEndHeaders | FlagEndStream, Stream: 1, Payload: block.Bytes()}})...))
		}()
		preface := make([]byte, len(Preface))
		if _, err := io.ReadFull(server, preface); err != nil {
			t.Fatal(err)
		}
		for {
			f, err := ReadFrame(server)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type == FrameHeaders {
				writeAsync(server, Frame{Type: FrameSettings}, Frame{Type: FrameHeaders, Stream: f.Stream, Payload: []byte{0x88}}) // :status 200, no END_HEADERS
				break
			}
		}
		go func() { _, _ = io.Copy(io.Discard, server) }()
		wait(t, done, errHeaderBlockTimeout)
	})
}
