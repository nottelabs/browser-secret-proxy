package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"

	"github.com/nottelabs/browser-secret-proxy/internal/clienthello"
	"github.com/nottelabs/browser-secret-proxy/internal/h2relay"
	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
)

func respondOK(c *tls.Conn) {
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
	}
}

func getOK(t *testing.T, conn io.ReadWriter, host string) {
	t.Helper()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
}

func normalized(values []uint16) []uint16 {
	out := make([]uint16, len(values))
	for i, v := range values {
		if clienthello.IsGREASE(v) {
			v = 0x0a0a
		}
		out[i] = v
	}
	return out
}

// The destination receives a ClientHello with the client's extensions in the
// client's order, the same cipher suites, groups and ALPN, but its own random
// and key shares, on every connection.
func TestClientHelloIsReplayedExactly(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, nil)

	orders := map[string]bool{}
	for i := 0; i < 4; i++ {
		conn, resp := connect(t, p.addr, allowedHost+":443", "")
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT answered %s", resp.Status)
		}
		rec := &recordingConn{Conn: conn}
		uconn := chromeClient(t, rec, allowedHost, p.ca)
		getOK(t, uconn, allowedHost)

		sent := parseHello(t, rec.sentHello(t))
		var received *clienthello.Hello
		select {
		case message := <-dest.hellos:
			received = parseHello(t, message)
		case <-time.After(5 * time.Second):
			t.Fatal("destination received no ClientHello")
		}

		if err := clienthello.Compare(sent, received); err != nil {
			t.Fatalf("connection %d: replay differs: %v", i, err)
		}
		if got, want := normalized(received.ExtensionTypes()), normalized(sent.ExtensionTypes()); !reflect.DeepEqual(got, want) {
			t.Fatalf("extension order %v, client sent %v", got, want)
		}
		for j := range sent.Extensions {
			if sent.Extensions[j].Type != received.Extensions[j].Type && !clienthello.IsGREASE(sent.Extensions[j].Type) {
				t.Fatalf("extension %d is %d, client sent %d", j, received.Extensions[j].Type, sent.Extensions[j].Type)
			}
		}
		if !reflect.DeepEqual(normalized(received.CipherSuites), normalized(sent.CipherSuites)) {
			t.Fatalf("cipher suites %v, client sent %v", received.CipherSuites, sent.CipherSuites)
		}
		if !reflect.DeepEqual(normalized(received.SupportedGroups()), normalized(sent.SupportedGroups())) {
			t.Fatalf("groups %v, client sent %v", received.SupportedGroups(), sent.SupportedGroups())
		}
		if !reflect.DeepEqual(received.ALPN(), sent.ALPN()) || len(sent.ALPN()) == 0 {
			t.Fatalf("ALPN %v, client sent %v", received.ALPN(), sent.ALPN())
		}
		if received.ServerName() != allowedHost {
			t.Fatalf("SNI %q", received.ServerName())
		}
		if bytes.Equal(received.Random, sent.Random) {
			t.Fatal("the client random reached the destination: the hello was not regenerated")
		}
		sentShares, receivedShares := sent.KeyShares(), received.KeyShares()
		if len(sentShares) == 0 || len(sentShares) != len(receivedShares) {
			t.Fatalf("key shares %d, client sent %d", len(receivedShares), len(sentShares))
		}
		for j := range sentShares {
			if !clienthello.IsGREASE(sentShares[j].Group) && bytes.Equal(sentShares[j].Key, receivedShares[j].Key) {
				t.Fatalf("key share for group %#04x was copied, not generated", sentShares[j].Group)
			}
		}
		orders[fmtUint16s(normalized(sent.ExtensionTypes()))] = true
	}
	// The Chrome client shuffles its extensions per connection; a copy keeps
	// each connection's own order rather than one fixed profile.
	if len(orders) < 2 {
		t.Fatalf("every connection used the same extension order; the test client did not shuffle")
	}
}

func fmtUint16s(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(int(v))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

type h2Request struct {
	fields   []hpack.HeaderField
	priority *h2relay.Priority
	body     []byte
}

type h2Capture struct {
	settingsPayload []byte
	frameTypes      []uint8 // the first frames, in order
	windowUpdate    uint32
	requests        map[uint32]*h2Request
	order           []uint32
}

var serverSettings = h2relay.AppendFrame(nil, h2relay.FrameSettings, 0, 0, []byte{0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0})

// h2Destination answers every request with 200 "ok" and reports what it saw
// once it has served `want` requests.
func h2Destination(want int, captures chan<- *h2Capture) func(*tls.Conn) {
	return func(c *tls.Conn) {
		preface := make([]byte, len(h2relay.Preface))
		if _, err := io.ReadFull(c, preface); err != nil || string(preface) != h2relay.Preface {
			return
		}
		if _, err := c.Write(serverSettings); err != nil {
			return
		}
		capture := &h2Capture{requests: map[uint32]*h2Request{}}
		dec := hpack.NewDecoder(65536, nil)
		var encBuf bytes.Buffer
		enc := hpack.NewEncoder(&encBuf)
		served := 0
		respond := func(stream uint32) error {
			encBuf.Reset()
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			b := h2relay.AppendFrame(nil, h2relay.FrameHeaders, h2relay.FlagEndHeaders, stream, encBuf.Bytes())
			b = h2relay.AppendFrame(b, h2relay.FrameData, h2relay.FlagEndStream, stream, []byte("ok"))
			_, err := c.Write(b)
			served++
			if served == want {
				captures <- capture
			}
			return err
		}
		for {
			f, err := h2relay.ReadFrame(c)
			if err != nil {
				return
			}
			if len(capture.frameTypes) < 3 {
				capture.frameTypes = append(capture.frameTypes, f.Type)
			}
			switch f.Type {
			case h2relay.FrameSettings:
				if f.Flags&h2relay.FlagAck == 0 {
					if capture.settingsPayload == nil {
						capture.settingsPayload = append([]byte{}, f.Payload...)
					}
					if _, err := c.Write(h2relay.AppendFrame(nil, h2relay.FrameSettings, h2relay.FlagAck, 0, nil)); err != nil {
						return
					}
				}
			case h2relay.FrameWindowUpdate:
				if f.Stream == 0 && capture.windowUpdate == 0 {
					capture.windowUpdate = binary.BigEndian.Uint32(f.Payload)
				}
			case h2relay.FrameHeaders:
				priority, fragment, err := h2relay.HeadersPayload(f.Flags, f.Payload)
				if err != nil {
					return
				}
				fields, err := dec.DecodeFull(fragment)
				if err != nil {
					return
				}
				capture.requests[f.Stream] = &h2Request{fields: fields, priority: priority}
				capture.order = append(capture.order, f.Stream)
				if f.Flags&h2relay.FlagEndStream != 0 && respond(f.Stream) != nil {
					return
				}
			case h2relay.FrameData:
				r := capture.requests[f.Stream]
				if r == nil {
					return
				}
				r.body = append(r.body, f.Payload...)
				if len(f.Payload) > 0 {
					wu := binary.BigEndian.AppendUint32(nil, uint32(len(f.Payload)))
					if _, err := c.Write(h2relay.AppendFrame(nil, h2relay.FrameWindowUpdate, 0, 0, wu)); err != nil {
						return
					}
				}
				if f.Flags&h2relay.FlagEndStream != 0 && respond(f.Stream) != nil {
					return
				}
			}
		}
	}
}

func names(fields []hpack.HeaderField) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Name
	}
	return out
}

func value(fields []hpack.HeaderField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// The destination sees the client's SETTINGS (values and order), its
// connection WINDOW_UPDATE, its request priorities and its pseudo-header and
// header order, over HTTP/2, with stand-ins swapped in the query, a header
// and a body whose content-length follows the new size.
func TestHTTP2IsMirrored(t *testing.T) {
	captures := make(chan *h2Capture, 1)
	dest := startDestination(t, allowedHost, []string{"h2", "http/1.1"}, h2Destination(2, captures))
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, nil)

	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	uconn := chromeClient(t, conn, allowedHost, p.ca)
	if got := uconn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated %q with the client, want h2", got)
	}

	// A Chrome-like connection start.
	settings := []byte{0, 1, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0, 0x60, 0, 0, 0, 6, 0, 4, 0, 0}
	var encBuf bytes.Buffer
	enc := hpack.NewEncoder(&encBuf)
	encode := func(fields []hpack.HeaderField) []byte {
		encBuf.Reset()
		for _, f := range fields {
			_ = enc.WriteField(f)
		}
		return append([]byte{}, encBuf.Bytes()...)
	}
	body := `{"card":"4242424242424242","token":"tok_standin"}`
	get := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: allowedHost},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/lookup?card=4242424242424242&q=1"},
		{Name: "sec-ch-ua", Value: `"Chromium";v="155"`},
		{Name: "sec-ch-ua-mobile", Value: "?0"},
		{Name: "user-agent", Value: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
		{Name: "accept", Value: "*/*"},
		{Name: "authorization", Value: "Bearer tok_standin", Sensitive: true},
		{Name: "accept-encoding", Value: "gzip, deflate, br, zstd"},
		{Name: "priority", Value: "u=1, i"},
	}
	post := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":authority", Value: allowedHost},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/charge"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
		{Name: "content-type", Value: "application/json"},
		{Name: "origin", Value: "https://" + allowedHost},
		{Name: "accept", Value: "*/*"},
		{Name: "priority", Value: "u=1, i"},
	}
	getPriority := h2relay.Priority{Exclusive: true, DependsOn: 0, Weight: 255}
	postPriority := h2relay.Priority{Exclusive: true, DependsOn: 0, Weight: 219}
	priorityBytes := func(p h2relay.Priority) []byte {
		v := p.DependsOn
		if p.Exclusive {
			v |= 1 << 31
		}
		return append(binary.BigEndian.AppendUint32(nil, v), p.Weight)
	}
	out := []byte(h2relay.Preface)
	out = h2relay.AppendFrame(out, h2relay.FrameSettings, 0, 0, settings)
	out = h2relay.AppendFrame(out, h2relay.FrameWindowUpdate, 0, 0, binary.BigEndian.AppendUint32(nil, 15663105))
	out = h2relay.AppendFrame(out, h2relay.FrameHeaders, h2relay.FlagEndHeaders|h2relay.FlagEndStream|h2relay.FlagPriority, 1,
		append(priorityBytes(getPriority), encode(get)...))
	out = h2relay.AppendFrame(out, h2relay.FrameHeaders, h2relay.FlagEndHeaders|h2relay.FlagPriority, 3,
		append(priorityBytes(postPriority), encode(post)...))
	out = h2relay.AppendFrame(out, h2relay.FrameData, 0, 3, []byte(body[:10]))
	out = h2relay.AppendFrame(out, h2relay.FrameData, h2relay.FlagEndStream, 3, []byte(body[10:]))
	if _, err := uconn.Write(out); err != nil {
		t.Fatal(err)
	}

	// Read until both responses ended.
	var gotServerSettings []byte
	responses := map[uint32]string{}
	ended := 0
	for ended < 2 {
		f, err := h2relay.ReadFrame(uconn)
		if err != nil {
			t.Fatalf("read from proxy: %v", err)
		}
		switch f.Type {
		case h2relay.FrameSettings:
			if f.Flags&h2relay.FlagAck == 0 {
				gotServerSettings = f.Payload
				if _, err := uconn.Write(h2relay.AppendFrame(nil, h2relay.FrameSettings, h2relay.FlagAck, 0, nil)); err != nil {
					t.Fatal(err)
				}
			}
		case h2relay.FrameData:
			responses[f.Stream] += string(f.Payload)
			if f.Flags&h2relay.FlagEndStream != 0 {
				ended++
			}
		case h2relay.FrameRSTStream, h2relay.FrameGoAway:
			t.Fatalf("proxy sent frame type %d", f.Type)
		}
	}
	if responses[1] != "ok" || responses[3] != "ok" {
		t.Fatalf("responses %v", responses)
	}
	if !bytes.Equal(gotServerSettings, serverSettings[9:]) {
		t.Fatalf("client received server SETTINGS %x, server sent %x", gotServerSettings, serverSettings[9:])
	}

	var capture *h2Capture
	select {
	case capture = <-captures:
	case <-time.After(5 * time.Second):
		t.Fatal("destination did not report")
	}
	if !bytes.Equal(capture.settingsPayload, settings) {
		t.Fatalf("destination SETTINGS %x, client sent %x", capture.settingsPayload, settings)
	}
	if want := []uint8{h2relay.FrameSettings, h2relay.FrameWindowUpdate, h2relay.FrameHeaders}; !reflect.DeepEqual(capture.frameTypes, want) {
		t.Fatalf("first frames %v, want %v", capture.frameTypes, want)
	}
	if capture.windowUpdate != 15663105 {
		t.Fatalf("connection WINDOW_UPDATE %d", capture.windowUpdate)
	}
	if len(capture.order) != 2 {
		t.Fatalf("destination saw %d requests", len(capture.order))
	}
	getSeen, postSeen := capture.requests[capture.order[0]], capture.requests[capture.order[1]]
	if value(getSeen.fields, ":method") != "GET" {
		getSeen, postSeen = postSeen, getSeen
	}
	if !reflect.DeepEqual(names(getSeen.fields), names(get)) || !reflect.DeepEqual(names(postSeen.fields), names(post)) {
		t.Fatalf("header order changed:\nGET  %v\nPOST %v", names(getSeen.fields), names(postSeen.fields))
	}
	if *getSeen.priority != getPriority || *postSeen.priority != postPriority {
		t.Fatalf("priorities %+v %+v", *getSeen.priority, *postSeen.priority)
	}
	if got := value(getSeen.fields, ":path"); got != "/lookup?card=4111111111111111&q=1" {
		t.Fatalf(":path %q", got)
	}
	if got := value(getSeen.fields, "authorization"); got != "Bearer sk_live_real_secret_value" {
		t.Fatalf("authorization %q", got)
	}
	for i, f := range getSeen.fields {
		if f.Name != "authorization" && f.Name != ":path" && f.Value != get[i].Value {
			t.Fatalf("%s changed from %q to %q", f.Name, get[i].Value, f.Value)
		}
	}
	wantBody := `{"card":"4111111111111111","token":"sk_live_real_secret_value"}`
	if string(postSeen.body) != wantBody {
		t.Fatalf("body %q", postSeen.body)
	}
	if got := value(postSeen.fields, "content-length"); got != strconv.Itoa(len(wantBody)) {
		t.Fatalf("content-length %s for a %d byte body", got, len(wantBody))
	}
	if strings.Contains(p.logs.String(), "4111111111111111") || strings.Contains(p.logs.String(), "sk_live_real_secret_value") {
		t.Fatal("a real value reached the log")
	}
}

// A host that is not on the allowlist is tunneled: the client completes its
// handshake with the destination's own certificate and the destination
// receives the client's ClientHello byte for byte.
func TestNonAllowlistedHostIsTunneled(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": dest.addr}, dest.ca, nil)

	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	rec := &recordingConn{Conn: conn}
	// Trusts only the destination's CA, not the proxy's.
	tlsConn := tls.Client(rec, &tls.Config{ServerName: otherHost, RootCAs: dest.ca, NextProtos: []string{"http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake through the tunnel: %v", err)
	}
	if issuer := tlsConn.ConnectionState().PeerCertificates[0].Issuer.CommonName; issuer != "destination CA" {
		t.Fatalf("certificate issued by %q", issuer)
	}
	getOK(t, tlsConn, otherHost)
	select {
	case message := <-dest.hellos:
		if !bytes.Equal(message, rec.sentHello(t)) {
			t.Fatal("the tunneled ClientHello was modified")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination received no ClientHello")
	}
	if !strings.Contains(p.logs.String(), `level=INFO msg="tunneling without decryption"`) {
		t.Fatalf("no tunnel log line:\n%s", p.logs.String())
	}
}

// A ClientHello that uTLS cannot rebuild exactly is refused: nothing reaches
// the destination, the proxy logs why and the client gets a 502 that says so.
func TestUnreplayableClientHelloFailsLoudly(t *testing.T) {
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, nil)

	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	uconn := utls.UClient(conn, &utls.Config{ServerName: allowedHost, RootCAs: p.ca}, utls.HelloCustom)
	err := uconn.ApplyPreset(&utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256}},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.GenericExtension{Id: 0x1337, Data: []byte{1, 2, 3}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("handshake for the error response: %v", err)
	}
	resp, err = http.ReadResponse(bufio.NewReader(uconn), nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(text), "cannot replay") || !strings.Contains(string(text), "4919") {
		t.Fatalf("got %d %q", resp.StatusCode, text)
	}
	if !strings.Contains(p.logs.String(), "refusing connection") {
		t.Fatalf("no log line:\n%s", p.logs.String())
	}
	select {
	case <-dest.hellos:
		t.Fatal("a ClientHello reached the destination")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestProxyAuthentication(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": dest.addr}, dest.ca, func(c *Config) {
		c.Username, c.Password = "user", "pass word" // pragma: allowlist secret
	})
	basic := func(credentials string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	for authorization, want := range map[string]int{
		"":                      http.StatusProxyAuthRequired,
		basic("user:wrong"):     http.StatusProxyAuthRequired,
		"Bearer user":           http.StatusProxyAuthRequired,
		basic("user:pass word"): http.StatusOK,
	} {
		_, resp := connect(t, p.addr, otherHost+":443", authorization)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("authorization %q: %s, want %d", authorization, resp.Status, want)
		}
	}
}

// A password without a username would leave authentication off, so the
// proxy refuses to start.
func TestPasswordWithoutUsernameIsRefused(t *testing.T) {
	authority, _ := testCA(t, "proxy CA")
	hosts, err := hostmatch.New([]string{allowedHost})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := resolve.NewStatic(map[string]string{"tok_standin": "sk_live_real_secret_value"})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := resolve.NewDetector(resolver, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		Authority: authority, Hosts: hosts, Resolver: resolver, Detector: detector, Dialer: mapDialer{},
		Password: "pass word", // pragma: allowlist secret
	})
	if err == nil {
		t.Fatal("a password without a username was accepted")
	}
}

func TestNonConnectAndUnreachableDestinations(t *testing.T) {
	p := startProxy(t, mapDialer{}, nil, nil)
	_, resp := connect(t, p.addr, "unreachable.test:443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unreachable destination: %s", resp.Status)
	}
	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("plain GET: %s", resp.Status)
	}
}

// Over HTTP/1.1 the destination receives the client's request line, header
// order, casing and spacing unchanged, apart from the swapped stand-ins and
// the content-length that follows the swapped body.
func TestHTTP1KeepsTheRawRequest(t *testing.T) {
	received := make(chan string, 2)
	dest := startDestination(t, allowedHost, []string{"http/1.1"}, func(c *tls.Conn) {
		br := bufio.NewReader(c)
		for {
			var head strings.Builder
			length := 0
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				head.WriteString(line)
				if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "content-length") {
					length, _ = strconv.Atoi(strings.TrimSpace(value))
				}
				if line == "\r\n" {
					break
				}
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(br, body); err != nil {
				return
			}
			received <- head.String() + string(body)
			if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				return
			}
		}
	})
	p := startProxy(t, mapDialer{allowedHost + ":443": dest.addr}, dest.ca, nil)

	conn, resp := connect(t, p.addr, allowedHost+":443", "")
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: allowedHost, RootCAs: p.ca, NextProtos: []string{"h2", "http/1.1"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated %q, the destination only speaks http/1.1", got)
	}
	body := "card=4242424242424242&token=tok_standin"
	request := "POST /pay?card=4242424242424242 HTTP/1.1\r\n" +
		"Host: " + allowedHost + "\r\n" +
		"X-Custom-Case:  Bearer tok_standin\r\n" +
		"content-type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Accept: */*\r\n\r\n" + body
	if _, err := io.WriteString(tlsConn, request); err != nil {
		t.Fatal(err)
	}
	responses := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(responses, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response %v, %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	swappedBody := "card=4111111111111111&token=sk_live_real_secret_value"
	want := "POST /pay?card=4111111111111111 HTTP/1.1\r\n" +
		"Host: " + allowedHost + "\r\n" +
		"X-Custom-Case:  Bearer sk_live_real_secret_value\r\n" +
		"content-type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + strconv.Itoa(len(swappedBody)) + "\r\n" +
		"Accept: */*\r\n\r\n" + swappedBody
	select {
	case got := <-received:
		if got != want {
			t.Fatalf("destination received:\n%q\nwant:\n%q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination received nothing")
	}

	// A client that sends Expect: 100-continue waits for approval before
	// its body; the proxy needs the body first, so it approves locally.
	uploadBody := `{"token":"tok_standin"}`
	if _, err := io.WriteString(tlsConn, "POST /upload HTTP/1.1\r\nHost: "+allowedHost+"\r\n"+
		"Content-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(uploadBody))+"\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, err := responses.ReadString('\n')
	if err != nil || status != "HTTP/1.1 100 Continue\r\n" {
		t.Fatalf("waiting for 100 Continue: %q, %v", status, err)
	}
	if blank, err := responses.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("100 Continue not terminated: %q, %v", blank, err)
	}
	_ = tlsConn.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(tlsConn, uploadBody); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(responses, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("upload response %v, %v", resp, err)
	}
	_ = resp.Body.Close()
	swappedUpload := `{"token":"sk_live_real_secret_value"}`
	wantUpload := "POST /upload HTTP/1.1\r\nHost: " + allowedHost + "\r\n" +
		"Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(swappedUpload)) + "\r\nExpect: 100-continue\r\n\r\n" + swappedUpload
	select {
	case got := <-received:
		if got != wantUpload {
			t.Fatalf("destination received:\n%q\nwant:\n%q", got, wantUpload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination received no upload")
	}
}

// An unauthenticated client cannot make the proxy buffer an endless request
// head: the proxy stops reading at its limit and closes the connection.
func TestOversizedProxyRequestHeadIsRefused(t *testing.T) {
	p := startProxy(t, mapDialer{}, nil, func(c *Config) {
		c.Username, c.Password = "user", "secret" // pragma: allowlist secret
	})
	conn, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const total = 32 << 20
	written := make(chan int, 1)
	go func() {
		n, _ := io.WriteString(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nX-Pad: ")
		chunk := strings.Repeat("a", 64<<10)
		_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
		for n < total {
			m, err := io.WriteString(conn, chunk)
			n += m
			if err != nil {
				break
			}
		}
		written <- n
	}()
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	reply, _ := io.ReadAll(conn)
	n := <-written
	if n >= total {
		t.Fatalf("the proxy accepted a %d byte request head", n)
	}
	if len(reply) > 0 && !strings.HasPrefix(string(reply), "HTTP/1.1 431 ") {
		t.Fatalf("reply %q", reply)
	}
	if !strings.Contains(p.logs.String(), "refusing a proxy request head over the limit") {
		t.Fatalf("no log line:\n%s", p.logs.String())
	}
}

// Stopping the proxy (closing its listener) closes open tunnels instead of
// waiting for clients to leave.
func TestShutdownClosesIdleTunnels(t *testing.T) {
	dest := startDestination(t, otherHost, []string{"http/1.1"}, respondOK)
	p := startProxy(t, mapDialer{otherHost + ":443": dest.addr}, dest.ca, nil)
	conn, resp := connect(t, p.addr, otherHost+":443", "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT answered %s", resp.Status)
	}
	// The tunnel is open and idle.
	if err := p.ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.served:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return while a tunnel was idle")
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the idle tunnel stayed open after shutdown: %v", err)
	}
}
