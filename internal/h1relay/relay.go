// Package h1relay relays an HTTP/1.1 connection between a client and an
// upstream server. Requests are forwarded with the client's own request line,
// header order, header name casing and spacing; only stand-ins change, plus
// content-length when a swap changes the body size. A request whose
// stand-ins cannot be swapped (see package scope) is answered 502 and not
// sent. A response head that the client could read differently from the
// relay is answered 502 instead. Responses are otherwise copied byte for
// byte, unless the connection's principal has values on record for masking
// (see package scope): then every real value in a response's header values,
// body and trailers is replaced by its stand-in before it reaches the
// client, a compressed body being decoded to do so.
package h1relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// Options configures a relay.
type Options struct {
	Hosts *hostmatch.List
	// Session resolves the stand-ins of each request on an allowlisted host.
	Session *scope.Session
	MaxBody int
	// MaxDecoded caps the decoded size of one compressed response that is
	// masked (default mask.DefaultMaxDecoded). A response past it is cut
	// off.
	MaxDecoded int64
	Logger     *slog.Logger
}

const (
	// maxHeadBytes caps a request line plus its headers.
	maxHeadBytes = 1 << 20
	// maxTrailerBytes caps the trailer section of a chunked body.
	maxTrailerBytes = 16 << 10
	// maxChunkLine caps a chunk-size line (size plus extensions).
	maxChunkLine = 4 << 10
)

// errLineTooLong is a line longer than the limit that applies to it.
var errLineTooLong = errors.New("line too long")

// Serve relays until either side closes. It closes both connections.
func Serve(client, server net.Conn, opts Options) error {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 32 << 20
	}
	if opts.MaxDecoded <= 0 {
		opts.MaxDecoded = mask.DefaultMaxDecoded
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	toClient := &lockedWriter{w: client}
	queue := make(chan *exchange, maxPipelined)
	responsesDone := make(chan struct{})
	progress := newProgress()
	done := make(chan error, 2)
	go func() {
		defer close(responsesDone)
		defer progress.stop()
		done <- responses(bufio.NewReader(server), toClient, queue, progress, opts)
	}()
	go func() {
		done <- requests(ctx, bufio.NewReader(client), server, toClient, queue, responsesDone, progress, opts)
	}()
	err := <-done
	cancel()
	_ = client.Close()
	_ = server.Close()
	<-done //nolint:errcheck // waits for the other side; err above is the cause
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, errRefused) {
		return nil // a refusal was logged when it was answered
	}
	return err
}

// lockedWriter keeps the relay's own interim responses from landing inside a
// response being copied from the server.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// progress counts the responses fully passed to the client, so the relay's
// own interim responses go out between responses, never inside one.
type progress struct {
	mu        sync.Mutex
	cond      *sync.Cond
	completed int
	stopped   bool
}

func newProgress() *progress {
	p := &progress{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *progress) complete() {
	p.mu.Lock()
	p.completed++
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *progress) stop() {
	p.mu.Lock()
	p.stopped = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

// wait blocks until n responses are complete; false when the response side
// stopped first.
func (p *progress) wait(n int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.completed < n && !p.stopped {
		p.cond.Wait()
	}
	return p.completed >= n
}

// exchange is a request forwarded to the server, awaiting its response.
type exchange struct {
	unsolicited bool // a response no request asked for, such as a 408
	method      string
	// switching requests (Upgrade, CONNECT) learn here whether the server
	// switched the connection to another protocol.
	switching bool
	upgrade   bool // the request carried Upgrade, so a 101 may answer it
	switched  chan bool
}

// framingHeaders describe the message or the connection, not its content:
// a stand-in that happens to match their value ("123" in Content-Length:
// 123) is not one. Content-Length is set from the body that is sent.
var framingHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true, "keep-alive": true, "expect": true,
}

// maxPipelined bounds requests awaiting a response.
const maxPipelined = 64

type header struct {
	raw   string // the line without CRLF
	name  string // lower case
	value string // without the SP and HTAB around it
}

// errRefused ends a connection after a request was answered 502 instead of
// being sent.
var errRefused = errors.New("request refused")

func requests(ctx context.Context, br *bufio.Reader, server io.Writer, client io.Writer, queue chan<- *exchange, responsesDone <-chan struct{}, progress *progress, opts Options) error {
	sent := 0 // requests forwarded so far
	for {
		requestLine, err := readLine(br, maxHeadBytes)
		if err != nil {
			return err
		}
		if requestLine == "" {
			continue // tolerated empty line between requests
		}
		parts := strings.SplitN(requestLine, " ", 3)
		if len(parts) != 3 {
			return fmt.Errorf("malformed request line")
		}
		var headers []header
		remaining := maxHeadBytes - len(requestLine)
		for {
			line, err := readLine(br, remaining)
			if err != nil {
				if errors.Is(err, errLineTooLong) {
					return errors.New("request head too large")
				}
				return err
			}
			if line == "" {
				break
			}
			remaining -= len(line)
			// A line without a colon or otherwise malformed is refused by
			// framing below.
			name, value, _ := strings.Cut(line, ":")
			headers = append(headers, header{raw: line, name: strings.ToLower(name), value: trimOWS(value)})
		}

		host, contentType := "", ""
		hosts := 0
		upgrade, expectContinue := false, false
		for _, h := range headers {
			switch h.name {
			case "host":
				host = h.value
				hosts++
			case "content-type":
				contentType = h.value
			case "upgrade":
				upgrade = true
			case "expect":
				expectContinue = strings.EqualFold(h.value, "100-continue")
			}
		}
		// The body is framed as the server will frame it, and the head is
		// split into the lines the server will see, or the request is
		// refused: otherwise bytes swapped here as body could reach the
		// server as another request, whose Host was never checked.
		chunked, contentLength, err := framing(requestLine, parts[2], headers)
		if err != nil {
			return refuse(client, progress, sent, host, opts, fmt.Errorf("%w: %w", scope.ErrRefused, err))
		}
		// Every request goes to the CONNECT host: one naming another host is
		// refused, so no value scoped to that host goes with it. A server
		// may route by any Host header, or by an absolute-form target
		// instead of Host (RFC 9112 3.2.2), so each must name that host.
		if hosts > 1 {
			return refuse(client, progress, sent, host, opts, fmt.Errorf("%w: more than one Host header", scope.ErrRefused))
		}
		authorities := []string{host}
		if authority, ok := targetAuthority(parts[0], parts[1]); ok {
			authorities = append(authorities, authority)
		}
		if err := opts.Session.CheckAuthority(authorities...); err != nil {
			return refuse(client, progress, sent, host, opts, err)
		}
		doSwap := opts.Hosts.Match(host)
		hasBody := chunked || contentLength > 0
		if hasBody && !chunked && contentLength > opts.MaxBody {
			return fmt.Errorf("request body of %d bytes is larger than the buffer limit", contentLength)
		}
		if expectContinue && hasBody {
			// The body is needed before the request can go upstream, so
			// approve it here, once every earlier response is complete so the
			// 100 cannot land inside one. A second 100 from the server is
			// harmless.
			if !progress.wait(sent) {
				return io.EOF
			}
			if _, err := io.WriteString(client, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
				return err
			}
		}

		var body, trailer []byte
		switch {
		case chunked:
			body, trailer, err = readChunked(br, opts.MaxBody)
		case contentLength > 0:
			body = make([]byte, contentLength)
			_, err = io.ReadFull(br, body)
		}
		if err != nil {
			return err
		}

		var out bytes.Buffer
		swapped := 0
		bodyChanged := false
		// The swapped head stays within maxHeadBytes and the body within
		// MaxBody; the swaps stop at those limits instead of allocating past
		// them. A request over a limit, or one that would put a line break
		// into a header, ends the connection: it cannot be sent as written.
		headRoom := maxHeadBytes - len(requestLine)
		for _, h := range headers {
			headRoom -= len(h.raw)
		}
		var swapper *swap.Swapper
		if doSwap {
			swapper, err = opts.Session.Swapper(ctx, swappableText(parts[1], headers, contentType, body)...)
			if err != nil {
				return refuse(client, progress, sent, host, opts, err)
			}
		}
		if swapper != nil {
			t, changed, err := swapper.Target(parts[1], len(parts[1])+headRoom)
			if err != nil {
				return fmt.Errorf("swapping stand-ins in the request target: %w", err)
			}
			if changed {
				headRoom -= len(t) - len(parts[1])
				parts[1] = t
				swapped++
			}
			b, changed, err := swapper.Body(contentType, body, opts.MaxBody)
			if err != nil {
				return fmt.Errorf("swapping stand-ins in the request body: %w", err)
			}
			if changed {
				body = b
				bodyChanged = true
				swapped++
			}
		}
		out.WriteString(strings.Join(parts, " ") + "\r\n")
		for _, h := range headers {
			line := h.raw
			if swapper != nil && !framingHeaders[h.name] {
				colon := strings.IndexByte(line, ':')
				value := line[colon+1:]
				s, changed, err := swapper.Header(value, len(value)+headRoom)
				if err != nil {
					return fmt.Errorf("swapping stand-ins in header %s: %w", h.name, err)
				}
				if changed {
					headRoom -= len(s) - len(value)
					line = line[:colon+1] + s
					swapped++
				}
			}
			if h.name == "content-length" && bodyChanged {
				colon := strings.IndexByte(line, ':')
				spacing := line[colon+1 : colon+1+len(line[colon+1:])-len(strings.TrimLeft(line[colon+1:], " \t"))]
				line = line[:colon+1] + spacing + strconv.Itoa(len(body))
			}
			out.WriteString(line + "\r\n")
		}
		out.WriteString("\r\n")
		if chunked {
			if len(body) > 0 {
				out.WriteString(strconv.FormatInt(int64(len(body)), 16) + "\r\n")
				out.Write(body)
				out.WriteString("\r\n")
			}
			out.WriteString("0\r\n")
			out.Write(trailer)
			out.WriteString("\r\n")
		} else {
			out.Write(body)
		}
		if swapped > 0 {
			opts.Logger.Info("swapped stand-ins in a request", "host", host, "parts", swapped)
		}
		ex := &exchange{method: strings.ToUpper(parts[0]), upgrade: upgrade}
		if upgrade || ex.method == "CONNECT" {
			ex.switching, ex.switched = true, make(chan bool, 1)
		}
		// Queued before the request is sent, so its response finds it.
		select {
		case queue <- ex:
		case <-responsesDone:
			return io.EOF
		}
		sent++
		if _, err := server.Write(out.Bytes()); err != nil {
			return err
		}
		if ex.switching {
			// Wait for the server's answer: only a switch makes the rest
			// of the connection a raw stream (a WebSocket, a tunnel). After
			// a refusal the client sends HTTP requests again, which are
			// swapped as usual.
			select {
			case switched := <-ex.switched:
				if switched {
					_, err := io.Copy(server, br)
					return err
				}
			case <-responsesDone:
				return io.EOF
			}
		}
	}
}

// framing checks a request head that a server could read differently from
// the relay, and returns how its body is framed: chunked, or its
// Content-Length (-1 when absent). It refuses, as RFC 9112 allows or
// requires (2.2, 5, 6.1, 6.3): a bare CR or a NUL in any line, a folded
// (obs-fold) header line, a header name that is not a token (such as one
// with a space before the colon), a control character other than HTAB in a
// header value (RFC 9110 5.5), Transfer-Encoding with Content-Length,
// Transfer-Encoding other than a single chunked or on a request that is not
// HTTP/1.1, and more than one Content-Length or one that is not a decimal
// number.
func framing(requestLine, version string, headers []header) (chunked bool, contentLength int, err error) {
	contentLength = -1
	if strings.ContainsAny(requestLine, "\r\x00") {
		return false, 0, errors.New("a bare CR or NUL in the request line")
	}
	encodings, lengths := 0, 0
	for _, h := range headers {
		if err := checkRequestFieldLine(h.raw); err != nil {
			return false, 0, err
		}
		switch h.name {
		case "transfer-encoding":
			encodings++
			chunked = isChunked(h.value)
		case "content-length":
			lengths++
			if !isDigits(h.value) {
				return false, 0, errors.New("an invalid Content-Length")
			}
			if contentLength, err = strconv.Atoi(h.value); err != nil {
				return false, 0, errors.New("an invalid Content-Length")
			}
		}
	}
	switch {
	case encodings > 0 && lengths > 0:
		return false, 0, errors.New("both Transfer-Encoding and Content-Length")
	case encodings > 1 || encodings == 1 && !chunked:
		return false, 0, errors.New("a Transfer-Encoding other than a single chunked")
	case chunked && version != "HTTP/1.1":
		return false, 0, errors.New("Transfer-Encoding on a request that is not HTTP/1.1")
	case lengths > 1:
		return false, 0, errors.New("more than one Content-Length")
	}
	return chunked, contentLength, nil
}

// checkFieldLine refuses a header or trailer line that a server could split
// or unfold into other lines than the relay reads, or whose name it could
// read as another: a bare CR or a NUL, a folded (obs-fold) line, and a name
// that is not a token.
func checkFieldLine(line string) error {
	if strings.ContainsAny(line, "\r\x00") {
		return errors.New("a bare CR or NUL in a header line")
	}
	if line != "" && (line[0] == ' ' || line[0] == '\t') {
		return errors.New("a folded header line")
	}
	name, _, ok := strings.Cut(line, ":")
	if !ok || !isToken(name) {
		return errors.New("a malformed header name")
	}
	return nil
}

// checkRequestFieldLine is checkFieldLine for a request, which also refuses
// a control character other than HTAB in the value (RFC 9110 5.5): a server
// may trim one from the ends of a value, as strings.TrimSpace does with VT
// and FF, or keep it, so "Host: allowed.test\v" could name another host to
// it than to the relay.
func checkRequestFieldLine(line string) error {
	if err := checkFieldLine(line); err != nil {
		return err
	}
	_, value, _ := strings.Cut(line, ":")
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < ' ' && c != '\t' || c == 0x7f {
			return errors.New("a control character in a header value")
		}
	}
	return nil
}

// trimOWS trims the whitespace around a header value: SP and HTAB only (RFC
// 9110 5.6.3). strings.TrimSpace also trims VT, FF and spaces that are not
// ASCII, such as NBSP, which a server or client may keep.
func trimOWS(s string) string { return strings.Trim(s, " \t") }

// isToken reports whether s is an RFC 9110 5.6.2 token, the syntax of a
// header name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTchar(s[i]) {
			return false
		}
	}
	return true
}

func isTchar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// isChunked reports whether s is the coding name chunked, in any ASCII case
// (RFC 9112 7). strings.EqualFold is not used: it also folds non-ASCII
// letters, such as the Kelvin sign to k.
func isChunked(s string) bool {
	const name = "chunked"
	if len(s) != len(name) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i]|0x20 != name[i] {
			return false
		}
	}
	return true
}

// isDigits reports whether s is one or more ASCII digits, the syntax of a
// Content-Length.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// swappableText is the text of a request that stand-ins are swapped in,
// each part with the place that decides how it is swapped: the query part of
// its target, its non-framing header values and its body.
func swappableText(target string, headers []header, contentType string, body []byte) []swap.Part {
	parts := make([]swap.Part, 0, len(headers)+2)
	if _, query, ok := strings.Cut(target, "?"); ok {
		query, _, _ = strings.Cut(query, "#")
		parts = append(parts, swap.Part{Place: swap.Query, Text: query})
	}
	for _, h := range headers {
		if !framingHeaders[h.name] {
			parts = append(parts, swap.Part{Place: swap.Literal, Text: h.value})
		}
	}
	return append(parts, swap.Part{Place: swap.BodyPlace(contentType), Text: string(body)})
}

// targetAuthority returns the authority a request target names, if any: the
// target of a CONNECT (authority-form), or the authority of an absolute-form
// target ("https://host/path"). An origin-form ("/path") or asterisk-form
// ("*") target names none. Any other target names an empty authority, which
// no connection is opened to.
func targetAuthority(method, target string) (string, bool) {
	switch {
	case strings.HasPrefix(target, "/") || target == "*":
		return "", false
	case method == "CONNECT":
		return target, true
	}
	_, rest, ok := strings.Cut(target, "://")
	if !ok {
		return "", true
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	return rest, true
}

// refuse answers a request that must not be sent with 502, once every
// earlier response is complete so the answer cannot land inside one, and
// ends the connection: the client may have pipelined more requests behind
// it.
func refuse(client io.Writer, progress *progress, sent int, host string, opts Options, cause error) error {
	opts.Logger.Warn("refusing a request", "host", host, "principal", opts.Session.Principal().ID, "reason", cause.Error())
	if !progress.wait(sent) {
		return io.EOF
	}
	body := "secret-proxy: " + cause.Error() + "\n"
	_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	return errRefused
}

// responses copies the server's responses to the client byte for byte,
// following message boundaries to tell each switching request whether the
// server switched protocols.
func responses(br *bufio.Reader, client io.Writer, queue <-chan *exchange, progress *progress, opts Options) error {
	var current *exchange
	for {
		head, status, length, chunked, err := readResponseHead(br)
		if errors.Is(err, errUnclearResponse) {
			// Nothing of this response was passed on yet.
			opts.Logger.Warn("refusing a response the client could read differently", "reason", err.Error())
			body := "secret-proxy: malformed response from the server\n"
			_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			return errRefused
		}
		if err != nil {
			return err
		}
		if current == nil {
			select {
			case current = <-queue:
			default:
				current = &exchange{unsolicited: true}
			}
		}
		// A 101 turns the rest of the connection into a raw stream that is
		// neither swapped nor masked, so only a request that asked to
		// upgrade may get one (RFC 9110 15.2.2). Any other 101 is refused.
		if status == 101 && !current.upgrade {
			opts.Logger.Warn("refusing a 101 to a request that did not ask to upgrade")
			body := "secret-proxy: unrequested protocol switch\n"
			_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			return errRefused
		}
		switched := status == 101 || current.method == "CONNECT" && status >= 200 && status < 300
		// Values resolved before this response's request was sent are on
		// record by now.
		masker := opts.Session.Masker()
		var plan maskPlan
		if masker != nil {
			head, plan, err = maskHead(head, status, current.method, switched, length, chunked, masker)
			if err != nil {
				opts.Logger.Warn("refusing a response that cannot be masked", "status", status, "reason", err.Error())
				body := "secret-proxy: the response cannot be masked\n"
				_, _ = fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				return errRefused
			}
		}
		if _, err := client.Write(head); err != nil {
			return err
		}
		if switched {
			if current.switching {
				current.switched <- true
			}
			_, err := io.Copy(client, br)
			return err
		}
		if status >= 100 && status < 200 {
			continue // interim response; the final one follows
		}
		switch {
		case current.method == "HEAD" || status == 204 || status == 304:
		case masker != nil && plan.hasBody:
			if plan.closeDelimited && current.switching {
				current.switched <- false
			}
			err = copyMaskedBody(br, client, plan, masker, opts.MaxDecoded)
			if err == nil && plan.closeDelimited {
				return io.EOF
			}
		case chunked:
			err = copyChunked(br, client)
		case length >= 0:
			_, err = io.CopyN(client, br, length)
		default:
			// The body runs until the server closes the connection.
			if current.switching {
				current.switched <- false
			}
			_, err := io.Copy(client, br)
			return err
		}
		if err != nil {
			return err
		}
		if current.switching {
			current.switched <- false
		}
		if !current.unsolicited {
			progress.complete()
		}
		current = nil
	}
}

// errUnclearResponse is a response head that a client could read
// differently from the relay. It is answered 502: the relay follows each
// response's framing to know where the next one, which it may have to mask,
// begins.
var errUnclearResponse = errors.New("unclear response head")

// readResponseHead reads a status line and headers, returning their raw
// bytes, the status code, the content length (-1 when absent) and whether
// the body is chunked. It returns errUnclearResponse for a status line with
// a bare CR or NUL, a header line that checkFieldLine refuses, or a
// Content-Length that is not a decimal number: only SP and HTAB may surround
// it, and the coding name chunked is matched in ASCII only, as a client
// matches them.
func readResponseHead(br *bufio.Reader) (head []byte, status int, length int64, chunked bool, err error) {
	length = -1
	for {
		line, err := readRawLine(br, maxHeadBytes-len(head))
		if err != nil {
			return nil, 0, 0, false, err
		}
		head = append(head, line...)
		// One line ending only: a line of "\r\r\n" does not end the head.
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if status == 0 {
			// A client ends the status line at a bare CR and reads what
			// follows as header lines the relay would not see.
			if strings.ContainsAny(text, "\r\x00") {
				return nil, 0, 0, false, fmt.Errorf("%w: a bare CR or NUL in the status line", errUnclearResponse)
			}
			fields := strings.Fields(text)
			if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
				return nil, 0, 0, false, fmt.Errorf("malformed status line")
			}
			if status, err = strconv.Atoi(fields[1]); err != nil || status < 100 {
				return nil, 0, 0, false, fmt.Errorf("malformed status line")
			}
			continue
		}
		if text == "" {
			return head, status, length, chunked, nil
		}
		if err := checkFieldLine(text); err != nil {
			return nil, 0, 0, false, fmt.Errorf("%w: %w", errUnclearResponse, err)
		}
		name, value, _ := strings.Cut(text, ":")
		value = trimOWS(value)
		switch strings.ToLower(name) {
		case "content-length":
			if !isDigits(value) {
				return nil, 0, 0, false, fmt.Errorf("%w: an invalid Content-Length", errUnclearResponse)
			}
			if length, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, 0, 0, false, fmt.Errorf("%w: an invalid Content-Length", errUnclearResponse)
			}
		case "transfer-encoding":
			codings := strings.Split(value, ",")
			chunked = isChunked(trimOWS(codings[len(codings)-1]))
		}
	}
}

// readRawLine reads one line with its line ending, refusing it once it is
// longer than limit bytes.
func readRawLine(br *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := br.ReadSlice('\n')
		if len(line)+len(fragment) > limit {
			return nil, errLineTooLong
		}
		line = append(line, fragment...)
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// copyChunked copies a chunked body unchanged, trailers included. The
// trailer section is read whole, up to maxHeadBytes, before it is copied: a
// line in it that checkFieldLine refuses ends the connection with none of it
// passed on, since the client could read the end of the body elsewhere than
// the relay.
func copyChunked(br *bufio.Reader, w io.Writer) error {
	for {
		line, err := readRawLine(br, maxChunkLine)
		if err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		sizeText, _, _ := strings.Cut(strings.TrimRight(string(line), "\r\n"), ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil || size < 0 {
			return errors.New("invalid chunk size in a response")
		}
		if size == 0 {
			var trailers []byte
			for {
				trailer, err := readRawLine(br, maxHeadBytes-len(trailers))
				if err != nil {
					return err
				}
				trailers = append(trailers, trailer...)
				if isEmptyLine(trailer) {
					_, err := w.Write(trailers)
					return err
				}
				if err := checkFieldLine(strings.TrimSuffix(strings.TrimSuffix(string(trailer), "\n"), "\r")); err != nil {
					return fmt.Errorf("malformed trailer line in a response: %w", err)
				}
			}
		}
		if _, err := io.CopyN(w, br, size+2); err != nil { // data and its CRLF
			return err
		}
	}
}

// isEmptyLine reports whether a raw line is the empty line that ends a head
// or a trailer section: a line ending alone, so "\r\r\n" is not one.
func isEmptyLine(line []byte) bool {
	return string(line) == "\r\n" || string(line) == "\n"
}

// readLine reads one line without its CRLF, refusing it once it is longer
// than limit bytes, before reading the rest.
func readLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		fragment, err := br.ReadSlice('\n')
		if len(line)+len(fragment) > limit+2 { // +2 for the CRLF
			return "", errLineTooLong
		}
		line = append(line, fragment...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
}

// readChunked reads a chunked body. It returns the body and the raw trailer
// lines (each with its CRLF), without the final empty line.
func readChunked(br *bufio.Reader, limit int) ([]byte, []byte, error) {
	var body, trailer bytes.Buffer
	for {
		line, err := readLine(br, maxChunkLine)
		if err != nil {
			return nil, nil, err
		}
		sizeText, _, _ := strings.Cut(line, ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil || size < 0 {
			return nil, nil, errors.New("invalid chunk size")
		}
		if size == 0 {
			break
		}
		if int64(body.Len())+size > int64(limit) {
			return nil, nil, errors.New("chunked request body is larger than the buffer limit")
		}
		if _, err := io.CopyN(&body, br, size); err != nil {
			return nil, nil, err
		}
		if crlf, err := readLine(br, 0); err != nil || crlf != "" {
			return nil, nil, errors.New("missing CRLF after chunk")
		}
	}
	for {
		line, err := readLine(br, maxTrailerBytes-trailer.Len())
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				return nil, nil, errors.New("chunked trailers too large")
			}
			return nil, nil, err
		}
		if line == "" {
			return body.Bytes(), trailer.Bytes(), nil
		}
		if err := checkRequestFieldLine(line); err != nil {
			return nil, nil, fmt.Errorf("malformed trailer line: %w", err)
		}
		trailer.WriteString(line + "\r\n")
	}
}
