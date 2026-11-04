// Package h1relay relays an HTTP/1.1 connection between a client and an
// upstream server. Requests are forwarded with the client's own request line,
// header order, header name casing and spacing; only stand-ins change, plus
// content-length when a swap changes the body size. A request whose
// stand-ins cannot be swapped (see package scope) is answered 502 and not
// sent. Responses are copied byte for byte.
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
	"github.com/nottelabs/browser-secret-proxy/internal/scope"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// Options configures a relay.
type Options struct {
	Hosts *hostmatch.List
	// Session resolves the stand-ins of each request on an allowlisted host.
	Session *scope.Session
	MaxBody int
	Logger  *slog.Logger
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
		done <- responses(bufio.NewReader(server), toClient, queue, progress)
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
	value string // trimmed
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
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				return fmt.Errorf("malformed header line")
			}
			headers = append(headers, header{raw: line, name: strings.ToLower(strings.TrimSpace(name)), value: strings.TrimSpace(value)})
		}

		host, contentType := "", ""
		chunked, upgrade, expectContinue := false, false, false
		contentLength := -1
		for _, h := range headers {
			switch h.name {
			case "host":
				host = h.value
			case "content-type":
				contentType = h.value
			case "transfer-encoding":
				chunked = strings.Contains(strings.ToLower(h.value), "chunked")
			case "content-length":
				n, err := strconv.Atoi(h.value)
				if err != nil || n < 0 {
					return fmt.Errorf("invalid content-length")
				}
				contentLength = n
			case "upgrade":
				upgrade = true
			case "expect":
				expectContinue = strings.EqualFold(h.value, "100-continue")
			}
		}
		// Every request goes to the CONNECT host: one naming another host is
		// refused, so no value scoped to that host goes with it.
		if err := opts.Session.CheckAuthority(host); err != nil {
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
			swapper, err = opts.Session.Swapper(ctx, swappableText(parts[1], headers, body)...)
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
			if h.name == "content-length" && !chunked && bodyChanged {
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
		ex := &exchange{method: strings.ToUpper(parts[0])}
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

// swappableText is the text of a request that stand-ins are swapped in: the
// query part of its target, its non-framing header values and its body.
func swappableText(target string, headers []header, body []byte) []string {
	texts := make([]string, 0, len(headers)+2)
	if _, query, ok := strings.Cut(target, "?"); ok {
		query, _, _ = strings.Cut(query, "#")
		texts = append(texts, query)
	}
	for _, h := range headers {
		if !framingHeaders[h.name] {
			texts = append(texts, h.value)
		}
	}
	return append(texts, string(body))
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
func responses(br *bufio.Reader, client io.Writer, queue <-chan *exchange, progress *progress) error {
	var current *exchange
	for {
		head, status, length, chunked, err := readResponseHead(br)
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
		if _, err := client.Write(head); err != nil {
			return err
		}
		switched := status == 101 || current.method == "CONNECT" && status >= 200 && status < 300
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

// readResponseHead reads a status line and headers, returning their raw
// bytes, the status code, the content length (-1 when absent) and whether
// the body is chunked.
func readResponseHead(br *bufio.Reader) (head []byte, status int, length int64, chunked bool, err error) {
	length = -1
	for {
		line, err := readRawLine(br, maxHeadBytes-len(head))
		if err != nil {
			return nil, 0, 0, false, err
		}
		head = append(head, line...)
		text := strings.TrimRight(string(line), "\r\n")
		if status == 0 {
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
		name, value, _ := strings.Cut(text, ":")
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			if length, err = strconv.ParseInt(value, 10, 64); err != nil || length < 0 {
				return nil, 0, 0, false, fmt.Errorf("invalid content-length in a response")
			}
		case "transfer-encoding":
			codings := strings.Split(strings.ToLower(value), ",")
			chunked = strings.TrimSpace(codings[len(codings)-1]) == "chunked"
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

// copyChunked copies a chunked body unchanged, trailers included.
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
			for {
				trailer, err := readRawLine(br, maxHeadBytes)
				if err != nil {
					return err
				}
				if _, err := w.Write(trailer); err != nil {
					return err
				}
				if strings.TrimRight(string(trailer), "\r\n") == "" {
					return nil
				}
			}
		}
		if _, err := io.CopyN(w, br, size+2); err != nil { // data and its CRLF
			return err
		}
	}
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
		trailer.WriteString(line + "\r\n")
	}
}
