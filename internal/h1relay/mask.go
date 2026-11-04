package h1relay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nottelabs/browser-secret-proxy/internal/mask"
)

// errUnmaskable is a response that cannot be masked and so is not passed on.
var errUnmaskable = errors.New("response cannot be masked")

// maskPlan is how a masked response is rewritten.
type maskPlan struct {
	hasBody        bool
	decode         mask.Encoding // decoded and sent without a content-coding
	keepFraming    bool          // the body keeps its length: framing unchanged
	inChunked      bool
	outChunked     bool // sent chunked (re-chunked, or chunked instead of a Content-Length)
	closeDelimited bool // the body runs until the server closes
	length         int64
	context        mask.Context // of the body, from its Content-Type
}

// responseHeaders the masker does not touch: they frame the message or the
// connection and carry no content.
var responseFraming = map[string]bool{
	"content-length": true, "transfer-encoding": true, "content-encoding": true, "connection": true,
	"keep-alive": true, "trailer": true, "upgrade": true,
}

// maskHead rewrites a response head for masking: every header value except
// framing headers is masked; a decodable Content-Encoding is dropped, since
// the body is decoded to be masked; a body whose length may change loses its
// Content-Length and is sent chunked. Headers are rewritten line by line,
// never by substitution in the raw head. It returns errUnmaskable for a
// response that cannot be masked: a folded (obs-fold) header line, whose
// value a client may unfold into another header than the one read here; an
// unknown or stacked content-coding (in one list or several headers); a
// transfer-coding other than chunked; or a partial response (206) whose
// ranges masking would shift.
func maskHead(head []byte, status int, method string, switched bool, length int64, chunked bool, m *mask.Masker) ([]byte, maskPlan, error) {
	lines := splitLines(head)
	var encodings, transferCodings []string
	contentType := ""
	for _, line := range lines[1 : len(lines)-1] {
		if line[0] == ' ' || line[0] == '\t' {
			return nil, maskPlan{}, fmt.Errorf("%w: a folded header line", errUnmaskable)
		}
		name, value, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
		if !ok {
			return nil, maskPlan{}, fmt.Errorf("%w: a header line without a colon", errUnmaskable)
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-encoding":
			encodings = append(encodings, value)
		case "transfer-encoding":
			// Every coding of every Transfer-Encoding header: repeated
			// headers are one list (RFC 9110 5.3).
			for _, c := range strings.Split(value, ",") {
				if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
					transferCodings = append(transferCodings, c)
				}
			}
		case "content-type":
			contentType = value
		}
	}
	p := maskPlan{context: mask.ContextOf(contentType)}
	bodiless := switched || method == "HEAD" || status == 204 || status == 304 || status < 200 || (!chunked && length == 0)
	p.hasBody = !bodiless
	enc, err := mask.ParseEncoding(encodings)
	if err != nil && !switched && status >= 200 {
		return nil, p, fmt.Errorf("%w: %w", errUnmaskable, err)
	}
	if p.hasBody {
		if len(transferCodings) > 0 && (len(transferCodings) != 1 || transferCodings[0] != "chunked") {
			return nil, p, fmt.Errorf("%w: transfer-codings %q", errUnmaskable, strings.Join(transferCodings, ", "))
		}
		if status == 206 && (enc != "" || !m.SameLength(p.context)) {
			return nil, p, fmt.Errorf("%w: a partial response whose content masking would change", errUnmaskable)
		}
		p.decode = enc
		p.inChunked = chunked
		p.closeDelimited = !chunked && length < 0
		p.length = length
		p.keepFraming = enc == "" && m.SameLength(p.context)
		p.outChunked = chunked || (!p.closeDelimited && !p.keepFraming)
	}
	// The coding is dropped on bodiless responses too, so a 304 or HEAD
	// cannot restore it on a cached copy that was decoded.
	dropEncoding := enc != "" && !switched && status >= 200

	out := make([]byte, 0, len(head)+32)
	out = append(out, lines[0]...)
	for _, line := range lines[1 : len(lines)-1] {
		raw := strings.TrimRight(line, "\r\n")
		name, value, _ := strings.Cut(raw, ":")
		lower := strings.ToLower(strings.TrimSpace(name))
		switch {
		case lower == "content-encoding" && dropEncoding:
			continue
		case lower == "content-length" && (p.hasBody && !p.keepFraming || method == "HEAD" && dropEncoding):
			continue
		case responseFraming[lower]:
			out = append(out, line...)
			continue
		}
		masked := m.String(mask.HeaderContext(lower), value)
		if unsafeHeader(masked, value) {
			return nil, p, fmt.Errorf("%w: a stand-in cannot go into a header", errUnmaskable)
		}
		out = append(out, name+":"+masked+"\r\n"...)
	}
	if p.outChunked && !p.inChunked {
		out = append(out, "Transfer-Encoding: chunked\r\n"...)
	}
	return append(out, "\r\n"...), p, nil
}

func unsafeHeader(masked, original string) bool {
	return masked != original && strings.ContainsAny(masked, "\r\n\x00")
}

// splitLines splits a head into its lines, each with its line ending; the
// last one is the empty line that ends the head.
func splitLines(head []byte) []string {
	var lines []string
	for rest := string(head); rest != ""; {
		i := strings.IndexByte(rest, '\n')
		lines = append(lines, rest[:i+1])
		rest = rest[i+1:]
	}
	return lines
}

// copyMaskedBody passes a response body on masked, decoded when it had a
// content-coding, and framed as plan says. It stops with an error, which
// ends the connection, when the body cannot be decoded or decodes past
// maxDecoded: the client then gets a truncated response, never unmasked
// bytes.
func copyMaskedBody(br *bufio.Reader, client io.Writer, plan maskPlan, m *mask.Masker, maxDecoded int64) error {
	var src io.Reader
	var chunks *chunkReader
	var limited *io.LimitedReader
	switch {
	case plan.inChunked:
		chunks = &chunkReader{br: br}
		src = chunks
	case plan.closeDelimited:
		src = br
	default:
		limited = &io.LimitedReader{R: br, N: plan.length}
		src = limited
	}
	decoded, err := mask.Decoder(plan.decode, src, maxDecoded)
	if err != nil {
		return fmt.Errorf("decoding a response to mask it: %w", err)
	}
	defer decoded.Close()
	if plan.decode == "" {
		decoded = io.NopCloser(src) // identity bodies are not capped
	}
	sink := client
	if plan.outChunked {
		sink = chunkWriter{w: client}
	}
	w := m.NewWriter(sink, plan.context)
	buf := make([]byte, 32<<10)
	if _, err := io.CopyBuffer(w, decoded, buf); err != nil {
		return fmt.Errorf("masking a response: %w", err)
	}
	// A compressed stream can end before the HTTP body does (a zlib
	// checksum before the zero chunk and its trailers): the response ends
	// with its framing, never with the decoder. Bytes after the end of the
	// compressed stream are not content and are dropped.
	if _, err := io.CopyBuffer(io.Discard, src, buf); err != nil {
		return fmt.Errorf("reading a response to its end: %w", err)
	}
	if limited != nil && limited.N > 0 {
		return io.ErrUnexpectedEOF
	}
	if err := w.Close(); err != nil {
		return err
	}
	if !plan.outChunked {
		return nil
	}
	end := []byte("0\r\n")
	if chunks != nil {
		for _, line := range chunks.trailers {
			raw := strings.TrimRight(line, "\r\n")
			if raw != "" && (raw[0] == ' ' || raw[0] == '\t') {
				return fmt.Errorf("%w: a folded trailer line", errUnmaskable)
			}
			name, value, ok := strings.Cut(raw, ":")
			if !ok {
				return fmt.Errorf("%w: a trailer line without a colon", errUnmaskable)
			}
			masked := m.String(mask.HeaderContext(strings.TrimSpace(name)), value)
			if unsafeHeader(masked, value) {
				return fmt.Errorf("%w: a stand-in cannot go into a trailer", errUnmaskable)
			}
			end = append(end, name+":"+masked+"\r\n"...)
		}
	}
	_, err = client.Write(append(end, "\r\n"...))
	return err
}

// chunkWriter writes each Write as one chunk.
type chunkWriter struct{ w io.Writer }

func (c chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b := make([]byte, 0, len(p)+16)
	b = strconv.AppendInt(b, int64(len(p)), 16)
	b = append(b, "\r\n"...)
	b = append(b, p...)
	b = append(b, "\r\n"...)
	if _, err := c.w.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

// chunkReader reads the data of a chunked body and keeps its trailers.
type chunkReader struct {
	br       *bufio.Reader
	left     int64
	started  bool
	done     bool
	trailers []string // raw lines, each with its line ending
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	for c.left == 0 {
		if c.started {
			crlf, err := readRawLine(c.br, 2)
			if err != nil || strings.TrimRight(string(crlf), "\r\n") != "" {
				return 0, errors.New("missing CRLF after a chunk in a response")
			}
		}
		c.started = true
		line, err := readRawLine(c.br, maxChunkLine)
		if err != nil {
			return 0, err
		}
		sizeText, _, _ := strings.Cut(strings.TrimRight(string(line), "\r\n"), ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil || size < 0 {
			return 0, errors.New("invalid chunk size in a response")
		}
		if size == 0 {
			total := 0
			for {
				trailer, err := readRawLine(c.br, maxHeadBytes-total)
				if err != nil {
					return 0, err
				}
				total += len(trailer)
				if strings.TrimRight(string(trailer), "\r\n") == "" {
					c.done = true
					return 0, io.EOF
				}
				c.trailers = append(c.trailers, string(trailer))
			}
		}
		c.left = size
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.br.Read(p)
	c.left -= int64(n)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
