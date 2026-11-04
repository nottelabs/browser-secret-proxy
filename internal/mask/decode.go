package mask

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// ErrUnsupportedEncoding is a Content-Encoding that cannot be decoded, so
// the content cannot be masked.
var ErrUnsupportedEncoding = errors.New("unsupported content encoding")

// ErrTooLarge is decoded content longer than its limit.
var ErrTooLarge = errors.New("decoded content is larger than the limit")

// DefaultMaxDecoded caps the decoded size of one compressed response that
// is masked, unless a relay sets its own limit.
const DefaultMaxDecoded = 64 << 20

// zstdWindow caps the window a zstd stream may ask for. RFC 9659 lets HTTP
// recipients refuse windows above 8 MiB.
const zstdWindow = 8 << 20

// Encoding is a parsed Content-Encoding header.
type Encoding string

// ParseEncoding reads the Content-Encoding values of a response. It returns
// "" for none or identity, the coding for a single one this package decodes
// (gzip, deflate, br, zstd), and ErrUnsupportedEncoding for anything else,
// several codings included. The error never quotes a coding: a destination
// can echo a real value into the header, and the error is logged.
func ParseEncoding(values []string) (Encoding, error) {
	var codings []string
	for _, v := range values {
		for _, c := range strings.Split(v, ",") {
			c = strings.ToLower(strings.TrimSpace(c))
			if c != "" && c != "identity" {
				codings = append(codings, c)
			}
		}
	}
	switch {
	case len(codings) == 0:
		return "", nil
	case len(codings) > 1:
		return "", fmt.Errorf("%w: %d codings", ErrUnsupportedEncoding, len(codings))
	}
	switch codings[0] {
	case "gzip", "x-gzip":
		return "gzip", nil
	case "deflate", "br", "zstd":
		return Encoding(codings[0]), nil
	}
	return "", fmt.Errorf("%w: an unknown coding", ErrUnsupportedEncoding)
}

// Decoder returns a reader of r decoded with e, which yields ErrTooLarge
// once more than limit bytes were decoded. Empty content decodes to nothing,
// whatever its coding.
func Decoder(e Encoding, r io.Reader, limit int64) (io.ReadCloser, error) {
	if e != "" {
		br := bufio.NewReader(r)
		if _, err := br.Peek(1); errors.Is(err, io.EOF) {
			return io.NopCloser(br), nil
		} else if err != nil {
			return nil, err
		}
		r = br
	}
	var rc io.ReadCloser
	switch e {
	case "":
		rc = io.NopCloser(r)
	case "gzip":
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		rc = z
	case "deflate":
		// "deflate" is meant to be zlib-wrapped (RFC 9110 8.4.1.2), but some
		// servers send raw DEFLATE; the zlib header tells them apart.
		br := bufio.NewReader(r)
		head, err := br.Peek(2)
		if err != nil {
			return nil, err
		}
		if (uint16(head[0])<<8|uint16(head[1]))%31 == 0 && head[0]&0x0f == 8 {
			z, err := zlib.NewReader(br)
			if err != nil {
				return nil, err
			}
			rc = z
		} else {
			rc = flate.NewReader(br)
		}
	case "br":
		rc = io.NopCloser(brotli.NewReader(r))
	case "zstd":
		z, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(zstdWindow))
		if err != nil {
			return nil, err
		}
		rc = z.IOReadCloser()
	default:
		return nil, ErrUnsupportedEncoding
	}
	return &limitedReader{rc: rc, left: limit}, nil
}

type limitedReader struct {
	rc   io.ReadCloser
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return 0, ErrTooLarge
	}
	return n, err
}

func (l *limitedReader) Close() error { return l.rc.Close() }
