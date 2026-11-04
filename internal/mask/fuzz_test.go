package mask

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

var fuzzEncodings = []Encoding{"", "gzip", "deflate", "raw-deflate", "br", "zstd"}

// FuzzDecoder decodes arbitrary content with each coding: it must not
// panic or hang, and never yields more than the limit.
func FuzzDecoder(f *testing.F) {
	for i, e := range fuzzEncodings {
		if e != "" {
			f.Add(uint8(i), encode(f, e, []byte("hello "+card)), uint16(64))
		}
	}
	f.Add(uint8(0), []byte("plain"), uint16(3))
	f.Add(uint8(4), []byte{0xce, 0xb2, 0xcf, 0x81}, uint16(1000))
	f.Fuzz(func(t *testing.T, enc uint8, data []byte, limit uint16) {
		e := fuzzEncodings[int(enc)%len(fuzzEncodings)]
		if e == "raw-deflate" {
			e = "deflate"
		}
		r, err := Decoder(e, bytes.NewReader(data), int64(limit))
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()
		got, err := io.ReadAll(io.LimitReader(r, int64(limit)+1<<20))
		if len(got) > int(limit) {
			t.Fatalf("%s: %d bytes decoded past the limit %d (%v)", e, len(got), limit, err)
		}
	})
}

// FuzzDecoderRoundTrip encodes data with each coding and decodes it: the
// result is the data when it fits the limit, else ErrTooLarge, with no more
// than the limit passed on.
func FuzzDecoderRoundTrip(f *testing.F) {
	for i := range fuzzEncodings {
		f.Add(uint8(i), []byte("hello "+card+" "+token), uint16(100))
		f.Add(uint8(i), []byte(""), uint16(0))
		f.Add(uint8(i), bytes.Repeat([]byte("ab"), 300), uint16(599))
	}
	f.Fuzz(func(t *testing.T, enc uint8, data []byte, limit uint16) {
		e := fuzzEncodings[int(enc)%len(fuzzEncodings)]
		content := data
		name := e
		if e != "" {
			content = encode(t, e, data)
		}
		if e == "raw-deflate" {
			name = "deflate"
		}
		r, err := Decoder(name, bytes.NewReader(content), int64(limit))
		if err != nil {
			t.Fatalf("%s: %v", e, err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		switch {
		case len(data) <= int(limit):
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s: %d bytes decoded to %d, %v", e, len(data), len(got), err)
			}
		case !errors.Is(err, ErrTooLarge):
			t.Fatalf("%s: %d bytes over the limit %d decoded with %v", e, len(data), limit, err)
		case len(got) > int(limit) || !bytes.HasPrefix(data, got):
			t.Fatalf("%s: passed on %d bytes over the limit %d", e, len(got), limit)
		}
	})
}

// FuzzParseEncoding checks that a Content-Encoding is read as no coding,
// one coding this package decodes, or ErrUnsupportedEncoding.
func FuzzParseEncoding(f *testing.F) {
	for _, s := range []string{"", "gzip", " GZip ", "x-gzip", "identity, br", "gzip, br", "gzip\ngzip", "compress", ",,zstd,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEncoding(strings.Split(s, "\n"))
		if err != nil {
			if !errors.Is(err, ErrUnsupportedEncoding) || e != "" {
				t.Fatalf("ParseEncoding(%q) = %q, %v", s, e, err)
			}
			return
		}
		switch e {
		case "", "gzip", "deflate", "br", "zstd":
		default:
			t.Fatalf("ParseEncoding(%q) = %q", s, e)
		}
		if _, err := Decoder(e, strings.NewReader(""), 0); err != nil {
			t.Fatalf("ParseEncoding(%q) = %q, which Decoder refuses: %v", s, e, err)
		}
	})
}
