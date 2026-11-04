package mask

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

// A body cut off in transit must not decode as complete content, or the
// relay would send the client a shortened body as if it were whole.
// Incompressible content makes the cut fall inside the coded data, where
// brotli before v1.2.0 stopped without an error.
func TestDecoderRefusesTruncatedContent(t *testing.T) {
	data := make([]byte, 20000)
	rand.New(rand.NewSource(1)).Read(data)
	for _, e := range []Encoding{"gzip", "deflate", "raw-deflate", "br", "zstd"} {
		t.Run(string(e), func(t *testing.T) {
			name := e
			if e == "raw-deflate" {
				name = "deflate"
			}
			encoded := encode(t, e, data)
			r, err := Decoder(name, bytes.NewReader(encoded[:len(encoded)/2]), int64(len(data)))
			if err != nil {
				return // refused before reading
			}
			if got, err := io.ReadAll(r); err == nil {
				t.Fatalf("decoded %d of %d bytes without an error", len(got), len(data))
			}
		})
	}
}
