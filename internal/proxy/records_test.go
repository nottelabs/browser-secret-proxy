package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"testing"
)

// keyLog collects a TLS key log, which holds secrets only for tests.
type keyLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (k *keyLog) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.buf.Write(p)
}

func (k *keyLog) secret(t *testing.T, label string) []byte {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	for line := range strings.Lines(k.buf.String()) {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == label {
			secret, err := hex.DecodeString(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return secret
		}
	}
	t.Fatalf("no %s in the key log", label)
	return nil
}

// recordSealer writes a TLS 1.3 client's records itself, so a test can send
// records crypto/tls never sends on its own, such as an empty application
// record or a KeyUpdate. Once it is used, every client record must go
// through it.
type recordSealer struct {
	w      io.Writer
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
}

// newRecordSealer takes over the writing side of conn, a TLS 1.3 client
// connection that has completed its handshake and sent no application
// records, using the traffic secret from its key log.
func newRecordSealer(t *testing.T, w io.Writer, conn *tls.Conn, log *keyLog) *recordSealer {
	t.Helper()
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %s, want TLS 1.3", tls.VersionName(state.Version))
	}
	if state.CipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		t.Skipf("negotiated %s; the test seals only TLS_AES_128_GCM_SHA256", tls.CipherSuiteName(state.CipherSuite))
	}
	s := &recordSealer{w: w}
	s.setSecret(t, log.secret(t, "CLIENT_TRAFFIC_SECRET_0"))
	return s
}

func expandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len("tls13 "+label)))
	info = append(info, "tls13 "+label...)
	info = append(info, 0) // no context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (s *recordSealer) setSecret(t *testing.T, secret []byte) {
	t.Helper()
	block, err := aes.NewCipher(expandLabel(t, secret, "key", 16))
	if err != nil {
		t.Fatal(err)
	}
	if s.aead, err = cipher.NewGCM(block); err != nil {
		t.Fatal(err)
	}
	s.secret, s.iv, s.seq = secret, expandLabel(t, secret, "iv", 12), 0
}

// seal writes one record of the given content type.
func (s *recordSealer) seal(t *testing.T, contentType byte, content []byte) {
	t.Helper()
	inner := append(append([]byte{}, content...), contentType)
	header := []byte{23, 3, 3, 0, 0} // application data, TLS 1.2 on the wire
	binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+s.aead.Overhead()))
	nonce := append([]byte{}, s.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(s.seq >> (8 * i))
	}
	s.seq++
	if _, err := s.w.Write(s.aead.Seal(header, nonce, inner, header)); err != nil {
		t.Fatal(err)
	}
}

func (s *recordSealer) writeString(t *testing.T, data string) {
	t.Helper()
	s.seal(t, 23, []byte(data))
}

// keyUpdate sends a KeyUpdate that asks for none in return, then seals
// with the next traffic secret.
func (s *recordSealer) keyUpdate(t *testing.T) {
	t.Helper()
	s.seal(t, 22, []byte{24, 0, 0, 1, 0}) // key_update, update_not_requested
	s.setSecret(t, expandLabel(t, s.secret, "traffic upd", sha256.Size))
}
