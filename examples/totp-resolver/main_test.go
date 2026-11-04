package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The seeds of RFC 6238 Appendix B, one per hash.
var rfcSeeds = map[string]string{
	"SHA1":   "12345678901234567890",
	"SHA256": "12345678901234567890123456789012",
	"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
}

func b32(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }

// TestCodeMatchesRFC6238 checks every test vector of RFC 6238 Appendix B
// (8 digits, 30-second steps).
func TestCodeMatchesRFC6238(t *testing.T) {
	vectors := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		for algorithm, want := range map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512} {
			s, err := newSeed(seedEntry{Secret: b32(rfcSeeds[algorithm]), Hosts: []string{"login.test"}, Digits: 8, Algorithm: algorithm})
			if err != nil {
				t.Fatal(err)
			}
			got, end := s.code(time.Unix(v.unix, 0))
			if got != want {
				t.Errorf("%s at %d: got %s, want %s", algorithm, v.unix, got, want)
			}
			if wantEnd := (v.unix/30 + 1) * 30; end.Unix() != wantEnd {
				t.Errorf("%s at %d: step ends at %d, want %d", algorithm, v.unix, end.Unix(), wantEnd)
			}
		}
	}
}

func TestSixDigitCodesKeepLeadingZeros(t *testing.T) {
	s, err := newSeed(seedEntry{Secret: b32(rfcSeeds["SHA1"]), Hosts: []string{"login.test"}})
	if err != nil {
		t.Fatal(err)
	}
	// 07081804 at 1111111109: the 6-digit code is its last six digits.
	if got, _ := s.code(time.Unix(1111111109, 0)); got != "081804" {
		t.Fatalf("got %s, want 081804", got)
	}
}

func TestSecretFormats(t *testing.T) {
	want, _ := mustSeed(t, b32(rfcSeeds["SHA1"])).code(time.Unix(59, 0))
	// Lower case, spaces and no padding, as authenticator setup pages show it.
	spaced := strings.ToLower(strings.TrimRight(b32(rfcSeeds["SHA1"]), "="))
	spaced = spaced[:4] + " " + spaced[4:8] + " " + spaced[8:]
	if got, _ := mustSeed(t, spaced).code(time.Unix(59, 0)); got != want {
		t.Fatalf("spaced lower-case secret: got %s, want %s", got, want)
	}
}

func mustSeed(t *testing.T, secret string) *seed {
	t.Helper()
	s, err := newSeed(seedEntry{Secret: secret, Hosts: []string{"login.test"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadSeedsRefusesBadEntries(t *testing.T) {
	cases := map[string]string{
		"no hosts":      `{"totp_a": {"secret": "GEZDGNBV"}}`,
		"bad secret":    `{"totp_a": {"secret": "not base32!", "hosts": ["login.test"]}}`,
		"empty secret":  `{"totp_a": {"secret": "", "hosts": ["login.test"]}}`,
		"digits":        `{"totp_a": {"secret": "GEZDGNBV", "hosts": ["login.test"], "digits": 4}}`,
		"period":        `{"totp_a": {"secret": "GEZDGNBV", "hosts": ["login.test"], "period": -5}}`,
		"algorithm":     `{"totp_a": {"secret": "GEZDGNBV", "hosts": ["login.test"], "algorithm": "MD5"}}`,
		"host with URL": `{"totp_a": {"secret": "GEZDGNBV", "hosts": ["https://login.test"]}}`,
		"unknown field": `{"totp_a": {"secret": "GEZDGNBV", "host": ["login.test"]}}`,
		"empty":         `{}`,
		"not JSON":      `nope`,
	}
	for name, data := range cases {
		_, err := loadSeeds([]byte(data))
		if err == nil {
			t.Errorf("%s: loaded", name)
			continue
		}
		if strings.Contains(err.Error(), "GEZDGNBV") {
			t.Errorf("%s: the error quotes the seed: %v", name, err)
		}
	}
}

type detokenizeAnswer struct {
	Values map[string]struct {
		Real      *string   `json:"real"`
		Hosts     []string  `json:"hosts"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"values"`
}

func call(t *testing.T, h http.Handler, body string) (int, detokenizeAnswer) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/detokenize", strings.NewReader(body)))
	var answer detokenizeAnswer
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, answer
}

func TestHandlerAnswersTheResolverAPI(t *testing.T) {
	seeds, err := loadSeeds([]byte(fmt.Sprintf(`{
		"totp_admin": {"secret": %q, "hosts": ["login.test"], "principals": ["proxy-user"], "digits": 8},
		"totp_any": {"secret": %q, "hosts": ["*.example.test"]}
	}`, b32(rfcSeeds["SHA1"]), b32(rfcSeeds["SHA1"]))))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1111111111, 0)
	h := handler(seeds, func() time.Time { return now })

	status, answer := call(t, h, `{"stand_ins": ["totp_admin", "totp_any", "totp_unknown"], "host": "login.test", "principal_id": "proxy-user"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	admin, ok := answer.Values["totp_admin"]
	if !ok || admin.Real == nil || *admin.Real != "14050471" {
		t.Fatalf("totp_admin: %+v", answer.Values)
	}
	if len(admin.Hosts) != 1 || admin.Hosts[0] != "login.test" {
		t.Fatalf("totp_admin hosts %v", admin.Hosts)
	}
	if want := time.Unix(1111111140, 0); !admin.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at %v, want %v", admin.ExpiresAt, want)
	}
	if _, ok := answer.Values["totp_any"]; ok {
		t.Fatal("totp_any was answered for a host outside its list")
	}
	if _, ok := answer.Values["totp_unknown"]; ok {
		t.Fatal("an unknown stand-in was answered")
	}

	// Another principal gets nothing for totp_admin.
	_, answer = call(t, h, `{"stand_ins": ["totp_admin"], "host": "login.test", "principal_id": "someone-else"}`)
	if len(answer.Values) != 0 {
		t.Fatalf("another principal got %v", answer.Values)
	}
	// Wildcard hosts match names below the domain, not the domain itself.
	_, answer = call(t, h, `{"stand_ins": ["totp_any"], "host": "auth.example.test", "principal_id": ""}`)
	if _, ok := answer.Values["totp_any"]; !ok {
		t.Fatal("totp_any was not answered for a host below its wildcard")
	}
	_, answer = call(t, h, `{"stand_ins": ["totp_any"], "host": "example.test", "principal_id": ""}`)
	if len(answer.Values) != 0 {
		t.Fatal("totp_any was answered for the wildcard's own domain")
	}
	// A host that only ends like an allowed one is not allowed.
	_, answer = call(t, h, `{"stand_ins": ["totp_admin"], "host": "evillogin.test", "principal_id": "proxy-user"}`)
	if len(answer.Values) != 0 {
		t.Fatal("totp_admin was answered for another host")
	}

	if status, _ := call(t, h, `nope`); status != http.StatusBadRequest {
		t.Fatalf("malformed request: status %d", status)
	}
}

func TestRequireName(t *testing.T) {
	check := requireName("browser-secret-proxy")
	state := func(cn string, dns ...string) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}}}
	}
	if err := check(state("browser-secret-proxy")); err != nil {
		t.Fatalf("common name: %v", err)
	}
	if err := check(state("other", "browser-secret-proxy")); err != nil {
		t.Fatalf("DNS name: %v", err)
	}
	if err := check(state("other", "other.test")); err == nil {
		t.Fatal("another client was accepted")
	}
	if err := check(tls.ConnectionState{}); err == nil {
		t.Fatal("no certificate was accepted")
	}
}

func TestAllowsIgnoresTrailingDotsAndCase(t *testing.T) {
	s := &seed{hosts: []string{"Login.Example.com.", "*.auth.example.com."}}
	for _, host := range []string{"login.example.com", "login.example.com.", "LOGIN.example.com", "eu.auth.example.com", "eu.auth.example.com."} {
		if !s.allows(host, "") {
			t.Errorf("allows(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"example.com", "auth.example.com", "login.example.com.evil.test"} {
		if s.allows(host, "") {
			t.Errorf("allows(%q) = true, want false", host)
		}
	}
}
