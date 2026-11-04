package scope

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nottelabs/browser-secret-proxy/internal/hostmatch"
	"github.com/nottelabs/browser-secret-proxy/internal/mask"
	"github.com/nottelabs/browser-secret-proxy/internal/resolve"
	"github.com/nottelabs/browser-secret-proxy/internal/swap"
)

// sealedScope is a masking Scope over a sealed resolver, and a function
// that seals one value for it.
func sealedScope(t *testing.T) (*Scope, *resolve.Sealed, func(sub, standIn, real string) string) {
	t.Helper()
	proxyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := resolve.NewSealed(resolve.SealedConfig{Keys: []crypto.PrivateKey{proxyKey}, IssuerKeys: []crypto.PublicKey{issuerKey}, Audience: "proxy-1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sealed.Close)
	hosts, _ := hostmatch.New([]string{"api.example.com"})
	detector, err := resolve.NewDetector(sealed, resolve.Patterns{})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := New(Config{Resolver: sealed, Detector: detector, Hosts: hosts, Mask: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	seal := func(sub, standIn, real string) string {
		t.Helper()
		token, err := resolve.Seal(&proxyKey.PublicKey, issuer, resolve.SealedPayload{
			Values: map[string]string{standIn: real}, Aud: jwt.Audience{"proxy-1"}, Exp: time.Now().Add(time.Hour).Unix(), Sub: sub,
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	return sc, sealed, seal
}

// A sealed token without sub is one principal whatever username the client
// gives with it: a value looked up on a connection as "a" is masked on a
// connection as "b".
func TestSealedTokenIsOnePrincipalWhateverTheUsername(t *testing.T) {
	sc, sealed, seal := sealedScope(t)
	token := seal("", "tok_standin_123", "sk_live_real_api_token")
	pa, err := sealed.Authenticate("a", token)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := sealed.Authenticate("b", token)
	if err != nil {
		t.Fatal(err)
	}
	a, b := sc.Session(pa, "api.example.com"), sc.Session(pb, "api.example.com")
	if _, err := a.Values(context.Background(), swap.Part{Text: "tok_standin_123"}); err != nil {
		t.Fatal(err)
	}
	if got := b.Masker().String(mask.Text, "echo sk_live_real_api_token"); got != "echo tok_standin_123" {
		t.Fatalf("looked up as %q, masked as %q on a connection as %q", pa.ID, got, pb.ID)
	}
}

// One token holder cannot push other principals off the record by opening
// MaxPrincipals connections under as many usernames: they are all one
// principal, so the other principals' values stay masked.
func TestOneSealedTokenCannotEvictOtherPrincipals(t *testing.T) {
	sc, sealed, seal := sealedScope(t)
	victim, err := sealed.Authenticate("victim", seal("victim", "tok_victim", "victim_real_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Session(victim, "api.example.com").Values(context.Background(), swap.Part{Text: "tok_victim"}); err != nil {
		t.Fatal(err)
	}
	attackerToken := seal("", "tok_attacker", "attacker_real_secret")
	for i := range MaxPrincipals {
		attacker, err := sealed.Authenticate("u"+itoa(i), attackerToken)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Session(attacker, "api.example.com").Values(context.Background(), swap.Part{Text: "tok_attacker"}); err != nil {
			t.Fatal(err)
		}
	}
	sc.record.mu.Lock()
	principals := len(sc.record.principals)
	sc.record.mu.Unlock()
	if principals != 2 {
		t.Errorf("%d principals on record, want the victim and the token holder", principals)
	}
	if got := sc.Session(victim, "api.example.com").Masker().String(mask.Text, "key=victim_real_secret"); got != "key=tok_victim" {
		t.Fatalf("after %d usernames on one token, the victim's value is masked to %q", MaxPrincipals, got)
	}
}
