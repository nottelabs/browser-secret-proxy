package main

import (
	"testing"
	"time"
)

// The SHA-1 test vectors of RFC 6238, appendix B.
func TestHOTPMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := hotp(secret, totpCounter(time.Unix(tc.unix, 0)), 8); got != tc.want {
			t.Errorf("T=%d: got %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestTOTPMatchesAdjacentSteps(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111111, 0)
	for _, offset := range []time.Duration{-totpStep, 0, totpStep} {
		if code := totp(secret, at.Add(offset)); !totpMatches(secret, code, at, at) {
			t.Errorf("the code %v away does not match", offset)
		}
	}
	if code := totp(secret, at.Add(2*totpStep)); totpMatches(secret, code, at, at) {
		t.Error("a code two steps away matches")
	}
}
