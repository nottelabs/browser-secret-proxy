package main

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238's default algorithm, what authenticator apps use.
	"encoding/binary"
	"fmt"
	"time"
)

// totpStep is the RFC 6238 time step.
const totpStep = 30 * time.Second

// totpCounter returns the RFC 6238 time step counter of t.
func totpCounter(t time.Time) uint64 {
	return uint64(t.Unix() / int64(totpStep/time.Second))
}

// hotp returns the RFC 4226 one-time password of counter with HMAC-SHA1.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// totp returns the 6-digit RFC 6238 code of secret at t.
func totp(secret []byte, t time.Time) string {
	return hotp(secret, totpCounter(t), 6)
}

// totpMatches reports whether code is the code of a time step from the one
// before from to the one after to, so a request that crossed a step
// boundary, or ran on a clock slightly off, still matches.
func totpMatches(secret []byte, code string, from, to time.Time) bool {
	for c := totpCounter(from) - 1; c <= totpCounter(to)+1; c++ {
		if hmac.Equal([]byte(hotp(secret, c, 6)), []byte(code)) {
			return true
		}
	}
	return false
}
