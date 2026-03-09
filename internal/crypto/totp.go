package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpWindow = 1 // allow +-1 time step
)

// ValidateTOTP checks a 6-digit TOTP code against a shared secret.
// Allows +-1 time step (30s window) to account for clock drift.
func ValidateTOTP(secret, code string) bool {
	now := time.Now().Unix()
	for offset := -totpWindow; offset <= totpWindow; offset++ {
		t := (now / totpPeriod) + int64(offset)
		expected := generateTOTPCode([]byte(secret), t)
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// generateTOTPCode produces a 6-digit HOTP code per RFC 4226.
func generateTOTPCode(secret []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	h := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 section 5.4)
	offset := h[len(h)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff

	otp := truncated % uint32(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, otp)
}
