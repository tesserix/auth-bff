package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"time"
)

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpWindow = 1 // allow +-1 time step
)

// GenerateTOTPSecret generates a random base32-encoded TOTP secret.
func GenerateTOTPSecret(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: failed to read random bytes: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// BuildTOTPURI returns an otpauth:// URI suitable for QR code generation.
func BuildTOTPURI(secret, email, issuer string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(email)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", "30")
	return "otpauth://totp/" + label + "?" + params.Encode()
}

// ValidateTOTP checks a 6-digit TOTP code against a base32-encoded shared secret.
// Allows +-1 time step (30s window) to account for clock drift.
func ValidateTOTP(secret, code string) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	for offset := -totpWindow; offset <= totpWindow; offset++ {
		t := (now / totpPeriod) + int64(offset)
		expected := generateTOTPCode(key, t)
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
