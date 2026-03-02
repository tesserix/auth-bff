package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const (
	backupCodeLength = 8
	backupCodeChars  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // No 0, O, 1, I for readability
)

// GenerateBackupCodes creates n random backup codes and returns
// both the plaintext codes (formatted as XXXX-XXXX) and their HMAC hashes.
func GenerateBackupCodes(n int, hmacKey string) (codes []string, hashes []string, err error) {
	codes = make([]string, n)
	hashes = make([]string, n)

	for i := 0; i < n; i++ {
		code, err := generateRandomCode(backupCodeLength)
		if err != nil {
			return nil, nil, fmt.Errorf("generate code: %w", err)
		}
		formatted := fmt.Sprintf("%s-%s", code[:4], code[4:])
		codes[i] = formatted
		hashes[i] = HMACCode(normalizeCode(code), hmacKey)
	}

	return codes, hashes, nil
}

// HMACCode produces an HMAC-SHA256 hex digest for a backup code.
func HMACCode(code, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyBackupCode checks if a code matches any of the provided hashes.
// Returns the index of the matching hash, or -1 if no match.
func VerifyBackupCode(code string, hashes []string, hmacKey string) int {
	normalized := normalizeCode(code)
	hash := HMACCode(normalized, hmacKey)
	for i, h := range hashes {
		if hmac.Equal([]byte(hash), []byte(h)) {
			return i
		}
	}
	return -1
}

// normalizeCode removes dashes and converts to uppercase for consistent hashing.
func normalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

func generateRandomCode(length int) (string, error) {
	result := make([]byte, length)
	max := big.NewInt(int64(len(backupCodeChars)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = backupCodeChars[n.Int64()]
	}
	return string(result), nil
}
