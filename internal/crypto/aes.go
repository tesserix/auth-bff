package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// EncryptAESGCM encrypts plaintext using AES-256-GCM.
// Returns format: "iv_hex:authTag_hex:ciphertext_hex" for TypeScript compatibility.
func EncryptAESGCM(plaintext []byte, keyHex string) (string, error) {
	key, err := deriveKey(keyHex)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, aead.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("random nonce: %w", err)
	}

	// GCM appends the auth tag to the ciphertext
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	// Split ciphertext and auth tag (last 16 bytes)
	tagSize := aead.Overhead() // 16 bytes
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]

	return fmt.Sprintf("%s:%s:%s",
		hex.EncodeToString(nonce),
		hex.EncodeToString(authTag),
		hex.EncodeToString(ciphertext),
	), nil
}

// DecryptAESGCM decrypts ciphertext encrypted by EncryptAESGCM.
// Expects format: "iv_hex:authTag_hex:ciphertext_hex".
func DecryptAESGCM(encrypted string, keyHex string) ([]byte, error) {
	parts := strings.SplitN(encrypted, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid encrypted format: expected iv:tag:ciphertext")
	}

	nonce, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	authTag, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode auth tag: %w", err)
	}

	ciphertext, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key, err := deriveKey(keyHex)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	// Recombine ciphertext + auth tag as GCM expects
	sealed := append(ciphertext, authTag...)

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// deriveKey produces a 32-byte AES key from the hex input.
// If the key is already 64 hex chars (32 bytes), use directly.
// Otherwise, use HMAC-SHA256 to derive a 32-byte key.
func deriveKey(keyHex string) ([]byte, error) {
	if len(keyHex) == 64 {
		return hex.DecodeString(keyHex)
	}
	// Derive via HMAC-SHA256 for shorter keys
	h := hmac.New(sha256.New, []byte(keyHex))
	h.Write([]byte("aes-key-derivation"))
	return h.Sum(nil), nil
}
