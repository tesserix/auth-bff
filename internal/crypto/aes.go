package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// EncryptAESGCM encrypts plaintext using AES-256-GCM with gzip compression.
// Returns format: "v2.<base64url(nonce + ciphertext + tag)>" — compact enough
// for browser cookies (4 KB limit). The "v2." prefix distinguishes this from
// the legacy hex format so DecryptAESGCM can handle both transparently.
func EncryptAESGCM(plaintext []byte, keyHex string) (string, error) {
	// Compress plaintext to reduce cookie size
	compressed, err := gzipCompress(plaintext)
	if err != nil {
		return "", fmt.Errorf("compress: %w", err)
	}

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

	// GCM Seal: nonce is NOT prepended automatically; sealed = ciphertext || tag
	sealed := aead.Seal(nil, nonce, compressed, nil)

	// Pack as: nonce || sealed (ciphertext || tag)
	raw := append(nonce, sealed...)

	return "v2." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecryptAESGCM decrypts ciphertext produced by EncryptAESGCM.
// Accepts both the new v2 format and the legacy hex format for backward
// compatibility during rolling deployments.
func DecryptAESGCM(encrypted string, keyHex string) ([]byte, error) {
	if strings.HasPrefix(encrypted, "v2.") {
		return decryptV2(encrypted[3:], keyHex)
	}
	return decryptLegacyHex(encrypted, keyHex)
}

// decryptV2 handles the compact base64url + gzip format.
func decryptV2(encoded string, keyHex string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
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

	nonceSize := aead.NonceSize()
	if len(raw) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := raw[:nonceSize]
	sealed := raw[nonceSize:]

	compressed, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	plaintext, err := gzipDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	return plaintext, nil
}

// decryptLegacyHex handles the old "iv_hex:authTag_hex:ciphertext_hex" format.
func decryptLegacyHex(encrypted string, keyHex string) ([]byte, error) {
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

// EncryptAESGCMLegacyHex encrypts using the old hex format (for tests only).
func EncryptAESGCMLegacyHex(plaintext []byte, keyHex string) (string, error) {
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
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("random nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	tagSize := aead.Overhead()
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]
	return fmt.Sprintf("%s:%s:%s", hex.EncodeToString(nonce), hex.EncodeToString(tag), hex.EncodeToString(ct)), nil
}

// gzipCompress compresses data using gzip.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gzipDecompress decompresses gzip data.
func gzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
