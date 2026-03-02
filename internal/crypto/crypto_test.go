package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	// 64-char hex key = 32 bytes
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple text", "hello world"},
		{"empty", ""},
		{"long text", strings.Repeat("abcdefghij", 100)},
		{"unicode", "こんにちは世界"},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"totp secret", "JBSWY3DPEHPK3PXP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptAESGCM([]byte(tt.plaintext), key)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			// Verify format: iv:tag:ciphertext
			parts := strings.SplitN(encrypted, ":", 3)
			if len(parts) != 3 {
				t.Fatalf("expected 3 parts, got %d", len(parts))
			}

			// IV should be 24 hex chars (12 bytes)
			if len(parts[0]) != 24 {
				t.Errorf("IV length = %d hex chars, want 24", len(parts[0]))
			}

			// Auth tag should be 32 hex chars (16 bytes)
			if len(parts[1]) != 32 {
				t.Errorf("auth tag length = %d hex chars, want 32", len(parts[1]))
			}

			// Decrypt
			decrypted, err := DecryptAESGCM(encrypted, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(decrypted) != tt.plaintext {
				t.Errorf("decrypted = %q, want %q", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestEncryptDecrypt_ShortKey(t *testing.T) {
	// Short key — will be derived via HMAC
	key := "my-short-encryption-key"
	plaintext := "test data"

	encrypted, err := EncryptAESGCM([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("Encrypt with short key: %v", err)
	}

	decrypted, err := DecryptAESGCM(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt with short key: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("got %q, want %q", string(decrypted), plaintext)
	}
}

func TestDecrypt_InvalidFormat(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	tests := []struct {
		name      string
		encrypted string
	}{
		{"no colons", "invaliddata"},
		{"one colon", "part1:part2"},
		{"invalid hex iv", "zzzzzzzzzzzzzzzzzzzzzzzz:00000000000000000000000000000000:00"},
		{"invalid hex tag", "000000000000000000000000:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:00"},
		{"invalid hex ct", "000000000000000000000000:00000000000000000000000000000000:zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAESGCM(tt.encrypted, key)
			if err == nil {
				t.Error("expected error for invalid format")
			}
		})
	}
}

func TestEncrypt_DifferentCiphertextEachTime(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	plaintext := "same input"

	enc1, _ := EncryptAESGCM([]byte(plaintext), key)
	enc2, _ := EncryptAESGCM([]byte(plaintext), key)

	if enc1 == enc2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (random IV)")
	}

	// But both should decrypt to the same thing
	dec1, _ := DecryptAESGCM(enc1, key)
	dec2, _ := DecryptAESGCM(enc2, key)
	if string(dec1) != string(dec2) {
		t.Error("both should decrypt to the same plaintext")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	encrypted, _ := EncryptAESGCM([]byte("secret"), key1)

	_, err := DecryptAESGCM(encrypted, key2)
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name    string
		keyHex  string
		wantLen int
	}{
		{"exact 32 bytes", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 32},
		{"short key", "shortkey", 32},
		{"medium key", "medium-encryption-key-here", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := deriveKey(tt.keyHex)
			if err != nil {
				t.Fatalf("deriveKey: %v", err)
			}
			if len(key) != tt.wantLen {
				t.Errorf("key length = %d, want %d", len(key), tt.wantLen)
			}
		})
	}
}

// Backup code tests

func TestGenerateBackupCodes(t *testing.T) {
	hmacKey := "test-hmac-key"

	codes, hashes, err := GenerateBackupCodes(10, hmacKey)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("got %d codes, want 10", len(codes))
	}
	if len(hashes) != 10 {
		t.Errorf("got %d hashes, want 10", len(hashes))
	}

	// Codes should be formatted as XXXX-XXXX
	for i, code := range codes {
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("code[%d] = %q, expected XXXX-XXXX format", i, code)
		}
	}

	// Hashes should be hex strings
	for i, hash := range hashes {
		if _, err := hex.DecodeString(hash); err != nil {
			t.Errorf("hash[%d] is not valid hex: %v", i, err)
		}
	}

	// All codes should be unique
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("duplicate code: %q", code)
		}
		seen[code] = true
	}
}

func TestVerifyBackupCode(t *testing.T) {
	hmacKey := "test-hmac-key"
	codes, hashes, _ := GenerateBackupCodes(5, hmacKey)

	tests := []struct {
		name    string
		code    string
		wantIdx int
	}{
		{"valid code exact", codes[0], 0},
		{"valid code uppercase stripped", strings.ReplaceAll(codes[2], "-", ""), 2},
		{"valid code lowercase", strings.ToLower(codes[3]), 3},
		{"invalid code", "XXXX-YYYY", -1},
		{"empty code", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := VerifyBackupCode(tt.code, hashes, hmacKey)
			if idx != tt.wantIdx {
				t.Errorf("VerifyBackupCode(%q) = %d, want %d", tt.code, idx, tt.wantIdx)
			}
		})
	}
}

func TestHMACCode_Deterministic(t *testing.T) {
	key := "test-key"
	code := "ABCD1234"

	h1 := HMACCode(code, key)
	h2 := HMACCode(code, key)

	if h1 != h2 {
		t.Error("HMAC should be deterministic")
	}

	// Different code = different hash
	h3 := HMACCode("DIFFERENT", key)
	if h1 == h3 {
		t.Error("different codes should produce different hashes")
	}

	// Different key = different hash
	h4 := HMACCode(code, "different-key")
	if h1 == h4 {
		t.Error("different keys should produce different hashes")
	}
}
