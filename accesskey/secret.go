package accesskey

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"strings"
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ErrMalformed identifies an invalid secret or subject without exposing its value.
var ErrMalformed = errors.New("accesskey: malformed credential")

// Secret is transient credential material. Persist only its Hash and Hint.
// Its zero value contains no credential.
type Secret struct {
	raw       string
	prefixLen int
}

// Generate creates a secret using 32 bytes from entropy, or crypto/rand when nil.
func Generate(prefix string, entropy io.Reader) (Secret, error) {
	if !validPrefix(prefix) {
		return Secret{}, ErrMalformed
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	var random [32]byte
	if _, err := io.ReadFull(entropy, random[:]); err != nil {
		return Secret{}, fmt.Errorf("accesskey: generate secret: %w", err)
	}
	var n big.Int
	body := "apk_" + prefix + "_" + base62(n.SetBytes(random[:]), 43)
	return Secret{raw: body + "_" + checksum(body), prefixLen: len(prefix)}, nil
}

// Parse validates the prefix, fixed-width base62 random part, and CRC32 checksum.
func Parse(raw string) (Secret, error) {
	if !IsSecret(raw) {
		return Secret{}, ErrMalformed
	}
	prefix, rest, _ := strings.Cut(raw[4:], "_")
	random, crc, _ := strings.Cut(rest, "_")
	if !validPrefix(prefix) || len(random) != 43 || len(crc) != 6 {
		return Secret{}, ErrMalformed
	}
	for i := range len(random) {
		if !strings.ContainsRune(base62Alphabet, rune(random[i])) {
			return Secret{}, ErrMalformed
		}
	}
	if checksum(raw[:len(raw)-7]) != crc {
		return Secret{}, ErrMalformed
	}
	return Secret{raw: raw, prefixLen: len(prefix)}, nil
}

// IsSecret only classifies the marker and number of segments; it is not validation.
func IsSecret(raw string) bool {
	return strings.HasPrefix(raw, "apk_") && strings.Count(raw, "_") == 3
}

func (s Secret) String() string { return s.raw }
func (s Secret) Hash() Hash     { return HashOf(s.raw) }

func (s Secret) Prefix() string {
	if s.raw == "" {
		return ""
	}
	return s.raw[4 : 4+s.prefixLen]
}

func (s Secret) Hint() string {
	if s.raw == "" {
		return ""
	}
	return s.raw[:5+s.prefixLen+4] + "…" + s.raw[len(s.raw)-4:]
}

func validPrefix(prefix string) bool {
	if len(prefix) < 3 || len(prefix) > 6 {
		return false
	}
	for i := range len(prefix) {
		c := prefix[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func checksum(body string) string {
	var n big.Int
	return base62(n.SetUint64(uint64(crc32.ChecksumIEEE([]byte(body)))), 6)
}

// base62 consumes n and left-pads to width. Go's big.Int.Text(62) uses a
// different alphabet, so division is explicit here.
func base62(n *big.Int, width int) string {
	var remainder big.Int
	radix := big.NewInt(62)
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		n.QuoRem(n, radix, &remainder)
		out[i] = base62Alphabet[remainder.Int64()]
	}
	return string(out)
}
