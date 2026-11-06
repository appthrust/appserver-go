package accesskey

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// Hash is the persisted SHA-256 digest, encoded as "sha256:<standard base64>".
type Hash string

func HashOf(raw string) Hash {
	sum := sha256.Sum256([]byte(raw))
	return Hash("sha256:" + base64.StdEncoding.EncodeToString(sum[:]))
}

// Equal compares equal-length hashes in constant time. Hash lengths are public.
func (h Hash) Equal(other Hash) bool {
	return subtle.ConstantTimeCompare([]byte(h), []byte(other)) == 1
}
