package accesskey

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSecretRoundTrip(t *testing.T) {
	for _, prefix := range []string{"abc", "knowl", "a1b2c3"} {
		t.Run(prefix, func(t *testing.T) {
			secret, err := Generate(prefix, bytes.NewReader(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(secret.String(), "_")
			if len(parts) != 4 || parts[2] != strings.Repeat("0", 43) || len(parts[3]) != 6 {
				t.Fatal("incorrect secret encoding or padding")
			}
			got, err := Parse(secret.String())
			if err != nil || got.String() != secret.String() || got.Prefix() != prefix {
				t.Fatalf("round trip failed: %v", err)
			}
			if !IsSecret(secret.String()) || !secret.Hash().Equal(HashOf(secret.String())) {
				t.Fatal("classification or hash mismatch")
			}
			if got.Hint() != "apk_"+prefix+"_0000…"+parts[3][2:] {
				t.Fatal("incorrect hint")
			}
		})
	}
}

func TestSecretBase62Alphabet(t *testing.T) {
	input := make([]byte, 32)
	input[31] = 61
	secret, err := Generate("abc", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Split(secret.String(), "_")[2] != strings.Repeat("0", 42)+"z" {
		t.Fatal("base62 must use 0-9A-Za-z order")
	}
}

func TestSecretMalformed(t *testing.T) {
	secret, err := Generate("abc", bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	raw := secret.String()
	parts := strings.Split(raw, "_")
	cases := map[string]string{
		"checksum":      raw[:len(raw)-1] + "!",
		"random tamper": "apk_abc_1" + parts[2][1:] + "_" + parts[3],
		"short random":  "apk_abc_" + parts[2][1:] + "_" + parts[3],
		"long random":   "apk_abc_0" + parts[2] + "_" + parts[3],
		"bad random":    "apk_abc_!" + parts[2][1:] + "_" + parts[3],
		"short prefix":  strings.Replace(raw, "abc", "ab", 1),
		"long prefix":   strings.Replace(raw, "abc", "abcdefg", 1),
		"upper prefix":  strings.Replace(raw, "abc", "Abc", 1),
		"bad prefix":    strings.Replace(raw, "abc", "a-c", 1),
		"extra segment": raw + "_x",
		"missing part":  strings.Join(parts[:3], "_"),
		"wrong marker":  strings.Replace(raw, "apk_", "key_", 1),
		"empty":         "",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); !errors.Is(err, ErrMalformed) {
				t.Fatalf("error = %v, want ErrMalformed", err)
			}
		})
	}
	for _, prefix := range []string{"ab", "abcdefg", "Abc", "a-c", ""} {
		if _, err := Generate(prefix, bytes.NewReader(make([]byte, 32))); !errors.Is(err, ErrMalformed) {
			t.Fatalf("invalid prefix error = %v", err)
		}
	}
	if _, err := Generate("abc", bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("short entropy error = %v", err)
	}
}

func TestIsSecretOnlyClassifiesShape(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"apk_x_bad_bad", true},
		{"apk___", true},
		{"apk_x_bad", false},
		{"apk_x_bad_bad_extra", false},
		{"other_x_bad_bad", false},
		{"", false},
	} {
		if got := IsSecret(tc.raw); got != tc.want {
			t.Errorf("IsSecret shape = %v, want %v", got, tc.want)
		}
	}
}

func TestHash(t *testing.T) {
	const want Hash = "sha256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
	if got := HashOf("abc"); got != want {
		t.Fatalf("hash format = %q, want %q", got, want)
	}
	for _, tc := range []struct {
		a, b Hash
		want bool
	}{
		{want, want, true},
		{want, HashOf("abd"), false},
		{want, "", false},
		{want, want + "x", false},
		{"", "", true},
	} {
		if tc.a.Equal(tc.b) != tc.want || tc.b.Equal(tc.a) != tc.want {
			t.Fatal("hash equality mismatch")
		}
	}
}
