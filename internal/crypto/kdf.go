package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

func DerivePpk(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	_, err := rand.Read(s)

	return s, err
}

// fingerprint
func Fingerprint(pub PublicKeyHandle, suite AlgSuite) (string, error) {
	provider, err := GetProvider(suite)
	if err != nil {
		return "", err
	}

	raw, err := provider.MarshalPublicKey(pub)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)
	out := make([]byte, 0, 32*3)
	for i, b := range sum[:] {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, fmt.Sprintf("%02X", b)...)
	}

	return string(out), nil
}

// fingerprint.replaceAll(':',”)
func FingerprintHex(pub PublicKeyHandle, suite AlgSuite) (string, error) {
	fp, err := Fingerprint(pub, suite)
	if err != nil {
		return "", err
	}

	out := make([]byte, 0, 64)
	for _, c := range []byte(fp) {
		if c != ':' {
			out = append(out, c)
		}
	}

	return string(out), nil
}

// fingerprint.raw
func FingerprintBytes(pub PublicKeyHandle, suite AlgSuite) ([]byte, error) {
	provider, err := GetProvider(suite)
	if err != nil {
		return nil, err
	}

	raw, err := provider.MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(raw)

	return sum[:], nil
}

// fingerprint.From(pem)
func FingerprintPem(pemBytes []byte, suite AlgSuite) (string, error) {
	provider, err := GetProvider(suite)
	if err != nil {
		return "", err
	}

	pub, err := provider.UnmarshalPublicKeyPem(pemBytes)
	if err != nil {
		return "", err
	}

	return Fingerprint(pub, suite)
}
