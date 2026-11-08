package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type providerRsaAes struct{}

var ProviderRsaAes = &providerRsaAes{}

func (p *providerRsaAes) SuiteId() AlgSuite { return AlgRsaAes }
func (p *providerRsaAes) Name() string      { return "rsa-aes" }

func (p *providerRsaAes) GenerateKeyPair() (PublicKeyHandle, PrivateKeyHandle, error) {
	sk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	return &sk.PublicKey, sk, nil
}

func (p *providerRsaAes) MarshalPublicKey(pub PublicKeyHandle) ([]byte, error) {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return x509.MarshalPKIXPublicKey(k)
}

func (p *providerRsaAes) UnmarshalPublicKey(raw []byte) (PublicKeyHandle, error) {
	return x509.ParsePKIXPublicKey(raw)
}

func (p *providerRsaAes) MarshalPublicKeyPem(pub PublicKeyHandle) ([]byte, error) {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (p *providerRsaAes) UnmarshalPublicKeyPem(pemBytes []byte) (PublicKeyHandle, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return k, nil
}

func (p *providerRsaAes) MarshalPrivateKey(sk PrivateKeyHandle) ([]byte, error) {
	k, ok := sk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	return x509.MarshalPKCS1PrivateKey(k), nil
}

func (p *providerRsaAes) UnmarshalPrivateKey(raw []byte) (PrivateKeyHandle, error) {
	return x509.ParsePKCS1PrivateKey(raw)
}

func (p *providerRsaAes) WrapDek(pub PublicKeyHandle, dek []byte) ([]byte, error) {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, k, dek, nil)
}

func (p *providerRsaAes) UnwrapDek(sk PrivateKeyHandle, wrapped []byte) ([]byte, error) {
	k, ok := sk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, k, wrapped, nil)
}

func (p *providerRsaAes) Sign(sk PrivateKeyHandle, data []byte) ([]byte, error) {
	k, ok := sk.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	hashed := sha256.Sum256(data)

	return rsa.SignPSS(rand.Reader, k, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
}

func (p *providerRsaAes) Verify(pub PublicKeyHandle, data, sig []byte) (bool, error) {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("not RSA public key")
	}

	hashed := sha256.Sum256(data)

	err := rsa.VerifyPSS(k, crypto.SHA256, hashed[:], sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (p *providerRsaAes) SymEncryptRandomIV(key, plain []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, 12+len(ct))
	out = append(out, nonce...) // nonce
	out = append(out, ct...)    // cipher

	return out, nil
}

func (p *providerRsaAes) SymDecryptWithBlob(key, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	overhead := gcm.Overhead()
	if len(blob) < nonceSize+overhead {
		return nil, errors.New("ciphertext too short")
	}

	nonce := blob[:nonceSize] // nonce
	ct := blob[nonceSize:]    // cipher

	return gcm.Open(nil, nonce, ct, nil)
}
