package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

const Sm2PublibKeyPemLabel = "SFM SM2 PUBLIC KEY"

// pack sm2 public key: 0x04 || X(32) || Y(32)
func sm2PubToRaw(pub PublicKeyHandle) ([]byte, error) {
	k, ok := pub.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("not SM2 public key")
	}

	x := k.X.Bytes()
	y := k.Y.Bytes()
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	copy(xp[32-len(x):], x)
	copy(yp[32-len(y):], y)

	out := make([]byte, 65)
	out[0] = 0x04
	copy(out[1:33], xp)
	copy(out[33:65], yp)

	return out, nil
}

// unpack sm2 public key
func sm2RawToPub(raw []byte) (*sm2.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("invalid SM2 raw public key (len=%d, tag=%02x)", len(raw), raw[0])
	}

	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])

	return &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}, nil
}

// wrap sm2 public key: pack -> pem
func wrapSm2Pem(raw []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(raw)

	var b strings.Builder
	b.WriteString("-----BEGIN ")
	b.WriteString(Sm2PublibKeyPemLabel)
	b.WriteString("-----\n")

	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		b.WriteString(b64[i:end])
		b.WriteByte('\n')
	}

	b.WriteString("-----END ")
	b.WriteString(Sm2PublibKeyPemLabel)
	b.WriteString("-----\n")

	return []byte(b.String())
}

// unwrap sm2 public key: pem -> pack
func unwrapSm2Pem(pem []byte) ([]byte, error) {
	text := strings.TrimSpace(string(pem))
	if !strings.Contains(text, "BEGIN "+Sm2PublibKeyPemLabel) {
		return nil, errors.New("not SM2 PEM")
	}

	var b64 strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b64.WriteString(line)
	}

	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, err
	}

	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("invalid SM2 PEM body: len=%d tag=%02x", len(raw), raw[0])
	}

	return raw, nil
}

type providerSm2Sm4 struct{}

var ProviderSm2Sm4 *providerSm2Sm4 = &providerSm2Sm4{}

func (p *providerSm2Sm4) SuiteId() AlgSuite { return AlgSm2Sm4 }
func (p *providerSm2Sm4) Name() string      { return "sm2-sm4" }

func (p *providerSm2Sm4) GenerateKeyPair() (PublicKeyHandle, PrivateKeyHandle, error) {
	sk, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return &sk.PublicKey, sk, nil
}

func (p *providerSm2Sm4) MarshalPublicKey(pub PublicKeyHandle) ([]byte, error) {
	return sm2PubToRaw(pub)
}

func (p *providerSm2Sm4) UnmarshalPublicKey(raw []byte) (PublicKeyHandle, error) {
	return sm2RawToPub(raw)
}

func (p *providerSm2Sm4) MarshalPublicKeyPem(pub PublicKeyHandle) ([]byte, error) {
	raw, err := sm2PubToRaw(pub)
	if err != nil {
		return nil, err
	}

	return wrapSm2Pem(raw), nil
}

func (p *providerSm2Sm4) UnmarshalPublicKeyPem(pemBytes []byte) (PublicKeyHandle, error) {
	trimmed := strings.TrimSpace(string(pemBytes))
	if strings.Contains(trimmed, "BEGIN "+Sm2PublibKeyPemLabel) {
		raw, err := unwrapSm2Pem([]byte(trimmed))
		if err != nil {
			return nil, err
		}

		return sm2RawToPub(raw)
	}

	return nil, fmt.Errorf("invalid SM2 PEM")
}

func (p *providerSm2Sm4) MarshalPrivateKey(sk PrivateKeyHandle) ([]byte, error) {
	k, ok := sk.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("not SM2 private key")
	}

	d := k.D.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(d):], d)

	return out, nil
}

func (p *providerSm2Sm4) UnmarshalPrivateKey(raw []byte) (PrivateKeyHandle, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("SM2 priv must be 32 bytes, got %d", len(raw))
	}

	d := new(big.Int).SetBytes(raw)
	curve := sm2.P256Sm2()
	x, y := curve.ScalarBaseMult(raw)

	return &sm2.PrivateKey{PublicKey: sm2.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

func (p *providerSm2Sm4) WrapDek(pub PublicKeyHandle, dek []byte) ([]byte, error) {
	k, ok := pub.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("not SM2 public key")
	}

	return sm2.Encrypt(k, dek, rand.Reader, sm2.C1C3C2)
}

func (p *providerSm2Sm4) UnwrapDek(sk PrivateKeyHandle, wrapped []byte) ([]byte, error) {
	k, ok := sk.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("not SM2 private key")
	}

	return sm2.Decrypt(k, wrapped, sm2.C1C3C2)
}

// sign: r_32 || s_32
func (p *providerSm2Sm4) Sign(sk PrivateKeyHandle, data []byte) ([]byte, error) {
	k, ok := sk.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("not SM2 private key")
	}

	r, s, err := sm2.Sm2Sign(k, data, nil, rand.Reader)
	if err != nil {
		return nil, err
	}

	return sm2SigToBytes(r, s), nil
}

func (p *providerSm2Sm4) Verify(pub PublicKeyHandle, data, sig []byte) (bool, error) {
	k, ok := pub.(*sm2.PublicKey)
	if !ok {
		return false, errors.New("not SM2 public key")
	}

	if len(sig) != 64 {
		return false, nil
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])

	return sm2.Sm2Verify(k, data, nil, r, s), nil
}

func sm2SigToBytes(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)

	return out
}

func (p *providerSm2Sm4) SymEncryptRandomIV(key, plain []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ct := SM4CbcEncrypt(key, iv, plain)
	mac := HmacSm3(key, append(iv, ct...))

	out := make([]byte, 0, 16+len(ct)+32)
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, mac...)

	return out, nil
}

func (p *providerSm2Sm4) SymDecryptWithBlob(key, blob []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("SM4 key must be 16 bytes, got %d", len(key))
	}

	if len(blob) < 16+32 {
		return nil, errors.New("ciphertext too short")
	}

	iv := blob[:16]
	ct := blob[16 : len(blob)-32]
	mac := blob[len(blob)-32:]
	expected := HmacSm3(key, append(iv, ct...))

	if !constantTimeEqual(mac, expected) {
		return nil, errors.New("HMAC mismatch")
	}

	return SM4CbcDecrypt(key, iv, ct), nil
}

func HmacSm3(key, data []byte) []byte {
	const block = 64

	k := make([]byte, block)
	if len(key) > block {
		sum := Sm3Hash(key)
		copy(k, sum)
	} else {
		copy(k[block-len(key):], key)
	}

	ipad := make([]byte, block)
	opad := make([]byte, block)
	for i := 0; i < block; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}

	inner := sm3.New()
	inner.Write(ipad)
	inner.Write(data)
	h0 := inner.Sum(nil)
	outer := sm3.New()
	outer.Write(opad)
	outer.Write(h0)

	return outer.Sum(nil)
}

func Sm3Hash(data []byte) []byte {
	h := sm3.New()
	h.Write(data)

	return h.Sum(nil)
}

func SM4CbcEncrypt(key, iv, plain []byte) []byte {
	pad := 16 - len(plain)%16
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	block, _ := sm4.NewCipher(key)
	out := make([]byte, len(padded))
	cbcEncryptBlock(block, out, padded, iv)

	return out
}

func SM4CbcDecrypt(key, iv, ct []byte) []byte {
	block, _ := sm4.NewCipher(key)
	out := make([]byte, len(ct))
	cbcDecryptBlock(block, out, ct, iv)
	if len(out) == 0 {
		return out
	}

	pad := int(out[len(out)-1])
	if pad < 1 || pad > 16 || pad > len(out) {
		return out
	}

	for i := len(out) - pad; i < len(out); i++ {
		if int(out[i]) != pad {
			return out
		}
	}

	return out[:len(out)-pad]
}

func cbcEncryptBlock(block Block, dst, src, iv []byte) {
	prev := append([]byte(nil), iv...)
	buf := make([]byte, 16)
	for i := 0; i < len(src); i += 16 {
		for j := 0; j < 16; j++ {
			buf[j] = src[i+j] ^ prev[j]
		}
		block.Encrypt(dst[i:], buf)
		copy(prev, dst[i:i+16])
	}
}

func cbcDecryptBlock(block Block, dst, src, iv []byte) {
	prev := append([]byte(nil), iv...)
	buf := make([]byte, 16)
	for i := 0; i < len(src); i += 16 {
		block.Decrypt(buf, src[i:])
		for j := 0; j < 16; j++ {
			dst[i+j] = buf[j] ^ prev[j]
		}
		copy(prev, src[i:i+16])
	}
}

type Block interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var d byte
	for i := 0; i < len(a); i++ {
		d |= a[i] ^ b[i]
	}

	return d == 0
}
