package crypto

import (
	"bytes"
	"errors"
)

func deriveKeyForSuite(ppk []byte, suite AlgSuite) []byte {
	switch suite {
	case AlgSm2Sm4:
		return Sm3Hash(ppk)[:16]
	default:
		return ppk
	}
}

func EncryptPrivateKey(ppk []byte, sk PrivateKeyHandle, suite AlgSuite) ([]byte, error) {
	provider, err := GetProvider(suite)
	if err != nil {
		return nil, err
	}

	raw, err := provider.MarshalPrivateKey(sk)
	if err != nil {
		return nil, err
	}

	symKey := deriveKeyForSuite(ppk, suite)

	blob, err := provider.SymEncryptRandomIV(symKey, raw)
	if err != nil {
		return nil, err
	}

	if len(blob) < 32 {
		return nil, errors.New("encrypted blob too short")
	}

	// simple handle the diff with rsa and sm2
	iv := blob[:16]
	ct := blob[16 : len(blob)-16]
	tag := blob[len(blob)-16:]

	var buf bytes.Buffer
	buf.WriteByte(0xA5)
	buf.WriteByte(byte(suite))
	buf.Write(iv)
	buf.Write(tag)
	buf.Write(ct)

	return buf.Bytes(), nil
}

func DecryptPrivateKey(ppk []byte, box []byte) (PrivateKeyHandle, error) {
	if len(box) < 1+1+16+16 {
		return nil, errors.New("keybox too short")
	}

	if box[0] != 0xA5 {
		return nil, errors.New("keybox magic mismatch")
	}

	suite := AlgSuite(box[1])
	provider, err := GetProvider(suite)
	if err != nil {
		return nil, err
	}

	iv := box[2:18]
	tag := box[18:34]
	ct := box[34:]

	symKey := deriveKeyForSuite(ppk, suite)

	blob := make([]byte, 0, 16+len(ct)+16)
	blob = append(blob, iv...)
	blob = append(blob, ct...)
	blob = append(blob, tag...)

	raw, err := provider.SymDecryptWithBlob(symKey, blob)
	if err != nil {
		return nil, ErrWrongPassword
	}

	return provider.UnmarshalPrivateKey(raw)
}
