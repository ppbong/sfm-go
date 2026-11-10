package crypto

import "errors"

var (
	ErrNoMatchingKey     = errors.New("no matching key found in current or history keys")
	ErrWrongPassword     = errors.New("wrong password: unable to decrypt private key")
	ErrCorruptedEnvelope = errors.New("envelope corrupted: magic/crc mismatch")
	ErrAlgNotSupported   = errors.New("algorithm suite not supported")
	ErrSignatureInvalid  = errors.New("signature invalid")
)

type PrivateKeyHandle any
type PublicKeyHandle any

type Provider interface {
	SuiteId() AlgSuite
	Name() string

	GenerateKeyPair() (PublicKeyHandle, PrivateKeyHandle, error)

	MarshalPublicKey(pub PublicKeyHandle) ([]byte, error)
	UnmarshalPublicKey(raw []byte) (PublicKeyHandle, error)

	MarshalPublicKeyPem(pub PublicKeyHandle) ([]byte, error)
	UnmarshalPublicKeyPem(pemBytes []byte) (PublicKeyHandle, error)

	MarshalPrivateKey(sk PrivateKeyHandle) ([]byte, error)
	UnmarshalPrivateKey(raw []byte) (PrivateKeyHandle, error)

	WrapDek(pub PublicKeyHandle, dek []byte) ([]byte, error)
	UnwrapDek(sk PrivateKeyHandle, wrapped []byte) ([]byte, error)

	Sign(sk PrivateKeyHandle, data []byte) ([]byte, error)
	Verify(pub PublicKeyHandle, data, sig []byte) (bool, error)

	SymEncryptRandomIV(key, plain []byte) ([]byte, error) // encrypt pvk
	SymDecryptWithBlob(key, blob []byte) ([]byte, error)  // decrypt pvk
}

func GetProvider(id AlgSuite) (Provider, error) {
	switch id {
	case AlgRsaAes:
		return ProviderRsaAes, nil
	case AlgSm2Sm4:
		if ProviderSm2Sm4 == nil {
			return nil, ErrAlgNotSupported
		}
		return ProviderSm2Sm4, nil
	}

	return nil, ErrAlgNotSupported
}
