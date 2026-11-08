package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRsaAesRoundTrip(t *testing.T) {
	p := ProviderRsaAes

	pub, sk, err := p.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	fp, err := Fingerprint(pub, AlgRsaAes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RSA pub fingerprint: %s", fp)

	pem, err := p.MarshalPublicKeyPem(pub)
	if err != nil {
		t.Fatal(err)
	}

	pub2, err := p.UnmarshalPublicKeyPem(pem)
	if err != nil {
		t.Fatal(err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	wrapped, err := p.WrapDek(pub2, dek)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := p.UnwrapDek(sk, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Fatal("DEK round-trip failed")
	}

	sig, err := p.Sign(sk, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := p.Verify(pub2, []byte("hello world"), sig)
	if !ok {
		t.Fatal("verify failed")
	}

	ok2, _ := p.Verify(pub2, []byte("hello world!"), sig)
	if ok2 {
		t.Fatal("verify should fail for different msg")
	}

	salt, _ := NewSalt()
	ppk, _ := DerivePpk("password1234", salt)
	box, err := EncryptPrivateKey(ppk, sk, AlgRsaAes)
	if err != nil {
		t.Fatal(err)
	}

	wrong, _ := DerivePpk("wrongpass", salt)
	_, err = DecryptPrivateKey(wrong, box)
	if err == nil {
		t.Fatal("wrong password should fail")
	}

	sk2, err := DecryptPrivateKey(ppk, box)
	if err != nil {
		t.Fatal(err)
	}

	sk2pem, _ := p.MarshalPrivateKey(sk2)
	skpem, _ := p.MarshalPrivateKey(sk)
	if !bytes.Equal(skpem, sk2pem) {
		t.Fatal("keybox round-trip failed")
	}

	t.Log("RSA+AES OK")
}

func TestSm2Sm4RoundTrip(t *testing.T) {
	p := ProviderSm2Sm4

	pub, sk, err := p.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	fp, err := Fingerprint(pub, AlgSm2Sm4)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SM2 pub fingerprint: %s", fp)

	pem, err := p.MarshalPublicKeyPem(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pem, []byte("SFM SM2 PUBLIC KEY")) {
		t.Fatalf("expected custom PEM label, got: %q", string(pem[:40]))
	}

	pub2, err := p.UnmarshalPublicKeyPem(pem)
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte{0x04}
	pubBytes, _ := p.MarshalPublicKey(pub)
	raw = pubBytes
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("MarshalPublicKey must return raw 65B, got len=%d first=%x", len(raw), raw[0])
	}

	pub3, err := p.UnmarshalPublicKey(raw)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey must accept raw 65B: %v", err)
	}
	_ = pub3

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	wrapped, err := p.WrapDek(pub2, dek)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := p.UnwrapDek(sk, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, unwrapped) {
		t.Fatal("SM2 DEK round-trip failed")
	}

	sig, err := p.Sign(sk, []byte("sm2 hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("SM2 sig len = %d, want 64", len(sig))
	}

	ok, _ := p.Verify(pub2, []byte("sm2 hello"), sig)
	if !ok {
		t.Fatal("SM2 verify failed")
	}

	ok2, _ := p.Verify(pub2, []byte("sm2 hello!"), sig)
	if ok2 {
		t.Fatal("SM2 verify should fail")
	}

	t.Log("SM2+SM4 OK")
}

func TestEnvelopeRsaAes(t *testing.T) {
	tmpIn, _ := os.CreateTemp("", "sfm-test-*.txt")
	defer os.Remove(tmpIn.Name())

	content := make([]byte, 1024*40+7)
	for i := range content {
		content[i] = byte(i % 256)
	}

	tmpIn.Write(content)
	tmpIn.Close()

	signerPub, signerSk, _ := ProviderRsaAes.GenerateKeyPair()
	fp, _ := Fingerprint(signerPub, AlgRsaAes)

	tmpOut, _ := os.CreateTemp("", "sfm-enc-*.sfe")
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	err := EncryptFile(tmpIn.Name(), tmpOut.Name(), make([]byte, 32), AlgRsaAes,
		[]RecipientInput{{
			Fingerprint: fp,
			PublicKey:   signerPub,
		}}, signerPub, signerSk, fp,
		EnvelopeMeta{Name: "test.bin", Ext: ".txt", Size: int64(len(content)), Mime: "application/octet-stream"},
		false, 1024*16)
	if err != nil {
		t.Fatal(err)
	}

	decryptResult, err := DecryptFile(tmpOut.Name(), filepath.Dir(tmpOut.Name()),
		func(_ []Recipient, _ AlgSuite) ([]byte, bool) { return nil, false },
		nil)
	if err == nil {
		t.Fatal("DEK unwrap should fail without proper unwrap fn")
	}

	_ = decryptResult

	t.Log("envelope RSA+AES encrypt+sign OK，decrypt need real unwrap so not test")
}

func TestAesGcmChunkRoundTrip(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	chunk := make([]byte, 4000)
	for i := range chunk {
		chunk[i] = byte(i % 251)
	}

	baseIv := make([]byte, 4)
	iv := chunkIv(baseIv, 0)
	aad := chunkAad(AlgRsaAes, 0)
	ct, tag := symEncryptAad(dek, iv, chunk, aad, AlgRsaAes)

	plain, err := symDecryptAad(dek, iv, ct, tag, aad, AlgRsaAes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk, plain) {
		t.Fatal("chunk round-trip failed")
	}

	bad := append([]byte{}, ct...)
	bad[0] ^= 0x01
	_, err = symDecryptAad(dek, iv, bad, tag, aad, AlgRsaAes)
	if err == nil {
		t.Fatal("tamper should be detected")
	}

	t.Log("AES-GCM chunk round-trip OK")
}

func TestSm4HmacChunkRoundTrip(t *testing.T) {
	if ProviderSm2Sm4 == nil {
		t.Skip("SM2/SM4 provider not available")
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	chunk := make([]byte, 4000)
	for i := range chunk {
		chunk[i] = byte(i % 251)
	}

	baseIv := make([]byte, 4)
	iv := chunkIv(baseIv, 0)
	aad := chunkAad(AlgSm2Sm4, 0)
	ct, tag, err := sm4HmacEnc(dek, iv, chunk, aad)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := sm4HmacDec(dek, iv, ct, tag, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chunk, plain) {
		t.Fatal("SM4 chunk round-trip failed")
	}

	_, err = sm4HmacDec(dek, iv, ct, tag, aad)
	if err != nil {
		t.Fatalf("decrypt should succeed: %v", err)
	}

	badCt := append([]byte{}, ct...)
	badCt[0] ^= 0x01
	_, err = sm4HmacDec(dek, iv, badCt, tag, aad)
	if err == nil {
		t.Fatal("SM4 tamper should be detected")
	}

	t.Log("SM4-CBC+HMAC chunk round-trip OK")
}
