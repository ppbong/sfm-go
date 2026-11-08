package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ENVELOPE_MAGIC         = "SFMENC01"
	ENVELOPE_VERSION       = 1
	ENVELOPE_FIXED_LEN     = 22 // magic + version + algCode + flags + headerLen + reserved
	ENVELOPE_IV_LEN        = 12
	ENVELOPE_TAG_LEN       = 16
	ENVELOPE_CHUNK_HEADER  = 4 + 12 + 16 // len + iv + tag
	ENVELOPE_DEFAULT_CHUNK = 4 * 1024 * 1024
)

const FLAG_SHARE uint16 = 0x0001

type EnvelopeHeader struct {
	FileId string `json:"fileId"`
	Meta   struct {
		Iv     string `json:"iv"`
		Tag    string `json:"tag"`
		Cipher string `json:"cipher"` // encrypted EnvelopeMeta
	} `json:"meta"`
	ChunkSize uint32 `json:"chunkSize"`
	CreatedAt int64  `json:"createdAt"`
	Sender    struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"sender"`
	Recipients []Recipient `json:"recipients"`
}

type Recipient struct {
	Fingerprint string `json:"fingerprint"`
	AlgCode     *byte  `json:"algCode,omitempty"`
	WrappedDek  string `json:"wrappedDek"` // encrypted Dek with PublicKey according to algCode
}

type EnvelopeMeta struct {
	Name string `json:"name"` // include ext
	Ext  string `json:"ext"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

func EncryptFile(inputPath, outputPath string, dek []byte, suite AlgSuite,
	recipients []RecipientInput, signerPub PublicKeyHandle, signerSk PrivateKeyHandle,
	signerFingerprint string, meta EnvelopeMeta, isShare bool, chunkSize uint32) error {

	if chunkSize == 0 {
		chunkSize = ENVELOPE_DEFAULT_CHUNK
	}

	p, err := GetProvider(suite)
	if err != nil {
		return err
	}

	stat, err := os.Stat(inputPath)
	if err != nil {
		return err
	}

	meta.Size = stat.Size()

	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	fileHash := sha256.Sum256(fileData)
	fileId := fmt.Sprintf("%x", fileHash[:])

	baseIv := make([]byte, 4)
	rand.Read(baseIv)

	// encrypt meta {name,ext,size,mime} (AAD='meta')
	metaBuf, _ := json.Marshal(meta)
	metaIv := make([]byte, ENVELOPE_IV_LEN)
	rand.Read(metaIv)
	metaCipher, metaTag := symEncryptAad(dek, metaIv, metaBuf, []byte("meta"), suite)

	// wrap dek
	for i, r := range recipients {
		alg := suite
		if r.AlgCode != nil {
			alg = AlgSuite(*r.AlgCode)
		}

		rp, err := GetProvider(alg)
		if err != nil {
			return err
		}

		wrapped, err := rp.WrapDek(r.PublicKey, dek)
		if err != nil {
			return err
		}

		recipients[i].wrappedDek = base64.StdEncoding.EncodeToString(wrapped)
		recipients[i].AlgCode = bytePtr(byte(alg))
	}

	// build envelop header
	hdr := EnvelopeHeader{
		FileId:    fileId,
		ChunkSize: chunkSize,
		CreatedAt: time.Now().UnixMilli(),
	}

	hdr.Meta.Iv = base64.StdEncoding.EncodeToString(metaIv)
	hdr.Meta.Tag = base64.StdEncoding.EncodeToString(metaTag)
	hdr.Meta.Cipher = base64.StdEncoding.EncodeToString(metaCipher)
	hdr.Sender.Fingerprint = signerFingerprint

	for _, r := range recipients {
		hdr.Recipients = append(hdr.Recipients, Recipient{
			Fingerprint: r.Fingerprint,
			AlgCode:     r.AlgCode,
			WrappedDek:  r.wrappedDek,
		})
	}

	headerBuf, _ := json.Marshal(hdr)

	// build fixed header
	fixed := make([]byte, ENVELOPE_FIXED_LEN) // 18..22 reserved
	copy(fixed[:8], ENVELOPE_MAGIC)
	binary.BigEndian.PutUint16(fixed[8:10], ENVELOPE_VERSION)
	binary.BigEndian.PutUint16(fixed[10:12], uint16(suite))
	flags := uint16(0)
	if isShare {
		flags = FLAG_SHARE
	}
	binary.BigEndian.PutUint16(fixed[12:14], flags)
	binary.BigEndian.PutUint32(fixed[14:18], uint32(len(headerBuf)))

	// build chunks
	var body bytes.Buffer
	hash := sha256.New()
	hash.Write(fixed)
	hash.Write(headerBuf)

	offset := 0
	idx := uint64(0)
	for offset < len(fileData) {
		end := offset + int(chunkSize)
		if end > len(fileData) {
			end = len(fileData)
		}
		plain := fileData[offset:end]

		iv := chunkIv(baseIv, idx)
		aad := chunkAad(suite, idx)
		ciphertext, tag := symEncryptAad(dek, iv, plain, aad, suite)

		chunk := make([]byte, 0, 4+12+16+len(ciphertext))
		chunkBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(chunkBuf, uint32(len(ciphertext)+12+16))
		chunk = append(chunk, chunkBuf...)   // size(4)
		chunk = append(chunk, iv...)         // iv(12)
		chunk = append(chunk, tag...)        // tag(16)
		chunk = append(chunk, ciphertext...) // cipher(n)

		body.Write(chunk)
		hash.Write(chunk)
		offset = end
		idx++
	}

	// sign: fixed + header + body
	sig, err := p.Sign(signerSk, hash.Sum(nil))
	if err != nil {
		return err
	}

	sigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(sig)))

	// output：fixed + header + body + sig + sigLen
	out := make([]byte, 0, len(fixed)+len(headerBuf)+body.Len()+len(sig)+4)
	out = append(out, fixed...)
	out = append(out, headerBuf...)
	out = append(out, body.Bytes()...)
	out = append(out, sig...)
	out = append(out, sigLenBuf...)

	return os.WriteFile(outputPath, out, 0o600)
}

func chunkIv(baseIv []byte, idx uint64) []byte {
	iv := make([]byte, ENVELOPE_IV_LEN)
	copy(iv[:4], baseIv[:4])
	binary.BigEndian.PutUint64(iv[4:], idx)

	return iv
}

func chunkAad(alg AlgSuite, idx uint64) []byte {
	aad := make([]byte, 10)
	binary.BigEndian.PutUint16(aad[:2], uint16(alg))
	binary.BigEndian.PutUint64(aad[2:], idx)

	return aad
}

type RecipientInput struct {
	Fingerprint string
	PublicKey   PublicKeyHandle
	AlgCode     *byte
	wrappedDek  string
}

func bytePtr(b byte) *byte { return &b }

type DecryptResult struct {
	Header     *EnvelopeHeader
	OutputPath string
	Meta       EnvelopeMeta
}

func DecryptFile(inputPath, outputDir string,
	unwrapDek func(recipients []Recipient, suite AlgSuite) ([]byte, bool),
	senderPub PublicKeyHandle) (*DecryptResult, error) {

	filename := filepath.Base(inputPath)
	if !strings.HasSuffix(filename, ".sfe") && !strings.HasSuffix(filename, ".sfx") {
		return nil, ErrEnvelopeFileSuffix
	}

	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	if len(fileData) < ENVELOPE_FIXED_LEN || string(fileData[:8]) != ENVELOPE_MAGIC {
		return nil, ErrEnvelopeMagic
	}

	version := binary.BigEndian.Uint16(fileData[8:10])
	if version != ENVELOPE_VERSION {
		return nil, ErrEnvelopeVersion
	}

	algCode := AlgSuite(binary.BigEndian.Uint16(fileData[10:12]))
	headerLen := binary.BigEndian.Uint32(fileData[14:18])
	bodyOffset := ENVELOPE_FIXED_LEN + int(headerLen)
	if len(fileData) < bodyOffset {
		return nil, ErrEnvelopeHeader
	}

	var hdr EnvelopeHeader
	if err := json.Unmarshal(fileData[ENVELOPE_FIXED_LEN:bodyOffset], &hdr); err != nil {
		return nil, ErrEnvelopeHeaderCtx
	}

	if len(fileData) < 4+bodyOffset {
		return nil, ErrEnvelopeBodyShort
	}

	sigLen := binary.BigEndian.Uint32(fileData[len(fileData)-4:])
	if sigLen == 0 || sigLen > 4096 || len(fileData)-4-int(sigLen) <= bodyOffset {
		return nil, ErrEnvelopeSignArea
	}

	sigStart := len(fileData) - 4 - int(sigLen)
	sig := fileData[sigStart : sigStart+int(sigLen)]
	bodyEnd := sigStart

	// unwrap dek
	dek, ok := unwrapDek(hdr.Recipients, algCode)
	if !ok || len(dek) == 0 {
		return nil, ErrNoMatchingKey
	}

	defer bytesZero(dek)

	// decrypt meta
	metaIv, _ := base64.StdEncoding.DecodeString(hdr.Meta.Iv)
	metaCipher, _ := base64.StdEncoding.DecodeString(hdr.Meta.Cipher)
	metaTag, _ := base64.StdEncoding.DecodeString(hdr.Meta.Tag)
	metaBuf, err := symDecryptAad(dek, metaIv, metaCipher, metaTag, []byte("meta"), algCode)
	if err != nil {
		return nil, ErrEnvelopeMetaDec
	}

	var meta EnvelopeMeta
	_ = json.Unmarshal(metaBuf, &meta)

	outputPath := filepath.Join(outputDir, filename[:len(filename)-4]+meta.Ext)

	// decrypt chunks
	plainOut, err := decryptChunks(fileData[bodyOffset:bodyEnd], hdr.ChunkSize, dek, algCode)
	if err != nil {
		return nil, err
	}

	// verify (optional)
	if senderPub != nil {
		p, err := GetProvider(algCode)
		if err == nil {
			hash := sha256.New()
			hash.Write(fileData[:bodyOffset])
			hash.Write(fileData[bodyOffset:bodyEnd])
			ok, _ := p.Verify(senderPub, hash.Sum(nil), sig)
			if !ok {
				return nil, ErrSignatureInvalid
			}
		}
	}

	if err := os.WriteFile(outputPath, plainOut, 0o600); err != nil {
		return nil, err
	}

	return &DecryptResult{Header: &hdr, OutputPath: outputPath, Meta: meta}, nil
}

func decryptChunks(body []byte, chunkSize uint32, dek []byte, suite AlgSuite) ([]byte, error) {
	var out bytes.Buffer
	pos := 0
	idx := uint64(0)
	chunkSize = chunkSize * 1

	for pos < len(body) {
		if pos+4 > len(body) {
			return nil, ErrEnvelopeChunkLenMiss
		}

		chunkLen := int(binary.BigEndian.Uint32(body[pos : pos+4]))
		if chunkLen < ENVELOPE_IV_LEN+ENVELOPE_TAG_LEN ||
			chunkLen > int(chunkSize)+ENVELOPE_IV_LEN+ENVELOPE_TAG_LEN+64 {
			return nil, ErrEnvelopeChunkLen
		}

		pos += 4
		if pos+chunkLen > len(body) {
			return nil, ErrEnvelopeChunkBody
		}

		chunk := body[pos : pos+chunkLen]
		pos += chunkLen
		iv := chunk[:ENVELOPE_IV_LEN]
		tag := chunk[ENVELOPE_IV_LEN : ENVELOPE_IV_LEN+ENVELOPE_TAG_LEN]
		ct := chunk[ENVELOPE_IV_LEN+ENVELOPE_TAG_LEN:]
		aad := chunkAad(suite, idx)

		plain, err := symDecryptAad(dek, iv, ct, tag, aad, suite)
		if err != nil {
			return nil, ErrEnvelopeChunkBodyDec
		}

		out.Write(plain)
		idx++
	}

	return out.Bytes(), nil
}

// block encrypt
func symEncryptAad(key, iv, plain, aad []byte, suite AlgSuite) (ciphertext, tag []byte) {
	switch suite {
	case AlgRsaAes:
		ct, t, err := aesGcmSeal(key, iv, plain, aad)
		if err != nil {
			panic(err)
		}
		return ct, t
	case AlgSm2Sm4:
		ct, t, err := sm4HmacEnc(key, iv, plain, aad)
		if err != nil {
			panic(err)
		}
		return ct, t
	}

	panic("unknown suite")
}

// block decrypt
func symDecryptAad(key, iv, ciphertext, tag, aad []byte, suite AlgSuite) ([]byte, error) {
	switch suite {
	case AlgRsaAes:
		return aesGcmOpen(key, iv, ciphertext, tag, aad)
	case AlgSm2Sm4:
		return sm4HmacDec(key, iv, ciphertext, tag, aad)
	}

	return nil, ErrAlgNotSupported
}

// aes gcm encrypt
func aesGcmSeal(key, iv, plain, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, nil, err
	}

	ct := gcm.Seal(nil, iv, plain, aad)
	tag := ct[len(ct)-gcm.Overhead():]
	ct = ct[:len(ct)-gcm.Overhead()]

	return ct, tag, nil
}

// aes gcm decrypt
func aesGcmOpen(key, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	ctAndTag := make([]byte, 0, len(ciphertext)+len(tag))
	ctAndTag = append(ctAndTag, ciphertext...)
	ctAndTag = append(ctAndTag, tag...)

	return gcm.Open(nil, iv, ctAndTag, aad)
}

// sm4 hmac encrypt
func sm4HmacEnc(dek, iv12, plain, aad []byte) ([]byte, []byte, error) {
	sm4Key := Sm3Hash(dek)[:16]
	sm4Iv := Sm3Hash(iv12)[:16]
	ct := SM4CbcEncrypt(sm4Key, sm4Iv, plain)

	macKey := sm4Key
	tag := HmacSm3(macKey, append(append(append([]byte{}, iv12...), aad...), ct...))[:16]

	return ct, tag, nil
}

// sm4 hmac decrypt
func sm4HmacDec(dek, iv12, ciphertext, tag, aad []byte) ([]byte, error) {
	sm4Key := Sm3Hash(dek)[:16]
	sm4Iv := Sm3Hash(iv12)[:16]
	macKey := sm4Key

	expected := HmacSm3(macKey, append(append(append([]byte{}, iv12...), aad...), ciphertext...))[:16]
	if !constantTimeEqual(tag, expected) {
		return nil, ErrSm4HmacDec
	}

	return SM4CbcDecrypt(sm4Key, sm4Iv, ciphertext), nil
}

func bytesZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
