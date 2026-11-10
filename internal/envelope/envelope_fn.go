package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	"sfm/internal/crypto"
	"sfm/internal/util"
)

func EncryptFile(
	inputPath, outputDir string,
	dek []byte,
	suite crypto.AlgSuite,
	recipients []Recipient,
	signerPub crypto.PublicKeyHandle,
	signerSk crypto.PrivateKeyHandle,
	signerFingerprint string,
	meta EnvelopeMetaPlain,
	isShare bool,
	chunkSize uint32) (*EnvelopeFileMemo, error) {

	if chunkSize == 0 {
		chunkSize = ENVELOPE_CHUNK_DEFAULT_SIZE
	}

	p, err := crypto.GetProvider(suite)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(inputPath)
	if err != nil {
		return nil, err
	}

	fileExt := ".sfe"
	if isShare {
		fileExt = ".sfx"
	}

	fileName := strings.ReplaceAll(meta.Name, meta.Ext, fileExt)
	outputPath := filepath.Join(outputDir, fileName)

	meta.Size = uint64(stat.Size())
	metaBuf, _ := json.Marshal(meta)
	metaIv := make([]byte, ENVELOPE_META_IV_LEN)
	rand.Read(metaIv)

	// encrypt meta {name,ext,size,mime} (AAD='meta')
	metaCipher, metaTag := symEncryptAad(dek, metaIv, metaBuf, []byte("meta"), suite)

	// wrap dek
	for i, r := range recipients {
		var alg uint16

		sn := crypto.SuiteName(crypto.AlgSuite(r.AlgCode))
		if sn == "unknown" {
			alg = uint16(suite)
		} else {
			alg = r.AlgCode
		}

		rp, err := crypto.GetProvider(crypto.AlgSuite(alg))
		if err != nil {
			return nil, err
		}

		wrapped, err := rp.WrapDek(r.PublicKey, dek)
		if err != nil {
			return nil, err
		}

		recipients[i].wrappedDek = base64.StdEncoding.EncodeToString(wrapped)
		recipients[i].AlgCode = alg
	}

	// build envelop header
	hdr := EnvelopeHeader{
		FileId:    uuid.NewV7().String(),
		ChunkSize: chunkSize,
		CreatedAt: time.Now().UnixMilli(),
	}

	hdr.Meta.Iv = base64.StdEncoding.EncodeToString(metaIv)
	hdr.Meta.Tag = base64.StdEncoding.EncodeToString(metaTag)
	hdr.Meta.Cipher = base64.StdEncoding.EncodeToString(metaCipher)
	hdr.Sender.Fingerprint = signerFingerprint

	for _, r := range recipients {
		hdr.Recipients = append(hdr.Recipients, EnvelopeRecipient{
			Fingerprint: r.Fingerprint,
			AlgCode:     r.AlgCode,
			WrappedDek:  r.wrappedDek,
		})
	}

	headerBuf, _ := json.Marshal(hdr)

	// build fixed header
	fixed := make([]byte, ENVELOPE_FIXED_LEN)
	copy(fixed[:8], ENVELOPE_MAGIC)
	copy(fixed[8:10], ENVELOPE_VERSION)
	binary.BigEndian.PutUint16(fixed[10:12], uint16(suite))

	flags := FLAG_LOCAL
	if isShare {
		flags = FLAG_SHARE
	}

	binary.BigEndian.PutUint16(fixed[12:14], flags)
	binary.BigEndian.PutUint32(fixed[14:18], uint32(len(headerBuf)))

	// file stream handle for chunk
	inFile, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	// write envelope fixed
	if _, err := outFile.Write(fixed); err != nil {
		return nil, err
	}

	// write envelope header
	if _, err := outFile.Write(headerBuf); err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write(fixed)
	hash.Write(headerBuf)

	baseIv := make([]byte, 4)
	rand.Read(baseIv)

	plainBuf := make([]byte, chunkSize)
	chunkPre := make([]byte, ENVELOPE_CHUNK_HEADER_LEN)

	idx := uint64(0)
	for {
		n, err := io.ReadFull(inFile, plainBuf)
		if err != nil && err != io.ErrUnexpectedEOF && !errors.Is(err, io.EOF) {
			return nil, err
		}

		if n == 0 && errors.Is(err, io.EOF) {
			break
		}

		isLastChunk := err == io.EOF || err == io.ErrUnexpectedEOF

		plain := plainBuf[:n]

		iv := chunkIv(baseIv, idx)
		aad := chunkAad(suite, idx)
		cipher, tag := symEncryptAad(dek, iv, plain, aad, suite)

		chunkLen := uint32(len(cipher) + ENVELOPE_CHUNK_IV_LEN + ENVELOPE_CHUNK_TAG_LEN)

		binary.BigEndian.PutUint32(chunkPre, chunkLen)
		copy(chunkPre[4:], iv)
		copy(chunkPre[4+ENVELOPE_CHUNK_IV_LEN:], tag)

		if _, err := outFile.Write(chunkPre); err != nil {
			return nil, err
		}

		if _, err := outFile.Write(cipher); err != nil {
			return nil, err
		}

		hash.Write(chunkPre)
		hash.Write(cipher)

		if isLastChunk {
			break
		}

		idx++
	}

	// sign: fixed + header + body
	sig, err := p.Sign(signerSk, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	sigLenBuf := make([]byte, ENVELOPE_SIG_LEN)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(sig)))

	if _, err := outFile.Write(sig); err != nil {
		return nil, err
	}

	if _, err := outFile.Write(sigLenBuf); err != nil {
		return nil, err
	}

	return &EnvelopeFileMemo{OutputPath: outputPath, Header: &hdr, Meta: meta}, nil
}

func chunkIv(baseIv []byte, idx uint64) []byte {
	iv := make([]byte, ENVELOPE_CHUNK_IV_LEN)
	copy(iv[:4], baseIv[:4])
	binary.BigEndian.PutUint64(iv[4:], idx)

	return iv
}

func chunkAad(alg crypto.AlgSuite, idx uint64) []byte {
	aad := make([]byte, 10)
	binary.BigEndian.PutUint16(aad[:2], uint16(alg))
	binary.BigEndian.PutUint64(aad[2:], idx)

	return aad
}

func DecryptFile(
	inputPath, outputDir string,
	unwrapDek func(recipients []EnvelopeRecipient, suite crypto.AlgSuite) ([]byte, bool),
	senderPub crypto.PublicKeyHandle) (*EnvelopeFileMemo, error) {

	fileName := filepath.Base(inputPath)
	if !strings.HasSuffix(fileName, ".sfe") && !strings.HasSuffix(fileName, ".sfx") {
		return nil, errors.New("envelope file suffix unsupported")
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	stat, err := inFile.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()
	if fileSize < ENVELOPE_FIXED_LEN+ENVELOPE_SIG_LEN {
		return nil, errors.New("envelope file too small")
	}

	// read fixed
	fixed := make([]byte, ENVELOPE_FIXED_LEN)
	if _, err := io.ReadFull(inFile, fixed); err != nil {
		return nil, errors.New("corrupted: cannot read fixed")
	}

	if string(fixed[:8]) != ENVELOPE_MAGIC {
		return nil, errors.New("envelope file magic invalid")
	}

	if string(fixed[8:10]) != ENVELOPE_VERSION {
		return nil, errors.New("envelope file version invalid")
	}

	algCode := crypto.AlgSuite(binary.BigEndian.Uint16(fixed[10:12]))
	headerLen := int(binary.BigEndian.Uint32(fixed[14:18]))

	bodyOffset := int64(ENVELOPE_FIXED_LEN) + int64(headerLen)
	if bodyOffset > fileSize {
		return nil, errors.New("envelope body too small")
	}

	if headerLen == 0 || headerLen > 1024*1024 {
		return nil, errors.New("envelope header too long")
	}

	// read header
	headerBuf := make([]byte, headerLen)
	if _, err := io.ReadFull(inFile, headerBuf); err != nil {
		return nil, errors.New("corrupted: cannot read header")
	}

	var hdr EnvelopeHeader
	if err := json.Unmarshal(headerBuf, &hdr); err != nil {
		return nil, errors.New("envelope header format invalid")
	}

	if _, err := inFile.Seek(-ENVELOPE_SIG_LEN, io.SeekEnd); err != nil {
		return nil, errors.New("corrupted: cannot seek to sig len")
	}

	sigLenBuf := make([]byte, ENVELOPE_SIG_LEN)
	if _, err := io.ReadFull(inFile, sigLenBuf); err != nil {
		return nil, errors.New("corrupted: cannot read to sig len")
	}

	sigLen := binary.BigEndian.Uint32(sigLenBuf)
	if sigLen == 0 || sigLen > 4096 {
		return nil, errors.New("corrupted: sig len invalid")
	}

	sigEnd := fileSize
	sigStart := sigEnd - ENVELOPE_SIG_LEN - int64(sigLen)
	if sigStart <= bodyOffset {
		return nil, errors.New("corrupted: sig len invalid 2")
	}

	bodyEnd := sigStart

	// read signature
	if _, err := inFile.Seek(sigStart, io.SeekStart); err != nil {
		return nil, errors.New("corrupted: cannot seek to signature")
	}

	sig := make([]byte, sigLen)
	if _, err := io.ReadFull(inFile, sig); err != nil {
		return nil, errors.New("corrupted: cannot read signature")
	}

	dek, ok := unwrapDek(hdr.Recipients, algCode)
	if !ok || len(dek) == 0 {
		return nil, errors.New("corrupted: recipient unknown")
	}
	defer util.ByteArrayZero(dek)

	// handle meta
	metaIv, _ := base64.StdEncoding.DecodeString(hdr.Meta.Iv)
	metaTag, _ := base64.StdEncoding.DecodeString(hdr.Meta.Tag)
	metaCipher, _ := base64.StdEncoding.DecodeString(hdr.Meta.Cipher)

	metaPlain, err := symDecryptAad(dek, metaIv, metaCipher, metaTag, []byte("meta"), algCode)
	if err != nil {
		return nil, fmt.Errorf("corrupted: meta decrypt: %w", err)
	}

	var meta EnvelopeMetaPlain
	_ = json.Unmarshal(metaPlain, &meta)

	outDir := outputDir
	if outDir == "" {
		outDir = filepath.Dir(inputPath)
	}

	outputPath := filepath.Join(outDir, fileName[:len(fileName)-4]+meta.Ext)
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	if _, err := inFile.Seek(bodyOffset, io.SeekStart); err != nil {
		return nil, errors.New("corrupted: cannot seek to body")
	}

	hash := sha256.New()
	hash.Write(fixed)
	hash.Write(headerBuf)

	idx := uint64(0)
	chunkPre := make([]byte, ENVELOPE_CHUNK_HEADER_LEN) // len + iv + tag
	ctBuf := make([]byte, hdr.ChunkSize+64)             // reserved padding
	bodyRemaining := bodyEnd - bodyOffset

	for bodyRemaining > 0 {
		if _, err := io.ReadFull(inFile, chunkPre); err != nil {
			return nil, fmt.Errorf("corrupted: chunk %d header: %w", idx, err)
		}

		chunkLen := int(binary.BigEndian.Uint32(chunkPre[:4]))
		if chunkLen < ENVELOPE_CHUNK_IV_LEN+ENVELOPE_CHUNK_TAG_LEN ||
			int64(chunkLen) > bodyRemaining {
			return nil, fmt.Errorf("corrupted: chunk %d len %d", idx, chunkLen)
		}

		iv := chunkPre[4 : 4+ENVELOPE_CHUNK_IV_LEN]
		tag := chunkPre[4+ENVELOPE_CHUNK_IV_LEN : 4+ENVELOPE_CHUNK_IV_LEN+ENVELOPE_CHUNK_TAG_LEN]

		ctLen := chunkLen - ENVELOPE_CHUNK_IV_LEN - ENVELOPE_CHUNK_TAG_LEN
		ct := ctBuf[:ctLen]
		if _, err := io.ReadFull(inFile, ct); err != nil {
			return nil, fmt.Errorf("corrupted: chunk %d ciphertext: %w", idx, err)
		}

		bodyRemaining -= int64(ENVELOPE_CHUNK_HEADER_LEN) + int64(ctLen)

		hash.Write(chunkPre)
		hash.Write(ct)

		aad := chunkAad(algCode, idx)
		plain, err := symDecryptAad(dek, iv, ct, tag, aad, algCode)
		if err != nil {
			return nil, fmt.Errorf("corrupted: chunk %d decrypt: %w", idx, err)
		}

		if _, err := outFile.Write(plain); err != nil {
			return nil, fmt.Errorf("write plaintext: %w", err)
		}

		idx++
	}

	if err := outFile.Sync(); err != nil {
		return nil, fmt.Errorf("flush outfile: %w", err)
	}

	if senderPub != nil {
		p, pErr := crypto.GetProvider(algCode)
		if pErr == nil {
			ok, _ := p.Verify(senderPub, hash.Sum(nil), sig)
			if !ok {
				return nil, errors.New("corrupted: signature verify invalid")
			}
		}
	}

	if err := outFile.Close(); err != nil {
		return nil, err
	}

	return &EnvelopeFileMemo{OutputPath: outputPath, Header: &hdr, Meta: meta}, nil
}

// block encrypt
func symEncryptAad(key, iv, plain, aad []byte, suite crypto.AlgSuite) (ciphertext, tag []byte) {
	switch suite {
	case crypto.AlgRsaAes:
		ct, t, err := aesGcmSeal(key, iv, plain, aad)
		if err != nil {
			panic(err)
		}
		return ct, t
	case crypto.AlgSm2Sm4:
		ct, t, err := sm4HmacEnc(key, iv, plain, aad)
		if err != nil {
			panic(err)
		}
		return ct, t
	}

	panic("unknown suite")
}

// block decrypt
func symDecryptAad(key, iv, ciphertext, tag, aad []byte, suite crypto.AlgSuite) ([]byte, error) {
	switch suite {
	case crypto.AlgRsaAes:
		return aesGcmOpen(key, iv, ciphertext, tag, aad)
	case crypto.AlgSm2Sm4:
		return sm4HmacDec(key, iv, ciphertext, tag, aad)
	}

	return nil, errors.New("decrypt alg suite unsupported")
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
	sm4Key := crypto.Sm3Hash(dek)[:16]
	sm4Iv := crypto.Sm3Hash(iv12)[:16]
	ct := crypto.SM4CbcEncrypt(sm4Key, sm4Iv, plain)

	macKey := sm4Key
	tag := crypto.HmacSm3(macKey, append(append(append([]byte{}, iv12...), aad...), ct...))[:16]

	return ct, tag, nil
}

// sm4 hmac decrypt
func sm4HmacDec(dek, iv12, ciphertext, tag, aad []byte) ([]byte, error) {
	sm4Key := crypto.Sm3Hash(dek)[:16]
	sm4Iv := crypto.Sm3Hash(iv12)[:16]
	macKey := sm4Key

	expected := crypto.HmacSm3(macKey, append(append(append([]byte{}, iv12...), aad...), ciphertext...))[:16]
	if !util.ByteArrayEqual(tag, expected) {
		return nil, errors.New("SM4 HMAC mismatch")
	}

	return crypto.SM4CbcDecrypt(sm4Key, sm4Iv, ciphertext), nil
}
