package envelope

import "sfm/internal/crypto"

const (
	ENVELOPE_MAGIC              = "SFMENC01"
	ENVELOPE_VERSION            = "10" // 1.0
	ENVELOPE_FIXED_LEN          = 22   // magic + version + alg + flag + hlen + reserved
	ENVELOPE_CHUNK_DEFAULT_SIZE = 4 * 1024 * 1024
	ENVELOPE_CHUNK_HEADER_LEN   = 32 // size + iv + tag
	ENVELOPE_CHUNK_IV_LEN       = 12
	ENVELOPE_CHUNK_TAG_LEN      = 16
	ENVELOPE_SIG_LEN            = 4 // signature
	ENVELOPE_META_IV_LEN        = 12
)

const (
	FLAG_LOCAL uint16 = 0
	FLAG_SHARE uint16 = 0x0001
)

type EnvelopeFile struct {
	Fixed        EnvelopeFixed
	Header       EnvelopeHeader
	Chunks       []EnvelopeChunk
	Signature    *byte
	SignatureLen uint32
}

type EnvelopeFixed struct {
	Magic             string
	Version           string
	AlgCode           uint16
	ShareFlag         uint16
	EnvelopeHeaderLen uint32
	reserved          uint32
}

type EnvelopeHeader struct {
	FileId string `json:"fileId"`
	Meta   struct {
		Iv     string `json:"iv"`     // base64
		Tag    string `json:"tag"`    // base64
		Cipher string `json:"cipher"` // base64
	} `json:"meta"`
	ChunkSize uint32 `json:"chunkSize"`
	CreatedAt int64  `json:"createdAt"`
	Sender    struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"sender"`
	Recipients []EnvelopeRecipient `json:"recipients"`
}

type EnvelopeMetaPlain struct {
	Name string `json:"name"` // include ext (eg: test.txt)
	Ext  string `json:"ext"`  // include dot (eg: .txt)
	Size uint64 `json:"size"`
	Mime string `json:"mime"`
}

type EnvelopeRecipient struct {
	Fingerprint string `json:"fingerprint"`
	AlgCode     uint16 `json:"algCode"`
	WrappedDek  string `json:"wrappedDek"` // base64
}

type EnvelopeChunk struct {
	Size   uint32
	Iv     *byte // 12 bytes
	Tag    *byte // 16 bytes
	Cipher *byte
}

type Recipient struct {
	Fingerprint string
	PublicKey   crypto.PublicKeyHandle
	AlgCode     uint16
	wrappedDek  string // base64
}

type EnvelopeFileMemo struct {
	OutputPath string
	Header     *EnvelopeHeader
	Meta       EnvelopeMetaPlain
}
