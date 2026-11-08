package repo

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sfm/internal/crypto"
)

func (r *Repo) LoadSalt() ([]byte, error) {
	return hexDecode(r.Cfg.SaltHex)
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}

	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var hi, lo byte
		for ci, c := range s[i : i+2] {
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = byte(c - '0')
			case c >= 'a' && c <= 'f':
				v = byte(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = byte(c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex char %c", c)
			}
			if ci == 0 {
				hi = v << 4
			} else {
				lo = v
			}
		}
		out[i/2] = hi | lo
	}

	return out, nil
}

func (r *Repo) LoadCurrentKey(password string) (crypto.Provider, crypto.PublicKeyHandle, crypto.PrivateKeyHandle, crypto.AlgSuite, string, error) {
	suite := crypto.SuiteIdByName(r.Cfg.AlgSuite)
	if suite == 0 {
		return nil, nil, nil, 0, "", fmt.Errorf("unknown alg_suite in config: %s", r.Cfg.AlgSuite)
	}

	provider, err := crypto.GetProvider(suite)
	if err != nil {
		return nil, nil, nil, 0, "", err
	}

	pemBytes, err := os.ReadFile(filepath.Join(r.KeysPath(), "current.pub"))
	if err != nil {
		return nil, nil, nil, 0, "", fmt.Errorf("read pub: %w", err)
	}

	pub, err := provider.UnmarshalPublicKeyPem(pemBytes)
	if err != nil {
		return nil, nil, nil, 0, "", fmt.Errorf("parse pub: %w", err)
	}

	salt, err := r.LoadSalt()
	if err != nil {
		return nil, nil, nil, 0, "", fmt.Errorf("read salt: %w", err)
	}

	ppk, err := crypto.DerivePpk(password, salt)
	if err != nil {
		return nil, nil, nil, 0, "", err
	}

	defer zero(ppk)

	box, err := os.ReadFile(filepath.Join(r.KeysPath(), "current.sk.enc"))
	if err != nil {
		return nil, nil, nil, 0, "", fmt.Errorf("read sk: %w", err)
	}

	sk, err := crypto.DecryptPrivateKey(ppk, box)
	if err != nil {
		return nil, nil, nil, 0, "", err
	}

	fp, _ := crypto.Fingerprint(pub, suite)

	return provider, pub, sk, suite, fp, nil
}

func (r *Repo) LoadCurrentPub() (crypto.Provider, crypto.PublicKeyHandle, crypto.AlgSuite, string, error) {
	suite := crypto.SuiteIdByName(r.Cfg.AlgSuite)
	if suite == 0 {
		return nil, nil, 0, "", fmt.Errorf("unknown alg_suite in config: %s", r.Cfg.AlgSuite)
	}

	provider, err := crypto.GetProvider(suite)
	if err != nil {
		return nil, nil, 0, "", err
	}

	pemBytes, err := os.ReadFile(filepath.Join(r.KeysPath(), "current.pub"))
	if err != nil {
		return nil, nil, 0, "", err
	}

	pub, err := provider.UnmarshalPublicKeyPem(pemBytes)
	if err != nil {
		return nil, nil, 0, "", err
	}

	fp, _ := crypto.Fingerprint(pub, suite)

	return provider, pub, suite, fp, nil
}

func (r *Repo) GetSalt() ([]byte, error) { return r.LoadSalt() }

func (r *Repo) FindMyRecipient(recs []crypto.Recipient) (*crypto.Recipient, string, bool) {
	if len(recs) == 0 {
		return nil, "", false
	}

	// match current
	curFp := r.Cfg.CurrentFingerprint
	if curFp == "" {
		if _, _, _, fp, err := r.LoadCurrentPub(); err == nil {
			curFp = fp
		}
	}

	if curFp != "" {
		for i := range recs {
			if strings.EqualFold(recs[i].Fingerprint, curFp) {
				return &recs[i], filepath.Join(r.KeysPath(), "current.sk.enc"), true
			}
		}
	}

	// match history
	history, err := r.ListHistoryKeys()
	if err != nil {
		return nil, "", false
	}

	idx := make(map[string]string, len(history))
	for _, h := range history {
		if h.Fingerprint != "" {
			idx[strings.ToUpper(h.Fingerprint)] = h.SkPath
		}
	}

	for i := range recs {
		if skPath, ok := idx[strings.ToUpper(recs[i].Fingerprint)]; ok {
			return &recs[i], skPath, true
		}
	}

	return nil, "", false
}

func (r *Repo) UnwrapDekForRecipients(password string, recs []crypto.Recipient, fileAlg crypto.AlgSuite) ([]byte, bool) {
	rec, skPath, ok := r.FindMyRecipient(recs)
	if !ok {
		return nil, false
	}

	rAlg := fileAlg
	if rec.AlgCode != nil {
		rAlg = crypto.AlgSuite(*rec.AlgCode)
	}

	provider, err := crypto.GetProvider(rAlg)
	if err != nil {
		return nil, false
	}

	wrapped, err := b64Decode(rec.WrappedDek)
	if err != nil {
		return nil, false
	}

	salt, err := r.LoadSalt()
	if err != nil {
		return nil, false
	}

	ppk, err := crypto.DerivePpk(password, salt)
	if err != nil {
		return nil, false
	}

	defer zero(ppk)

	dek, ok := tryUnwrapWithBox(provider, ppk, skPath, wrapped)

	return dek, ok
}

func tryUnwrapWithBox(provider crypto.Provider, ppk []byte, boxPath string, wrapped []byte) ([]byte, bool) {
	box, err := os.ReadFile(boxPath)
	if err != nil {
		return nil, false
	}

	sk, err := crypto.DecryptPrivateKey(ppk, box)
	if err != nil {
		return nil, false
	}

	dek, err := provider.UnwrapDek(sk, wrapped)
	if err != nil || len(dek) == 0 {
		return nil, false
	}

	return dek, true
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
