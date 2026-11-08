package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"sfm/internal/crypto"

	"gopkg.in/yaml.v3"
)

var historyRe = regexp.MustCompile(`^history-(\d+)\.(pub|sk\.enc)$`)

type HistoryKey struct {
	Index       int
	PubPath     string
	SkPath      string
	Fingerprint string
	AlgSuite    crypto.AlgSuite
}

type KeyRecord struct {
	Index       int    `yaml:"index"`
	AlgSuite    string `yaml:"alg_suite"`
	AlgCode     byte   `yaml:"alg_code"`
	Fingerprint string `yaml:"fingerprint"`
	PublicKey   string `yaml:"public_key"`
	PrivateKey  string `yaml:"private_key"`
	CreatedAt   string `yaml:"created_at,omitempty"`
	ArchivedAt  string `yaml:"archived_at,omitempty"`
}

type KeysManifest struct {
	Version   string      `yaml:"version"`
	UpdatedAt string      `yaml:"updated_at,omitempty"`
	Current   *KeyRecord  `yaml:"current,omitempty"`
	History   []KeyRecord `yaml:"history,omitempty"`
}

func (r *Repo) LoadKeysManifest() (*KeysManifest, error) {
	data, err := os.ReadFile(r.KeysManifestPath())
	if err != nil {
		if os.IsNotExist(err) {
			return r.scanKeysManifest(), nil
		}
		return nil, err
	}

	var m KeysManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse keys manifest: %w", err)
	}

	return &m, nil
}

func (r *Repo) SaveKeysManifest(m *KeysManifest) error {
	m.Version = "1"
	m.UpdatedAt = time.Now().Format(time.RFC3339)

	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}

	return os.WriteFile(r.KeysManifestPath(), data, 0o600)
}

func (r *Repo) scanKeysManifest() *KeysManifest {
	m := &KeysManifest{Version: "1"}
	cfgSuite := crypto.SuiteIdByName(r.Cfg.AlgSuite)

	curPub := filepath.Join(r.KeysPath(), "current.pub")
	if _, err := os.Stat(curPub); err == nil {
		fp, s := r.detectPubFingerprint(curPub, cfgSuite)
		m.Current = &KeyRecord{
			Index:       0,
			AlgSuite:    crypto.SuiteName(s),
			AlgCode:     byte(s),
			Fingerprint: fp,
			PublicKey:   "current.pub",
			PrivateKey:  "current.sk.enc",
			CreatedAt:   r.Cfg.CreatedAt.Format(time.RFC3339),
		}
	}

	if entries, err := os.ReadDir(r.KeysPath()); err == nil {
		seen := map[int]bool{}

		for _, e := range entries {
			match := historyRe.FindStringSubmatch(e.Name())
			if match == nil {
				continue
			}

			var idx int
			fmt.Sscanf(match[1], "%d", &idx)
			if seen[idx] {
				continue
			}

			seen[idx] = true

			pubPath := filepath.Join(r.KeysPath(), fmt.Sprintf("history-%02d.pub", idx))
			if _, err := os.Stat(pubPath); err != nil {
				continue
			}

			fp, s := r.detectPubFingerprint(pubPath, cfgSuite)

			m.History = append(m.History, KeyRecord{
				Index:       idx,
				AlgSuite:    crypto.SuiteName(s),
				AlgCode:     byte(s),
				Fingerprint: fp,
				PublicKey:   fmt.Sprintf("history-%02d.pub", idx),
				PrivateKey:  fmt.Sprintf("history-%02d.sk.enc", idx),
			})
		}
	}

	sort.Slice(m.History, func(i, j int) bool { return m.History[i].Index < m.History[j].Index })

	return m
}

func (r *Repo) ListHistoryKeys() ([]HistoryKey, error) {
	m, err := r.LoadKeysManifest()
	if err != nil {
		return nil, err
	}

	cfgSuite := crypto.SuiteIdByName(r.Cfg.AlgSuite)

	var keys []HistoryKey
	for _, rec := range m.History {
		pubPath := filepath.Join(r.KeysPath(), rec.PublicKey)
		skPath := filepath.Join(r.KeysPath(), rec.PrivateKey)
		if _, err := os.Stat(pubPath); err != nil {
			continue
		}

		suite := crypto.SuiteIdByName(rec.AlgSuite)
		if suite == 0 {
			suite = cfgSuite
		}

		fp := rec.Fingerprint
		if fp == "" {
			fp, suite = r.detectPubFingerprint(pubPath, suite)
		}

		keys = append(keys, HistoryKey{
			Index:       rec.Index,
			PubPath:     pubPath,
			SkPath:      skPath,
			Fingerprint: fp,
			AlgSuite:    suite,
		})
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].Index < keys[j].Index })

	return keys, nil
}

func NextIndexFromManifest(m *KeysManifest) int {
	next := 1
	for _, rec := range m.History {
		if rec.Index >= next {
			next = rec.Index + 1
		}
	}

	return next
}

func (r *Repo) detectPubFingerprint(pubPath string, suite crypto.AlgSuite) (string, crypto.AlgSuite) {
	pemBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return "", suite
	}

	candidates := append([]crypto.AlgSuite{suite}, crypto.AllSuites()...)

	for _, s := range candidates {
		provider, err := crypto.GetProvider(s)
		if err != nil {
			continue
		}

		pub, err := provider.UnmarshalPublicKeyPem(pemBytes)
		if err != nil {
			continue
		}

		fp, err := crypto.Fingerprint(pub, s)
		if err != nil || fp == "" {
			continue
		}

		return fp, s
	}

	return "", suite
}
