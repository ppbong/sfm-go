package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sfm/internal/crypto"

	"gopkg.in/yaml.v3"
)

const (
	RepoDir          = ".sfm"
	ConfigFile       = "config.yaml"
	KeysDir          = "keys"
	MetaDir          = "meta"
	EncDir           = "encrypted"
	ShareDir         = "shared"
	InboxDir         = "inbox"
	PlainDir         = "plain"
	ContactsDir      = "contacts"
	ManifestFile     = "manifest.yaml"
	KeysManifestFile = "manifest-keys.yaml"
)

type Config struct {
	Version            string    `yaml:"version"`
	CreatedAt          time.Time `yaml:"created_at"`
	AlgSuite           string    `yaml:"alg_suite"`
	CurrentFingerprint string    `yaml:"current_key_fingerprint"`
	SaltHex            string    `yaml:"salt_hex"`
	KeysDir            string    `yaml:"keys_dir"`
	OutputDirs         struct {
		Encrypted string `yaml:"encrypted"`
		Shared    string `yaml:"shared"`
		Inbox     string `yaml:"inbox"`
		Plain     string `yaml:"plain"`
	} `yaml:"output_dirs"`
}

type Repo struct {
	Root string
	Cfg  *Config
}

// find repo
func FindRepo(startDir string) (string, error) {
	dir := startDir
	for {
		p := filepath.Join(dir, RepoDir)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
	}

	return "", fmt.Errorf("not inside an sfm repository (no .sfm/ found)")
}

// load repo config
func LoadRepo(cwd string) (*Repo, error) {
	root, err := FindRepo(cwd)
	if err != nil {
		return nil, err
	}

	cfg, err := LoadConfig(root)
	if err != nil {
		return nil, err
	}

	return &Repo{Root: root, Cfg: cfg}, nil
}

func (r *Repo) ConfigPath() string       { return filepath.Join(r.Root, ConfigFile) }
func (r *Repo) KeysPath() string         { return filepath.Join(r.Root, KeysDir) }
func (r *Repo) MetaPath() string         { return filepath.Join(r.Root, MetaDir) }
func (r *Repo) ManifestPath() string     { return filepath.Join(r.Root, MetaDir, ManifestFile) }
func (r *Repo) KeysManifestPath() string { return filepath.Join(r.Root, MetaDir, KeysManifestFile) }

func (r *Repo) BaseDir() string { return filepath.Dir(r.Root) }

func (r *Repo) dirPath(cfgVal, def string) string {
	if cfgVal == "" {
		return filepath.Join(r.BaseDir(), def)
	}

	if !filepath.IsAbs(cfgVal) {
		return filepath.Join(r.BaseDir(), cfgVal)
	}

	if r.IsInside(cfgVal) {
		return cfgVal
	}

	return filepath.Join(r.BaseDir(), def)
}

func (r *Repo) EncPath() string   { return r.dirPath(r.Cfg.OutputDirs.Encrypted, EncDir) }
func (r *Repo) SharePath() string { return r.dirPath(r.Cfg.OutputDirs.Shared, ShareDir) }
func (r *Repo) InboxPath() string { return r.dirPath(r.Cfg.OutputDirs.Inbox, InboxDir) }
func (r *Repo) PlainPath() string { return r.dirPath(r.Cfg.OutputDirs.Plain, PlainDir) }

func (r *Repo) ContactsPath() string { return filepath.Join(r.BaseDir(), ContactsDir) }

var DefaultStorageDirs = []string{EncDir, ShareDir, InboxDir, PlainDir}

func (r *Repo) cipherStorageDir(name string) (string, bool) {
	switch name {
	case EncDir:
		return r.EncPath(), true
	case ShareDir:
		return r.SharePath(), true
	case InboxDir:
		return r.InboxPath(), true
	}

	return "", false
}

func (r *Repo) plainStorageDir(name string) (string, bool) {
	switch name {
	case PlainDir:
		return r.PlainPath(), true
	}

	return "", false
}

func (r *Repo) IsInside(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}

	base, err := filepath.Abs(r.BaseDir())
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(base, abs)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// specail decrypt input directory: encrypted/ shared/ inbox/
func (r *Repo) ResolveInputRef(ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("input is required")
	}

	if filepath.IsAbs(ref) {
		return "", fmt.Errorf("input must be a relative path starting with encrypted/, shared/ or inbox/")
	}

	for _, part := range strings.Split(filepath.ToSlash(ref), "/") {
		if part == ".." {
			return "", fmt.Errorf("input must not contain '..'")
		}
	}

	clean := filepath.Clean(ref)
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) < 2 {
		return "", fmt.Errorf("input must start with one of: encrypted/, shared/, inbox/")
	}

	dir, ok := r.cipherStorageDir(parts[0])
	if !ok {
		return "", fmt.Errorf("input must start with one of: encrypted/, shared/, inbox/ (got %q)", parts[0])
	}

	fp := filepath.Join(append([]string{dir}, parts[1:]...)...)
	if !r.IsInside(fp) {
		return "", fmt.Errorf("input path escapes the repository")
	}
	
	return fp, nil
}

// special encrpt input and decrypt output directory: plain/
func (r *Repo) ResolveFileName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("file name is required")
	}

	if filepath.IsAbs(name) || strings.ContainsRune(name, filepath.Separator) ||
		name == "." || name == ".." {
		return "", fmt.Errorf("input must be a plain file name without path")
	}

	p := filepath.Join(r.PlainPath(), name)
	if !r.IsInside(p) {
		return "", fmt.Errorf("input path escapes the repository")
	}

	return p, nil
}

// repo scope
func (r *Repo) ResolveRepoPath(ref string) (string, error) {
	var p string

	if filepath.IsAbs(ref) {
		p = filepath.Clean(ref)
	} else {
		p = filepath.Join(r.BaseDir(), ref)
	}

	if !r.IsInside(p) {
		return "", fmt.Errorf("output path %q is outside the repository (%s)", ref, r.BaseDir())
	}

	return p, nil
}

// load config file
func LoadConfig(repoRoot string) (*Config, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ConfigFile))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// save config file
func SaveConfig(repoRoot string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(repoRoot, ConfigFile), data, 0o600)
}

// initialize repo
func InitRepo(cwd string, suite crypto.AlgSuite, password string) (*Repo, error) {
	repoRoot := filepath.Join(cwd, RepoDir)
	if _, err := os.Stat(repoRoot); err == nil {
		return nil, fmt.Errorf("sfm repo already exists at %s", repoRoot)
	}

	dirs := []string{
		repoRoot,
		filepath.Join(repoRoot, KeysDir),
		filepath.Join(repoRoot, MetaDir),
		filepath.Join(cwd, EncDir),
		filepath.Join(cwd, ShareDir),
		filepath.Join(cwd, InboxDir),
		filepath.Join(cwd, PlainDir),
		filepath.Join(cwd, ContactsDir),
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	provider, err := crypto.GetProvider(suite)
	if err != nil {
		return nil, err
	}

	pub, sk, err := provider.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	fp, err := crypto.Fingerprint(pub, suite)
	if err != nil {
		return nil, err
	}

	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}

	ppk, err := crypto.DerivePpk(password, salt)
	if err != nil {
		return nil, err
	}

	defer zero(ppk)

	box, err := crypto.EncryptPrivateKey(ppk, sk, suite)
	if err != nil {
		return nil, err
	}

	pemBytes, err := provider.MarshalPublicKeyPem(pub)
	if err != nil {
		return nil, err
	}

	pubFile := filepath.Join(repoRoot, KeysDir, "current.pub")
	skFile := filepath.Join(repoRoot, KeysDir, "current.sk.enc")

	if err := os.WriteFile(pubFile, pemBytes, 0o600); err != nil {
		return nil, err
	}

	if err := os.WriteFile(skFile, box, 0o600); err != nil {
		return nil, err
	}

	cfg := &Config{
		Version:            "1",
		CreatedAt:          time.Now(),
		AlgSuite:           crypto.SuiteName(suite),
		CurrentFingerprint: fp,
		SaltHex:            fmt.Sprintf("%x", salt),
		KeysDir:            KeysDir,
	}

	cfg.OutputDirs.Encrypted = EncDir
	cfg.OutputDirs.Shared = ShareDir
	cfg.OutputDirs.Inbox = InboxDir
	cfg.OutputDirs.Plain = PlainDir

	if err := SaveConfig(repoRoot, cfg); err != nil {
		return nil, err
	}

	repo := &Repo{Root: repoRoot, Cfg: cfg}

	km := &KeysManifest{
		Version: "1",
		Current: &KeyRecord{
			Index:       0,
			AlgSuite:    crypto.SuiteName(suite),
			AlgCode:     byte(suite),
			Fingerprint: fp,
			PublicKey:   "current.pub",
			PrivateKey:  "current.sk.enc",
			CreatedAt:   cfg.CreatedAt.Format(time.RFC3339),
		},
	}

	if err := repo.SaveKeysManifest(km); err != nil {
		return nil, err
	}

	return repo, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
