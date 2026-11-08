package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sfm/internal/crypto"
	"sfm/internal/prompt"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type ExportOrgin string

const (
	ExportedFromCli      ExportOrgin = "sfm-go"       // cli
	ExportedFromElectron ExportOrgin = "sfm-electron" // desktop (windows/linux/macos)
	ExportedFromNative   ExportOrgin = "sfm-native"   // native (android/ios)
)

// .sfpub file structure
type SfpubFile struct {
	Format      string `json:"format"`                   // "sfpub"
	Version     int    `json:"version"`                  // 1
	PublicKey   string `json:"publicKey"`                // PEM
	Fingerprint string `json:"fingerprint"`              // hex.join(':')
	Alg         string `json:"alg"`                      // "rsa-aes" / "sm2-sm4"
	ExportedAt  int64  `json:"exportedAt"`               // unix ms
	ExportedFrom  string `json:"exportedFrom,omitempty"` // 如 "sfm-go" / "sfm-electron"
	Signature   string `json:"signature,omitempty"`      // base64(sign(sha256(payload)))
}

// payload bytes
func (s SfpubFile) signablePayload() ([]byte, error) {
	copyObj := struct {
		Format      string `json:"format"`
		Version     int    `json:"version"`
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
		Alg         string `json:"alg"`
		ExportedAt  int64  `json:"exportedAt"`
		ExportedFrom  string `json:"exportedFrom,omitempty"`
	}{
		Format: s.Format, Version: s.Version,
		PublicKey: s.PublicKey, Fingerprint: s.Fingerprint,
		Alg: s.Alg, ExportedAt: s.ExportedAt, ExportedFrom: s.ExportedFrom,
	}

	return json.Marshal(copyObj)
}

func parsePubkeyInput(content []byte) (suite crypto.AlgSuite, pem string, fingerprint string, isSfpub bool, exportedFrom string, err error) {
	text := strings.TrimSpace(string(content))
	if len(text) == 0 {
		return 0, "", "", false, "", fmt.Errorf("empty public key file")
	}

	if strings.HasPrefix(text, "{") {
		var sf SfpubFile
		if err := json.Unmarshal([]byte(text), &sf); err != nil {
			return 0, "", "", false, "", fmt.Errorf("parse .sfpub JSON: %w", err)
		}

		if sf.Format != "sfpub" || sf.PublicKey == "" {
			return 0, "", "", false, "", fmt.Errorf("not a valid .sfpub file (format=%q)", sf.Format)
		}

		suite = crypto.SuiteIdByName(sf.Alg)
		if suite == 0 {
			if s, ok := detectSuiteFromPem(sf.PublicKey); ok {
				suite = s
			} else {
				return 0, "", "", false, "", fmt.Errorf("unknown alg %q and unable to detect by content", sf.Alg)
			}
		}

		p, _ := crypto.GetProvider(suite)
		if _, err := p.UnmarshalPublicKeyPem([]byte(sf.PublicKey)); err != nil {
			return 0, "", "", false, "", fmt.Errorf("publicKey content does not match declared alg: %w", err)
		}

		fp, _ := crypto.FingerprintPem([]byte(sf.PublicKey), suite)
		if sf.Fingerprint != "" && !strings.EqualFold(sf.Fingerprint, fp) {
			return 0, "", "", false, "", fmt.Errorf("fingerprint mismatch: file claims %s but key computes to %s (file may be tampered)",
				sf.Fingerprint, fp)
		}

		if sf.Signature != "" {
			payload, _ := sf.signablePayload()
			if !verifySfpubSignature(sf, suite, payload) {
				return 0, "", "", false, "", fmt.Errorf(".sfpub signature verification failed")
			}
		}

		return suite, sf.PublicKey, fp, true, sf.ExportedFrom, nil
	}

	// only PEM
	suite, ok := detectSuiteFromPem(text)
	if !ok {
		return 0, "", "", false, "", fmt.Errorf("unable to identify public key format (expected .sfpub JSON or PEM)")
	}

	p, _ := crypto.GetProvider(suite)
	if _, err := p.UnmarshalPublicKeyPem([]byte(text)); err != nil {
		return 0, "", "", false, "", fmt.Errorf("invalid PEM content: %w", err)
	}

	fp, _ := crypto.FingerprintPem([]byte(text), suite)

	return suite, text, fp, false, "", nil
}

func detectSuiteFromPem(content string) (crypto.AlgSuite, bool) {
	if strings.Contains(content, "BEGIN PUBLIC KEY") && !strings.Contains(content, crypto.Sm2PublibKeyPemLabel) {
		p, err := crypto.GetProvider(crypto.AlgRsaAes)
		if err == nil {
			if _, err := p.UnmarshalPublicKeyPem([]byte(content)); err == nil {
				return crypto.AlgRsaAes, true
			}
		}
	}

	if strings.Contains(content, "BEGIN "+crypto.Sm2PublibKeyPemLabel) {
		p, err := crypto.GetProvider(crypto.AlgSm2Sm4)
		if err == nil {
			if _, err := p.UnmarshalPublicKeyPem([]byte(content)); err == nil {
				return crypto.AlgSm2Sm4, true
			}
		}
	}

	return 0, false
}

func verifySfpubSignature(sf SfpubFile, suite crypto.AlgSuite, payload []byte) bool {
	p, err := crypto.GetProvider(suite)
	if err != nil {
		return false
	}

	pub, err := p.UnmarshalPublicKeyPem([]byte(sf.PublicKey))
	if err != nil {
		return false
	}

	digest := sha256.Sum256(payload)
	sig, err := base64.StdEncoding.DecodeString(sf.Signature)
	if err != nil {
		return false
	}

	ok, _ := p.Verify(pub, digest[:], sig)

	return ok
}

// contact name rule
func sanitizeContactName(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_':
			b.WriteRune(c)
		}
	}

	return b.String()
}

// overwrite confirm
func askOverwrite(path string) (bool, error) {
	overwrite, err := prompt.ReadLine(fmt.Sprintf("contacts/%s.yaml already exists. Overwrite? [y/N]: ", path))
	if err != nil {
		return false, nil
	}

	switch strings.ToLower(strings.TrimSpace(overwrite)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// ---------------- export ----------------

var pubExportOutput string
var pubExportFormat string // "sfpub" 或 "pem"
var pubExportPassword string

var pubExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the current public key (.sfpub JSON or plain .pem)",
	Long: `Export the repository's current public key in one of two formats:

  sfpub  (default) self-describing JSON with fingerprint + self-signature.
  pem    Plain PEM (.pem) — standard PKIX for RSA, custom pem for SM2.

Share the exported file with others and they can import it via 'sfm key import'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pubExportOutput == "" {
			return fmt.Errorf("-o <output file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		outPath, err := r.ResolveRepoPath(pubExportOutput)
		if err != nil {
			return err
		}

		password := pubExportPassword
		if password == "" {
			var err error
			password, err = prompt.ReadPassword("Password (for signing the export): ")
			if err != nil {
				return err
			}
		}

		p, pub, sk, suite, fp, err := r.LoadCurrentKey(password)
		if err != nil {
			return fmt.Errorf("load key: %w", err)
		}

		pemBytes, err := p.MarshalPublicKeyPem(pub)
		if err != nil {
			return err
		}

		pemStr := string(pemBytes)

		format := pubExportFormat
		if format == "" {
			switch strings.ToLower(filepath.Ext(outPath)) {
			case ".pem":
				format = "pem"
			default:
				format = "sfpub"
			}
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
			return err
		}

		if format == "pem" {
			if err := os.WriteFile(outPath, []byte(pemStr), 0o600); err != nil {
				return err
			}

			fmt.Printf("Exported -> %s  (plain PEM, %s)\n", outPath, crypto.SuiteName(suite))
			fmt.Printf("  Fingerprint: %s\n", fp)
			return nil
		}

		sf := SfpubFile{
			Format:       "sfpub",
			Version:      1,
			PublicKey:    pemStr,
			Fingerprint:  fp,
			Alg:          crypto.SuiteName(suite),
			ExportedAt:   time.Now().UnixMilli(),
			ExportedFrom: string(ExportedFromCli),
		}

		payload, _ := sf.signablePayload()
		digest := sha256.Sum256(payload)
		sig, err := p.Sign(sk, digest[:])
		if err != nil {
			return fmt.Errorf("sign export: %w", err)
		}

		sf.Signature = base64.StdEncoding.EncodeToString(sig)

		data, err := json.MarshalIndent(&sf, "", "  ")
		if err != nil {
			return err
		}

		if err := os.WriteFile(outPath, data, 0o600); err != nil {
			return err
		}

		fmt.Printf("Exported -> %s  (.sfpub JSON, %s, signed)\n", outPath, crypto.SuiteName(suite))
		fmt.Printf("  Fingerprint: %s\n", fp)
		fmt.Printf("  ExportedFrom:  %s\n", ExportedFromCli)
		return nil
	},
}

// ---------------- import ----------------

var pubImportInput string
var pubImportName string

var pubImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a public key (.sfpub JSON or plain .pem)",
	Long: `Import a public key into the repository's contacts/ directory.

Supported inputs:
  - .sfpub JSON  (preferred) with fingerprint + optional signature
  - .pem         plain PEM — RSA standard PKIX, SM2 custom PEM

Contact naming rules:
  - .sfpub:  if --name is omitted, takes the input file's basename
             (without extension) as the contact name
  - .pem:    --name is REQUIRED, because PEM has no embedded identity

If a contact file with the chosen name already exists you are prompted
whether to overwrite it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pubImportInput == "" {
			return fmt.Errorf("-i <input file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		inPath, err := r.ResolveRepoPath(pubImportInput)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("read public key file: %w", err)
		}

		suite, pemStr, fp, isSfpub, exportedFrom, err := parsePubkeyInput(data)
		if err != nil {
			return err
		}

		var name string

		if pubImportName != "" {
			name = pubImportName
		} else if isSfpub {
			base := filepath.Base(inPath)
			base = strings.TrimSuffix(base, filepath.Ext(base))
			name = base
		} else {
			return fmt.Errorf("--name is required when importing a plain PEM file")
		}

		name = sanitizeContactName(name)
		if name == "" {
			return fmt.Errorf("contact name is empty after sanitization")
		}

		contactsDir := r.ContactsPath()
		if err := os.MkdirAll(contactsDir, 0o700); err != nil {
			return err
		}

		outPath := filepath.Join(contactsDir, name+".yaml")
		if _, err := os.Stat(outPath); err == nil {
			ok, err := askOverwrite(name)
			if err != nil {
				return err
			}

			if !ok {
				fmt.Println("Import cancelled.")
				return nil
			}
		}

		algShort := strings.Split(crypto.SuiteName(suite), "-")[0]

		rf := RecipientFile{Recipients: []RecipientEntry{{
			Name: name,
			Alg:  algShort,
			Pub:  pemStr,
		}}}

		out, err := yaml.Marshal(&rf)
		if err != nil {
			return err
		}

		if err := os.WriteFile(outPath, out, 0o600); err != nil {
			return err
		}

		fmt.Printf("Imported -> %s\n", outPath)
		fmt.Printf("  Name:        %s\n", name)
		fmt.Printf("  Suite:       %s\n", crypto.SuiteName(suite))
		fmt.Printf("  Fingerprint: %s\n", fp)
		if isSfpub && exportedFrom != "" {
			fmt.Printf("  ExportedFrom:  %s\n", exportedFrom)
		}
		fmt.Println()

		return nil
	},
}

func init() {
	// export args
	pubExportCmd.Flags().StringVarP(&pubExportOutput, "output", "o", "", "Output file path inside the repository scope (required)")
	pubExportCmd.Flags().StringVar(&pubExportFormat, "format", "", "Output format: sfpub (default) | pem (infer from extension)")
	pubExportCmd.Flags().StringVar(&pubExportPassword, "password", "", "Password (omit to prompt)")
	// import args
	pubImportCmd.Flags().StringVarP(&pubImportInput, "input", "i", "", "Input public key file path : .sfpub or .pem (required)")
	pubImportCmd.Flags().StringVarP(&pubImportName, "name", "n", "", "Contact name, will be file name: contacts/<name>.yaml (required)")
	
	pubCmd.AddCommand(pubExportCmd, pubImportCmd)
}
