package cmd

import (
	"crypto/rand"
	"encoding/base64"
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

var shareInput string
var shareContacts string
var shareOutput string
var sharePassword string

type RecipientFile struct {
	Recipients []RecipientEntry `yaml:"recipients"`
}

type RecipientEntry struct {
	Name string `yaml:"name,omitempty"`
	Alg  string `yaml:"alg"`  // "rsa" or "sm2"
	Pub  string `yaml:"pub"`  // PEM for RSA, SM2
}

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Encrypt a file for one or more recipients (outputs .sfx)",
	Long: `Encrypt a file so that specified recipients can decrypt it.
	
The input is a plain file name located in the repository scope.
The output is stored in shared/ directory by default with .sfx extension.
Recipient public keys are read from one or more YAML file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if shareInput == "" {
			return fmt.Errorf("-i <input> is required")
		}

		if shareContacts == "" {
			return fmt.Errorf("--contact <name1,name2,...> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		inputPath, err := r.ResolveFileName(shareInput)
		if err != nil {
			return err
		}

		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input file not found in repository: %s", shareInput)
		}

		password := sharePassword
		if password == "" {
			var err error
			password, err = prompt.ReadPassword("Password: ")
			if err != nil {
				return err
			}
		}

		_, myPub, mySk, mySuite, myFp, err := r.LoadCurrentKey(password)
		if err != nil {
			return fmt.Errorf("load key: %w", err)
		}

		recPath, err := r.ResolveRepoPath(shareContacts)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(recPath)
		if err != nil {
			return fmt.Errorf("read recipients: %w", err)
		}

		var rf RecipientFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return fmt.Errorf("parse recipients YAML: %w", err)
		}

		if len(rf.Recipients) == 0 {
			return fmt.Errorf("no recipients in %s", shareContacts)
		}

		recipients := []crypto.RecipientInput{}
		for _, entry := range rf.Recipients {
			suite := crypto.SuiteIdByName(entry.Alg)
			if suite == 0 {
				return fmt.Errorf("unknown alg %q for recipient %s", entry.Alg, entry.Name)
			}

			p, err := crypto.GetProvider(suite)
			if err != nil {
				return err
			}

			var pemBytes []byte
			if strings.Contains(entry.Pub, "BEGIN ") {
				pemBytes = []byte(entry.Pub)
			} else {
				pemBytes, err = base64.StdEncoding.DecodeString(entry.Pub)
				if err != nil {
					return fmt.Errorf("decode pub for %s: %w", entry.Name, err)
				}
			}

			pub, err := p.UnmarshalPublicKeyPem(pemBytes)
			if err != nil {
				return fmt.Errorf("parse pub for %s: %w", entry.Name, err)
			}

			fp, _ := crypto.Fingerprint(pub, suite)
			algByte := byte(suite)

			recipients = append(recipients, crypto.RecipientInput{
				Fingerprint: fp,
				PublicKey:   pub,
				AlgCode:     &algByte,
			})
		}

		outDir := r.SharePath()
		outputPath := ""
		if shareOutput != "" {
			p, err := r.ResolveRepoPath(shareOutput)
			if err != nil {
				return err
			}

			outputPath = p
			outDir = filepath.Dir(p)
		}

		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return err
		}

		baseName := filepath.Base(inputPath)
		outName := baseName + ".sfx"
		if outputPath == "" {
			outputPath = filepath.Join(outDir, outName)
		}

		dek := make([]byte, 32)
		rand.Read(dek)

		stat, _ := os.Stat(inputPath)
		meta := crypto.EnvelopeMeta{Name: baseName, Size: stat.Size()}

		err = crypto.EncryptFile(inputPath, outputPath, dek, mySuite,
			recipients, myPub, mySk, myFp, meta, true, 0)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		_ = r.AppendManifest(repo.FileEntry{
			Name:      filepath.Base(outputPath),
			Path:      outputPath,
			Kind:      "shared",
			Size:      stat.Size(),
			CreatedAt: time.Now(),
		})

		fmt.Printf("Shared   -> %s\n", outputPath)
		fmt.Printf("  Suite:       %s\n", crypto.SuiteName(mySuite))
		fmt.Printf("  Recipients:  %d\n", len(recipients))
		for i, entry := range rf.Recipients {
			name := entry.Name
			if name == "" {
				name = fmt.Sprintf("#%d", i+1)
			}
			fmt.Printf("    - %s (%s)\n", name, entry.Alg)
		}

		return nil
	},
}

func init() {
	shareCmd.Flags().StringVarP(&shareInput, "input", "i", "", "Input file name in the repository root (required)")
	shareCmd.Flags().StringVarP(&shareContacts, "contact", "c", "", "Contact names with comma to separate (required)")
	shareCmd.Flags().StringVarP(&shareOutput, "output", "o", "", "Output path inside the repository (default: shared/<name>.sfx)")
	shareCmd.Flags().StringVar(&sharePassword, "password", "", "Password (omit to prompt)")
	rootCmd.AddCommand(shareCmd)
}
