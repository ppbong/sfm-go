package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sfm/internal/crypto"
	"sfm/internal/envelope"
	"sfm/internal/prompt"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var encInput string
var encOutput string
var encPassword string
var encFileSuffix string

var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "Encrypt a file into an .sfe envelope",
	Long: `Encrypt a file with your current key pair. 

The input is a plain file name located in the repository scope.
The output is directory`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if encInput == "" {
			return fmt.Errorf("-i <input file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		inputPath := encInput

		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input file not found: %s", inputPath)
		}

		password := encPassword
		if password == "" {
			var err error
			password, err = prompt.ReadPassword("Password: ")
			if err != nil {
				return err
			}
		}

		_, pub, sk, suite, fp, err := r.LoadCurrentKey(password)
		if err != nil {
			return fmt.Errorf("load key: %w", err)
		}

		outputDir := encOutput

		if outputDir == "" {
			outputDir = filepath.Dir(inputPath)
		}

		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return err
		}

		baseName := filepath.Base(inputPath)
		count := strings.Count(baseName, ".")

		var fileExt string

		if count == 0 {
			fileExt = ""
		} else if count == 1 {
			fileExt = strings.Split(baseName, ".")[1]
		} else {
			if encFileSuffix == "" {
				return fmt.Errorf("filename has %d dot more than one, need --ext args", count)
			}

			fileExt = encFileSuffix
		}

		dek := make([]byte, 32)
		rand.Read(dek)

		// as a recipient
		recipients := []envelope.Recipient{
			{Fingerprint: fp, PublicKey: pub},
		}

		stat, _ := os.Stat(inputPath)
		meta := envelope.EnvelopeMetaPlain{
			Name: baseName,
			Ext:  fileExt,
			Size: uint64(stat.Size()),
			Mime: "application/octet-stream",
		}

		memo, err := envelope.EncryptFile(inputPath, outputDir, dek, suite,
			recipients, pub, sk, fp, meta, false, 0)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		// append to manifest
		_ = r.AppendManifest(repo.FileEntry{
			Name:      filepath.Base(memo.OutputPath),
			Path:      memo.OutputPath,
			Kind:      "encrypted",
			Size:      stat.Size(),
			CreatedAt: time.Now(),
		})

		fmt.Printf("Encrypted -> %s\n", memo.OutputPath)
		fmt.Printf("  Suite:       %s\n", crypto.SuiteName(suite))
		fmt.Printf("  Recipients:  1 (you)\n")
		return nil
	},
}

func init() {
	encCmd.Flags().StringVarP(&encInput, "input", "i", "", "Input file name in the repository scope (required)")
	encCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output directory (optional)")
	encCmd.Flags().StringVar(&encFileSuffix, "ext", "", "Input file suffix include dot, if file name contains more than one dot")
	encCmd.Flags().StringVar(&encPassword, "password", "", "Password (omit to prompt)")
	rootCmd.AddCommand(encCmd)
}
