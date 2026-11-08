package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sfm/internal/crypto"
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
The output is stored in the repository's encrypted/ directory by default, with .sfe extension.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if encInput == "" {
			return fmt.Errorf("-i <input file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		inputPath, err := r.ResolveFileName(encInput)
		if err != nil {
			return err
		}

		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input file not found in repository root: %s", encInput)
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

		outDir := r.EncPath()
		outputPath := ""

		if encOutput != "" {
			p, err := r.ResolveRepoPath(encOutput)
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
		count := strings.Count(baseName, ".")

		var fileName string
		var fileExt string

		if count == 0 {
			fileName = baseName
			fileExt = ""
		} else if count == 1 {
			parts := strings.Split(fileName, ".")
			fileName = parts[0]
			fileExt = parts[1]
		} else {
			if encFileSuffix == "" {
				return fmt.Errorf("filename has %d dot more than one, need --ext args", count)
			}

			fileName = strings.ReplaceAll(baseName, encFileSuffix, ".sfe")
			fileExt = encFileSuffix
		}

		if outputPath == "" {
			outputPath = filepath.Join(outDir, fileName)
		}

		dek := make([]byte, 32)
		rand.Read(dek)

		// as a recipient
		recipients := []crypto.RecipientInput{
			{Fingerprint: fp, PublicKey: pub},
		}

		stat, _ := os.Stat(inputPath)
		meta := crypto.EnvelopeMeta{
			Name: baseName,
			Ext: fileExt,
			Size: stat.Size(),
			Mime: "application/octet-stream",
		}

		err = crypto.EncryptFile(inputPath, outputPath, dek, suite,
			recipients, pub, sk, fp, meta, false, 0)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		// append to manifest
		_ = r.AppendManifest(repo.FileEntry{
			Name:      filepath.Base(outputPath),
			Path:      outputPath,
			Kind:      "encrypted",
			Size:      stat.Size(),
			CreatedAt: time.Now(),
		})

		fmt.Printf("Encrypted -> %s\n", outputPath)
		fmt.Printf("  Suite:       %s\n", crypto.SuiteName(suite))
		fmt.Printf("  Recipients:  1 (you)\n")
		return nil
	},
}

func init() {
	encCmd.Flags().StringVarP(&encInput, "input", "i", "", "Input file name in the repository scope (required)")
	encCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output path inside the repository scope, default: encrypted/* (optional)")
	encCmd.Flags().StringVar(&encFileSuffix, "ext", "", "Input file suffix include dot, if file name contains more than one dot")
	encCmd.Flags().StringVar(&encPassword, "password", "", "Password (omit to prompt)")
	rootCmd.AddCommand(encCmd)
}
