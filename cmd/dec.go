package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sfm/internal/crypto"
	"sfm/internal/prompt"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var decInput string
var decOutput string
var decPassword string

var decCmd = &cobra.Command{
	Use:   "dec",
	Short: "Decrypt an .sfe or .sfx envelope file",
	Long: `Decrypt an encrypted file. Tries the current key first, then all history keys.

The input must be a relative path prefixed with one of the repository data directories:
  (default) encrypted/<file>   files you encrypted yourself
  (default) shared/<file>      files you shared with others
  (default) inbox/<file>       files shared to you by others

Output defaults to the repository data directory:
  (default) plain/             directory you decrypted output`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if decInput == "" {
			return fmt.Errorf("-i <input file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		// encrypted/ shared/ inbox/
		inputPath, err := r.ResolveInputRef(decInput)
		if err != nil {
			return err
		}

		if _, err := os.Stat(inputPath); err != nil {
			return fmt.Errorf("input file not found: %s", decInput)
		}

		password := decPassword
		if password == "" {
			var err error
			password, err = prompt.ReadPassword("Password: ")
			if err != nil {
				return err
			}
		}

		outputDir := r.PlainPath() // r.BaseDir()/plain

		if decOutput != "" {
			p, err := r.ResolveRepoPath(decOutput)
			if err != nil {
				return err
			}

			outputDir = p
		}

		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return err
		}

		baseName := filepath.Base(inputPath)
		origName := baseName

		if strings.HasSuffix(origName, ".sfe") {
			origName = origName[:len(origName)-4]
		} else if strings.HasSuffix(origName, ".sfx") {
			origName = origName[:len(origName)-4]
		}

		var senderPub crypto.PublicKeyHandle = nil

		res, err := crypto.DecryptFile(inputPath, outputDir,
			func(recs []crypto.Recipient, fileAlg crypto.AlgSuite) ([]byte, bool) {
				return r.UnwrapDekForRecipients(password, recs, fileAlg)
			},
			senderPub)

		if err != nil {
			if err == crypto.ErrNoMatchingKey {
				return fmt.Errorf("no matching private key found: this file was neither encrypted by you nor shared to you")
			}

			return fmt.Errorf("decrypt: %w", err)
		}

		fmt.Printf("Decrypted -> %s\n", res.OutputPath)
		fmt.Printf("  File ID:     %s\n", res.Header.FileId)
		fmt.Printf("  Sender FP:   %s\n", res.Header.Sender.Fingerprint)
		if res.Meta.Name != "" {
			fmt.Printf("  Orig name:   %s\n", res.Meta.Name)
		}
		
		return nil
	},
}

func init() {
	decCmd.Flags().StringVarP(&decInput, "input", "i", "", "Input file path relative to the repo, default: encrypted/* shared/* inbox/* (required)")
	decCmd.Flags().StringVarP(&decOutput, "output", "o", "", "Output directory inside the repository, default: plain/ (optional)")
	decCmd.Flags().StringVar(&decPassword, "password", "", "Password (omit to prompt)")
	rootCmd.AddCommand(decCmd)
}
