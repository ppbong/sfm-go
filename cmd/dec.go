package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"sfm/internal/crypto"
	"sfm/internal/envelope"
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

Input is file path,Output is file directory`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if decInput == "" {
			return fmt.Errorf("-i <input file> is required")
		}

		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		inputPath := decInput

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

		outputDir := decOutput
		if outputDir == "" {
			outputDir = filepath.Base(inputPath)
		}

		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return err
		}

		var senderPub crypto.PublicKeyHandle = nil

		res, err := envelope.DecryptFile(inputPath, outputDir,
			func(recs []envelope.EnvelopeRecipient, fileAlg crypto.AlgSuite) ([]byte, bool) {
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
	decCmd.Flags().StringVarP(&decInput, "input", "i", "", "Input file path (required)")
	decCmd.Flags().StringVarP(&decOutput, "output", "o", "", "Output directory  (optional)")
	decCmd.Flags().StringVar(&decPassword, "password", "", "Password (omit to prompt)")
	rootCmd.AddCommand(decCmd)
}
