package cmd

import (
	"fmt"
	"os"

	"sfm/internal/crypto"
	"sfm/internal/prompt"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var initPassword string
var initAlg string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize an sfm repository in the current directory",
	Long: `Create a .sfm/ directory with a key store and configuration.

Generates a new key pair (RSA-4096 or SM2) and protects the private key with a password-derived key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()

		var suite crypto.AlgSuite
		if initAlg != "" {
			suite = crypto.SuiteIdByName(initAlg)
			if suite == 0 {
				return fmt.Errorf("unknown algorithm: %s (use rsa or sm2)", initAlg)
			}
		} else {
			var err error
			suite, err = prompt.ChooseAlgSuite()
			if err != nil {
				return err
			}
		}

		var password string
		if initPassword != "" {
			password = initPassword
		} else {
			var err error
			password, err = prompt.ReadPasswordTwice()
			if err != nil {
				return err
			}
		}

		r, err := repo.InitRepo(cwd, suite, password)
		if err != nil {
			return err
		}

		suiteName := crypto.SuiteName(suite)

		fmt.Printf("Initialized sfm repo at %s\n", r.Root)
		fmt.Printf("  Suite:          %s\n", suiteName)
		fmt.Printf("  Fingerprint:    %s\n", r.Cfg.CurrentFingerprint)
		fmt.Printf("  Encrypted dir:  %s\n", r.EncPath())
		fmt.Printf("  Shared dir:     %s\n", r.SharePath())
		fmt.Printf("  Inbox dir:      %s\n", r.InboxPath())
		fmt.Printf("  Plain dir:      %s\n", r.PlainPath())
		fmt.Println()
		fmt.Println("Use 'sfm enc -i <file>' to encrypt files.")
		fmt.Println("Use 'sfm dec -i encrypted/<file> to decrypt files.")
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initPassword, "password", "", "Password to protect the private key (omit to prompt)")
	initCmd.Flags().StringVar(&initAlg, "alg", "", "Algorithm suite: rsa or sm2 (omit to prompt)")
	rootCmd.AddCommand(initCmd)
}
