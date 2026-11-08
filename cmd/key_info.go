package cmd

import (
	"fmt"
	"os"
	"time"

	"sfm/internal/crypto"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var keyInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show current public key information",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		p, pub, suite, fp, err := r.LoadCurrentPub()
		if err != nil {
			return fmt.Errorf("load pub: %w", err)
		}

		fmt.Println("Current key:")
		fmt.Printf("  Suite:       %s\n", crypto.SuiteName(suite))
		fmt.Printf("  Fingerprint: %s\n", fp)

		createdAt := r.Cfg.CreatedAt
		if km, err := r.LoadKeysManifest(); err == nil && km.Current != nil && km.Current.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, km.Current.CreatedAt); err == nil {
				createdAt = t
			}
		}
		fmt.Printf("  Created:     %s\n", createdAt.Format("2006-01-02 15:04:05"))

		history, _ := r.ListHistoryKeys()
		if len(history) > 0 {
			fmt.Println()
			fmt.Printf("History keys (%d):\n", len(history))
			for _, h := range history {
				fmt.Printf("  #%02d  %-8s %s\n", h.Index, crypto.SuiteName(h.AlgSuite), h.Fingerprint)
			}
		}
		fmt.Println()

		if suite == crypto.AlgRsaAes {
			pemBytes, _ := p.MarshalPublicKeyPem(pub)
			fmt.Println("Current public key (PEM):")
			fmt.Println(string(pemBytes))
		} else {
			raw, _ := p.MarshalPublicKey(pub)
			fmt.Printf("Current public key (%d raw bytes, hex):\n", len(raw))
			for i := 0; i < len(raw); i += 16 {
				end := i + 16
				if end > len(raw) {
					end = len(raw)
				}
				for j := i; j < end; j++ {
					fmt.Printf("%02X", raw[j])
				}
				fmt.Println()
			}
		}
		return nil
	},
}

func init() {
	keyCmd.AddCommand(keyInfoCmd)
}
