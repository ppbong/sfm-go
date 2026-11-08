package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"sfm/internal/crypto"
	"sfm/internal/prompt"
	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var keyUpdateAlg string
var keyUpdatePassword string

var keyUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Generate a new key pair and archive current as history",
	Long: `Generate a new key pair. The current key pair is archived as history-NN.
Old files encrypted with the previous key remain decryptable because history keys
are kept and tried automatically during decryption.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		suite := crypto.SuiteIdByName(r.Cfg.AlgSuite)
		if keyUpdateAlg != "" {
			suite = crypto.SuiteIdByName(keyUpdateAlg)
			if suite == 0 {
				return fmt.Errorf("unknown algorithm: %s", keyUpdateAlg)
			}
		}

		password := keyUpdatePassword
		if password == "" {
			var err error
			password, err = prompt.ReadPassword("Current password: ")
			if err != nil {
				return err
			}
		}

		_, _, _, curSuite, curFp, err := r.LoadCurrentKey(password)
		if err != nil {
			return fmt.Errorf("wrong password: %w", err)
		}

		km, err := r.LoadKeysManifest()
		if err != nil {
			return err
		}

		idx := repo.NextIndexFromManifest(km)

		// archive history-NN
		oldRec := repo.KeyRecord{
			Index:       idx,
			AlgSuite:    crypto.SuiteName(curSuite),
			AlgCode:     byte(curSuite),
			Fingerprint: curFp,
			PublicKey:   fmt.Sprintf("history-%02d.pub", idx),
			PrivateKey:  fmt.Sprintf("history-%02d.sk.enc", idx),
			ArchivedAt:  time.Now().Format(time.RFC3339),
		}

		if km.Current != nil && km.Current.CreatedAt != "" {
			oldRec.CreatedAt = km.Current.CreatedAt
		}

		keysDir := r.KeysPath()

		curPub := filepath.Join(keysDir, "current.pub")
		curSk := filepath.Join(keysDir, "current.sk.enc")
		histPub := filepath.Join(keysDir, fmt.Sprintf("history-%02d.pub", idx))
		histSk := filepath.Join(keysDir, fmt.Sprintf("history-%02d.sk.enc", idx))

		if err := os.Rename(curPub, histPub); err != nil {
			return fmt.Errorf("archive pub: %w", err)
		}

		if err := os.Rename(curSk, histSk); err != nil {
			return fmt.Errorf("archive sk: %w", err)
		}

		p, err := crypto.GetProvider(suite)
		if err != nil {
			return err
		}

		pub, sk, err := p.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate: %w", err)
		}

		fp, err := crypto.Fingerprint(pub, suite)
		if err != nil {
			return err
		}

		salt, err := r.LoadSalt()
		if err != nil {
			return err
		}

		ppk, err := crypto.DerivePpk(password, salt)
		if err != nil {
			return err
		}

		defer zeroBytes(ppk)

		box, err := crypto.EncryptPrivateKey(ppk, sk, suite)
		if err != nil {
			return err
		}

		pemBytes, err := p.MarshalPublicKeyPem(pub)
		if err != nil {
			return err
		}

		if err := os.WriteFile(curPub, pemBytes, 0o600); err != nil {
			return err
		}

		if err := os.WriteFile(curSk, box, 0o600); err != nil {
			return err
		}

		r.Cfg.AlgSuite = crypto.SuiteName(suite)
		r.Cfg.CurrentFingerprint = fp
		if err := repo.SaveConfig(r.Root, r.Cfg); err != nil {
			return err
		}

		km.Current = &repo.KeyRecord{
			Index:       0,
			AlgSuite:    crypto.SuiteName(suite),
			AlgCode:     byte(suite),
			Fingerprint: fp,
			PublicKey:   "current.pub",
			PrivateKey:  "current.sk.enc",
			CreatedAt:   time.Now().Format(time.RFC3339),
		}

		km.History = append(km.History, oldRec)

		sort.Slice(km.History, func(i, j int) bool { return km.History[i].Index < km.History[j].Index })
		
		if err := r.SaveKeysManifest(km); err != nil {
			return fmt.Errorf("save keys manifest: %w", err)
		}

		fmt.Printf("Key updated.\n")
		fmt.Printf("  New fingerprint: %s\n", fp)
		fmt.Printf("  Archived as:      history-%02d\n", idx)
		return nil
	},
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func init() {
	keyUpdateCmd.Flags().StringVar(&keyUpdateAlg, "alg", "", "Algorithm suite (default: keep current)")
	keyUpdateCmd.Flags().StringVar(&keyUpdatePassword, "password", "", "Password (omit to prompt)")
	keyCmd.AddCommand(keyUpdateCmd)
}
