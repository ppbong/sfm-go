package cmd

import "github.com/spf13/cobra"

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage keys (info / update)",
}

func init() {
	rootCmd.AddCommand(keyCmd)
}
