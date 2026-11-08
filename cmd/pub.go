package cmd

import "github.com/spf13/cobra"

var pubCmd = &cobra.Command{
	Use:   "pub",
	Short: "Manage public keys (export / import)",
}

func init() {
	rootCmd.AddCommand(pubCmd)
}
