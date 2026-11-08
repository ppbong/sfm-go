package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "sfm",
	Short: "SecureFileManager — secure file encryption CLI",
	Long: `SecureFileManager (sfm) is a command-line tool for encrypted file storage and sharing.

Before you can encrypt or decrypt files, initialize a repository with:
  sfm init

This creates a .sfm/ directory with your keys and local settings.`,
	SilenceUsage:  true,
	SilenceErrors: false,
	Version:       Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
