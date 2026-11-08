package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"sfm/internal/repo"

	"github.com/spf13/cobra"
)

var listType string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List encrypted, shared and inbox files in the repository",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, _ := os.Getwd()
		r, err := repo.LoadRepo(cwd)
		if err != nil {
			return err
		}

		files, err := r.ListStoredFiles(listType)
		if err != nil {
			return err
		}

		if len(files) == 0 {
			fmt.Println("No files found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "PATH\tSIZE\tMODIFIED")
		for _, f := range files {
			fmt.Fprintf(w, "%s/%s\t%s\t%s\n",
				f.Kind, f.Name, humanSize(f.Size), f.CreatedAt.Format("2006-01-02 15:04"))
		}
		w.Flush()

		return nil
	},
}

func humanSize(n int64) string {
	const unit = 1024
	
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	div, exp := int64(unit), 0
	for nn := n / unit; nn >= unit; nn /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func init() {
	listCmd.Flags().StringVar(&listType, "type", "all", "File type to show: all | encrypted | shared | inbox")
	rootCmd.AddCommand(listCmd)
}
