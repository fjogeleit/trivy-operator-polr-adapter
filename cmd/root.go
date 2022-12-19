package cmd

import (
	"github.com/spf13/cobra"
)

// NewCLI creates a new instance of the root CLI
func NewCLI(version string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "trivy-operator-polr-adapter",
		Short: "Generates PolicyReports for different Trivy Operator CRDs",
	}

	rootCmd.AddCommand(newRunCMD())
	rootCmd.AddCommand(newVersionCMD(version))

	return rootCmd
}
