package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCMD(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "CLI Version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version: %s\n", version)
		},
	}
}
