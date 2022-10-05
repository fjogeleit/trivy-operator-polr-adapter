package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCMD() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "CLI Version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("v0.1.1")
		},
	}
}
