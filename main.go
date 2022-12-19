package main

import (
	"fmt"
	"os"

	"github.com/fjogeleit/trivy-operator-polr-adapter/cmd"
)

var Version = "development"

func main() {
	if err := cmd.NewCLI(Version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
