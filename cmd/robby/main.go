package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configPath string

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "robby",
		Short:   "robby: a lightweight AT Protocol PDS",
		Version: version,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "robby.toml", "path to config file")

	root.AddCommand(newServeCmd())
	root.AddCommand(newAccountCmd())
	root.AddCommand(newRelayCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
