package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configPath string

func main() {
	root := &cobra.Command{
		Use:   "pdslight",
		Short: "pds-light: a lightweight AT Protocol PDS",
	}
	root.PersistentFlags().StringVar(&configPath, "config", "pdslight.toml", "path to config file")

	root.AddCommand(newServeCmd())
	root.AddCommand(newAccountCmd())
	root.AddCommand(newRelayCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
