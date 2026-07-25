package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/vrypan/pds-light/internal/config"
	"github.com/vrypan/pds-light/internal/relay"
)

func newRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Interact with upstream relays",
	}

	requestCrawl := &cobra.Command{
		Use:   "request-crawl [relay-url ...]",
		Short: "Ask relays to crawl this PDS (declares it so accounts become network-visible)",
		Long: "Calls com.atproto.sync.requestCrawl on the given relay URLs, or on\n" +
			"the relays from the config file if none are given. This is what makes\n" +
			"hosted accounts and their posts discoverable via AppViews and the wider\n" +
			"network: the relay subscribes to this PDS's firehose and backfills its\n" +
			"repos. No auth required.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			relays := args
			if len(relays) == 0 {
				relays = cfg.Relays
			}
			if len(relays) == 0 {
				return fmt.Errorf("no relays given and none configured")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			var failed bool
			for _, r := range relays {
				if err := relay.RequestCrawl(ctx, r, cfg.Hostname); err != nil {
					fmt.Printf("%s\tFAILED: %v\n", r, err)
					failed = true
				} else {
					fmt.Printf("%s\tOK\n", r)
				}
			}
			if failed {
				return fmt.Errorf("one or more relays failed")
			}
			return nil
		},
	}
	cmd.AddCommand(requestCrawl)

	return cmd
}
