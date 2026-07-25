// Package relay handles declaring this PDS to upstream relays via
// com.atproto.sync.requestCrawl, so the relay subscribes to the PDS
// firehose and backfills its repos — the step that makes hosted accounts
// visible to AppViews and the wider network.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RequestCrawl calls com.atproto.sync.requestCrawl on relayURL, declaring
// hostname (this PDS). It does not require auth.
func RequestCrawl(ctx context.Context, relayURL, hostname string) error {
	body, err := json.Marshal(map[string]string{"hostname": hostname})
	if err != nil {
		return err
	}

	url := strings.TrimRight(relayURL, "/") + "/xrpc/com.atproto.sync.requestCrawl"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contacting relay %s: %w", relayURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("relay %s rejected requestCrawl (status %d): %s", relayURL, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// RequestCrawlAll declares hostname to every relay in relayURLs, returning
// the combined error (if any) but attempting all of them.
func RequestCrawlAll(ctx context.Context, relayURLs []string, hostname string) error {
	var errs []string
	for _, relayURL := range relayURLs {
		if err := RequestCrawl(ctx, relayURL, hostname); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
