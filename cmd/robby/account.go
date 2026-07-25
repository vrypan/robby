package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	"github.com/vrypan/robby/internal/config"
)

func newAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Manage accounts via the running server's admin API",
	}

	var password string
	create := &cobra.Command{
		Use:   "create <handle>",
		Short: "Create a new account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pw := password
			var err error
			if pw == "" {
				pw, err = promptPassword()
				if err != nil {
					return err
				}
			}
			var out map[string]any
			if err := adminRequest(http.MethodPost, "net.vrypan.robby.admin.createAccount", map[string]any{
				"handle":   args[0],
				"password": pw,
			}, &out); err != nil {
				return err
			}
			fmt.Printf("created account: did=%s handle=%s status=%s\n", out["did"], out["handle"], out["status"])
			return nil
		},
	}
	create.Flags().StringVar(&password, "password", "", "account password (prompted if omitted)")
	cmd.AddCommand(create)

	list := &cobra.Command{
		Use:   "list",
		Short: "List accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Accounts []struct {
					DID    string `json:"did"`
					Handle string `json:"handle"`
					Status string `json:"status"`
				} `json:"accounts"`
			}
			if err := adminRequest(http.MethodGet, "net.vrypan.robby.admin.listAccounts", nil, &out); err != nil {
				return err
			}
			for _, a := range out.Accounts {
				fmt.Printf("%s\t%s\t%s\n", a.DID, a.Handle, a.Status)
			}
			return nil
		},
	}
	cmd.AddCommand(list)

	var setPasswordPassword string
	setPassword := &cobra.Command{
		Use:   "set-password <did>",
		Short: "Set an account's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pw := setPasswordPassword
			var err error
			if pw == "" {
				pw, err = promptPassword()
				if err != nil {
					return err
				}
			}
			var out map[string]any
			if err := adminRequest(http.MethodPost, "net.vrypan.robby.admin.setPassword", map[string]any{
				"did":      args[0],
				"password": pw,
			}, &out); err != nil {
				return err
			}
			fmt.Println("password updated")
			return nil
		},
	}
	setPassword.Flags().StringVar(&setPasswordPassword, "password", "", "new password (prompted if omitted)")
	cmd.AddCommand(setPassword)

	deactivate := &cobra.Command{
		Use:   "deactivate <did>",
		Short: "Deactivate an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := adminRequest(http.MethodPost, "net.vrypan.robby.admin.deactivateAccount", map[string]any{
				"did": args[0],
			}, &out); err != nil {
				return err
			}
			fmt.Println("account deactivated")
			return nil
		},
	}
	cmd.AddCommand(deactivate)

	takedown := &cobra.Command{
		Use:   "takedown <did>",
		Short: "Take down an account (moderation action; stronger than deactivate)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := adminRequest(http.MethodPost, "net.vrypan.robby.admin.takedownAccount", map[string]any{
				"did": args[0],
			}, &out); err != nil {
				return err
			}
			fmt.Println("account taken down")
			return nil
		},
	}
	cmd.AddCommand(takedown)

	approvePlcOp := &cobra.Command{
		Use:   "approve-plc-op <did>",
		Short: "Issue a one-time token authorizing identity.signPlcOperation for an account",
		Long: "Admin-CLI stand-in for the email-gated requestPlcOperationSignature flow.\n" +
			"Share the printed token with the account owner out of band; it expires in 15 minutes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return approveToken(args[0], "plc_sign")
		},
	}
	cmd.AddCommand(approvePlcOp)

	approveDelete := &cobra.Command{
		Use:   "approve-delete <did>",
		Short: "Issue a one-time token authorizing server.deleteAccount for an account",
		Long: "Admin-CLI stand-in for the email-gated requestAccountDelete flow.\n" +
			"Share the printed token with the account owner out of band; it expires in 15 minutes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return approveToken(args[0], "delete_account")
		},
	}
	cmd.AddCommand(approveDelete)

	return cmd
}

func approveToken(did, purpose string) error {
	var out map[string]any
	if err := adminRequest(http.MethodPost, "net.vrypan.robby.admin.approveToken", map[string]any{
		"did":     did,
		"purpose": purpose,
	}, &out); err != nil {
		return err
	}
	fmt.Printf("token: %s (expires %s)\n", out["token"], out["expiresAt"])
	return nil
}

func promptPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Password: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// adminRequest loads the config to discover the admin base URL and admin
// password, then makes an authenticated request to a net.vrypan.robby.admin.*
// endpoint on the running server.
func adminRequest(method, nsid string, body any, out any) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	baseURL, err := adminBaseURL(cfg.Listen)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, baseURL+"/xrpc/"+nsid, reqBody)
	if err != nil {
		return err
	}
	req.SetBasicAuth("admin", cfg.AdminPassword)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("contacting server (is it running?): %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

func adminBaseURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("parsing listen address %q: %w", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}
