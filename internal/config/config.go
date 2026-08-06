// Package config loads the robby TOML configuration file.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Hostname      string   `toml:"hostname"`
	DataDir       string   `toml:"data_dir"`
	Listen        string   `toml:"listen"`
	PLCURL        string   `toml:"plc_url"`
	AppviewURL    string   `toml:"appview_url"`
	AppviewDID    string   `toml:"appview_did"`
	Relays        []string `toml:"relays"`
	JWTSecret     string   `toml:"jwt_secret"`
	AdminPassword string   `toml:"admin_password"`
	// AdminNetworks lists the CIDRs allowed to call the admin API
	// (net.vrypan.robby.admin.*). Requests arriving through a Cloudflare
	// Tunnel are judged by their CF-Connecting-IP, so the default —
	// loopback only — shuts the admin API off from the public hostname
	// while keeping the local admin CLI working.
	AdminNetworks []string `toml:"admin_networks"`

	// adminPrefixes is AdminNetworks parsed once by Load.
	adminPrefixes []netip.Prefix
}

// AdminPrefixes returns the parsed admin_networks allowlist.
func (c *Config) AdminPrefixes() []netip.Prefix {
	return c.adminPrefixes
}

func defaults() Config {
	return Config{
		Listen:        ":3000",
		PLCURL:        "https://plc.directory",
		AppviewURL:    "https://api.bsky.app",
		AppviewDID:    "did:web:api.bsky.app",
		Relays:        []string{"https://bsky.network"},
		AdminNetworks: []string{"127.0.0.0/8", "::1/128"},
	}
}

// Load reads the config file at path. If jwt_secret or admin_password are
// empty, it generates fresh random values and rewrites the file so the
// server has stable secrets across restarts.
func Load(path string) (*Config, error) {
	cfg := defaults()

	if err := validateRegularConfig(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if cfg.Hostname == "" {
		return nil, fmt.Errorf("config %s: hostname is required", path)
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("config %s: data_dir is required", path)
	}
	for _, s := range cfg.AdminNetworks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("config %s: admin_networks: %q is not a valid CIDR", path, s)
		}
		cfg.adminPrefixes = append(cfg.adminPrefixes, p)
	}

	changed := false
	if cfg.JWTSecret == "" {
		secret, err := randomHex(32)
		if err != nil {
			return nil, fmt.Errorf("generating jwt_secret: %w", err)
		}
		cfg.JWTSecret = secret
		changed = true
	}
	if cfg.AdminPassword == "" {
		pass, err := randomHex(16)
		if err != nil {
			return nil, fmt.Errorf("generating admin_password: %w", err)
		}
		cfg.AdminPassword = pass
		changed = true
	}

	if changed {
		out, err := toml.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("marshaling config: %w", err)
		}
		if err := writePrivateConfig(path, out); err != nil {
			return nil, err
		}
	} else if err := makeConfigPrivate(path); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validateRegularConfig(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting config %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config %s: symlinks are not allowed", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config %s: must be a regular file", path)
	}
	return nil
}

func makeConfigPrivate(path string) error {
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("setting private permissions on config %s: %w", path, err)
	}
	return verifyPrivateConfig(path)
}

func writePrivateConfig(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary config near %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting private permissions on temporary config %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temporary config %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary config %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replacing config %s: %w", path, err)
	}
	tmpPath = ""

	return verifyPrivateConfig(path)
}

func verifyPrivateConfig(path string) error {
	if err := validateRegularConfig(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting config %s: %w", path, err)
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("config %s: private permissions were not applied", path)
	}
	return nil
}
