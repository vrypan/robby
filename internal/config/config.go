// Package config loads the pds-light TOML configuration file.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

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
}

func defaults() Config {
	return Config{
		Listen:     ":3000",
		PLCURL:     "https://plc.directory",
		AppviewURL: "https://api.bsky.app",
		AppviewDID: "did:web:api.bsky.app",
		Relays:     []string{"https://bsky.network"},
	}
}

// Load reads the config file at path. If jwt_secret or admin_password are
// empty, it generates fresh random values and rewrites the file so the
// server has stable secrets across restarts.
func Load(path string) (*Config, error) {
	cfg := defaults()

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
		if err := os.WriteFile(path, out, 0600); err != nil {
			return nil, fmt.Errorf("writing config %s: %w", path, err)
		}
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
