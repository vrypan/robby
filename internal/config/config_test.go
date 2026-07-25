package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const populatedConfig = `hostname = "pds.example.com"
data_dir = "/var/lib/pdslight"
jwt_secret = "present"
admin_password = "present"
`

const blankSecretsConfig = `hostname = "pds.example.com"
data_dir = "/var/lib/pdslight"
`

func TestLoadTightensExistingConfigPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pdslight.toml")
	if err := os.WriteFile(path, []byte(populatedConfig), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	assertPrivateMode(t, path)
}

func TestLoadGeneratesSecretsWithPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pdslight.toml")
	if err := os.WriteFile(path, []byte(blankSecretsConfig), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWTSecret == "" || cfg.AdminPassword == "" {
		t.Fatal("expected generated secrets")
	}
	assertPrivateMode(t, path)
}

func TestLoadRejectsSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	if err := os.WriteFile(target, []byte("invalid = ["), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pdslight.toml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatal("expected symlink config to be rejected before parsing")
	}
}

func assertPrivateMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("got mode %04o, want 0600", info.Mode().Perm())
	}
}
