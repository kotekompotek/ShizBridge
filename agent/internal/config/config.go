// Package config stores the agent's pairing state (~/.shizbridge on POSIX,
// %AppData%\shizbridge on Windows).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kotekompotek/ShizBridge/agent/internal/cryptox"
)

// ErrNotPaired is returned when no pairing state exists yet.
var ErrNotPaired = errors.New("not paired yet — run: shizbridge pair <code> --server <phone>:8787")

// Config is the persisted agent configuration.
type Config struct {
	ServerHost  string `json:"server_host"`
	ServerPort  int    `json:"server_port"`
	ServerPin   string `json:"server_pin"`
	LocalListen string `json:"local_listen"`
	Label       string `json:"label"`
}

// Addr returns "host:port" of the phone server.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.ServerHost, c.ServerPort)
}

// Dir returns the configuration directory, creating it if needed.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config dir: %w", err)
	}
	d := filepath.Join(base, "shizbridge")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	return d, nil
}

func filePath(name string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// Load reads the configuration; returns ErrNotPaired when absent.
func Load() (*Config, error) {
	p, err := filePath("config.json")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotPaired
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ServerPin == "" || c.ServerHost == "" {
		return nil, ErrNotPaired
	}
	return &c, nil
}

// Save writes the configuration atomically.
func Save(c *Config) error {
	p, err := filePath("config.json")
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(raw, '\n'), 0o600)
}

// LoadIdentity reads the client identity (created by NewIdentity/SaveIdentity).
func LoadIdentity() (*cryptox.Identity, error) {
	certPath, err := filePath("client.crt")
	if err != nil {
		return nil, err
	}
	keyPath, err := filePath("client.key")
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotPaired
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	der, err := cryptox.CertDERFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	return &cryptox.Identity{CertDER: der, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// SaveIdentity persists a freshly generated identity.
func SaveIdentity(id *cryptox.Identity) error {
	certPath, err := filePath("client.crt")
	if err != nil {
		return err
	}
	keyPath, err := filePath("client.key")
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, id.CertPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath, id.KeyPEM, 0o600)
}

// NewIdentity generates and persists a client identity if none exists yet.
func NewIdentity(label string) (*cryptox.Identity, bool, error) {
	if id, err := LoadIdentity(); err == nil {
		return id, false, nil
	}
	id, err := cryptox.MakeIdentity(label)
	if err != nil {
		return nil, false, err
	}
	if err := SaveIdentity(id); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// Revoke deletes all local pairing state (identity + config).
func Revoke() error {
	for _, n := range []string{"config.json", "client.crt", "client.key"} {
		p, err := filePath(n)
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
