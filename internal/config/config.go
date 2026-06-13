package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var Version = "dev"

// ── Sub-types ─────────────────────────────────────────────────────────────────

type RemoteTarget struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Path    string `json:"path"`
	KeyFile string `json:"key_file,omitempty"`
}

type Schedule struct {
	Enabled  bool   `json:"enabled"`
	CronExpr string `json:"cron_expr"` // "0 3 * * *"
}

type AppConfig struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Path          string   `json:"path"`
	Retain        int      `json:"retain"`
	Schedule      Schedule `json:"schedule"`
	Pinned        bool     `json:"pinned"`                   // if true, skip scheduled backups
	ContainerName string   `json:"container_name,omitempty"` // real Docker container name from discovery; used by FindContainers instead of guessing from app ID
}

// NotifyConfig holds all notification channel settings.
// Each channel is independently enabled and separately configured.
type NotifyConfig struct {
	// Telegram
	TelegramToken   string `json:"telegram_token,omitempty"`
	TelegramChatID  string `json:"telegram_chat_id,omitempty"`
	TelegramEnabled bool   `json:"telegram_enabled"`

	// Discord webhook
	DiscordURL     string `json:"discord_url,omitempty"`
	DiscordEnabled bool   `json:"discord_enabled"`

	// Ntfy
	NtfyURL     string `json:"ntfy_url,omitempty"`   // e.g. https://ntfy.sh/my-topic
	NtfyToken   string `json:"ntfy_token,omitempty"` // optional auth token
	NtfyEnabled bool   `json:"ntfy_enabled"`

	// Generic webhook (POST JSON to any URL — Gotify, Home Assistant, etc.)
	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookEnabled bool   `json:"webhook_enabled"`

	// Which events fire notifications (applies to all channels)
	OnBackupSuccess  bool `json:"on_backup_success"`
	OnBackupFail     bool `json:"on_backup_fail"`
	OnRestoreSuccess bool `json:"on_restore_success"`
	OnRestoreFail    bool `json:"on_restore_fail"`
}

// User is a PrestoBack login account.
type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"` // bcrypt hash
	Role     string `json:"role"` // "admin" (only role for now)
}

// disk is the on-disk JSON shape.
type disk struct {
	APIKey  string         `json:"api_key"`
	Apps    []AppConfig    `json:"apps"`
	Remotes []RemoteTarget `json:"remotes"`
	Notify  NotifyConfig   `json:"notify"`
	Users   []User         `json:"users,omitempty"`
}

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	DataDir    string
	VolumesDir string

	mu            sync.RWMutex
	apiKey        string
	apps          map[string]AppConfig
	remotes       map[string]RemoteTarget
	notify        NotifyConfig
	users         map[string]User
	revokedTokens map[string]struct{} // in-memory revocation set
}

func Load(dataDir string) (*Config, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	c := &Config{
		DataDir:       dataDir,
		apps:          make(map[string]AppConfig),
		remotes:       make(map[string]RemoteTarget),
		users:         make(map[string]User),
		revokedTokens: make(map[string]struct{}),
	}
	path := filepath.Join(dataDir, "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First run — generate API key
		c.apiKey = generateKey()
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var d disk
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	c.apiKey = d.APIKey
	if c.apiKey == "" {
		c.apiKey = generateKey()
	}
	for _, a := range d.Apps {
		if a.Retain <= 0 {
			a.Retain = 5
		}
		c.apps[a.ID] = a
	}
	for _, r := range d.Remotes {
		if r.Port <= 0 {
			r.Port = 22
		}
		c.remotes[r.ID] = r
	}
	c.notify = d.Notify
	for _, u := range d.Users {
		c.users[u.Username] = u
	}
	return c, nil
}

func (c *Config) Save() error {
	c.mu.RLock()
	d := disk{
		APIKey: c.apiKey,
		Notify: c.notify,
	}
	for _, a := range c.apps {
		d.Apps = append(d.Apps, a)
	}
	for _, r := range c.remotes {
		d.Remotes = append(d.Remotes, r)
	}
	for _, u := range c.users {
		d.Users = append(d.Users, u)
	}
	c.mu.RUnlock()

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.DataDir, "config.json.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.DataDir, "config.json"))
}

// ── API key ───────────────────────────────────────────────────────────────────

func (c *Config) APIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

func (c *Config) RegenerateAPIKey() string {
	c.mu.Lock()
	c.apiKey = generateKey()
	c.revokedTokens = make(map[string]struct{}) // old tokens are all invalid now
	c.mu.Unlock()
	_ = c.Save()
	return c.apiKey
}

// ── Apps ──────────────────────────────────────────────────────────────────────

func (c *Config) ListApps() []AppConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]AppConfig, 0, len(c.apps))
	for _, a := range c.apps {
		out = append(out, a)
	}
	return out
}

func (c *Config) GetApp(id string) (AppConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	a, ok := c.apps[id]
	return a, ok
}

func (c *Config) AddApp(a AppConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.apps[a.ID]; exists {
		return fmt.Errorf("app '%s' already exists", a.ID)
	}
	if a.Retain <= 0 {
		a.Retain = 5
	}
	c.apps[a.ID] = a
	return nil
}

func (c *Config) UpdateApp(a AppConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.apps[a.ID]; !exists {
		return fmt.Errorf("app '%s' not found", a.ID)
	}
	c.apps[a.ID] = a
	return nil
}

func (c *Config) DeleteApp(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.apps[id]; !exists {
		return fmt.Errorf("app '%s' not found", id)
	}
	delete(c.apps, id)
	return nil
}

func (c *Config) AppCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.apps)
}

// ── Remotes ───────────────────────────────────────────────────────────────────

func (c *Config) ListRemotes() []RemoteTarget {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]RemoteTarget, 0, len(c.remotes))
	for _, r := range c.remotes {
		out = append(out, r)
	}
	return out
}

func (c *Config) AddRemote(r RemoteTarget) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.remotes[r.ID]; exists {
		return fmt.Errorf("remote '%s' already exists", r.ID)
	}
	if r.Port <= 0 {
		r.Port = 22
	}
	c.remotes[r.ID] = r
	return nil
}

func (c *Config) DeleteRemote(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.remotes[id]; !exists {
		return fmt.Errorf("remote '%s' not found", id)
	}
	delete(c.remotes, id)
	return nil
}

// ── Notifications ─────────────────────────────────────────────────────────────

func (c *Config) GetNotify() NotifyConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.notify
}

func (c *Config) SetNotify(n NotifyConfig) {
	c.mu.Lock()
	c.notify = n
	c.mu.Unlock()
	_ = c.Save()
}

// ── Misc ──────────────────────────────────────────────────────────────────────

func (c *Config) BackupDir() string   { return filepath.Join(c.DataDir, "backups") }
func (c *Config) HistoryFile() string { return filepath.Join(c.DataDir, "history.json") }

func generateKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (c *Config) HasUsers() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.users) > 0
}

func (c *Config) GetUser(username string) (User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	u, ok := c.users[username]
	return u, ok
}

func (c *Config) AddUser(u User) error {
	c.mu.Lock()
	if _, exists := c.users[u.Username]; exists {
		c.mu.Unlock()
		return fmt.Errorf("user '%s' already exists", u.Username)
	}
	c.users[u.Username] = u
	c.mu.Unlock()
	return c.Save() // persist immediately
}

// ── Token revocation (in-memory) ─────────────────────────────────────────────

func (c *Config) RevokeToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokedTokens[token] = struct{}{}
}

func (c *Config) IsTokenRevoked(token string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, revoked := c.revokedTokens[token]
	return revoked
}
