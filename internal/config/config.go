package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// ModifyWindow adds --modify-window=1 to rsync, which prevents false
	// "file changed" mismatches when the destination uses NTFS (Windows).
	ModifyWindow bool `json:"modify_window,omitempty"`
}

type Schedule struct {
	Enabled  bool   `json:"enabled"`
	CronExpr string `json:"cron_expr"` // "0 3 * * *"
}

// VolumeConfig is a single directory to back up within an app.
// Apps can have multiple volumes (e.g. mosquitto has config/, data/, log/).
type VolumeConfig struct {
	// Slug is a short identifier used in archive filenames: "config", "data", "log".
	// Auto-derived from the last path component if not set.
	Slug     string   `json:"slug"`
	Path     string   `json:"path"`
	Label    string   `json:"label,omitempty"` // human name shown in UI; defaults to Slug
	Excludes []string `json:"excludes,omitempty"`
	Enabled  bool     `json:"enabled"` // false = skip this volume in backups
}

// AppConfig represents a single application with one or more volumes to back up.
//
// Migration: the old single-path schema (Path/Excludes) is still read from disk
// for existing entries, then promoted to Volumes on first load.
type AppConfig struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Retain        int            `json:"retain"`
	Schedule      Schedule       `json:"schedule"`
	Pinned        bool           `json:"pinned"`
	ContainerName string         `json:"container_name,omitempty"`
	Volumes       []VolumeConfig `json:"volumes"`

	// Path is a computed convenience field (first enabled volume path).
	// It is written to JSON so the existing frontend keeps working unchanged.
	// On disk it is also used as the legacy single-path for old entries —
	// the Load() migration reads it and promotes it into Volumes, then
	// re-populates it from PrimaryPath() before serialising.
	Path string `json:"path,omitempty"`

	// Excludes is the legacy top-level excludes list (old single-path schema).
	// Read during migration only; never written after that.
	Excludes []string `json:"excludes,omitempty"`
}

// PrimaryPath returns the path of the first enabled volume, for display.
func (a AppConfig) PrimaryPath() string {
	for _, v := range a.Volumes {
		if v.Enabled {
			return v.Path
		}
	}
	if len(a.Volumes) > 0 {
		return a.Volumes[0].Path
	}
	return ""
}

// EnabledVolumes returns only the volumes that are active for backups.
func (a AppConfig) EnabledVolumes() []VolumeConfig {
	var out []VolumeConfig
	for _, v := range a.Volumes {
		if v.Enabled {
			out = append(out, v)
		}
	}
	return out
}

// NotifyConfig holds all notification channel settings.
type NotifyConfig struct {
	TelegramToken   string `json:"telegram_token,omitempty"`
	TelegramChatID  string `json:"telegram_chat_id,omitempty"`
	TelegramEnabled bool   `json:"telegram_enabled"`

	DiscordURL     string `json:"discord_url,omitempty"`
	DiscordEnabled bool   `json:"discord_enabled"`

	NtfyURL     string `json:"ntfy_url,omitempty"`
	NtfyToken   string `json:"ntfy_token,omitempty"`
	NtfyEnabled bool   `json:"ntfy_enabled"`

	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookEnabled bool   `json:"webhook_enabled"`

	OnBackupSuccess  bool `json:"on_backup_success"`
	OnBackupFail     bool `json:"on_backup_fail"`
	OnRestoreSuccess bool `json:"on_restore_success"`
	OnRestoreFail    bool `json:"on_restore_fail"`
}

// User is a PrestoBack login account.
type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Role     string `json:"role"`
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
	revokedTokens map[string]struct{}
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
		// ── Migration: promote legacy single-path → Volumes ───────────────────
		// Old schema: app had a top-level `path` and `excludes`.
		// New schema: app has `volumes[]`. If we loaded an old entry, promote it.
		if len(a.Volumes) == 0 && a.Path != "" {
			slug := slugFromPath(a.Path)
			a.Volumes = []VolumeConfig{{
				Slug:     slug,
				Path:     a.Path,
				Label:    slug,
				Excludes: a.Excludes,
				Enabled:  true,
			}}
			a.Excludes = nil // now lives inside the volume
		}
		// Normalise all volumes
		for i := range a.Volumes {
			if a.Volumes[i].Slug == "" {
				a.Volumes[i].Slug = slugFromPath(a.Volumes[i].Path)
			}
			if a.Volumes[i].Label == "" {
				a.Volumes[i].Label = a.Volumes[i].Slug
			}
			// Enabled is a new field — JSON zero value is false, but any volume
			// with a non-empty path should default to enabled. We unconditionally
			// set true here so a config.json saved by the old broken version
			// (which wrote Enabled:false) is automatically healed on next load.
			if a.Volumes[i].Path != "" {
				a.Volumes[i].Enabled = true
			}
		}
		// Always keep the top-level Path field in sync with the first enabled
		// volume so the existing frontend (reads app.path) keeps working.
		a.Path = a.PrimaryPath()
		a.Excludes = nil // legacy field; now lives inside each VolumeConfig
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
	// Persist migrated form immediately so next load is clean
	_ = c.save()
	return c, nil
}

func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.save()
}

// save is the internal (lock-free) version, called when the caller already holds a lock.
func (c *Config) save() error {
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
	c.revokedTokens = make(map[string]struct{})
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
	// Normalise volumes
	for i := range a.Volumes {
		if a.Volumes[i].Slug == "" {
			a.Volumes[i].Slug = slugFromPath(a.Volumes[i].Path)
		}
		if a.Volumes[i].Label == "" {
			a.Volumes[i].Label = a.Volumes[i].Slug
		}
		if !a.Volumes[i].Enabled {
			a.Volumes[i].Enabled = true
		}
	}
	a.Path = a.PrimaryPath()
	c.apps[a.ID] = a
	return nil
}

func (c *Config) UpdateApp(a AppConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.apps[a.ID]; !exists {
		return fmt.Errorf("app '%s' not found", a.ID)
	}
	// Normalise volumes
	for i := range a.Volumes {
		if a.Volumes[i].Slug == "" {
			a.Volumes[i].Slug = slugFromPath(a.Volumes[i].Path)
		}
		if a.Volumes[i].Label == "" {
			a.Volumes[i].Label = a.Volumes[i].Slug
		}
	}
	a.Path = a.PrimaryPath()
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

func (c *Config) UpdateRemote(r RemoteTarget) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.remotes[r.ID]; !exists {
		return fmt.Errorf("remote '%s' not found", r.ID)
	}
	if r.Port <= 0 {
		r.Port = 22
	}
	c.remotes[r.ID] = r
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

// slugFromPath derives a short identifier from the last component of a path.
// "/volumes/mosquitto/config" → "config"
// "/volumes/homepage"         → "homepage"
func slugFromPath(p string) string {
	base := filepath.Base(filepath.Clean(p))
	// Replace non-alphanumeric (except dash) with underscore, lowercase
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" {
		return "vol"
	}
	return s
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
	return c.Save()
}

// ── Token revocation ──────────────────────────────────────────────────────────

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
