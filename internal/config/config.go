package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version is a plain package-level var (not const) so the Docker build can
// override it via `-ldflags "-X .../config.Version=..."`. docker-build.yml
// already does this for every build: a `v*` tag gets the tag's own version,
// and every dev-branch push gets `dev-<short-sha>` — specifically so the
// running version string always identifies exactly which commit produced
// it. This literal is only the fallback for a bare `go build`/`go run` that
// skips that flag entirely — it will not appear in any image the CI
// pipeline actually produces, so there's no reason to hand-bump it; see
// CHANGELOG.md instead for tracking what changed and when.
var Version = "dev"

// ── Sub-types ─────────────────────────────────────────────────────────────────

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

	// CreatedAt fixes app ordering. apps is a Go map (see Config below),
	// and map iteration order is deliberately randomized by the runtime —
	// ListApps used to range over it with no sort at all, so the
	// Applications page could come back in a different order on every
	// single load, including right after saving an unrelated field on a
	// different app entirely (a reported bug: editing one app's schedule
	// and going back to the list changed everyone's position). CreatedAt
	// gives ListApps a stable, meaningful sort key — the order apps were
	// actually added in — instead of whatever order the map's internal
	// hash table happened to produce this time. Omitted from existing
	// configs predating this field; ListApps' sort falls back to Name for
	// any two apps that both have a zero CreatedAt, so pre-existing apps
	// still sort deterministically (just alphabetically) rather than
	// randomly, without needing a migration.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// PreBackupCmd is an optional shell command run BEFORE container stop and
	// archiving begins — e.g. `docker exec postgres pg_dump -U app app > /volumes/app/dump.sql`.
	// Runs via `sh -c`, output streamed to SSE logs. Failures are logged but
	// do not abort the backup (the command may be best-effort, e.g. a cache warm).
	PreBackupCmd string `json:"pre_backup_cmd,omitempty"`

	// PostRestoreHint is set automatically when a PreBackupCmd suggestion is
	// applied. Shown in the Restore modal after a successful restore to tell
	// the user how to activate the dump file that's now on disk (e.g. rename
	// db.sqlite3.bak → db.sqlite3 or run pg_restore). Empty for apps that
	// don't use a pre-backup dump command.
	PostRestoreHint string `json:"post_restore_hint,omitempty"`

	// LinkedContainers names additional containers (by exact Docker name,
	// not service name) to quiesce alongside this app's own matched
	// containers — typically a compose-declared dependency like a database
	// or cache, detected via ComposeDependencies() and confirmed by the
	// user in the Edit App UI. Empty by default: most apps either have no
	// separate DB container, or back up that DB via PreBackupCmd instead
	// (the zero-downtime option), so nothing is auto-included.
	LinkedContainers []string `json:"linked_containers,omitempty"`

	// LinkedContainersSet distinguishes "user has never reviewed the
	// dependency checklist" from "user reviewed it and explicitly unchecked
	// everything." Both states produce an empty LinkedContainers slice, which
	// is indistinguishable on its own — the Edit App UI used to default to
	// "first time, so check everything" purely based on the slice being
	// empty, which meant an explicit "no, I don't want this linked" choice
	// silently reverted to checked again the next time the modal opened.
	// Set to true by the frontend on every Edit App save; the UI then only
	// applies its "default checked" convenience behavior while this is false.
	LinkedContainersSet bool `json:"linked_containers_set,omitempty"`

	// ContainerStrategy controls how running containers are quiesced during
	// backup/restore:
	//   "stop"  (default, safest) — graceful SIGTERM, archive, then restart.
	//   "pause" — freeze via SIGSTOP instead of stopping. Much faster (no
	//             restart/health-check wait), and crash-consistent — the same
	//             guarantee LVM/ZFS snapshots give, which SQLite/Postgres/MySQL
	//             WAL journaling is designed to recover from cleanly. Only a
	//             real downgrade for apps that don't journal their writes.
	//   "none"  — don't touch the container at all (stateless apps, or apps
	//             whose PreBackupCmd already produces a consistent dump).
	// Empty string is treated as "stop" for backward compatibility.
	ContainerStrategy string `json:"container_strategy,omitempty"`

	// Path is a computed convenience field (first enabled volume path).
	// It is written to JSON so the existing frontend keeps working unchanged.
	// On disk it is also used as the legacy single-path for old entries —
	// the Load() migration reads it and promotes it into Volumes, then
	// re-populates it from PrimaryPath() before serialising.
	Path string `json:"path,omitempty"`

	// Excludes is the legacy top-level excludes list (old single-path schema).
	// Read during migration only; never written after that.
	Excludes []string `json:"excludes,omitempty"`

	// Encrypted overrides the global encryption default for this app's
	// backups. nil means "inherit the global default" — most apps should
	// leave this unset. A non-nil value is an explicit per-app choice made
	// in the Edit App UI (e.g. "never encrypt this one, it's already public
	// data" or "always encrypt this one even if the global default is off").
	Encrypted *bool `json:"encrypted,omitempty"`
}

// EffectiveEncrypted resolves whether this app's backups should be
// encrypted, given the global default. Per-app override always wins when set.
func (a AppConfig) EffectiveEncrypted(globalDefault bool) bool {
	if a.Encrypted != nil {
		return *a.Encrypted
	}
	return globalDefault
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

// EncryptionConfig holds the global default for backup-archive encryption.
//
// Passphrase storage tradeoff (deliberate, not accidental): the passphrase
// is stored here so *scheduled/unattended* backups can encrypt automatically
// — a cron-triggered backup can't pause and wait for someone to type a
// passphrase at 3am. This means anyone with filesystem access to config.json
// (0600, same host) can also decrypt any archive on that same host — at-rest
// encryption here protects an archive that LEAVES the host (stolen backup
// drive, a copied file, a future remote push) more than it protects against
// full host compromise, which no config-stored secret can fix anyway.
//
// To keep restores honest despite that: the stored passphrase is used only
// for the WRITE path (new backups). The READ path (restore) never uses it
// silently — internal/api/server.go's restore handler always requires the
// passphrase to be supplied explicitly in the request, even when one is
// stored here. That way "restore succeeded" always means a human typed the
// right passphrase for that specific action, not "the config file happened
// to still have it."
type EncryptionConfig struct {
	Enabled    bool   `json:"enabled"`
	Passphrase string `json:"passphrase,omitempty"`
}

// RemoteTarget is one configured off-box backup destination. Mirrors
// backup.RemoteTarget field-for-field deliberately — this is the persisted
// shape, backup.RemoteTarget is the runtime shape internal/backup/remote.go
// actually operates on. Kept as two separate types rather than one shared
// struct because internal/config must not import internal/backup (backup
// already imports config, and Go doesn't allow the cycle) — server.go,
// which imports both, is the one place that translates between them.
type RemoteTarget struct {
	Name string `json:"name"` // display name, e.g. "Synology NAS"
	Kind string `json:"kind"` // "mount" | "sftp" | "s3"

	// Kind == "mount": a directory already accessible inside this
	// container (a bind-mounted SMB/CIFS or NFS share).
	MountPath string `json:"mount_path,omitempty"`

	// Kind == "sftp": direct SSH/SFTP, no external binary — see
	// internal/backup/sftpconn.go for exactly how each field is used.
	SFTPHost           string `json:"sftp_host,omitempty"`
	SFTPPort           int    `json:"sftp_port,omitempty"` // 0 defaults to 22
	SFTPUser           string `json:"sftp_user,omitempty"`
	SFTPPassword       string `json:"sftp_password,omitempty"`         // either this or a private key
	SFTPPrivateKeyPath string `json:"sftp_private_key_path,omitempty"` // path INSIDE this container to a mounted private key file
	SFTPPrivateKeyPass string `json:"sftp_private_key_pass,omitempty"` // passphrase for the private key, if it has one
	SFTPKnownHostsPath string `json:"sftp_known_hosts_path,omitempty"` // optional — blank means accept any host key
	SFTPBaseDir        string `json:"sftp_base_dir,omitempty"`         // remote directory backups live under

	// Kind == "s3": S3-compatible object storage (AWS S3, MinIO, Backblaze
	// B2's S3-compatible endpoint, Wasabi, ...) — a hand-rolled SigV4
	// client, no SDK. See internal/backup/s3.go.
	S3Endpoint  string `json:"s3_endpoint,omitempty"` // full URL including scheme
	S3Bucket    string `json:"s3_bucket,omitempty"`
	S3AccessKey string `json:"s3_access_key,omitempty"`
	S3SecretKey string `json:"s3_secret_key,omitempty"`
	S3Region    string `json:"s3_region,omitempty"`   // optional, defaults to "us-east-1"
	S3BaseDir   string `json:"s3_base_dir,omitempty"` // optional key prefix
}

// RemoteConfig holds every configured push destination. Push is additive to
// the existing local backup, never a replacement for it — Enabled here
// only controls whether PushAppBackup is attempted after a local backup
// succeeds, the same relationship OnBackupSuccess etc. have to
// notify.Dispatch.
type RemoteConfig struct {
	Enabled bool           `json:"enabled"`
	Targets []RemoteTarget `json:"targets,omitempty"`
}

// User is a PrestoBack login account.
type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Role     string `json:"role"`
}

// PairedKey is one API key issued through the device-pairing flow (see
// pairing.go), distinct from the single legacy master key returned by
// APIKey(). Each paired key is independently named and independently
// revocable — deleting one doesn't touch any other integration.
//
// KeyHash, never the raw key: the actual key is shown to the user exactly
// once, at the moment ClaimPairing generates it, and only ever compared by
// hash from here on — same "never store what you don't have to need again"
// posture as bcrypt password hashes elsewhere in this codebase. KeyHash
// DOES need to round-trip through config.json (so pairing survives a
// restart), so it keeps a normal json tag here — internal/api/server.go's
// HTTP handler is responsible for stripping it before ever serializing a
// PairedKey out to the browser, the same way handleUsers already strips
// User.Hash today.
type PairedKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	KeyHash   string     `json:"key_hash"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// disk is the on-disk JSON shape.
type disk struct {
	APIKey     string           `json:"api_key"`
	Apps       []AppConfig      `json:"apps"`
	Notify     NotifyConfig     `json:"notify"`
	Users      []User           `json:"users,omitempty"`
	Encryption EncryptionConfig `json:"encryption,omitempty"`
	Remote     RemoteConfig     `json:"remote,omitempty"`
	PairedKeys []PairedKey      `json:"paired_keys,omitempty"`
}

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	DataDir    string
	VolumesDir string
	// ComposeFile is the path, inside this container, to the docker-compose.yml
	// that manages the apps PrestoBack monitors. Set via PRESTOBACK_COMPOSE_FILE
	// env var or --compose-file flag. Not persisted — set at startup only.
	// Example: /compose/docker-compose.yml (with host ~/presto mounted at /compose).
	ComposeFile string

	mu            sync.RWMutex
	apiKey        string
	apps          map[string]AppConfig
	notify        NotifyConfig
	encryption    EncryptionConfig
	remote        RemoteConfig
	users         map[string]User
	revokedTokens map[string]struct{}

	// pairedKeys are additional, independently-revocable API keys issued via
	// the QR/device-pairing flow (pairing.go) — separate from the single
	// legacy apiKey above. Keyed by PairedKey.ID.
	pairedKeys map[string]PairedKey
	// pending holds in-progress pairing sessions (code -> pendingPairing).
	// Deliberately NOT persisted to disk: same reasoning as revokedTokens
	// and loginAttempts elsewhere in this codebase — these are short-lived
	// (minutes) by design, so losing them on restart is a non-event, and
	// keeping them out of config.json means a stale one can never linger
	// across restarts either.
	pending map[string]*pendingPairing
}

func Load(dataDir string) (*Config, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	c := &Config{
		DataDir:       dataDir,
		apps:          make(map[string]AppConfig),
		users:         make(map[string]User),
		revokedTokens: make(map[string]struct{}),
		pairedKeys:    make(map[string]PairedKey),
		pending:       make(map[string]*pendingPairing),
	}
	path := filepath.Join(dataDir, "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		c.apiKey = GenerateAPIKey()
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
		c.apiKey = GenerateAPIKey()
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
	c.notify = d.Notify
	c.encryption = d.Encryption
	c.remote = d.Remote
	for _, u := range d.Users {
		c.users[u.Username] = u
	}
	for _, pk := range d.PairedKeys {
		c.pairedKeys[pk.ID] = pk
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
		APIKey:     c.apiKey,
		Notify:     c.notify,
		Encryption: c.encryption,
		Remote:     c.remote,
	}
	for _, a := range c.apps {
		d.Apps = append(d.Apps, a)
	}
	sort.Slice(d.Apps, func(i, j int) bool {
		if !d.Apps[i].CreatedAt.Equal(d.Apps[j].CreatedAt) {
			return d.Apps[i].CreatedAt.Before(d.Apps[j].CreatedAt)
		}
		return d.Apps[i].Name < d.Apps[j].Name
	})
	for _, u := range c.users {
		d.Users = append(d.Users, u)
	}
	for _, pk := range c.pairedKeys {
		d.PairedKeys = append(d.PairedKeys, pk)
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

// APIKey returns the raw master key. Used only where the raw value is
// actually required — signing/verifying JWTs (it doubles as the HMAC
// secret, see internal/api/auth.go's jwtSecret) and displaying/regenerating
// it in the settings UI. Anything that's checking a caller-supplied
// candidate against this must call ValidateAPIKey instead of comparing the
// return value directly — see that method's doc comment for why.
func (c *Config) APIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

// ValidateAPIKey reports whether candidate matches the current master API
// key. This is the ONLY sanctioned way to check a caller-supplied key
// against the stored one — it compares via SecureEquals (apikey.go),
// which is constant-time and doesn't leak the key's length the way a
// plain `candidate == c.APIKey()` would. Every credential check in
// PrestoBack (this one, and ValidatePairedKey in pairing.go) goes through
// SecureEquals for exactly this reason; a new credential type added later
// should do the same rather than reintroducing a bare `==`.
func (c *Config) ValidateAPIKey(candidate string) bool {
	if candidate == "" {
		return false
	}
	c.mu.RLock()
	key := c.apiKey
	c.mu.RUnlock()
	return SecureEquals(candidate, key)
}

func (c *Config) RegenerateAPIKey() string {
	c.mu.Lock()
	c.apiKey = GenerateAPIKey()
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
	// c.apps is a map — iteration order above is randomized by the Go
	// runtime, not just "unspecified once and stable after that." Without
	// this sort, GET /api/apps could (and did) come back in a different
	// order on every single call, so the Applications page visibly
	// reshuffled on any reload, including one triggered by saving a
	// completely unrelated field on a different app. CreatedAt gives a
	// real, stable ordering (the order apps were added); Name is only the
	// tie-break for apps predating that field, whose CreatedAt is the zero
	// value and would otherwise all tie against each other.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (c *Config) GetApp(id string) (AppConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	a, ok := c.apps[id]
	return a, ok
}

// PathInUse reports whether path is already registered as a volume on a
// different app, returning that app's ID and Name for a clear error message.
// Used to stop the same directory silently ending up backed up under two
// independent app entries (e.g. a Discover Apps "Choose items" import that
// happens to pick a path already covered by an existing app).
func (c *Config) PathInUse(path string, excludeID string) (id, name string, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	clean := filepath.Clean(path)
	for aid, a := range c.apps {
		if aid == excludeID {
			continue
		}
		for _, v := range a.Volumes {
			if filepath.Clean(v.Path) == clean {
				return aid, a.Name, true
			}
		}
	}
	return "", "", false
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
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	// Normalise volumes
	for i := range a.Volumes {
		if a.Volumes[i].Slug == "" {
			a.Volumes[i].Slug = slugFromPathFor(a.Volumes[i].Path, a.ID)
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
	existing, exists := c.apps[a.ID]
	if !exists {
		return fmt.Errorf("app '%s' not found", a.ID)
	}
	// The Edit App form has no CreatedAt field and never sends one back —
	// without this, every save would silently zero it out again (a is a
	// fresh struct built from the request body), right back to the
	// map-iteration-order bug ListApps' sort exists to fix.
	if a.CreatedAt.IsZero() {
		a.CreatedAt = existing.CreatedAt
	}
	// The Edit App UI exposes a single "Config directory path" field, which
	// maps to the top-level Path — but Path is normally just a *computed*
	// display value derived from Volumes[0].Path (see PrimaryPath below).
	// Without this, an edited Path is silently discarded a few lines down
	// when it gets overwritten by PrimaryPath(). For the common single-volume
	// case, treat an edited Path as an edit to that volume's own path, and
	// re-derive its slug/label from the new location (matching what you'd
	// get by deleting and re-adding the app at the new path).
	if a.Path != "" && len(a.Volumes) == 1 && filepath.Clean(a.Path) != filepath.Clean(a.Volumes[0].Path) {
		a.Volumes[0].Path = a.Path
		a.Volumes[0].Slug = slugFromPath(a.Path)
		a.Volumes[0].Label = a.Volumes[0].Slug
	}
	// Normalise volumes
	for i := range a.Volumes {
		if a.Volumes[i].Slug == "" {
			a.Volumes[i].Slug = slugFromPathFor(a.Volumes[i].Path, a.ID)
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

// ── Encryption ────────────────────────────────────────────────────────────────

// GetEncryption returns the global encryption settings. The passphrase IS
// included here deliberately (unlike a "safe to expose" getter) — the one
// caller that needs it (the backup write path) needs the real value, and
// this is an internal Go API, not the HTTP layer. internal/api/server.go's
// HTTP handler for this settings screen must redact Passphrase before
// sending it to the browser (see server.go's handleGetEncryption).
func (c *Config) GetEncryption() EncryptionConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.encryption
}

func (c *Config) SetEncryption(e EncryptionConfig) {
	c.mu.Lock()
	c.encryption = e
	c.mu.Unlock()
	_ = c.Save()
}

// ── Remote ────────────────────────────────────────────────────────────────────

func (c *Config) GetRemote() RemoteConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remote
}

func (c *Config) SetRemote(r RemoteConfig) {
	c.mu.Lock()
	c.remote = r
	c.mu.Unlock()
	_ = c.Save()
}

// ── Misc ──────────────────────────────────────────────────────────────────────

func (c *Config) BackupDir() string   { return filepath.Join(c.DataDir, "backups") }
func (c *Config) HistoryFile() string { return filepath.Join(c.DataDir, "history.json") }

// slugFromPath derives a short identifier from the last component of a path.
// "/volumes/mosquitto/config" → "config"
// "/volumes/homepage"         → "homepage"
// slugFromPath derives a short identifier from the last path component.
// appID is provided so we can avoid producing a slug identical to it —
// that causes archive names like "caddy_caddy_..." which is confusing.
// When the path tail matches the app ID, we use "data" instead, which
// is the conventional name for an app's primary data volume.
func slugFromPath(p string) string {
	return slugFromPathFor(p, "")
}

func slugFromPathFor(p, appID string) string {
	base := filepath.Base(filepath.Clean(p))
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" || (appID != "" && s == appID) {
		return "data"
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

// ListUsers returns every user account, sorted by username. Hashes are
// included since this is an internal type — callers rendering to JSON for
// the API must strip Hash themselves (see handleUsers in server.go).
func (c *Config) ListUsers() []User {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]User, 0, len(c.users))
	for _, u := range c.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// DeleteUser removes a user account. Returns an error if it's the last
// remaining account — PrestoBack must always have at least one login, or the
// UI becomes permanently inaccessible (there's no "forgot password" recovery
// flow other than editing config.json directly on disk).
func (c *Config) DeleteUser(username string) error {
	c.mu.Lock()
	if len(c.users) <= 1 {
		c.mu.Unlock()
		return fmt.Errorf("cannot delete the last remaining account")
	}
	if _, exists := c.users[username]; !exists {
		c.mu.Unlock()
		return fmt.Errorf("user '%s' not found", username)
	}
	delete(c.users, username)
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
