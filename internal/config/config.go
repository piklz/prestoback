package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	// PausedAt is set the moment Enabled transitions to false (see
	// UpdateApp), and cleared the moment it transitions back to true —
	// how long a paused schedule has actually been paused, for the
	// "you've had this off for a week, still want that?" reminder
	// (pausedScheduleReminderLoop in internal/api/server.go). Nil for an
	// app that's never had its schedule paused, or one that was never
	// scheduled in the first place.
	PausedAt *time.Time `json:"paused_at,omitempty"`
	// LastReminderAt tracks the last time a reminder was actually sent,
	// separate from PausedAt, so reminders can repeat periodically (once
	// a week, say) for as long as the schedule stays paused, rather than
	// firing exactly once and then going silent even if it's still paused
	// months later.
	LastReminderAt *time.Time `json:"last_reminder_at,omitempty"`
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

// RetentionPolicy is a grandfather-father-son retention scheme — the
// same shape Kopia/Borg/most serious backup tools offer, and the #1 gap
// flagged against them in the 2026-08-25 audit: a flat "keep N" count
// (AppConfig.Retain) can't express "I want a backup for every day this
// week, but only one per week going back a couple months, and one per
// month beyond that" — the actual shape of how people think about
// backup history. Kept as a separate, optional struct rather than
// changing what Retain means: nil (the default) means "keep using the
// flat Retain count," so every existing app config keeps behaving
// exactly as it does today with zero migration needed.
//
// Selection algorithm (selectGFSKeep, engine.go): a backup is kept if it
// is the NEWEST backup within its calendar day, for the Daily most
// recent such days; independently, the newest within its ISO week, for
// the Weekly most recent such weeks; independently, the newest within
// its calendar month, for the Monthly most recent such months. A backup
// can qualify under more than one tier at once (the newest backup
// overall is almost always the daily/weekly/monthly "son" for all three
// simultaneously) — the kept set is the union, not additive counting.
type RetentionPolicy struct {
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// AppConfig represents a single application with one or more volumes to back up.
//
// Migration: the old single-path schema (Path/Excludes) is still read from disk
// for existing entries, then promoted to Volumes on first load.
type AppConfig struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Retain int    `json:"retain"`
	// RetentionPolicy, when non-nil, replaces the flat Retain-count
	// pruning in PruneBackups/PruneRemote with grandfather-father-son
	// selection — see RetentionPolicy's own doc comment above. Retain is
	// still read/written as before (kept as the fallback and as what a
	// plain "keep last N" UI continues to edit); this field is strictly
	// additive.
	RetentionPolicy *RetentionPolicy `json:"retention_policy,omitempty"`
	Schedule        Schedule         `json:"schedule"`
	Pinned          bool             `json:"pinned"`
	ContainerName   string           `json:"container_name,omitempty"`
	Volumes         []VolumeConfig   `json:"volumes"`

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

	// RawSyncPath, when set, opts this app into ALSO maintaining a plain,
	// uncompressed mirror of every volume's live files at
	// <RawSyncPath>/<volume-slug>/ on every backup run — in addition to,
	// never instead of, the normal encrypted/compressed tar.gz archive
	// (PruneBackups/retention/remote-push all keep working exactly as
	// they do today; this is a side effect bolted onto backupVolumeLocked,
	// not a replacement backup mode).
	//
	// Why this exists: PrestoBack's own archives are opaque to any
	// external dedup/snapshot tool (Kopia, restic, Duplicati) — a
	// tar.gz's bytes change completely between runs even when the
	// underlying files barely did, so pointing one of those tools AT a
	// PrestoBack archive gets none of its dedup benefit. Those tools all
	// want a real, on-disk file tree to diff against their own repository
	// — this gives them one. The mirror itself is produced by
	// SyncRawTree (see engine.go): changed/new files are copied,
	// unchanged files are hardlinked from the previous mirror pass (so
	// mtime/inode churn stays minimal — most snapshot tools, Kopia
	// included, use exactly that signal to skip re-reading a file's
	// content), and files removed from the source are removed from the
	// mirror too, so the mirror always reflects "what's really there
	// right now," not an ever-growing pile of history (the history is
	// what Kopia's own snapshot repository is for).
	//
	// Typical use: point RawSyncPath at a bind mount shared with a
	// separately-run Kopia container (e.g. backed by SeaweedFS as its
	// blob store), whose own snapshot policy watches that same path.
	// PrestoBack's tar.gz stays the fast, self-contained "restore this
	// one app right now" safety net; Kopia's repository becomes the
	// long-horizon, deduplicated, space-efficient history across every
	// app sharing one RawSyncPath tree. Left empty (the default), no
	// mirror is maintained and nothing changes from today's behavior.
	RawSyncPath string `json:"raw_sync_path,omitempty"`

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

	OnBackupSuccess          bool `json:"on_backup_success"`
	OnBackupFail             bool `json:"on_backup_fail"`
	OnRestoreSuccess         bool `json:"on_restore_success"`
	OnRestoreFail            bool `json:"on_restore_fail"`
	OnRemoteReceive          bool `json:"on_remote_receive"`
	OnSchedulePausedReminder bool `json:"on_schedule_paused_reminder"`
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
	// PassphraseUpdatedAt tracks when Passphrase last actually changed —
	// used only to detect recovery-phrase staleness (RecoveryPossiblyStale)
	// below. Not touched on a write that doesn't change the value (e.g.
	// toggling Enabled alone) — see SetEncryption.
	PassphraseUpdatedAt *time.Time `json:"passphrase_updated_at,omitempty"`

	// Recovery: an independent secret that can reveal Passphrase above if
	// it's ever lost — see the "Encryption recovery phrase" section
	// further down this file for the full design and why this is
	// deliberately NOT the same thing as a generated passphrase.
	RecoverySalt    string     `json:"recovery_salt,omitempty"`
	RecoveryWrapped string     `json:"recovery_wrapped,omitempty"` // hex: iv || ciphertext || hmac
	RecoverySetAt   *time.Time `json:"recovery_set_at,omitempty"`
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

	// Kind == "prestoback": push to ANOTHER PrestoBack instance, paired
	// via the MITM-resistant handshake in nodeidentity.go/remotepairing.go
	// — see those files' package comments for the full protocol. The three
	// Pinned* fields are set ONCE, at pairing time, from the receiver's QR
	// (an out-of-band, human-verified channel) — never updated silently
	// afterward; see internal/backup/prestobackremote.go for how every
	// subsequent push re-verifies against them.
	PrestoBackURL             string `json:"prestoback_url,omitempty"`
	PrestoBackPinnedNodeID    string `json:"prestoback_pinned_node_id,omitempty"`
	PrestoBackPinnedPublicKey string `json:"prestoback_pinned_public_key,omitempty"`
	PrestoBackPushCredential  string `json:"prestoback_push_credential,omitempty"`

	// AppendOnly opts a mount/sftp/s3 target OUT of PruneRemote's
	// retention deletes entirely (see internal/backup/remote.go) — new
	// archives keep pushing, nothing already written to this target is
	// ever removed by PrestoBack itself. This is the same idea as Borg's
	// `--append-only` and Kopia's S3 Object-Lock support: a ransomware
	// attacker (or a compromised admin session) who can reach this
	// instance's normal backup flow still can't wipe out prior
	// generations on a target marked this way — only a human explicitly
	// unchecking this box, or acting directly on the storage backend
	// itself (e.g. an S3 bucket's own Object Lock, which this flag does
	// NOT configure on its own — see the S3 target's own field comment),
	// can. Does not apply to Kind == "prestoback"; that transport has its
	// own, receiver-enforced equivalent — see RemotePusher.AppendOnly in
	// remotepairing.go, which is the flag that actually matters there
	// since a pusher's own copy of this struct is exactly what an
	// attacker with pusher-side access would be trying to flip back off.
	AppendOnly bool `json:"append_only,omitempty"`
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

	// MFA fields — all zero-value ("", false, nil) for an account that
	// hasn't enabled a second factor, which is the common case and the
	// default for every existing account after an upgrade (no migration
	// needed: an absent/empty MFASecret is exactly equivalent to "MFA was
	// never set up").
	//
	// MFASecret is the raw base32 TOTP secret — kept raw, not hashed,
	// because TOTP verification requires recomputing HMAC(secret, time)
	// and comparing to the submitted code; there's no way to verify a TOTP
	// code against a one-way hash of its secret. Same category of
	// exception as Config.apiKey itself (see apikey.go) — a value that
	// must stay raw because the algorithm that consumes it needs the raw
	// form, not because it's exempt from the "don't store secrets you
	// don't have to" principle.
	MFASecret string `json:"mfa_secret,omitempty"`
	// MFAEnabled is the actual on/off switch. MFASecret can be non-empty
	// while this is false — that's the "setup in progress, not yet
	// confirmed" state (see Config.BeginMFAEnrollment/ConfirmMFAEnrollment
	// in mfa.go) — so login must check MFAEnabled, never just
	// MFASecret != "".
	MFAEnabled bool `json:"mfa_enabled,omitempty"`
	// MFABackupCodeHashes are HashAPIKey(normalizeBackupCode(code)) for
	// each still-unused recovery code. A code is removed from this slice
	// the moment it's successfully used (see
	// Config.VerifyAndConsumeBackupCode) — single-use, enforced under the
	// same write-lock as every other mutation here, so two concurrent
	// requests racing to use the same code can't both succeed.
	MFABackupCodeHashes []string `json:"mfa_backup_code_hashes,omitempty"`
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
	APIKey         string           `json:"api_key"`
	Apps           []AppConfig      `json:"apps"`
	Notify         NotifyConfig     `json:"notify"`
	Users          []User           `json:"users,omitempty"`
	Encryption     EncryptionConfig `json:"encryption,omitempty"`
	Remote         RemoteConfig     `json:"remote,omitempty"`
	PairedKeys     []PairedKey      `json:"paired_keys,omitempty"`
	NodeIdentity   *NodeIdentity    `json:"node_identity,omitempty"`
	RemotePushers  []RemotePusher   `json:"remote_pushers,omitempty"`
	TrustedDevices []TrustedDevice  `json:"trusted_devices,omitempty"`
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

	// mfaPending holds in-progress two-step logins: password already
	// verified, second-factor code not yet submitted. Same
	// deliberately-not-persisted, short-TTL posture as pending above, for
	// the same reasons — see mfa.go.
	mfaPending map[string]*pendingMFALogin

	// nodeIdentity is this instance's permanent Ed25519 keypair — see
	// nodeidentity.go. Generated once on first run and never changed
	// afterward except by explicit user action (RegenerateNodeIdentity),
	// same posture as the master API key.
	nodeIdentity *NodeIdentity

	// remotePending holds in-progress PrestoBack-to-PrestoBack pairing
	// sessions on the RECEIVING side (the instance whose QR is being
	// scanned) — see remotepairing.go. Same deliberately-not-persisted,
	// short-TTL posture as pending/mfaPending above.
	remotePending map[string]*pendingRemotePairing

	// remotePushers holds every OTHER PrestoBack instance that has
	// successfully paired with THIS one as a receiver — i.e. the accepted
	// pusher registry a receiving instance checks incoming pushes against.
	// Persisted (unlike remotePending) — these are the actual long-lived
	// authorization records, not in-progress handshakes.
	remotePushers map[string]RemotePusher

	// trustedDevices holds "skip MFA on this device for 30 days" records
	// — see mfa.go's device-trust section. Persisted, like remotePushers:
	// a real, long-lived authorization a user should be able to see and
	// revoke, not an ephemeral handshake.
	trustedDevices map[string]TrustedDevice

	// mfaAttempts tracks failed second-factor verifications per username,
	// independent of the password-login lockout in internal/api/auth.go.
	// Without this, an attacker who already has a valid password (leaked/
	// reused elsewhere) could guess a 6-digit TOTP code indefinitely —
	// each guess just costs one more password-verified login round trip,
	// which the password lockout doesn't rate-limit at all since the
	// password itself is correct every time. Deliberately not persisted,
	// same short-lived-in-memory posture as every other lockout/pending
	// map in this struct — see mfa.go's lockout section for the actual
	// threshold/duration and reasoning.
	mfaAttempts map[string]*mfaLockoutState
}

func Load(dataDir string) (*Config, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	c := &Config{
		DataDir:        dataDir,
		apps:           make(map[string]AppConfig),
		users:          make(map[string]User),
		revokedTokens:  make(map[string]struct{}),
		pairedKeys:     make(map[string]PairedKey),
		pending:        make(map[string]*pendingPairing),
		mfaPending:     make(map[string]*pendingMFALogin),
		remotePending:  make(map[string]*pendingRemotePairing),
		remotePushers:  make(map[string]RemotePusher),
		trustedDevices: make(map[string]TrustedDevice),
		mfaAttempts:    make(map[string]*mfaLockoutState),
	}
	path := filepath.Join(dataDir, "config.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		c.apiKey = GenerateAPIKey()
		identity, err := GenerateNodeIdentity()
		if err != nil {
			return nil, fmt.Errorf("generate node identity: %w", err)
		}
		c.nodeIdentity = identity
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
	for _, rp := range d.RemotePushers {
		c.remotePushers[rp.ID] = rp
	}
	for _, td := range d.TrustedDevices {
		c.trustedDevices[td.ID] = td
	}
	if d.NodeIdentity != nil {
		c.nodeIdentity = d.NodeIdentity
	} else {
		// Upgrading from a version before node identities existed — mint
		// one now rather than leaving it nil, same "heal on load" pattern
		// as the volume-migration logic above. Existing remote pairings
		// can't have referenced this instance's identity yet (the feature
		// didn't exist), so there's nothing to invalidate by generating a
		// fresh one here.
		identity, genErr := GenerateNodeIdentity()
		if genErr != nil {
			return nil, fmt.Errorf("generate node identity: %w", genErr)
		}
		c.nodeIdentity = identity
	}
	migrateLegacyRemoteNames(&c.remote, c.remotePushers)
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
		APIKey:       c.apiKey,
		Notify:       c.notify,
		Encryption:   c.encryption,
		Remote:       c.remote,
		NodeIdentity: c.nodeIdentity,
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
	for _, rp := range c.remotePushers {
		d.RemotePushers = append(d.RemotePushers, rp)
	}
	for _, td := range c.trustedDevices {
		d.TrustedDevices = append(d.TrustedDevices, td)
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

	// Track when the backup schedule was paused, so a "you've had this
	// paused for a week, still want that?" reminder (see
	// pausedScheduleReminderLoop in internal/api/server.go) knows how long
	// it's actually been, and doesn't need every one of the several places
	// that can flip Schedule.Enabled (the dashboard's pause button,
	// Telegram's /schedpause and /schedresume) to separately remember to
	// stamp a timestamp — this is the one place ALL of them funnel through
	// to persist the change, so it's the one place this needs to live.
	if existing.Schedule.Enabled && !a.Schedule.Enabled {
		now := time.Now()
		a.Schedule.PausedAt = &now
		a.Schedule.LastReminderAt = nil
	} else if !existing.Schedule.Enabled && a.Schedule.Enabled {
		a.Schedule.PausedAt = nil
		a.Schedule.LastReminderAt = nil
	} else if existing.Schedule.PausedAt != nil && a.Schedule.PausedAt == nil {
		// The incoming request is a fresh struct from a form that has no
		// field for this (same reasoning as CreatedAt above) — preserve
		// it rather than silently losing track of how long a still-paused
		// schedule has actually been paused.
		a.Schedule.PausedAt = existing.Schedule.PausedAt
		a.Schedule.LastReminderAt = existing.Schedule.LastReminderAt
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

// MarkScheduleReminderSent records that a paused-schedule reminder was
// just sent for appID — a small, targeted update rather than routing
// through the generic full-object UpdateApp, since this is called from a
// background loop (pausedScheduleReminderLoop) that has no reason to
// touch, or risk racing against, anything else about the app.
func (c *Config) MarkScheduleReminderSent(appID string) error {
	c.mu.Lock()
	a, ok := c.apps[appID]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("app '%s' not found", appID)
	}
	now := time.Now()
	a.Schedule.LastReminderAt = &now
	c.apps[appID] = a
	c.mu.Unlock()
	return c.Save()
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
	if e.Passphrase != c.encryption.Passphrase {
		// Track when the live passphrase last changed — this is what lets
		// RecoveryPossiblyStale (below) tell the admin "the recovery
		// phrase you generated no longer matches what's actually
		// protecting new backups," without needing to unwrap anything to
		// find out.
		now := time.Now()
		e.PassphraseUpdatedAt = &now
	} else {
		e.PassphraseUpdatedAt = c.encryption.PassphraseUpdatedAt
	}
	c.encryption = e
	c.mu.Unlock()
	_ = c.Save()
}

// ── Encryption recovery phrase ──────────────────────────────────────────────
//
// This is deliberately NOT "generate a strong passphrase for me" (that
// would just be a password generator wired to the passphrase field, and
// isn't what a recovery phrase is). A recovery phrase is a SECOND,
// INDEPENDENT credential — same idea as Bitwarden's account recovery
// process, or a disk-encryption "recovery key" alongside your normal
// unlock password: it exists purely to reveal the real passphrase later
// if that's ever lost, and is meant to be written down and stored
// somewhere durable and SEPARATE from wherever the day-to-day passphrase
// lives — so losing one doesn't automatically mean losing both.
//
// Mechanism: GenerateEncryptionRecovery takes a snapshot of the CURRENT
// EncryptionConfig.Passphrase and encrypts it (PBKDF2-HMAC-SHA256 key
// derivation, AES-256-CTR + HMAC-SHA256 authentication — the identical
// construction backupcrypto.go already uses for archives, reimplemented
// here directly rather than imported, since this operates on a few bytes
// of passphrase rather than a multi-GB stream and pulling in a
// stream-oriented API buys nothing at this size) under a key derived
// from a freshly generated recovery phrase. The wrapped blob is stored;
// the raw recovery phrase is returned to the caller exactly once and
// never stored anywhere, matching the ClaimPairing/API-key-regeneration
// precedent elsewhere in this package.
//
// Staleness: because the raw recovery phrase is never retained, this
// server has no way to automatically re-wrap a NEW passphrase if the
// admin changes it later — the recovery phrase can only ever reveal the
// passphrase as it stood at generation time. RecoveryPossiblyStale
// surfaces exactly that by comparing timestamps, so the UI can prompt
// "regenerate your recovery phrase" rather than let it silently go
// stale and fail someone at the worst possible moment.

const recoveryPhraseAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford Base32 minus ambiguous glyphs — see NodeID's chunking comment (nodeidentity.go) for the same rationale

// GenerateRecoverySeedPhrase returns a fresh ~120-bit random phrase (24
// chars from a 32-symbol alphabet, chunked in groups of 4 for
// readability). Used as the wrapping key for the recovery mechanism
// below — never as a passphrase substitute.
func GenerateRecoverySeedPhrase() (string, error) {
	const length = 24
	const groupSize = 4
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("config: crypto/rand unavailable: %w", err)
	}
	var out strings.Builder
	for i, r := range b {
		out.WriteByte(recoveryPhraseAlphabet[int(r)%len(recoveryPhraseAlphabet)])
		if (i+1)%groupSize == 0 && i != length-1 {
			out.WriteByte('-')
		}
	}
	return out.String(), nil
}

// GenerateEncryptionRecovery generates a new recovery phrase, wraps the
// CURRENT passphrase under it, stores the wrapped blob, and returns the
// raw phrase for one-time display. Errors if encryption isn't enabled or
// no passphrase is set yet — there is nothing meaningful to protect.
func (c *Config) GenerateEncryptionRecovery() (phrase string, err error) {
	c.mu.Lock()
	cur := c.encryption
	c.mu.Unlock()
	if cur.Passphrase == "" {
		return "", fmt.Errorf("no passphrase is set yet — set one before generating a recovery phrase")
	}

	phrase, err = GenerateRecoverySeedPhrase()
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("config: crypto/rand unavailable: %w", err)
	}
	wrapped, err := wrapSecret([]byte(cur.Passphrase), phrase, salt)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	now := time.Now()
	c.encryption.RecoverySalt = hex.EncodeToString(salt)
	c.encryption.RecoveryWrapped = hex.EncodeToString(wrapped)
	c.encryption.RecoverySetAt = &now
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		return "", err
	}
	return phrase, nil
}

// RecoverEncryptionPassphrase unwraps the passphrase a previously
// generated recovery phrase protects. stale reports whether the LIVE
// passphrase has changed since this recovery phrase was generated — the
// unwrapped value is still returned in that case (it's real, it just may
// no longer be what's protecting new backups), so the caller can decide
// what to do with it rather than have it silently withheld.
func (c *Config) RecoverEncryptionPassphrase(recoveryPhrase string) (passphrase string, stale bool, err error) {
	c.mu.RLock()
	cur := c.encryption
	c.mu.RUnlock()
	if cur.RecoveryWrapped == "" || cur.RecoverySalt == "" {
		return "", false, fmt.Errorf("no recovery phrase has been generated")
	}
	salt, err := hex.DecodeString(cur.RecoverySalt)
	if err != nil {
		return "", false, fmt.Errorf("stored recovery data is corrupt: %w", err)
	}
	wrapped, err := hex.DecodeString(cur.RecoveryWrapped)
	if err != nil {
		return "", false, fmt.Errorf("stored recovery data is corrupt: %w", err)
	}
	plain, err := unwrapSecret(wrapped, recoveryPhrase, salt)
	if err != nil {
		return "", false, fmt.Errorf("incorrect recovery phrase")
	}
	recovered := string(plain)
	stale = recovered != cur.Passphrase
	return recovered, stale, nil
}

// RecoveryPossiblyStale reports whether the current passphrase has
// changed since the recovery phrase was last generated — a cheap,
// timestamp-only check the GET /api/encryption endpoint can surface
// without unwrapping anything, so the UI can nudge "regenerate your
// recovery phrase" before it's actually needed rather than only
// discovering the mismatch during a real recovery attempt.
func (c *Config) RecoveryPossiblyStale() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e := c.encryption
	if e.RecoverySetAt == nil || e.PassphraseUpdatedAt == nil {
		return false
	}
	return e.PassphraseUpdatedAt.After(*e.RecoverySetAt)
}

// wrapSecret / unwrapSecret — small-blob sibling of backupcrypto.go's
// EncryptStream/DecryptStream: identical construction (PBKDF2-HMAC-
// SHA256 key derivation into separate AES and HMAC subkeys, AES-256-CTR
// for encryption, HMAC-SHA256 for authentication, encrypt-then-MAC), but
// operating on an in-memory []byte rather than a stream, since what's
// being wrapped here is a passphrase (bytes, not gigabytes). Output
// layout: iv (16 bytes) || ciphertext || hmac (32 bytes) — the caller
// supplies and stores salt separately since GenerateEncryptionRecovery
// needs it before Save() is called.
func wrapSecret(plaintext []byte, passphrase string, salt []byte) ([]byte, error) {
	aesKey, hmacKey := deriveWrapKeys(passphrase, salt)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(iv)+len(ciphertext)+len(tag))
	out = append(out, iv...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out, nil
}

func unwrapSecret(blob []byte, passphrase string, salt []byte) ([]byte, error) {
	if len(blob) < aes.BlockSize+sha256.Size {
		return nil, fmt.Errorf("wrapped data too short")
	}
	iv := blob[:aes.BlockSize]
	tag := blob[len(blob)-sha256.Size:]
	ciphertext := blob[aes.BlockSize : len(blob)-sha256.Size]

	aesKey, hmacKey := deriveWrapKeys(passphrase, salt)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, fmt.Errorf("authentication failed — wrong recovery phrase or corrupted data")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// deriveWrapKeys mirrors backupcrypto.go's deriveKeys exactly (same
// iteration count, same split of one PBKDF2 pass into two subkeys) —
// duplicated rather than imported for the same reason wrapSecret/
// unwrapSecret are implemented locally: package config does not import
// package backup (server.go, in package api, is the one place that
// glues the two together), and this is a small enough primitive that
// duplicating it here is simpler and safer than introducing a new
// cross-package dependency for it.
func deriveWrapKeys(passphrase string, salt []byte) (aesKey, hmacKey []byte) {
	const iterations = 200_000
	out := pbkdf2HMACSHA256([]byte(passphrase), salt, iterations, 64)
	return out[:32], out[32:]
}

func pbkdf2HMACSHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		blockIndex := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
		prf.Reset()
		prf.Write(salt)
		prf.Write(blockIndex)
		u := prf.Sum(nil)
		result := make([]byte, len(u))
		copy(result, u)
		for i := 2; i <= iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range result {
				result[j] ^= u[j]
			}
		}
		dk = append(dk, result...)
	}
	return dk[:keyLen]
}

// ── Remote ────────────────────────────────────────────────────────────────────

func (c *Config) GetRemote() RemoteConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remote
}

func (c *Config) SetRemote(r RemoteConfig) error {
	c.mu.Lock()
	c.remote = r
	c.mu.Unlock()
	return c.Save()
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
