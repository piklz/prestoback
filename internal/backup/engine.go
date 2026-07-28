package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Status string

const (
	StatusIdle    Status = "idle"
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
)

// BackupMeta describes a single archive on disk.
// One app backup run may produce multiple BackupMeta (one per volume).
type BackupMeta struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	AppName    string     `json:"app_name"`
	VolumeSlug string     `json:"volume_slug,omitempty"` // "config", "data", "log" etc.
	SourcePath string     `json:"source_path,omitempty"` // original source directory that was archived
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Status     Status     `json:"status"`
	Error      string     `json:"error,omitempty"`
	FilePath   string     `json:"file_path"`
	// Remote lists every configured target this specific archive has been
	// successfully pushed to (see internal/backup/remote.go PushAppBackup
	// and ManifestEntry.Remote below, which is the field actually persisted
	// across restarts — ListBackups populates this one by reading manifests
	// back off disk, same as it derives everything else about a listed
	// archive from what's actually there).
	Remote     []string `json:"remote,omitempty"`
	PreRestore bool     `json:"pre_restore,omitempty"`
	// Encrypted is true when this archive was written through EncryptStream
	// (see backupcrypto.go). When true, SizeBytes and the manifest's SHA256
	// both describe the CIPHERTEXT on disk, not the plaintext — restoring
	// requires the passphrase, and any archive re-hash for tamper-detection
	// is naturally comparing ciphertext bytes too.
	Encrypted bool `json:"encrypted,omitempty"`
}

// ProgressInfo is a throttled byte-progress sample for a running job. Not
// every JobUpdate carries one — see emitProgress's time-based throttle.
type ProgressInfo struct {
	BytesDone  int64   `json:"bytes_done"`
	BytesTotal int64   `json:"bytes_total"`
	Percent    float64 `json:"percent"`
	// CurrentVolume names which volume is being processed right now, so a
	// single aggregate bar can still show "3/5 — plex_data" alongside the
	// overall percentage, rather than resetting to 0% per volume.
	CurrentVolume string `json:"current_volume,omitempty"`
}

type JobUpdate struct {
	AppID    string        `json:"app_id"`
	Backup   BackupMeta    `json:"backup"`
	Log      string        `json:"log"`
	Update   *UpdateResult `json:"update,omitempty"`
	Progress *ProgressInfo `json:"progress,omitempty"`
}

type Engine struct {
	backupDir string
	mu        sync.Mutex
	running   map[string]bool
	updates   chan JobUpdate
}

func NewEngine(backupDir string) *Engine {
	return &Engine{
		backupDir: backupDir,
		running:   make(map[string]bool),
		updates:   make(chan JobUpdate, 128),
	}
}

func (e *Engine) Updates() <-chan JobUpdate { return e.updates }

// ── Archive naming ────────────────────────────────────────────────────────────
//
// Archives live in:  backups/{appID}/{appID}_{volumeSlug}_{timestamp}.tar.gz
//
// Examples:
//   backups/mosquitto/mosquitto_config_20250615_120000.tar.gz
//   backups/mosquitto/mosquitto_data_20250615_120000.tar.gz
//   backups/homepage/homepage_homepage_20250615_120000.tar.gz  (single-volume app)
//
// Pre-restore snapshots append "_prerestore":
//   backups/mosquitto/mosquitto_config_20250615_120000_prerestore.tar.gz

func archiveFilename(appID, volumeSlug, timestamp string, preRestore bool) string {
	name := fmt.Sprintf("%s_%s_%s", appID, volumeSlug, timestamp)
	if preRestore {
		name += "_prerestore"
	}
	return name + ".tar.gz"
}

// archiveID returns the filename stem (without .tar.gz) for use as a BackupMeta.ID.
func archiveID(appID, volumeSlug, timestamp string, preRestore bool) string {
	s := fmt.Sprintf("%s_%s_%s", appID, volumeSlug, timestamp)
	if preRestore {
		s += "_prerestore"
	}
	return s
}

// ── VolumeTarget is passed in from the server layer ───────────────────────────

type VolumeTarget struct {
	Slug     string
	Path     string
	Excludes []string
}

// ── Backup ────────────────────────────────────────────────────────────────────

// CheckAllDiskSpace measures every volume's source size and confirms the
// backup destination has enough free space for ALL of them combined, before
// any container is stopped. This is the pre-flight gate that runBackup calls
// up-front — if it fails, the backup is aborted before any downtime occurs.
//
// This is intentionally separate from the per-volume checkDiskSpace done
// later inside backupVolumes (which remains as a defense-in-depth check in
// case free space changes between the pre-flight and the actual write).
// EstimateVolumesSize sums the regular-file size of every volume's source
// directory. Shared by CheckAllDiskSpace (pre-flight free-space check) and
// the /api/estimate endpoint (pre-flight size+duration estimate for the
// large-operation confirm modal) and backupVolumes (so the aggregate
// progress bar knows a total to divide by) — one walk implementation, three
// callers, rather than three slightly different ones drifting apart.
func EstimateVolumesSize(volumes []VolumeTarget) int64 {
	var total int64
	for _, vol := range volumes {
		_ = filepath.Walk(vol.Path, func(_ string, info os.FileInfo, err error) error {
			if err == nil && info != nil && info.Mode().IsRegular() {
				total += info.Size()
			}
			return nil
		})
	}
	return total
}

func (e *Engine) CheckAllDiskSpace(appID string, volumes []VolumeTarget, emit func(string)) error {
	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("cannot prepare backup directory: %w", err)
	}

	totalSrcBytes := EstimateVolumesSize(volumes)

	var stat syscall.Statfs_t
	if err := syscall.Statfs(destDir, &stat); err != nil {
		emit(fmt.Sprintf("⚠  disk space check skipped (statfs %s: %v)", destDir, err))
		return nil
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)

	// Require 1.2× combined source size free (worst case: no compression).
	required := uint64(float64(totalSrcBytes) * 1.2)
	if required > freeBytes {
		return fmt.Errorf(
			"source totals %.1f GB across %d volume(s), need %.1f GB free, only %.1f GB available on backup volume",
			float64(totalSrcBytes)/1e9, len(volumes),
			float64(required)/1e9, float64(freeBytes)/1e9,
		)
	}

	emit(fmt.Sprintf("✓ disk space OK (source %.1f GB total, free %.1f GB)",
		float64(totalSrcBytes)/1e9, float64(freeBytes)/1e9))
	return nil
}

// RunPreBackupCmd executes a shell command (e.g. `pg_dump ... > /data/dump.sql`)
// before containers are stopped, streaming combined stdout/stderr to emit as
// it runs. A 5-minute timeout prevents a hung hook from blocking the backup
// indefinitely.
func (e *Engine) RunPreBackupCmd(appID, cmdStr string, emit func(string)) error {
	cmdStr = strings.TrimSpace(cmdStr)
	if cmdStr == "" {
		return nil
	}

	cmd := exec.Command("sh", "-c", cmdStr)

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create output pipe: %w", err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return fmt.Errorf("start command: %w", err)
	}
	// Close our copy of the write end so the reader sees EOF once the child exits.
	pw.Close()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := pr.Read(buf)
			if n > 0 {
				for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\n"), "\n") {
					if line != "" {
						emit("  [pre-backup] " + line)
					}
				}
			}
			if rerr != nil {
				break
			}
		}
		close(done)
	}()

	timer := time.AfterFunc(5*time.Minute, func() {
		emit("⚠  pre-backup command exceeded 5m timeout — killing")
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	<-done
	pr.Close()
	if werr := cmd.Wait(); werr != nil {
		return fmt.Errorf("command exited with error: %w", werr)
	}
	return nil
}

// BackupVolumes archives each supplied volume into the app's backup directory.
// Returns one BackupMeta per volume (in the same order), plus the first error encountered.
// On error the remaining volumes are still attempted; caller gets all results.
// BackupVolumes archives each supplied volume. passphrase enables archive
// encryption for this run when non-empty (resolved by the caller from
// config.EncryptionConfig + the app's per-app override — see
// AppConfig.EffectiveEncrypted in internal/config/config.go); pass "" to
// write plaintext archives as before.
func (e *Engine) BackupVolumes(appID, appName string, volumes []VolumeTarget, passphrase string) ([]BackupMeta, error) {
	return e.backupVolumes(appID, appName, volumes, false, passphrase)
}

func (e *Engine) backupVolumes(appID, appName string, volumes []VolumeTarget, preRestore bool, passphrase string) ([]BackupMeta, error) {
	e.mu.Lock()
	if e.running[appID] {
		e.mu.Unlock()
		return nil, fmt.Errorf("a job is already running for %s", appID)
	}
	e.running[appID] = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.running, appID)
		e.mu.Unlock()
	}()

	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	timestamp := time.Now().Format("20060102_150405")
	label := "backup"
	if preRestore {
		label = "pre-restore snapshot"
	}

	var results []BackupMeta
	var firstErr error

	// Aggregate progress across the whole run, not per-volume — see
	// progressEmitter's doc comment above. Sizing this against plaintext
	// source bytes (not the eventual, slightly-different, on-disk archive
	// size) is intentional: it's the only total known before any volume has
	// actually been archived yet.
	totalBytes := EstimateVolumesSize(volumes)
	progressMeta := &BackupMeta{AppID: appID, AppName: appName, Status: StatusRunning}
	prog := newProgressEmitter(e, progressMeta, totalBytes)

	for _, vol := range volumes {
		id := archiveID(appID, vol.Slug, timestamp, preRestore)
		destFile := filepath.Join(destDir, id+".tar.gz")
		prog.startVolume(vol.Slug)

		meta := BackupMeta{
			ID:         id,
			AppID:      appID,
			AppName:    appName,
			VolumeSlug: vol.Slug,
			SourcePath: vol.Path, // recorded in manifest for self-describing restore
			StartedAt:  time.Now(),
			Status:     StatusRunning,
			FilePath:   destFile,
			PreRestore: preRestore,
		}

		if len(vol.Excludes) > 0 {
			e.emit(&meta, fmt.Sprintf("Starting %s: %s [%s] (excluding: %s)",
				label, vol.Slug, vol.Path, strings.Join(vol.Excludes, ", ")))
		} else {
			e.emit(&meta, fmt.Sprintf("Starting %s: %s [%s]", label, vol.Slug, vol.Path))
		}

		// Secondary safety net: re-check this volume's space immediately before
		// writing. The primary gate is Engine.CheckAllDiskSpace, called by the
		// server BEFORE any container is stopped — this catches the rarer case
		// where free space dropped between that check and now.
		if err := checkDiskSpace(vol.Path, destDir, e, &meta); err != nil {
			meta.Status = StatusFailed
			meta.Error = err.Error()
			if firstErr == nil {
				firstErr = err
			}
			results = append(results, meta)
			continue
		}

		size, err := tarGz(vol.Path, destFile, vol.Excludes, prog.onBytes)
		fin := time.Now()
		meta.FinishedAt = &fin

		if err != nil {
			_ = os.Remove(destFile)
			meta.Status = StatusFailed
			meta.Error = err.Error()
			e.emit(&meta, fmt.Sprintf("%s FAILED (%s): %s", label, vol.Slug, err.Error()))
			if firstErr == nil {
				firstErr = err
			}
			results = append(results, meta)
			continue
		}

		// ── Post-backup integrity verification ───────────────────────────────
		// Open the freshly written archive and walk every header via the tar
		// reader. This catches truncated writes, bad gzip footers, or corrupt
		// archives BEFORE containers are restarted — so a failed verification
		// still leaves us able to immediately retry against live (not yet
		// restarted) containers if the caller chooses to.
		e.emit(&meta, fmt.Sprintf("Verifying archive integrity: %s", id))
		if verr := verifyArchive(destFile); verr != nil {
			_ = os.Remove(destFile)
			meta.Status = StatusFailed
			meta.Error = fmt.Sprintf("archive verification failed: %v", verr)
			e.emit(&meta, fmt.Sprintf("%s FAILED verification (%s): %v — archive discarded", label, vol.Slug, verr))
			if firstErr == nil {
				firstErr = fmt.Errorf("archive verification failed for %s: %w", vol.Slug, verr)
			}
			results = append(results, meta)
			continue
		}

		finalSize := size
		if passphrase != "" {
			e.emit(&meta, fmt.Sprintf("Encrypting archive: %s", id))
			encSize, encErr := encryptArchiveInPlace(destFile, passphrase, prog.onBytes)
			if encErr != nil {
				_ = os.Remove(destFile)
				meta.Status = StatusFailed
				meta.Error = fmt.Sprintf("encryption failed: %v", encErr)
				e.emit(&meta, fmt.Sprintf("%s FAILED encryption (%s): %v — archive discarded", label, vol.Slug, encErr))
				if firstErr == nil {
					firstErr = fmt.Errorf("encryption failed for %s: %w", vol.Slug, encErr)
				}
				results = append(results, meta)
				continue
			}
			meta.Encrypted = true
			finalSize = encSize
		}

		meta.SizeBytes = finalSize
		meta.Status = StatusSuccess
		prog.flush() // make sure the final sample reads 100% for this volume, not whatever the last throttled tick left it at
		encNote := ""
		if meta.Encrypted {
			encNote = ", encrypted 🔒"
		}
		e.emit(&meta, fmt.Sprintf("%s complete (%s, %.1f MB, verified ✓%s): %s",
			label, vol.Slug, float64(finalSize)/1e6, encNote, id))
		results = append(results, meta)
	}
	return results, firstErr
}

// ── Legacy single-volume shim (keeps server.go compile-clean during transition) ─

// BackupApp is kept for callers that still pass a single path. Not currently
// called anywhere in server.go (multi-volume BackupVolumes replaced it) —
// kept only so it still compiles for any external caller. Always writes
// plaintext; nothing currently exercises this path so there's no passphrase
// to wire through.
func (e *Engine) BackupApp(appID, appName, srcPath string, excludes []string) (*BackupMeta, error) {
	slug := slugFromPath(srcPath)
	metas, err := e.backupVolumes(appID, appName, []VolumeTarget{{Slug: slug, Path: srcPath, Excludes: excludes}}, false, "")
	if len(metas) > 0 {
		return &metas[0], err
	}
	return nil, err
}

// ── Restore ───────────────────────────────────────────────────────────────────

// RestoreOptions controls how RestoreVolume handles encryption on both sides
// of a restore: decrypting the archive being restored FROM, and (optionally)
// encrypting the pre-restore safety snapshot taken of what's currently on
// disk before it gets overwritten.
type RestoreOptions struct {
	// ArchiveEncrypted must be set from the manifest's ManifestEntry.Encrypted
	// for the specific archive being restored — RestoreVolume does not try to
	// guess this from file content.
	ArchiveEncrypted bool
	// RestorePassphrase decrypts the archive above. Required (and never
	// silently substituted from config) when ArchiveEncrypted is true — see
	// EncryptionConfig's doc comment in internal/config/config.go for why
	// restore never uses the auto-stored passphrase on its own.
	RestorePassphrase string
	// SnapshotPassphrase optionally encrypts the pre-restore safety snapshot
	// this function takes automatically in Step 1. Empty means "don't
	// encrypt the snapshot" — typically the caller passes the same
	// auto-stored global passphrase used for scheduled backups, since taking
	// a snapshot is a write-path operation like any other backup.
	SnapshotPassphrase string
}

// RestoreVolume restores a single archive into destPath, taking a pre-restore snapshot first.
func (e *Engine) RestoreVolume(appID, appName, volumeSlug, archivePath, destPath string, opts RestoreOptions) error {
	e.mu.Lock()
	if e.running[appID] {
		e.mu.Unlock()
		return fmt.Errorf("a job is already running for %s", appID)
	}
	e.running[appID] = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.running, appID)
		e.mu.Unlock()
	}()

	sentinel := &BackupMeta{AppID: appID, AppName: appName, VolumeSlug: volumeSlug, Status: StatusRunning}

	// Step 1 — pre-restore safety snapshot
	e.emit(sentinel, fmt.Sprintf("Taking pre-restore snapshot of %s [%s]…", appName, volumeSlug))
	if _, snapErr := e.backupVolumeLocked(appID, appName, VolumeTarget{Slug: volumeSlug, Path: destPath}, true, opts.SnapshotPassphrase); snapErr != nil {
		e.emit(sentinel, fmt.Sprintf("Warning: could not snapshot %s: %v — continuing", volumeSlug, snapErr))
	}

	// Step 2 — decrypt (if needed), then extract
	extractSrc := archivePath
	if opts.ArchiveEncrypted {
		e.emit(sentinel, "Verifying archive authenticity and decrypting…")
		decPath, decErr := decryptArchiveToTemp(archivePath, opts.RestorePassphrase)
		if decErr != nil {
			sentinel.Status = StatusFailed
			if errors.Is(decErr, ErrAuthenticationFailed) {
				sentinel.Error = "wrong passphrase or corrupted archive"
			} else {
				sentinel.Error = decErr.Error()
			}
			e.emit(sentinel, "Restore FAILED: "+sentinel.Error)
			return decErr
		}
		defer os.Remove(decPath)
		extractSrc = decPath
	}

	prog := newProgressEmitter(e, sentinel, EstimateVolumesSize([]VolumeTarget{{Path: destPath}}))
	// destPath doesn't hold the NEW content's size yet (that's what we're
	// about to write) — this estimate is necessarily approximate, based on
	// whatever's there now (e.g. the old data being replaced, similar order
	// of magnitude in the common case). Good enough for a progress bar;
	// not used for anything that needs to be exact.
	prog.startVolume(volumeSlug)

	e.emit(sentinel, fmt.Sprintf("Extracting %s → %s", filepath.Base(archivePath), destPath))
	if err := extractTarGz(extractSrc, destPath, prog.onBytes); err != nil {
		sentinel.Status = StatusFailed
		sentinel.Error = err.Error()
		e.emit(sentinel, "Restore FAILED: "+err.Error())
		return err
	}
	prog.flush()

	fin := time.Now()
	sentinel.FinishedAt = &fin
	sentinel.Status = StatusSuccess
	e.emit(sentinel, fmt.Sprintf("Restore complete ✓ — %s written to %s", volumeSlug, destPath))
	return nil
}

// RestoreApp is the legacy single-path shim. Not currently called anywhere
// (multi-volume RestoreVolume replaced it) — kept for compile-safety only,
// always unencrypted since nothing exercises this path.
func (e *Engine) RestoreApp(appID, appName, archivePath, destPath string) error {
	slug := slugFromPath(destPath)
	return e.RestoreVolume(appID, appName, slug, archivePath, destPath, RestoreOptions{})
}

// backupVolumeLocked backs up a single volume while the engine lock is held.
// passphrase encrypts the result when non-empty — used by RestoreVolume for
// the pre-restore snapshot, which is a real archive on disk like any other
// and gets the same at-rest protection when encryption is configured.
func (e *Engine) backupVolumeLocked(appID, appName string, vol VolumeTarget, preRestore bool, passphrase string) (*BackupMeta, error) {
	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}
	timestamp := time.Now().Format("20060102_150405")
	id := archiveID(appID, vol.Slug, timestamp, preRestore)
	destFile := filepath.Join(destDir, id+".tar.gz")

	meta := &BackupMeta{
		ID:         id,
		AppID:      appID,
		AppName:    appName,
		VolumeSlug: vol.Slug,
		StartedAt:  time.Now(),
		Status:     StatusRunning,
		FilePath:   destFile,
		PreRestore: preRestore,
	}
	size, err := tarGz(vol.Path, destFile, vol.Excludes, nil)
	fin := time.Now()
	meta.FinishedAt = &fin
	if err != nil {
		_ = os.Remove(destFile)
		meta.Status = StatusFailed
		meta.Error = err.Error()
		return meta, err
	}
	finalSize := size
	if passphrase != "" {
		encSize, encErr := encryptArchiveInPlace(destFile, passphrase, nil)
		if encErr != nil {
			_ = os.Remove(destFile)
			meta.Status = StatusFailed
			meta.Error = fmt.Sprintf("encryption failed: %v", encErr)
			return meta, encErr
		}
		meta.Encrypted = true
		finalSize = encSize
	}
	meta.SizeBytes = finalSize
	meta.Status = StatusSuccess
	return meta, nil
}

// ── List / Delete / Prune ─────────────────────────────────────────────────────

// ListBackups returns all backup archives for an appID, newest first.
// Archives are grouped by volume slug in the BackupMeta.VolumeSlug field.
func (e *Engine) ListBackups(appID string) ([]BackupMeta, error) {
	dir := filepath.Join(e.backupDir, appID)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	remoteByFile := loadRemoteStatus(dir)

	var metas []BackupMeta
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".tar.gz")
		preRestore := strings.HasSuffix(id, "_prerestore")
		slug := volumeSlugFromID(appID, id)

		metas = append(metas, BackupMeta{
			ID:         id,
			AppID:      appID,
			VolumeSlug: slug,
			FilePath:   filepath.Join(dir, entry.Name()),
			SizeBytes:  info.Size(),
			StartedAt:  info.ModTime(),
			Status:     StatusSuccess,
			PreRestore: preRestore,
			Remote:     remoteByFile[entry.Name()],
		})
	}
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].StartedAt.After(metas[j].StartedAt)
	})
	return metas, nil
}

// loadRemoteStatus scans every *_manifest.json in dir ONCE and returns a
// map of archive file name → the remote target paths/URIs it has reached,
// so ListBackups can show "pushed to NAS ✓" without needing to know which
// specific run-manifest a given archive belongs to — a listing spans many
// runs, and manifests batch several volumes' archives from one run
// together, so there's no single manifest filename to construct from an
// archive ID alone. Best-effort throughout: an unreadable or unparsable
// manifest is skipped, never fails the whole listing — a backup you can
// already see and restore shouldn't disappear from the list just because
// one manifest file went stale.
func loadRemoteStatus(dir string) map[string][]string {
	result := map[string][]string{}
	matches, _ := filepath.Glob(filepath.Join(dir, "*_manifest.json"))
	for _, mp := range matches {
		data, err := os.ReadFile(mp)
		if err != nil {
			continue
		}
		var m Manifest
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		for _, ent := range m.Entries {
			if len(ent.Remote) > 0 {
				result[ent.FileName] = ent.Remote
			}
		}
	}
	return result
}

// volumeSlugFromID extracts the volume slug from an archive ID.
// Archive ID format: {appID}_{volumeSlug}_{timestamp}[_prerestore]
// e.g. "mosquitto_config_20250615_120000" → "config"
func volumeSlugFromID(appID, id string) string {
	// Strip appID prefix and the trailing timestamp (YYYYMMDD_HHMMSS)
	// We know appID, so strip it plus the following underscore
	prefix := appID + "_"
	rest := id
	if strings.HasPrefix(id, prefix) {
		rest = strings.TrimPrefix(id, prefix) // "config_20250615_120000" or "config_20250615_120000_prerestore"
	}
	// If id doesn't carry the expected appID_ prefix (e.g. an archive
	// pulled from a remote target whose filename was produced by a
	// differently-configured or renamed app), fall back to slugging the
	// id as-is rather than collapsing it into a shared "" bucket. A
	// shared bucket lets unrelated volumes' archives count against each
	// other's retain budget, which looks like — and functionally is — a
	// retention bug from the outside.
	// Strip _prerestore suffix
	rest = strings.TrimSuffix(rest, "_prerestore")
	// Strip trailing _YYYYMMDD_HHMMSS (17 chars: 8 + _ + 6)
	// Format: slug_20250615_120000 — timestamp is always the last two segments (date_time)
	parts := strings.Split(rest, "_")
	if len(parts) < 3 {
		// Single-word slug with no extra underscores, or old format
		if len(parts) >= 1 {
			return parts[0]
		}
		return rest
	}
	// Last two parts are YYYYMMDD and HHMMSS
	slugParts := parts[:len(parts)-2]
	return strings.Join(slugParts, "_")
}

// DeleteBackup removes a backup archive by file path.
func (e *Engine) DeleteBackup(archivePath string) error {
	return os.Remove(archivePath)
}

// DeleteAppBackups removes the entire backup directory for an app.
// Called when an app is deleted and the user opts to purge backups.
func (e *Engine) DeleteAppBackups(appID string) error {
	dir := filepath.Join(e.backupDir, appID)
	return os.RemoveAll(dir)
}

// PruneBackups keeps only the newest `retain` non-prerestore backups per
// volume slug, then removes any manifest.json whose referenced archives have
// ALL since been deleted.
//
// BUG THIS FIXES: the original version only ever deleted .tar.gz files via
// the loop below — it never looked at *_manifest.json at all. Manifests
// accumulated forever regardless of retain count, which is why a directory
// with retain:2 could show 11 manifests spanning 9 days but only 2 real
// archives from the last 2 days: retention was correctly pruning tars the
// whole time, it just never took the matching manifest litter with it.
//
// The cleanup pass below is deliberately conservative: it reads each
// manifest's own list of archive filenames (ManifestEntry.FileName) and only
// deletes the manifest if NONE of the files it references still exist on
// disk. A manifest covering multiple volume slugs survives as long as any
// one of those slugs still has a retained archive — so InspectOrphan (which
// depends on manifests to recover app details for orphaned backup dirs)
// keeps working correctly through partial prunes.
func (e *Engine) PruneBackups(appID string, retain int) error {
	if retain <= 0 {
		retain = 5
	}
	dir := filepath.Join(e.backupDir, appID)
	metas, err := e.ListBackups(appID)
	if err != nil {
		return err
	}

	// Group regular (non-prerestore) backups by volume slug, and
	// pre-restore safety snapshots (see RestoreVolume's own doc comment
	// for what these are) by volume slug SEPARATELY. These used to share
	// nothing but the exclusion check below — regular backups were
	// retained correctly, but pre-restore snapshots were never counted
	// against ANY limit at all, anywhere, and so accumulated forever: one
	// new one per restore ever performed on that volume, with no cap. An
	// app restored 5 times ends up with retain (say 5) regular backups
	// PLUS 5 pre-restore snapshots — 10 total archives on disk despite a
	// retain setting of 5, which looks exactly like a retention bug from
	// the outside because it is one. Pre-restore snapshots now respect
	// the same retain count, counted independently of regular backups —
	// independently because they answer a different question ("can I
	// undo my last few restores") than retain does ("how much backup
	// history do I want"), so one setting shouldn't silently starve the
	// other; same count because introducing a second, differently-sized
	// limit here would be one more number for a user to reason about for
	// a marginal benefit over just reusing the one they already set.
	bySlug := map[string][]BackupMeta{}
	preRestoreBySlug := map[string][]BackupMeta{}
	for _, m := range metas {
		if m.PreRestore {
			preRestoreBySlug[m.VolumeSlug] = append(preRestoreBySlug[m.VolumeSlug], m)
		} else {
			bySlug[m.VolumeSlug] = append(bySlug[m.VolumeSlug], m)
		}
	}

	for slug, list := range bySlug {
		// list is already newest-first from ListBackups sort
		if len(list) <= retain {
			continue
		}
		for _, m := range list[retain:] {
			log.Printf("[prune] removing old backup: %s (%s)", m.FilePath, slug)
			_ = os.Remove(m.FilePath)
		}
	}
	for slug, list := range preRestoreBySlug {
		if len(list) <= retain {
			continue
		}
		for _, m := range list[retain:] {
			log.Printf("[prune] removing old pre-restore snapshot: %s (%s)", m.FilePath, slug)
			_ = os.Remove(m.FilePath)
		}
	}

	if err := e.pruneOrphanedManifests(dir); err != nil {
		// Non-fatal — the archives themselves were pruned successfully above,
		// which is the part that actually matters for disk space and
		// retention correctness. Log and move on rather than fail the whole
		// prune run over a manifest-cleanup hiccup.
		log.Printf("[prune] manifest cleanup warning for %s: %v", appID, err)
	}
	return nil
}

// pruneOrphanedManifests deletes any {appID}_{timestamp}_manifest.json in dir
// where none of the archive files it references (via ManifestEntry.FileName)
// still exist on disk. Manifests that fail to parse, or that list zero
// entries, are left alone — we only ever delete a manifest when we're
// certain every archive it once described is gone.
func (e *Engine) pruneOrphanedManifests(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), "_manifest.json") {
			continue
		}
		manifestPath := filepath.Join(dir, ent.Name())
		data, readErr := os.ReadFile(manifestPath)
		if readErr != nil {
			continue
		}
		var m Manifest
		if jsonErr := json.Unmarshal(data, &m); jsonErr != nil {
			continue // don't touch anything we can't confidently parse
		}
		if len(m.Entries) == 0 {
			continue // nothing to check against — leave it rather than guess
		}
		anyArchiveSurvives := false
		for _, entMeta := range m.Entries {
			if entMeta.FileName == "" {
				continue
			}
			if _, statErr := os.Stat(filepath.Join(dir, entMeta.FileName)); statErr == nil {
				anyArchiveSurvives = true
				break
			}
		}
		if !anyArchiveSurvives {
			log.Printf("[prune] removing orphaned manifest (all referenced archives gone): %s", manifestPath)
			_ = os.Remove(manifestPath)
		}
	}
	return nil
}

// ── Manifest ──────────────────────────────────────────────────────────────────
//
// After every backup run, PrestoBack writes a {appID}_{timestamp}_manifest.json
// alongside the archives. It lists every produced file with its size and a
// SHA-256 hash, plus the overall run duration — a tamper-evident record of
// exactly what was on disk after this run, independent of the archives
// themselves. Useful for audit trails, scripted verification, or detecting
// silent corruption of an archive after the fact (re-hash and compare).

// ManifestEntry describes one archive produced by a backup run.
type ManifestEntry struct {
	VolumeSlug string `json:"volume_slug"`
	FileName   string `json:"file_name"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
	Status     Status `json:"status"`
	Error      string `json:"error,omitempty"`
	// SourcePath is the absolute path on the source system that was archived.
	// Stored in every manifest so a restore-to-new-system flow can pre-fill
	// volume paths exactly as they were, without needing the original config.json.
	// Example: /home/pi/presto/volumes/plex/Library/Application Support/Plex Media Server/Plug-in Support/Databases
	SourcePath string `json:"source_path,omitempty"`
	// Encrypted mirrors BackupMeta.Encrypted — see that field's comment.
	// A restore flow reads this from the manifest to decide whether to
	// prompt for a passphrase, without needing to guess from file content.
	Encrypted bool `json:"encrypted,omitempty"`
	// Remote lists every target (by remote path/URI) this archive has been
	// successfully pushed to — see UpdateManifestRemoteStatus below.
	// Written after the fact by a separate call, not by WriteManifest
	// itself, because pushing happens AFTER the manifest is first written
	// (a remote holding archives with no manifest describing them is a
	// worse state than the reverse ordering — see pushToRemotes in
	// internal/api/server.go for why).
	Remote []string `json:"remote,omitempty"`
}

// Manifest is the full record for a single backup run (all volumes).
type Manifest struct {
	AppID      string          `json:"app_id"`
	AppName    string          `json:"app_name"`
	RunAt      time.Time       `json:"run_at"`
	DurationMs int64           `json:"duration_ms"`
	Entries    []ManifestEntry `json:"entries"`
}

// WriteManifest hashes every successfully produced archive from this run and
// writes a manifest JSON file into the app's backup directory. Returns the
// path to the written manifest.
func (e *Engine) WriteManifest(appID, appName string, metas []BackupMeta, durationMs int64) (string, error) {
	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", err
	}

	m := Manifest{
		AppID:      appID,
		AppName:    appName,
		RunAt:      time.Now().UTC(),
		DurationMs: durationMs,
	}

	for _, meta := range metas {
		entry := ManifestEntry{
			VolumeSlug: meta.VolumeSlug,
			SourcePath: meta.SourcePath,
			FileName:   filepath.Base(meta.FilePath),
			SizeBytes:  meta.SizeBytes,
			Status:     meta.Status,
			Error:      meta.Error,
			Encrypted:  meta.Encrypted,
		}
		if meta.Status == StatusSuccess {
			// meta.FilePath already points at whatever is actually on disk by
			// this point — ciphertext if Encrypted, plaintext otherwise —
			// because encryption (see encryptArchiveInPlace) runs and renames
			// over the file inside backupVolumes, before WriteManifest is
			// ever called. So this hash is always "hash of what's on disk",
			// which is the ciphertext for encrypted archives — deliberately,
			// see EncryptionConfig's doc comment in internal/config/config.go
			// for why that's the right checksum semantics here.
			sum, err := sha256File(meta.FilePath)
			if err != nil {
				entry.Error = fmt.Sprintf("manifest hash failed: %v", err)
			} else {
				entry.SHA256 = sum
			}
		}
		m.Entries = append(m.Entries, entry)
	}

	timestamp := m.RunAt.Format("20060102_150405")
	manifestPath := filepath.Join(destDir, fmt.Sprintf("%s_%s_manifest.json", appID, timestamp))

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return "", err
	}
	return manifestPath, nil
}

// UpdateManifestRemoteStatus records that pushedPaths (local archive file
// path → remote path/URI, as returned by backup.PushAppBackup) succeeded,
// by appending to each matching ManifestEntry.Remote in the manifest at
// manifestPath.
//
// Called once per configured remote target (see pushToRemotes in
// internal/api/server.go), so pushing the same archive to N targets over N
// calls ACCUMULATES rather than overwrites — Remote ends up listing every
// target a file reached, not just the most recent one. Best-effort: a
// failure here (unreadable/unparsable manifest, disk write error) is
// logged by the caller and never undoes or blocks the push itself — the
// archive already safely landed on the remote target either way, this is
// purely bookkeeping for the UI.
func (e *Engine) UpdateManifestRemoteStatus(manifestPath string, pushedPaths map[string]string) error {
	if len(pushedPaths) == 0 {
		return nil
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// pushedPaths is keyed by the local FILE PATH (e.g.
	// /data/backups/myapp/myapp_data_20260707_120000.tar.gz) but
	// ManifestEntry only stores the base filename — index by that instead.
	byBase := map[string]string{}
	for localPath, remotePath := range pushedPaths {
		byBase[filepath.Base(localPath)] = remotePath
	}

	changed := false
	for i := range m.Entries {
		remotePath, ok := byBase[m.Entries[i].FileName]
		if !ok {
			continue
		}
		if !containsString(m.Entries[i].Remote, remotePath) {
			m.Entries[i].Remote = append(m.Entries[i].Remote, remotePath)
			changed = true
		}
	}
	if !changed {
		return nil // e.g. this manifest doesn't mention any of pushedPaths — the manifest for the archive's OWN run, not this one
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := manifestPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, manifestPath)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ── Archive encryption (wires backupcrypto.go's EncryptStream/DecryptStream
// into the actual backup-write and restore-read paths) ───────────────────────

// encryptArchiveInPlace re-encrypts a freshly written, already-verified
// plaintext .tar.gz using backupcrypto.go's EncryptStream, then renames the
// ciphertext over the original path — so every other piece of code that
// refers to a BackupMeta.FilePath keeps working unchanged; it just finds
// ciphertext there instead of plaintext from this point on.
//
// Runs AFTER verifyArchive succeeds, deliberately: verifyArchive's tar/gzip
// structural check is only meaningful against plaintext — encrypting first
// would make every archive "look the same" (opaque ciphertext) to that
// check, silently defeating it.
func encryptArchiveInPlace(path, passphrase string, onBytes func(int64)) (int64, error) {
	src, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open for encryption: %w", err)
	}
	tmpPath := path + ".enc.tmp"
	dst, err := os.Create(tmpPath)
	if err != nil {
		src.Close()
		return 0, fmt.Errorf("create ciphertext temp file: %w", err)
	}

	encErr := EncryptStream(dst, &countingReader{r: src, onBytes: onBytes}, passphrase)
	src.Close()
	closeErr := dst.Close()

	if encErr != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("encrypt archive: %w", encErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("close ciphertext temp file: %w", closeErr)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("replace archive with encrypted version: %w", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// decryptArchiveToTemp decrypts an encrypted archive into a sibling temp
// file (same directory, so the later os.Rename-free extractTarGz read is on
// the same filesystem) and returns its path. The caller is responsible for
// removing it once extraction is done — RestoreVolume does this via defer.
//
// No byte-progress callback here — see countingReader's doc comment above
// for why DecryptStream's two-pass read (verify-then-decrypt) makes a naive
// percentage misleading rather than useful.
// DecryptArchiveToTempForPreview is decryptArchiveToTemp exported for
// handleRestorePreview's use — a preview needs to decrypt an encrypted
// archive to inspect it, exactly like a real restore does, so it reuses
// the same temp-file decrypt helper rather than a second copy of it.
// Caller must os.Remove the returned path when done, same contract as the
// unexported version.
func DecryptArchiveToTempForPreview(archivePath, passphrase string) (string, error) {
	return decryptArchiveToTemp(archivePath, passphrase)
}

func decryptArchiveToTemp(archivePath, passphrase string) (string, error) {
	src, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open encrypted archive: %w", err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(archivePath), "prestoback-decrypt-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create decrypt temp file: %w", err)
	}
	tmpPath := tmp.Name()

	decErr := DecryptStream(tmp, src, passphrase)
	closeErr := tmp.Close()

	if decErr != nil {
		_ = os.Remove(tmpPath)
		// ErrAuthenticationFailed is returned as-is (not wrapped) so callers
		// can errors.Is() against it to show "wrong passphrase or corrupted
		// archive" instead of a generic decrypt error.
		if errors.Is(decErr, ErrAuthenticationFailed) {
			return "", ErrAuthenticationFailed
		}
		return "", fmt.Errorf("decrypt archive: %w", decErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close decrypt temp file: %w", closeErr)
	}
	return tmpPath, nil
}

// sha256File computes the hex-encoded SHA-256 digest of a file's contents
// by streaming it through the hasher — no full-file buffering, safe for
// multi-GB archives.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// OrphanInspection summarizes what a backup directory's manifests reveal
// about the app that used to own it — enough to pre-fill a "recreate this
// app" form, including the original source paths for each volume.
type OrphanInspection struct {
	AppID       string            `json:"app_id"`
	AppName     string            `json:"app_name"`
	VolumeSlugs []string          `json:"volume_slugs"`
	VolumePaths map[string]string `json:"volume_paths"` // slug → last-known source path
	BackupCount int               `json:"backup_count"`
	LatestRunAt time.Time         `json:"latest_run_at"`
}

// InspectOrphan reads every manifest in dirName (oldest to newest) to recover
// the app_id (= dirName itself), the most recently seen app_name, and the
// union of every volume slug ever backed up there — including volumes that
// may have been since disabled, so old recoverable history isn't hidden.
func (e *Engine) InspectOrphan(dirName string) (*OrphanInspection, error) {
	dir := filepath.Join(e.backupDir, dirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var manifestNames []string
	tarCount := 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if strings.HasSuffix(ent.Name(), "_manifest.json") {
			manifestNames = append(manifestNames, ent.Name())
		}
		if strings.HasSuffix(ent.Name(), ".tar.gz") {
			tarCount++
		}
	}
	if len(manifestNames) == 0 {
		return nil, fmt.Errorf("no manifest files found in %q — can't auto-detect app details, but you can still add an app manually with ID %q to claim these backups", dirName, dirName)
	}
	sort.Strings(manifestNames) // timestamp is embedded in the filename, so this sorts chronologically

	slugSeen := map[string]bool{}
	var slugs []string
	volumePaths := map[string]string{} // slug → most recent known source path
	var appName string
	var latestRunAt time.Time
	for _, name := range manifestNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.AppName != "" {
			appName = m.AppName
		}
		if m.RunAt.After(latestRunAt) {
			latestRunAt = m.RunAt
		}
		for _, ent := range m.Entries {
			if ent.VolumeSlug == "" {
				continue
			}
			if !slugSeen[ent.VolumeSlug] {
				slugSeen[ent.VolumeSlug] = true
				slugs = append(slugs, ent.VolumeSlug)
			}
			// Always overwrite with the latest-seen path — later manifests
			// are more up-to-date if paths ever changed between runs.
			if ent.SourcePath != "" {
				volumePaths[ent.VolumeSlug] = ent.SourcePath
			}
		}
	}
	if appName == "" {
		appName = dirName
	}
	return &OrphanInspection{
		AppID:       dirName,
		AppName:     appName,
		VolumeSlugs: slugs,
		VolumePaths: volumePaths,
		BackupCount: tarCount,
		LatestRunAt: latestRunAt,
	}, nil
}

// OrphanedBackupDirs returns backup directories that have no registered app.
// registeredIDs is the set of known app IDs from config.
func (e *Engine) OrphanedBackupDirs(registeredIDs map[string]bool) ([]string, error) {
	entries, err := os.ReadDir(e.backupDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var orphans []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !registeredIDs[entry.Name()] {
			orphans = append(orphans, entry.Name())
		}
	}
	return orphans, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (e *Engine) IsRunning(appID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running[appID]
}

func (e *Engine) AnyRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running) > 0
}

func (e *Engine) emit(m *BackupMeta, msg string) {
	select {
	case e.updates <- JobUpdate{AppID: m.AppID, Backup: *m, Log: msg}:
	default:
	}
}

// emitProgress sends a byte-progress sample the same non-blocking way emit
// does — a slow consumer just misses a sample, it never blocks the backup
// itself. Called from progressEmitter, throttled by time, not by every
// single Write.
func (e *Engine) emitProgress(m *BackupMeta, p ProgressInfo) {
	select {
	case e.updates <- JobUpdate{AppID: m.AppID, Backup: *m, Progress: &p}:
	default:
	}
}

// ── Byte-level progress ───────────────────────────────────────────────────────
//
// There's no OS-level "percent copied" hook for a tar/gzip stream — the same
// constraint tools like Portainer run into (its own volume backup is a
// browser-native file download with the browser's own progress bar; it
// doesn't compute a server-side percentage for the copy itself). The pattern
// used here is the same one those tools fall back to: wrap the destination
// writer to count bytes as they're actually written, and sample that counter
// on a timer rather than on every single Write — so a fast local disk
// doesn't flood the SSE channel with one event per megabyte, and a slow
// remote target still gets at least one update per tick.
//
// progressEmitter owns the running total across an entire multi-volume
// backup run (not just the current volume) so the bar reported to the UI is
// one aggregate percentage for the whole app run, with CurrentVolume as a
// label alongside it — e.g. "42% — plex_data (2/3)" — rather than resetting
// to 0% every time a new volume starts.
const progressEmitInterval = 500 * time.Millisecond

type progressEmitter struct {
	e          *Engine
	meta       *BackupMeta
	totalBytes int64 // across ALL volumes in this run; 0 disables percent (still reports raw bytes)

	doneBeforeCurrent int64 // bytes already accounted for by previously finished volumes
	currentVolume     string
	currentBytes      int64
	lastEmit          time.Time
}

func newProgressEmitter(e *Engine, meta *BackupMeta, totalBytes int64) *progressEmitter {
	return &progressEmitter{e: e, meta: meta, totalBytes: totalBytes}
}

// startVolume resets the per-volume counter and folds the just-finished
// volume's bytes into doneBeforeCurrent, so the aggregate total keeps moving
// forward across volume boundaries instead of dipping back down.
func (p *progressEmitter) startVolume(slug string) {
	p.doneBeforeCurrent += p.currentBytes
	p.currentBytes = 0
	p.currentVolume = slug
}

// onBytes is passed as the callback to tarGz/extractTarGz/encryptArchiveInPlace.
func (p *progressEmitter) onBytes(n int64) {
	p.currentBytes += n
	if time.Since(p.lastEmit) < progressEmitInterval {
		return
	}
	p.lastEmit = time.Now()
	p.flush()
}

// flush emits immediately regardless of the time throttle — used for the
// final 100% sample so the UI doesn't sit at "97%" after the operation has
// actually finished.
func (p *progressEmitter) flush() {
	done := p.doneBeforeCurrent + p.currentBytes
	var pct float64
	if p.totalBytes > 0 {
		pct = float64(done) / float64(p.totalBytes) * 100
		if pct > 100 {
			pct = 100
		}
	}
	p.e.emitProgress(p.meta, ProgressInfo{
		BytesDone:     done,
		BytesTotal:    p.totalBytes,
		Percent:       pct,
		CurrentVolume: p.currentVolume,
	})
}

// countingWriter wraps an io.Writer and reports every successful Write's
// byte count to onBytes. Used to instrument tarGz's and extractTarGz's
// existing io.Copy calls without changing their control flow.
type countingWriter struct {
	w       io.Writer
	onBytes func(int64)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 && c.onBytes != nil {
		c.onBytes(int64(n))
	}
	return n, err
}

// countingReader is the read-side equivalent, used to report progress
// through encryptArchiveInPlace's single streaming pass (EncryptStream reads
// plaintext from this and writes ciphertext out — counting the read side
// tracks "how much of the plaintext has been processed so far").
//
// Deliberately NOT used for decryptArchiveToTemp: DecryptStream (see
// backupcrypto.go, unmodified here) reads the source archive twice — once to
// verify the HMAC, once to actually decrypt — so a naive byte counter would
// run to ~200% and reset, which is more misleading than no percentage at
// all. Restore-side decryption gets a log line ("Verifying archive
// authenticity…", "Decrypting…") instead of a bar; see RestoreVolume.
type countingReader struct {
	r       io.Reader
	onBytes func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.onBytes != nil {
		c.onBytes(int64(n))
	}
	return n, err
}

func (e *Engine) EmitLog(appID, msg string) {
	select {
	case e.updates <- JobUpdate{
		AppID:  appID,
		Backup: BackupMeta{AppID: appID, Status: StatusRunning},
		Log:    msg,
	}:
	default:
	}
}

func (e *Engine) EmitUpdate(u UpdateResult) {
	select {
	case e.updates <- JobUpdate{
		AppID:  "_system",
		Backup: BackupMeta{AppID: "_system", Status: StatusRunning},
		Log:    u.Stage + ": " + u.Message,
		Update: &u,
	}:
	default:
	}
}

// slugFromPath is a copy of the config helper so engine has no import cycle.
func slugFromPath(p string) string {
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
	if s == "" {
		return "vol"
	}
	return s
}

// ── Tar/Gzip ──────────────────────────────────────────────────────────────────

var KnownCachePatterns = map[string][]string{
	// Metadata/ and Media/ hold downloaded poster art, fanart, and episode
	// thumbnails — fully regenerable by re-scanning the library, and often the
	// single largest component of a real library (easily dwarfing Cache/).
	// Transcode/ lives under Cache/ already, not as its own top-level folder.
	"plex":          {"Cache/", "Metadata/", "Media/", "Logs/", "Crash Reports/"},
	"jellyfin":      {"cache/", "metadata/", "log/"},
	"sonarr":        {"logs/", "Backups/"},
	"radarr":        {"logs/", "Backups/"},
	"lidarr":        {"logs/", "Backups/"},
	"prowlarr":      {"logs/", "Backups/"},
	"readarr":       {"logs/", "Backups/"},
	"bazarr":        {"log/"},
	"nextcloud":     {"cache/", "data/"},
	"homeassistant": {".cache/", "home-assistant.log"},
}

// PreBackupSuggestion pairs a command template with a post-restore instruction
// so both halves of the workflow are surfaced, not just the backup side.
type PreBackupSuggestion struct {
	// Cmd is the shell command to run before backup, with {container} as a
	// placeholder for the actual container name (substituted in the UI).
	Cmd string `json:"cmd"`
	// DumpFile is the path (inside the volume) where the dump lands — shown
	// in the UI and in the post-restore hint so the user knows where to look.
	DumpFile string `json:"dump_file"`
	// PostRestoreHint is a human-readable instruction shown after a successful
	// restore if this app has a PreBackupCmd set. The dump file is already on
	// disk (extracted from the tar), but the user needs to activate it.
	PostRestoreHint string `json:"post_restore_hint"`
	// DocNote explains why this approach is safe (runs inside the target
	// container — no dependencies on the Pi host or PrestoBack image).
	DocNote string `json:"doc_note"`
}

// KnownPreBackupCmds maps image-name substrings to suggested pre-backup
// commands. All commands use `docker exec {container}` so they run inside
// the target container — no sqlite3/pg_dump/mysqldump needs to be installed
// on the Pi host or inside the PrestoBack image.
var KnownPreBackupCmds = map[string]PreBackupSuggestion{
	"homebox": {
		Cmd:      `docker exec {container} sqlite3 /data/homebox-data/homebox.db ".backup /data/homebox-data/homebox.db.bak"`,
		DumpFile: "homebox-data/homebox.db.bak",
		PostRestoreHint: "The archive contains a clean SQLite dump at homebox-data/homebox.db.bak. " +
			"To activate it: docker exec {container} cp /data/homebox-data/homebox.db.bak /data/homebox-data/homebox.db",
		DocNote: "Runs sqlite3 inside the Homebox container — no extra tools needed on your Pi.",
	},
	"vaultwarden": {
		Cmd:      `docker exec {container} sqlite3 /data/db.sqlite3 ".backup /data/db.sqlite3.bak"`,
		DumpFile: "db.sqlite3.bak",
		PostRestoreHint: "The archive contains a clean SQLite dump at db.sqlite3.bak. " +
			"To activate it: docker exec {container} cp /data/db.sqlite3.bak /data/db.sqlite3",
		DocNote: "Runs sqlite3 inside the Vaultwarden container — no extra tools needed on your Pi.",
	},
	"postgres": {
		Cmd:      `docker exec {container} pg_dump -U postgres --format=custom --file=/var/lib/postgresql/data/prestoback_dump.pgdump`,
		DumpFile: "prestoback_dump.pgdump",
		PostRestoreHint: "The archive contains a pg_dump at prestoback_dump.pgdump. " +
			"To restore it: docker exec {container} pg_restore -U postgres -d postgres /var/lib/postgresql/data/prestoback_dump.pgdump",
		DocNote: "Runs pg_dump inside the Postgres container — no extra tools needed on your Pi.",
	},
	"mariadb": {
		Cmd:      `docker exec {container} sh -c 'mysqldump -u root -p"$MYSQL_ROOT_PASSWORD" --all-databases > /var/lib/mysql/prestoback_dump.sql'`,
		DumpFile: "prestoback_dump.sql",
		PostRestoreHint: "The archive contains a mysqldump at prestoback_dump.sql. " +
			`To restore it: docker exec {container} sh -c 'mysql -u root -p"$MYSQL_ROOT_PASSWORD" < /var/lib/mysql/prestoback_dump.sql'`,
		DocNote: "Runs mysqldump inside the MariaDB container — no extra tools needed on your Pi.",
	},
	"mysql": {
		Cmd:      `docker exec {container} sh -c 'mysqldump -u root -p"$MYSQL_ROOT_PASSWORD" --all-databases > /var/lib/mysql/prestoback_dump.sql'`,
		DumpFile: "prestoback_dump.sql",
		PostRestoreHint: "The archive contains a mysqldump at prestoback_dump.sql. " +
			`To restore it: docker exec {container} sh -c 'mysql -u root -p"$MYSQL_ROOT_PASSWORD" < /var/lib/mysql/prestoback_dump.sql'`,
		DocNote: "Runs mysqldump inside the MySQL container — no extra tools needed on your Pi.",
	},
}

// SuggestPreBackupCmd returns a pre-backup command suggestion for a given
// container image, or nil if no suggestion is available. The {container}
// placeholder in Cmd and PostRestoreHint is substituted by the caller
// using the app's actual ContainerName.
func SuggestPreBackupCmd(image string) *PreBackupSuggestion {
	imageLower := strings.ToLower(image)
	for key, suggestion := range KnownPreBackupCmds {
		if strings.Contains(imageLower, key) {
			s := suggestion // copy to avoid returning pointer into the map
			return &s
		}
	}
	return nil
}

func SuggestExcludes(image string) []string {
	imageLower := strings.ToLower(image)
	for key, patterns := range KnownCachePatterns {
		if strings.Contains(imageLower, key) {
			return patterns
		}
	}
	return nil
}

// MatchesExclude reports whether relPath matches any of the given exclude
// patterns. Exported so other parts of the app (e.g. the size-estimate
// endpoint) can show numbers that agree with what actually gets archived,
// instead of maintaining a second copy of this matching logic.
func MatchesExclude(relPath string, excludes []string) bool {
	for _, pattern := range excludes {
		if strings.HasSuffix(pattern, "/") {
			dir := strings.TrimSuffix(pattern, "/")
			if relPath == dir || strings.HasPrefix(relPath, dir+"/") ||
				strings.Contains(relPath, "/"+dir+"/") ||
				strings.HasSuffix(relPath, "/"+dir) {
				return true
			}
			continue
		}
		if strings.Contains(pattern, "*") {
			base := filepath.Base(relPath)
			if matched, _ := filepath.Match(pattern, base); matched {
				return true
			}
			continue
		}
		if relPath == pattern || filepath.Base(relPath) == pattern {
			return true
		}
	}
	return false
}

// checkDiskSpace walks srcDir to measure its raw size, then checks that the
// backup destination has at least 1.2× that available. The 1.2× margin covers:
//   - tar metadata overhead
//   - already-compressed content (Plex, media) that won't shrink under gzip
//   - other writes happening concurrently on the same volume
//
// Returns a descriptive error (emitted as a log line) if space is insufficient.
func checkDiskSpace(srcDir, destDir string, e *Engine, meta *BackupMeta) error {
	// Measure raw source size
	var srcBytes int64
	_ = filepath.Walk(srcDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Mode().IsRegular() {
			srcBytes += info.Size()
		}
		return nil
	})

	// Get free bytes on the backup destination filesystem
	var stat syscall.Statfs_t
	if err := syscall.Statfs(destDir, &stat); err != nil {
		// Can't check — warn but don't block the backup
		e.emit(meta, fmt.Sprintf("⚠  disk space check skipped (statfs %s: %v)", destDir, err))
		return nil
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)

	// Require 1.2× source size free (worst-case: no compression)
	required := uint64(float64(srcBytes) * 1.2)
	if required > freeBytes {
		return fmt.Errorf(
			"insufficient disk space: source is %.1f GB, need %.1f GB free on backup volume, only %.1f GB available — backup aborted",
			float64(srcBytes)/1e9,
			float64(required)/1e9,
			float64(freeBytes)/1e9,
		)
	}

	e.emit(meta, fmt.Sprintf("✓ disk space OK (source %.1f GB, free %.1f GB)",
		float64(srcBytes)/1e9, float64(freeBytes)/1e9))
	return nil
}

func tarGz(srcDir, destFile string, excludes []string, onBytes func(int64)) (int64, error) {
	srcDir = filepath.Clean(srcDir)
	if _, err := os.Stat(srcDir); err != nil {
		return 0, fmt.Errorf("source path %q: %w", srcDir, err)
	}
	baseName := filepath.Base(srcDir)
	parentDir := filepath.Dir(srcDir)

	f, err := os.Create(destFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// BestSpeed, not the Go default (level 6): backup archives are dominated
	// by already-compressed content in practice — media thumbnails, transcoded
	// video, sqlite DBs — which barely shrinks at any gzip level. Spending
	// extra CPU chasing a marginal size win isn't worth it, especially since
	// this runs while the source container is stopped/paused — every second
	// here is directly user-visible downtime, not just archive job time.
	gw, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return 0, fmt.Errorf("gzip writer: %w", err)
	}
	tw := tar.NewWriter(gw)

	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			log.Printf("walk warning: %v — skipping %s", walkErr, path)
			return nil
		}
		// info comes from Lstat (filepath.Walk never follows symlinks for
		// its own traversal), so a symlink's mode has ModeSymlink set and
		// previously failed both the IsDir() and IsRegular() checks below
		// — meaning every symlink was silently dropped from every backup,
		// with no log line and no trace it ever existed. Confirmed this
		// isn't just theoretical: a real scan of this stack's volumes
		// turned up rolling-log and latest-snapshot symlinks (overseerr,
		// motioneye) that were vanishing on every single backup.
		//
		// Symlinks are archived as their literal target string (via
		// os.Readlink, unresolved) — not followed, not verified to exist,
		// not required to point inside srcDir. That matches what tar/rsync
		// do, and what extractTarGz already expects on the restore side
		// (os.Symlink(hdr.Linkname, target), which likewise doesn't care
		// whether the target exists). A symlink pointing at a directory is
		// archived as a leaf, same as any other symlink — Walk doesn't
		// descend through it, so there's no directory-cycle risk from a
		// self-referential or circular symlink chain.
		isSymlink := info.Mode()&os.ModeSymlink != 0
		if !info.Mode().IsDir() && !info.Mode().IsRegular() && !isSymlink {
			return nil
		}
		rel, err := filepath.Rel(parentDir, path)
		if err != nil {
			return err
		}
		if rel == "." || rel == "" {
			return nil
		}
		relFromApp := rel
		if idx := strings.Index(rel, "/"); idx >= 0 {
			relFromApp = rel[idx+1:]
		}
		if len(excludes) > 0 && relFromApp != "" && MatchesExclude(relFromApp, excludes) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if isSymlink {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				log.Printf("warn: cannot read symlink target for %s: %v — skipping", path, err)
				return nil
			}
			hdr, err := tar.FileInfoHeader(info, linkTarget)
			if err != nil {
				return err
			}
			hdr.Name = filepath.ToSlash(rel)
			return tw.WriteHeader(hdr)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			log.Printf("warn: cannot open %s: %v — skipping", path, err)
			return nil
		}
		_, copyErr := io.Copy(&countingWriter{w: tw, onBytes: onBytes}, src)
		src.Close()
		if copyErr != nil {
			return copyErr
		}
		fileCount++
		return nil
	})
	if err != nil {
		tw.Close()
		gw.Close()
		return 0, fmt.Errorf("walk %s: %w", srcDir, err)
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := gw.Close(); err != nil {
		return 0, err
	}
	log.Printf("[tarGz] archived %d files from %s → %s", fileCount, baseName, destFile)
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if fi.Size() == 0 {
		return 0, fmt.Errorf("archive is empty — check that %s contains files and is readable", srcDir)
	}
	return fi.Size(), nil
}

// verifyArchive performs a quick integrity pass over a freshly written
// .tar.gz: open it, initialize a gzip reader, and walk every tar header via
// tr.Next() until EOF. This is much cheaper than re-reading file contents,
// but still catches the failure modes that actually matter for backups —
// truncated writes (process killed mid-write, disk full), corrupt gzip
// footers, and malformed tar structure — without re-hashing every byte.
//
// Modeled on the same philosophy as Duplicati's post-backup verification
// pass: never trust a freshly written archive until you've proven you can
// read it back.
func verifyArchive(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for verification: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip header invalid: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	entryCount := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("truncated or corrupt archive after %d entries: %w", entryCount, err)
		}
		entryCount++
	}
	if entryCount == 0 {
		return fmt.Errorf("archive contains zero entries")
	}
	// Confirm the gzip stream itself closes cleanly (catches a truncated
	// trailer that tr.Next() alone might not surface on some payloads).
	if _, err := io.Copy(io.Discard, gr); err != nil {
		return fmt.Errorf("gzip stream did not close cleanly: %w", err)
	}
	return nil
}

func extractTarGz(archivePath, destPath string, onBytes func(int64)) error {
	if _, err := os.Stat(destPath); err != nil {
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("destination path %s does not exist and could not be created: %w", destPath, err)
		}
	}
	probe := filepath.Join(destPath, ".prestoback_write_probe")
	if err := os.WriteFile(probe, []byte("ok"), 0600); err != nil {
		return fmt.Errorf("destination %s is not writable (is it mounted read-only?): %w", destPath, err)
	}
	_ = os.Remove(probe)

	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	fileCount := 0
	// chownFailures counts entries whose original owner could NOT be
	// restored (summarized once at the end, not logged per-file, so a
	// restore onto a filesystem/user that can't chown — e.g. not running as
	// root, or a target FS like some NFS/CIFS mounts that reject arbitrary
	// ownership — doesn't flood the log for every entry in a large
	// archive). This is never fatal to the restore itself: the file is
	// still written with its original permission bits either way, just not
	// necessarily its original owner.
	chownFailures := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive entry: %w", err)
		}
		parts := strings.SplitN(filepath.ToSlash(hdr.Name), "/", 2)
		var rel string
		if len(parts) > 1 {
			rel = parts[1]
		} else {
			rel = hdr.Name
		}
		if rel == "" || rel == "/" {
			continue
		}
		target := filepath.Join(destPath, filepath.Clean("/"+rel))
		if !strings.HasPrefix(target, filepath.Clean(destPath)+string(os.PathSeparator)) {
			log.Printf("warn: skipping suspicious path in archive: %s", hdr.Name)
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)|0755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			if err := restoreOwnership(target, hdr); err != nil {
				chownFailures++
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent for %s: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0600)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(&countingWriter{w: out, onBytes: onBytes}, tr); err != nil {
				out.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			out.Close()
			if err := restoreOwnership(target, hdr); err != nil {
				chownFailures++
			}
			fileCount++
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				log.Printf("warn: symlink %s → %s: %v", target, hdr.Linkname, err)
				continue
			}
			// Lchown, not Chown — a symlink's own ownership is a distinct
			// attribute from its target's; Chown here would follow the
			// link and (mis)chown whatever it points at instead.
			if err := restoreOwnership(target, hdr); err != nil {
				chownFailures++
			}
		}
	}
	log.Printf("Extracted %d files to %s", fileCount, destPath)
	if chownFailures > 0 {
		log.Printf("warn: restored %d entries without their original owner (uid/gid) — permission bits were still restored. "+
			"This usually means prestoback isn't running as root (chown to an arbitrary uid/gid requires it) or the destination filesystem doesn't support it. "+
			"Affected apps may need a manual chown if they run as a non-root user.", chownFailures)
	}
	return nil
}

// restoreOwnership applies hdr's original uid/gid to the just-created entry
// at target, using Lchown so a symlink's own ownership is set rather than
// its target's (see the TypeSymlink case above). The tar header already
// carries this — tarGz's own writer populates it automatically via
// tar.FileInfoHeader on Linux — extraction just wasn't using it. Errors are
// intentionally non-fatal to the overall restore (see chownFailures above);
// the caller is responsible for counting/reporting them.
func restoreOwnership(target string, hdr *tar.Header) error {
	return os.Lchown(target, hdr.Uid, hdr.Gid)
}
