package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Status     Status     `json:"status"`
	Error      string     `json:"error,omitempty"`
	FilePath   string     `json:"file_path"`
	Remote     string     `json:"remote,omitempty"`
	PreRestore bool       `json:"pre_restore,omitempty"`
}

type JobUpdate struct {
	AppID  string        `json:"app_id"`
	Backup BackupMeta    `json:"backup"`
	Log    string        `json:"log"`
	Update *UpdateResult `json:"update,omitempty"`
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

// BackupVolumes archives each supplied volume into the app's backup directory.
// Returns one BackupMeta per volume (in the same order), plus the first error encountered.
// On error the remaining volumes are still attempted; caller gets all results.
func (e *Engine) BackupVolumes(appID, appName string, volumes []VolumeTarget) ([]BackupMeta, error) {
	return e.backupVolumes(appID, appName, volumes, false)
}

func (e *Engine) backupVolumes(appID, appName string, volumes []VolumeTarget, preRestore bool) ([]BackupMeta, error) {
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

	for _, vol := range volumes {
		id := archiveID(appID, vol.Slug, timestamp, preRestore)
		destFile := filepath.Join(destDir, id+".tar.gz")

		meta := BackupMeta{
			ID:         id,
			AppID:      appID,
			AppName:    appName,
			VolumeSlug: vol.Slug,
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

		size, err := tarGz(vol.Path, destFile, vol.Excludes)
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
		} else {
			meta.SizeBytes = size
			meta.Status = StatusSuccess
			e.emit(&meta, fmt.Sprintf("%s complete (%s, %.1f MB): %s",
				label, vol.Slug, float64(size)/1e6, id))
		}
		results = append(results, meta)
	}
	return results, firstErr
}

// ── Legacy single-volume shim (keeps server.go compile-clean during transition) ─

// BackupApp is kept for callers that still pass a single path.
// Internally it becomes a single-volume BackupVolumes call.
func (e *Engine) BackupApp(appID, appName, srcPath string, excludes []string) (*BackupMeta, error) {
	slug := slugFromPath(srcPath)
	metas, err := e.backupVolumes(appID, appName, []VolumeTarget{{Slug: slug, Path: srcPath, Excludes: excludes}}, false)
	if len(metas) > 0 {
		return &metas[0], err
	}
	return nil, err
}

// ── Restore ───────────────────────────────────────────────────────────────────

// RestoreVolume restores a single archive into destPath, taking a pre-restore snapshot first.
func (e *Engine) RestoreVolume(appID, appName, volumeSlug, archivePath, destPath string) error {
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
	if _, snapErr := e.backupVolumeLocked(appID, appName, VolumeTarget{Slug: volumeSlug, Path: destPath}, true); snapErr != nil {
		e.emit(sentinel, fmt.Sprintf("Warning: could not snapshot %s: %v — continuing", volumeSlug, snapErr))
	}

	// Step 2 — extract archive
	e.emit(sentinel, fmt.Sprintf("Extracting %s → %s", filepath.Base(archivePath), destPath))
	if err := extractTarGz(archivePath, destPath); err != nil {
		sentinel.Status = StatusFailed
		sentinel.Error = err.Error()
		e.emit(sentinel, "Restore FAILED: "+err.Error())
		return err
	}

	fin := time.Now()
	sentinel.FinishedAt = &fin
	sentinel.Status = StatusSuccess
	e.emit(sentinel, fmt.Sprintf("Restore complete ✓ — %s written to %s", volumeSlug, destPath))
	return nil
}

// RestoreApp is the legacy single-path shim.
func (e *Engine) RestoreApp(appID, appName, archivePath, destPath string) error {
	slug := slugFromPath(destPath)
	return e.RestoreVolume(appID, appName, slug, archivePath, destPath)
}

// backupVolumeLocked backs up a single volume while the engine lock is held.
func (e *Engine) backupVolumeLocked(appID, appName string, vol VolumeTarget, preRestore bool) (*BackupMeta, error) {
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
	size, err := tarGz(vol.Path, destFile, vol.Excludes)
	fin := time.Now()
	meta.FinishedAt = &fin
	if err != nil {
		_ = os.Remove(destFile)
		meta.Status = StatusFailed
		meta.Error = err.Error()
		return meta, err
	}
	meta.SizeBytes = size
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
		})
	}
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].StartedAt.After(metas[j].StartedAt)
	})
	return metas, nil
}

// volumeSlugFromID extracts the volume slug from an archive ID.
// Archive ID format: {appID}_{volumeSlug}_{timestamp}[_prerestore]
// e.g. "mosquitto_config_20250615_120000" → "config"
func volumeSlugFromID(appID, id string) string {
	// Strip appID prefix and the trailing timestamp (YYYYMMDD_HHMMSS)
	// We know appID, so strip it plus the following underscore
	prefix := appID + "_"
	if !strings.HasPrefix(id, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(id, prefix) // "config_20250615_120000" or "config_20250615_120000_prerestore"
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

// PruneBackups keeps only the newest `retain` non-prerestore backups per volume slug.
func (e *Engine) PruneBackups(appID string, retain int) error {
	if retain <= 0 {
		retain = 5
	}
	metas, err := e.ListBackups(appID)
	if err != nil {
		return err
	}

	// Group regular (non-prerestore) backups by volume slug
	bySlug := map[string][]BackupMeta{}
	for _, m := range metas {
		if !m.PreRestore {
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
	return nil
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
	"plex":          {"Cache/", "Transcodes/", "logs/"},
	"jellyfin":      {"cache/", "log/"},
	"sonarr":        {"logs/", "Backups/"},
	"radarr":        {"logs/", "Backups/"},
	"lidarr":        {"logs/", "Backups/"},
	"prowlarr":      {"logs/", "Backups/"},
	"readarr":       {"logs/", "Backups/"},
	"bazarr":        {"log/"},
	"nextcloud":     {"cache/", "data/"},
	"homeassistant": {".cache/", "home-assistant.log"},
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

func matchesExclude(relPath string, excludes []string) bool {
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

func tarGz(srcDir, destFile string, excludes []string) (int64, error) {
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

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			log.Printf("walk warning: %v — skipping %s", walkErr, path)
			return nil
		}
		if !info.Mode().IsDir() && !info.Mode().IsRegular() {
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
		if len(excludes) > 0 && relFromApp != "" && matchesExclude(relFromApp, excludes) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
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
		_, copyErr := io.Copy(tw, src)
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

func extractTarGz(archivePath, destPath string) error {
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
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent for %s: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0600)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			out.Close()
			fileCount++
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				log.Printf("warn: symlink %s → %s: %v", target, hdr.Linkname, err)
			}
		}
	}
	log.Printf("Extracted %d files to %s", fileCount, destPath)
	return nil
}
