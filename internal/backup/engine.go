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

type BackupMeta struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	AppName    string     `json:"app_name"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	SizeBytes  int64      `json:"size_bytes"`
	Status     Status     `json:"status"`
	Error      string     `json:"error,omitempty"`
	FilePath   string     `json:"file_path"`
	Remote     string     `json:"remote,omitempty"`
	// PreRestore marks this as an auto-snapshot taken before a restore operation.
	PreRestore bool `json:"pre_restore,omitempty"`
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

// ── Backup ────────────────────────────────────────────────────────────────────

// BackupApp archives the app's directory into a .tar.gz and returns metadata.
func (e *Engine) BackupApp(appID, appName, srcPath string) (*BackupMeta, error) {
	return e.backupApp(appID, appName, srcPath, false)
}

func (e *Engine) backupApp(appID, appName, srcPath string, preRestore bool) (*BackupMeta, error) {
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

	now := time.Now()
	suffix := now.Format("20060102_150405")
	if preRestore {
		suffix += "_prerestore"
	}
	backupID := fmt.Sprintf("%s_%s", appID, suffix)
	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}
	destFile := filepath.Join(destDir, backupID+".tar.gz")

	meta := &BackupMeta{
		ID:         backupID,
		AppID:      appID,
		AppName:    appName,
		StartedAt:  now,
		Status:     StatusRunning,
		FilePath:   destFile,
		PreRestore: preRestore,
	}

	label := "backup"
	if preRestore {
		label = "pre-restore snapshot"
	}
	e.emit(meta, fmt.Sprintf("Starting %s of %s", label, srcPath))

	size, err := tarGz(srcPath, destFile)
	fin := time.Now()
	meta.FinishedAt = &fin

	if err != nil {
		// Clean up partial archive
		_ = os.Remove(destFile)
		meta.Status = StatusFailed
		meta.Error = err.Error()
		e.emit(meta, fmt.Sprintf("%s FAILED: %s", label, err.Error()))
		return meta, err
	}

	meta.SizeBytes = size
	meta.Status = StatusSuccess
	e.emit(meta, fmt.Sprintf("%s complete (%.1f MB): %s", label, float64(size)/1e6, backupID))
	return meta, nil
}

// ── Restore ───────────────────────────────────────────────────────────────────

// RestoreApp performs a safe restore:
//  1. Takes a pre-restore safety snapshot of the current state
//  2. Extracts the chosen archive into destPath
//  3. Emits SSE events throughout
//
// The container stop/start is handled by the caller (server layer) so it can
// emit container-specific log lines with the actual container name.
func (e *Engine) RestoreApp(appID, appName, archivePath, destPath string) error {
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

	sentinel := &BackupMeta{AppID: appID, AppName: appName, Status: StatusRunning}

	// Step 1 — pre-restore safety snapshot (runs inside the lock so nothing
	// else can touch this app while we work).
	e.emit(sentinel, "Taking pre-restore safety snapshot of current state…")
	_, snapErr := e.backupAppLocked(appID, appName, destPath, true)
	if snapErr != nil {
		// Non-fatal: warn but continue — user already confirmed they want to restore.
		e.emit(sentinel, fmt.Sprintf("Warning: could not take safety snapshot: %v — continuing anyway", snapErr))
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
	e.emit(sentinel, "Restore complete ✓ — files written to "+destPath)
	return nil
}

// backupAppLocked runs a backup while the engine lock is already held by RestoreApp.
// It bypasses the running-check and lock acquisition since we're already inside it.
func (e *Engine) backupAppLocked(appID, appName, srcPath string, preRestore bool) (*BackupMeta, error) {
	now := time.Now()
	suffix := now.Format("20060102_150405")
	if preRestore {
		suffix += "_prerestore"
	}
	backupID := fmt.Sprintf("%s_%s", appID, suffix)
	destDir := filepath.Join(e.backupDir, appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}
	destFile := filepath.Join(destDir, backupID+".tar.gz")

	meta := &BackupMeta{
		ID:         backupID,
		AppID:      appID,
		AppName:    appName,
		StartedAt:  now,
		Status:     StatusRunning,
		FilePath:   destFile,
		PreRestore: preRestore,
	}

	size, err := tarGz(srcPath, destFile)
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
		metas = append(metas, BackupMeta{
			ID:         id,
			AppID:      appID,
			FilePath:   filepath.Join(dir, entry.Name()),
			SizeBytes:  info.Size(),
			StartedAt:  info.ModTime(),
			Status:     StatusSuccess,
			PreRestore: strings.HasSuffix(id, "_prerestore"),
		})
	}
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].StartedAt.After(metas[j].StartedAt)
	})
	return metas, nil
}

// DeleteBackup removes a backup archive.
func (e *Engine) DeleteBackup(archivePath string) error {
	return os.Remove(archivePath)
}

// PruneBackups keeps only the newest `retain` non-prerestore backups.
// Pre-restore snapshots are always kept (they are safety nets — user deletes manually).
func (e *Engine) PruneBackups(appID string, retain int) error {
	if retain <= 0 {
		retain = 5
	}
	metas, err := e.ListBackups(appID)
	if err != nil {
		return err
	}
	// Only count and prune regular backups
	var regular []BackupMeta
	for _, m := range metas {
		if !m.PreRestore {
			regular = append(regular, m)
		}
	}
	if len(regular) <= retain {
		return nil
	}
	for _, m := range regular[retain:] {
		log.Printf("Pruning old backup: %s", m.FilePath)
		_ = os.Remove(m.FilePath)
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (e *Engine) IsRunning(appID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running[appID]
}

func (e *Engine) emit(m *BackupMeta, msg string) {
	select {
	case e.updates <- JobUpdate{AppID: m.AppID, Backup: *m, Log: msg}:
	default:
	}
}

// EmitLog sends a freeform log line to the SSE stream (used by server layer for
// container stop/start messages that don't have a BackupMeta).
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

// ── Tar/Gzip ──────────────────────────────────────────────────────────────────

// tarGz creates a .tar.gz of srcDir at destFile, returns bytes written.
// srcDir is cleaned so trailing slashes never cause filepath.Rel to produce ".".
func tarGz(srcDir, destFile string) (int64, error) {
	// Clean removes trailing slashes: "/volumes/plex/" -> "/volumes/plex"
	srcDir = filepath.Clean(srcDir)

	if _, err := os.Stat(srcDir); err != nil {
		return 0, fmt.Errorf("source path %q: %w", srcDir, err)
	}

	// baseName is what appears as the top-level dir inside the archive
	baseName := filepath.Base(srcDir)
	// parentDir is used as the Rel base so paths are "basename/subdir/file"
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
		// Skip sockets, devices and other un-archivable file types
		if !info.Mode().IsDir() && !info.Mode().IsRegular() {
			return nil
		}

		// rel is e.g. "plex/config/file.db"
		rel, err := filepath.Rel(parentDir, path)
		if err != nil {
			return err
		}
		// Sanity check: rel must start with baseName
		if rel == "." || rel == "" {
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

		// Open, copy, close — no defer inside Walk to avoid fd leak
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
		tw.Close(); gw.Close()
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

// extractTarGz extracts archive into destPath.
// It strips exactly one leading path component (the root dir inside the archive).
func extractTarGz(archivePath, destPath string) error {
	// Verify destination exists and is writable before we do anything
	if _, err := os.Stat(destPath); err != nil {
		// Try to create it
		if err := os.MkdirAll(destPath, 0755); err != nil {
			return fmt.Errorf("destination path %s does not exist and could not be created: %w", destPath, err)
		}
	}
	// Write-test
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

		// Strip the leading component (the source dir name baked into the archive)
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

		// Security: prevent path traversal
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
			// Remove existing before creating symlink
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				log.Printf("warn: symlink %s → %s: %v", target, hdr.Linkname, err)
			}
		}
	}
	log.Printf("Extracted %d files to %s", fileCount, destPath)
	return nil
}

// AnyRunning returns true if any backup/restore job is currently active.
func (e *Engine) AnyRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running) > 0
}

// EmitUpdate sends a self-update progress event over the SSE stream.
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
