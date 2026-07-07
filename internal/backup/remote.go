package backup

// remote.go — pushes finished backup archives to an off-box destination and
// pulls them back again for restore. Two backend kinds, chosen per target:
//
//   "mount"  — the remote is already a filesystem path inside this
//              container: a bind-mounted SMB/CIFS or NFS share, e.g. a
//              Synology/TrueNAS box mounted on the HOST and passed through
//              with `-v /mnt/nas/presto-backups:/remote/nas`. Zero new
//              dependencies — just a streaming copy + hash verify, the
//              same "don't trust it, verify it" posture EncryptStream/
//              DecryptStream already use in backupcrypto.go.
//
//   "rclone" — anything rclone supports with non-interactive credentials:
//              S3-compatible (AWS, MinIO, Backblaze B2, Wasabi...), SFTP,
//              a genuine SMB *remote* (rclone's own smb: backend — handy
//              when you'd rather hand PrestoBack a host/user/pass than
//              manage a container bind-mount), and WebDAV. Deliberately NOT
//              wiring up rclone's OAuth-based backends (Google Drive,
//              OneDrive, Dropbox) here — those need an interactive browser
//              consent flow that doesn't fit a headless container. Every
//              kind this file supports authenticates with a plain
//              key/secret or user/password, configured once, outside
//              PrestoBack, via `rclone config` (or by mounting an existing
//              rclone.conf into the container). rclone itself is invoked
//              exactly like `docker` and `docker compose` are shelled out
//              to elsewhere in this codebase — an external binary, not a
//              vendored library.
//
// Both kinds operate on an ALREADY-FINISHED local archive
// (BackupMeta.FilePath). Remote push is always a second step after a
// normal local backup completes, never a replacement for it — if the
// remote is unreachable or the push fails, the local backup still exists
// and nothing about this run is lost.
//
// Layout mirrors the local one on purpose: archives live under
// "<remote root>/<appID>/<file>.tar.gz", exactly like ListBackups
// (engine.go) expects under e.backupDir/<appID>/ — so PullArchive can drop
// a file straight into the local backups dir and every existing restore
// code path (RestoreVolume, RestoreApp) works completely unchanged. A
// remote-sourced restore and a local-disk restore are indistinguishable to
// the rest of the codebase from that point on.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RemoteTarget describes one configured off-box destination. See config.go's
// RemoteConfig for how a list of these is persisted.
type RemoteTarget struct {
	Name string `json:"name"` // display name, e.g. "Synology NAS"
	Kind string `json:"kind"` // "mount" | "rclone"

	// Kind == "mount": MountPath is a directory already accessible inside
	// this container.
	MountPath string `json:"mount_path,omitempty"`

	// Kind == "rclone": RcloneRemote is exactly what appears in
	// `rclone listremotes` / rclone.conf, e.g. "nas-smb:presto-backups" or
	// "b2:my-bucket/presto". PrestoBack never writes or reads rclone.conf
	// itself — that file is managed outside PrestoBack entirely, the same
	// division of responsibility docker-compose.yml already has.
	RcloneRemote string `json:"rclone_remote,omitempty"`
}

// RemoteFile describes one archive found on a remote target.
type RemoteFile struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"` // full remote path/URI as the backend understands it
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

const rcloneTimeout = 2 * time.Hour // large archives over slow uplinks — matches pullTimeout's spirit in docker.go

// ── Reachability ─────────────────────────────────────────────────────────────

// RemoteReachable does a fast pre-flight check before a push/list/pull is
// attempted, so callers can surface a clear "NAS unreachable"/"remote
// misconfigured" error instead of a slow copy timing out or a wall of
// rclone error output.
func RemoteReachable(t RemoteTarget) error {
	switch t.Kind {
	case "mount":
		info, err := os.Stat(t.MountPath)
		if err != nil {
			return fmt.Errorf("mount path %q not accessible: %w", t.MountPath, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("mount path %q is not a directory", t.MountPath)
		}
		// Write-test: a stale or read-only SMB/NFS mount often stats fine
		// but rejects writes — catch that here rather than mid-copy.
		probe := filepath.Join(t.MountPath, ".prestoback_write_test")
		if err := os.WriteFile(probe, []byte("ok"), 0644); err != nil {
			return fmt.Errorf("mount path %q is not writable: %w", t.MountPath, err)
		}
		_ = os.Remove(probe)
		return nil

	case "rclone":
		if _, err := exec.LookPath("rclone"); err != nil {
			return fmt.Errorf("rclone binary not found in PATH — install it or use a \"mount\" remote instead")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "rclone", "lsd", t.RcloneRemote).CombinedOutput()
		if err != nil {
			return fmt.Errorf("rclone remote %q not reachable: %s", t.RcloneRemote, stripANSIRemote(string(out)))
		}
		return nil

	default:
		return fmt.Errorf("unknown remote kind %q (expected \"mount\" or \"rclone\")", t.Kind)
	}
}

// ── Push ──────────────────────────────────────────────────────────────────────

// PushFile copies one already-finished local file (an archive or a
// manifest) into "<remote root>/<appID>/" on t, verifying the copy landed
// intact before reporting success. Returns the remote-side path/URI to
// store in BackupMeta.Remote.
func PushFile(localPath, appID string, t RemoteTarget, emit func(string)) (string, error) {
	if err := RemoteReachable(t); err != nil {
		return "", err
	}
	name := filepath.Base(localPath)

	switch t.Kind {
	case "mount":
		destDir := filepath.Join(t.MountPath, appID)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return "", fmt.Errorf("create remote app dir: %w", err)
		}
		destPath := filepath.Join(destDir, name)
		emit(fmt.Sprintf("Copying %s to %s…", name, t.Name))
		if err := copyFileVerified(localPath, destPath); err != nil {
			return "", err
		}
		emit(fmt.Sprintf("✓ %s pushed to %s", name, t.Name))
		return destPath, nil

	case "rclone":
		destDir := strings.TrimRight(t.RcloneRemote, "/") + "/" + appID
		// Best-effort — most rclone backends (S3, B2) have no real
		// directories and don't need this; SFTP/SMB-style ones do. Ignored
		// on failure since copyto below will surface any real problem.
		_ = exec.Command("rclone", "mkdir", destDir).Run()

		dest := destDir + "/" + name
		emit(fmt.Sprintf("Uploading %s to %s (rclone)…", name, t.Name))
		ctx, cancel := context.WithTimeout(context.Background(), rcloneTimeout)
		defer cancel()
		// --checksum: rclone verifies with its own hash comparison rather
		// than trusting size+modtime alone — the network-transfer analogue
		// of copyFileVerified's local sha256File check below.
		out, err := exec.CommandContext(ctx, "rclone", "copyto", localPath, dest, "--checksum").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("rclone upload failed: %s", stripANSIRemote(string(out)))
		}
		emit(fmt.Sprintf("✓ %s pushed to %s", name, t.Name))
		return dest, nil

	default:
		return "", fmt.Errorf("unknown remote kind %q", t.Kind)
	}
}

// PushAppBackup pushes every successful archive from one backup run (plus
// its manifest) to t, and is the intended call site right after
// Engine.WriteManifest succeeds. Best-effort per file — matches this
// codebase's existing posture elsewhere (safeRemove, disconnectAllNetworks)
// of not letting one non-critical failure abort everything else: a NAS
// hiccup on one volume's archive shouldn't stop the other volumes' archives
// from reaching the remote too. Returns the local→remote path map for
// whatever succeeded, plus a combined error listing anything that didn't
// (nil if everything succeeded).
func PushAppBackup(appID string, metas []BackupMeta, manifestPath string, t RemoteTarget, emit func(string)) (map[string]string, error) {
	pushed := map[string]string{}
	var failures []string

	for _, m := range metas {
		if m.Status != StatusSuccess {
			continue // nothing to push — this volume's local backup didn't succeed either
		}
		remotePath, err := PushFile(m.FilePath, appID, t, emit)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", filepath.Base(m.FilePath), err))
			continue
		}
		pushed[m.FilePath] = remotePath
	}

	if manifestPath != "" {
		if remotePath, err := PushFile(manifestPath, appID, t, emit); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", filepath.Base(manifestPath), err))
		} else {
			pushed[manifestPath] = remotePath
		}
	}

	if len(failures) > 0 {
		return pushed, fmt.Errorf("some files did not reach %s: %s", t.Name, strings.Join(failures, "; "))
	}
	return pushed, nil
}

// ── List (for restore) ───────────────────────────────────────────────────────

// ListRemoteFiles lists archives for appID under "<remote root>/<appID>/" on
// t — mirrors ListBackups's local directory scan (engine.go) so a "restore
// from NAS" picker can use the same app-scoped listing shape the local
// restore UI already has.
func ListRemoteFiles(t RemoteTarget, appID string) ([]RemoteFile, error) {
	switch t.Kind {
	case "mount":
		dir := filepath.Join(t.MountPath, appID)
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var out []RemoteFile
		for _, e := range entries {
			// Only archives are restorable "backups" — the manifest that
			// PushAppBackup copies alongside them is metadata, not a
			// second thing to restore, same distinction ListBackups draws
			// locally (engine.go) by skipping non-.tar.gz files.
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, RemoteFile{
				Name: e.Name(), Path: filepath.Join(dir, e.Name()),
				SizeBytes: info.Size(), ModTime: info.ModTime(),
			})
		}
		return out, nil

	case "rclone":
		dir := strings.TrimRight(t.RcloneRemote, "/") + "/" + appID
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "rclone", "lsjson", dir).CombinedOutput()
		if err != nil {
			// A brand-new app with nothing pushed yet looks like "path not
			// found" to most rclone backends — treat that as "no files"
			// rather than an error, matching os.IsNotExist(err) above.
			if strings.Contains(string(out), "directory not found") {
				return nil, nil
			}
			return nil, fmt.Errorf("rclone list failed: %s", stripANSIRemote(string(out)))
		}
		var raw []struct {
			Name    string    `json:"Name"`
			Size    int64     `json:"Size"`
			ModTime time.Time `json:"ModTime"`
			IsDir   bool      `json:"IsDir"`
		}
		if err := json.Unmarshal(out, &raw); err != nil {
			return nil, fmt.Errorf("rclone list: unexpected output: %w", err)
		}
		var files []RemoteFile
		for _, r := range raw {
			if r.IsDir || !strings.HasSuffix(r.Name, ".tar.gz") {
				continue
			}
			files = append(files, RemoteFile{
				Name: r.Name, Path: dir + "/" + r.Name,
				SizeBytes: r.Size, ModTime: r.ModTime,
			})
		}
		return files, nil

	default:
		return nil, fmt.Errorf("unknown remote kind %q", t.Kind)
	}
}

// ── Pull (for restore) ───────────────────────────────────────────────────────

// PullArchive copies a remote archive back into localDestDir — normally
// Engine.backupDir/<appID>, i.e. exactly where ListBackups/RestoreVolume
// already look — and returns the local path. This is deliberately the ONLY
// thing remote.go does for restore: once the file is local, the existing
// restore code path takes over completely unchanged.
func PullArchive(rf RemoteFile, t RemoteTarget, localDestDir string, emit func(string)) (string, error) {
	if err := os.MkdirAll(localDestDir, 0755); err != nil {
		return "", fmt.Errorf("create local dest dir: %w", err)
	}
	destPath := filepath.Join(localDestDir, rf.Name)

	switch t.Kind {
	case "mount":
		emit(fmt.Sprintf("Copying %s from %s…", rf.Name, t.Name))
		if err := copyFileVerified(rf.Path, destPath); err != nil {
			return "", err
		}

	case "rclone":
		emit(fmt.Sprintf("Downloading %s from %s (rclone)…", rf.Name, t.Name))
		ctx, cancel := context.WithTimeout(context.Background(), rcloneTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "rclone", "copyto", rf.Path, destPath, "--checksum").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("rclone download failed: %s", stripANSIRemote(string(out)))
		}

	default:
		return "", fmt.Errorf("unknown remote kind %q", t.Kind)
	}

	emit(fmt.Sprintf("✓ %s ready locally at %s", rf.Name, destPath))
	return destPath, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// copyFileVerified streams src to dst then confirms the copy landed
// byte-for-byte via sha256File (engine.go) — cheap insurance against a
// silently truncated write, a known failure mode on flaky wifi-backed NAS
// mounts, and a much clearer error than a restore failing weeks later on a
// corrupt archive nobody knew about. Writes to a ".partial" sibling first
// and only renames over the final name once the hash check passes, so a
// concurrent reader (or ListRemoteFiles) never sees a half-written file at
// the real path.
func copyFileVerified(src, dst string) error {
	wantSum, err := sha256File(src)
	if err != nil {
		return fmt.Errorf("hash source: %w", err)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	gotSum, err := sha256File(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("hash copy: %w", err)
	}
	if gotSum != wantSum {
		_ = os.Remove(tmp)
		return fmt.Errorf("copy verification failed — hash mismatch (got %s…, want %s…)", gotSum[:12], wantSum[:12])
	}

	return os.Rename(tmp, dst)
}

// stripANSIRemote strips escape/control noise from rclone's CLI output so
// errors surfaced to the user or Telegram stay clean — same motivation as
// stripDockerOutput in docker.go, kept separate since this package doesn't
// import that one.
func stripANSIRemote(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\x1b' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}
