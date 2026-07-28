package backup

// remote.go — pushes finished backup archives to an off-box destination and
// pulls them back again for restore. Three backend kinds, chosen per
// target, ALL implemented in-process — no external binary is shelled out
// to anywhere in this file:
//
//   "mount" — the remote is already a filesystem path inside this
//             container: a bind-mounted SMB/CIFS or NFS share, e.g. a
//             Synology/TrueNAS box mounted on the HOST and passed through
//             with `-v /mnt/nas/presto-backups:/remote/nas`. Zero
//             dependencies — a streaming copy + hash verify, the same
//             "don't trust it, verify it" posture EncryptStream/
//             DecryptStream already use in backupcrypto.go.
//
//   "sftp"  — a direct SSH/SFTP connection (sftpconn.go, built on
//             golang.org/x/crypto/ssh + github.com/pkg/sftp) — the native
//             equivalent of what Duplicati, Restic, Kopia, and Borg all
//             support directly. Every NAS that speaks SFTP works here
//             (Synology, TrueNAS, QNAP, a plain Linux box) with nothing
//             more than the credentials already in hand — no client-side
//             mount, no host-level setup at all.
//
//   "s3"    — S3-compatible object storage (s3.go, a hand-rolled AWS
//             SigV4 client over stdlib net/http — see that file's
//             comment for why not an SDK). Covers AWS S3 itself, MinIO,
//             Backblaze B2 (S3-compatible endpoint), Wasabi, and anything
//             else speaking the same API.
//
// An earlier version of this file shelled out to the `rclone` binary
// instead. That's a reasonable design (many tools do exactly this), but
// it made "no external app to install" impossible, and on reflection it
// isn't actually what purpose-built backup tools do: Restic, Kopia, and
// Duplicati all embed their SFTP/S3 clients directly rather than
// depending on an external data-mover, and only reach for something like
// rclone as a bridge for backends they don't support natively (Borg's
// well-documented gap for S3/B2, for instance). SFTP and S3-compatible
// storage between them cover the overwhelming majority of self-hosted
// "back up to my NAS or my own bucket" use cases, so embedding both
// directly — matching that same-standard behavior — beats requiring a
// separate binary just to reach either one. OAuth-only services (Google
// Drive, OneDrive, Dropbox) are still out of scope, unchanged from
// before: they need an interactive browser consent flow that doesn't fit
// a headless container, native or not.
//
// Every kind operates on an ALREADY-FINISHED local archive
// (BackupMeta.FilePath). Remote push is always a second step after a
// normal local backup completes, never a replacement for it — if the
// remote is unreachable or the push fails, the local backup still exists
// and nothing about this run is lost.
//
// Layout mirrors the local one on purpose: archives live under
// "<remote root>/<appID>/<file>.tar.gz", exactly like ListBackups
// (engine.go) expects under e.backupDir/<appID>/ — so PullArchive can
// drop a file straight into the local backups dir and every existing
// restore code path (RestoreVolume, RestoreApp) works completely
// unchanged. A remote-sourced restore and a local-disk restore are
// indistinguishable to the rest of the codebase from that point on.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RemoteTarget describes one configured off-box destination. See config.go's
// RemoteConfig for how a list of these is persisted.
type RemoteTarget struct {
	Name string `json:"name"` // display name, e.g. "Synology NAS"
	Kind string `json:"kind"` // "mount" | "sftp" | "s3"

	// Kind == "mount": a directory already accessible inside this container.
	MountPath string `json:"mount_path,omitempty"`

	// Kind == "sftp": see sftpconn.go for exactly how each field is used.
	SFTPHost           string `json:"sftp_host,omitempty"`
	SFTPPort           int    `json:"sftp_port,omitempty"` // 0 defaults to 22
	SFTPUser           string `json:"sftp_user,omitempty"`
	SFTPPassword       string `json:"sftp_password,omitempty"`         // either this or a private key
	SFTPPrivateKeyPath string `json:"sftp_private_key_path,omitempty"` // path INSIDE this container to a mounted private key file
	SFTPPrivateKeyPass string `json:"sftp_private_key_pass,omitempty"` // passphrase for the private key, if it has one
	SFTPKnownHostsPath string `json:"sftp_known_hosts_path,omitempty"` // optional — blank means accept any host key, see sftpconn.go
	SFTPBaseDir        string `json:"sftp_base_dir,omitempty"`         // remote directory backups live under, e.g. "/backups/presto"

	// Kind == "s3": see s3.go for exactly how each field is used.
	S3Endpoint  string `json:"s3_endpoint,omitempty"` // full URL including scheme, e.g. "https://s3.us-west-002.backblazeb2.com"
	S3Bucket    string `json:"s3_bucket,omitempty"`
	S3AccessKey string `json:"s3_access_key,omitempty"`
	S3SecretKey string `json:"s3_secret_key,omitempty"`
	S3Region    string `json:"s3_region,omitempty"`   // optional — defaults to "us-east-1", many S3-compatible services ignore it entirely
	S3BaseDir   string `json:"s3_base_dir,omitempty"` // optional key prefix, e.g. "presto-backups"

	// Kind == "prestoback": push to ANOTHER PrestoBack instance's own API,
	// paired via the MITM-resistant handshake in internal/config/nodeidentity.go
	// and internal/config/remotepairing.go — see those files' package
	// comments for the full protocol. The three Pinned* fields are set
	// ONCE, at pairing time, from the receiver's QR (an out-of-band,
	// human-verified channel) — never updated silently afterward. If the
	// receiver's actual identity ever stops matching PrestoBackPinnedNodeID,
	// every push and reachability check refuses rather than silently
	// trusting whatever answers now, the same "host key changed" posture
	// sftpconn.go's KnownHostsPath already takes for SSH.
	PrestoBackURL             string `json:"prestoback_url,omitempty"`              // e.g. "http://192.168.1.50:8778"
	PrestoBackPinnedNodeID    string `json:"prestoback_pinned_node_id,omitempty"`    // set once at pairing time, never updated silently
	PrestoBackPinnedPublicKey string `json:"prestoback_pinned_public_key,omitempty"` // base64, set once at pairing time
	PrestoBackPushCredential  string `json:"prestoback_push_credential,omitempty"`   // issued at pairing time, sent on every push
}

// RemoteFile describes one archive found on a remote target.
type RemoteFile struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"` // full remote path/key as the backend understands it
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

const remoteOpTimeout = 2 * time.Hour // large archives, slow uplinks

// ── Reachability ─────────────────────────────────────────────────────────────

// RemoteReachable does a fast pre-flight check before a push/list/pull is
// attempted, so callers can surface a clear "NAS unreachable"/"remote
// misconfigured" error instead of a slow copy timing out deep inside a
// push.
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
		probe := filepath.Join(t.MountPath, ".prestoback_write_test")
		if err := os.WriteFile(probe, []byte("ok"), 0644); err != nil {
			return fmt.Errorf("mount path %q is not writable: %w", t.MountPath, err)
		}
		_ = os.Remove(probe)
		return nil

	case "sftp":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		client, closeFn, err := sftpDial(ctx, t)
		if err != nil {
			return err
		}
		defer closeFn()
		dir := t.SFTPBaseDir
		if dir == "" {
			dir = "."
		}
		if _, err := client.ReadDir(dir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot list %q on %s: %w", dir, t.SFTPHost, err)
		}
		return nil

	case "s3":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if t.S3Endpoint == "" || t.S3Bucket == "" {
			return fmt.Errorf("s3_endpoint and s3_bucket are required")
		}
		return newS3Client(t).reachable(ctx)

	case "prestoback":
		return prestobackReachable(t)

	default:
		return fmt.Errorf("unknown remote kind %q (expected \"mount\", \"sftp\", \"s3\", or \"prestoback\")", t.Kind)
	}
}

// ── Push ──────────────────────────────────────────────────────────────────────

// PushFile copies one already-finished local file (an archive or a
// manifest) into "<remote root>/<appID>/" on t, verifying the copy landed
// intact before reporting success. Returns the remote-side path/key to
// store in the manifest (see UpdateManifestRemoteStatus in engine.go).
func PushFile(localPath, appID string, t RemoteTarget, emit func(string)) (string, error) {
	if err := RemoteReachable(t); err != nil {
		return "", err
	}
	name := filepath.Base(localPath)

	info, err := os.Stat(localPath)
	if err != nil {
		return "", fmt.Errorf("stat local file: %w", err)
	}

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

	case "sftp":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		client, closeFn, err := sftpDial(ctx, t)
		if err != nil {
			return "", err
		}
		defer closeFn()

		destPath := sftpJoin(t.SFTPBaseDir, appID, name)
		emit(fmt.Sprintf("Uploading %s to %s (sftp)…", name, t.Name))
		f, err := os.Open(localPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if err := sftpPut(client, destPath, f); err != nil {
			return "", fmt.Errorf("sftp upload failed: %w", err)
		}
		// Size sanity check — SFTP has no built-in content-hash verify the
		// way copyFileVerified's local sha256File comparison gives us for
		// "mount"; comparing the remote file's resulting size against what
		// we meant to send is the cheap check that's actually available
		// here without downloading the whole thing back to hash it.
		if remoteInfo, statErr := client.Stat(destPath); statErr == nil && remoteInfo.Size() != info.Size() {
			return "", fmt.Errorf("sftp upload size mismatch: sent %d bytes, remote shows %d", info.Size(), remoteInfo.Size())
		}
		emit(fmt.Sprintf("✓ %s pushed to %s", name, t.Name))
		return destPath, nil

	case "s3":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		key := s3Join(t.S3BaseDir, appID, name)
		emit(fmt.Sprintf("Uploading %s to %s (s3)…", name, t.Name))
		f, err := os.Open(localPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if err := newS3Client(t).putObject(ctx, key, f, info.Size()); err != nil {
			return "", fmt.Errorf("s3 upload failed: %w", err)
		}
		emit(fmt.Sprintf("✓ %s pushed to %s", name, t.Name))
		return key, nil

	case "prestoback":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		emit(fmt.Sprintf("Verifying %s's identity…", t.Name))
		if err := prestobackChallenge(ctx, t); err != nil {
			return "", err
		}
		emit(fmt.Sprintf("Pushing %s to %s (prestoback)…", name, t.Name))
		remotePath, err := prestobackPushFile(ctx, localPath, appID, t)
		if err != nil {
			return "", fmt.Errorf("prestoback push failed: %w", err)
		}
		emit(fmt.Sprintf("✓ %s pushed to %s", name, t.Name))
		return remotePath, nil

	default:
		return "", fmt.Errorf("unknown remote kind %q", t.Kind)
	}
}

// PushAppBackup pushes every successful archive from one backup run (plus
// its manifest) to t, and is the intended call site right after
// Engine.WriteManifest succeeds (see pushToRemotes in internal/api/
// server.go). Best-effort per file — a NAS hiccup on one volume's archive
// shouldn't stop the other volumes' archives from reaching the remote
// too. Returns the local→remote path map for whatever succeeded, plus a
// combined error listing anything that didn't (nil if everything
// succeeded).
func PushAppBackup(appID string, metas []BackupMeta, manifestPath string, t RemoteTarget, emit func(string)) (map[string]string, error) {
	pushed := map[string]string{}
	var failures []string

	for _, m := range metas {
		if m.Status != StatusSuccess {
			continue
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

// ListRemoteFiles lists archives for appID under "<remote root>/<appID>/"
// on t — mirrors ListBackups's local directory scan (engine.go) so a
// "restore from NAS" picker can use the same app-scoped listing shape the
// local restore UI already has.
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

	case "sftp":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, closeFn, err := sftpDial(ctx, t)
		if err != nil {
			return nil, err
		}
		defer closeFn()

		dir := sftpJoin(t.SFTPBaseDir, appID)
		entries, err := client.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		var out []RemoteFile
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
				continue
			}
			out = append(out, RemoteFile{
				Name: e.Name(), Path: dir + "/" + e.Name(),
				SizeBytes: e.Size(), ModTime: e.ModTime(),
			})
		}
		return out, nil

	case "s3":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		prefix := s3Join(t.S3BaseDir, appID) + "/"
		objs, err := newS3Client(t).listObjects(ctx, prefix)
		if err != nil {
			return nil, err
		}
		var out []RemoteFile
		for _, o := range objs {
			name := strings.TrimPrefix(o.Key, prefix)
			if strings.Contains(name, "/") || !strings.HasSuffix(name, ".tar.gz") {
				continue // nested "directory" or the manifest, not a restorable archive
			}
			out = append(out, RemoteFile{Name: name, Path: o.Key, SizeBytes: o.SizeBytes, ModTime: o.LastModified})
		}
		return out, nil

	case "prestoback":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := prestobackChallenge(ctx, t); err != nil {
			return nil, err
		}
		return prestobackListFiles(ctx, t, appID)

	default:
		return nil, fmt.Errorf("unknown remote kind %q", t.Kind)
	}
}

// ── Prune (retention on the remote itself) ───────────────────────────────────
//
// PruneRemote enforces `retain` on t the same way Engine.PruneBackups
// enforces it locally (engine.go): newest `retain` non-prerestore archives
// kept per volume slug, and pre-restore snapshots capped at `retain`
// independently of regular ones. Before this existed, PushAppBackup/PushFile
// only ever ADDED archives to a remote target — nothing ever deleted an old
// one from mount/sftp/s3 storage, so those three kinds accumulated backups
// forever regardless of the configured retain count, even though the local
// copy was being pruned correctly the whole time. That's the actual reason
// remote storage can show more archives than `retain` implies.
//
// "prestoback" targets are deliberately excluded here — that kind already
// enforces its own retention on the RECEIVING instance (see
// remotepairing_handlers.go's disk-space + retention limits), which is the
// receiver's own config, not this pusher's. Pruning it from here too would
// mean two independent retain counts fighting over the same directory.
//
// Grouping uses the exact same volumeSlugFromID/PreRestore parsing
// ListBackups and PruneBackups use locally, so a slug on the remote means
// the same thing it means on disk — this is deliberately not a separate
// parser that could drift from the local one.
func PruneRemote(t RemoteTarget, appID string, retain int) error {
	if t.Kind == "prestoback" {
		return nil
	}
	if retain <= 0 {
		retain = 5
	}

	files, err := ListRemoteFiles(t, appID)
	if err != nil {
		return fmt.Errorf("list remote files for prune: %w", err)
	}
	if len(files) == 0 {
		return nil
	}

	type named struct {
		RemoteFile
		slug       string
		preRestore bool
	}
	bySlug := map[string][]named{}
	preRestoreBySlug := map[string][]named{}
	for _, f := range files {
		id := strings.TrimSuffix(f.Name, ".tar.gz")
		pr := strings.HasSuffix(id, "_prerestore")
		slug := volumeSlugFromID(appID, id)
		n := named{RemoteFile: f, slug: slug, preRestore: pr}
		if pr {
			preRestoreBySlug[slug] = append(preRestoreBySlug[slug], n)
		} else {
			bySlug[slug] = append(bySlug[slug], n)
		}
	}

	var lastErr error
	prune := func(group map[string][]named) {
		for _, list := range group {
			if len(list) <= retain {
				continue
			}
			// Newest-first, same ordering ListBackups produces locally —
			// ListRemoteFiles carries ModTime for every kind (mount:
			// os.FileInfo; sftp: fs.FileInfo; s3: LastModified), so this is
			// consistent across backends.
			sort.Slice(list, func(i, j int) bool { return list[i].ModTime.After(list[j].ModTime) })
			for _, f := range list[retain:] {
				if err := deleteRemoteFile(t, f.Path); err != nil {
					lastErr = fmt.Errorf("delete %s: %w", f.Name, err)
					continue
				}
			}
		}
	}
	prune(bySlug)
	prune(preRestoreBySlug)
	return lastErr
}

// deleteRemoteFile removes one archive from t by its ListRemoteFiles Path,
// dispatching to the same per-kind primitive PushFile/ListRemoteFiles
// already use for that kind (mount: os.Remove; sftp: an SFTP client's
// Remove; s3: an authenticated DELETE).
func deleteRemoteFile(t RemoteTarget, path string) error {
	switch t.Kind {
	case "mount":
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil

	case "sftp":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		client, closeFn, err := sftpDial(ctx, t)
		if err != nil {
			return err
		}
		defer closeFn()
		if err := client.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil

	case "s3":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return newS3Client(t).deleteObject(ctx, path)

	default:
		return fmt.Errorf("unknown remote kind %q", t.Kind)
	}
}

// ── Pull (for restore) ───────────────────────────────────────────────────────

// PullArchive copies a remote archive back into localDestDir — normally
// Engine.backupDir/<appID>, i.e. exactly where ListBackups/RestoreVolume
// already look — and returns the local path. This is deliberately the
// ONLY thing remote.go does for restore: once the file is local, the
// existing restore code path takes over completely unchanged.
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

	case "sftp":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		client, closeFn, err := sftpDial(ctx, t)
		if err != nil {
			return "", err
		}
		defer closeFn()

		emit(fmt.Sprintf("Downloading %s from %s (sftp)…", rf.Name, t.Name))
		src, err := client.Open(rf.Path)
		if err != nil {
			return "", fmt.Errorf("sftp download failed: %w", err)
		}
		defer src.Close()
		tmp := destPath + ".partial"
		out, err := os.Create(tmp)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			_ = os.Remove(tmp)
			return "", fmt.Errorf("sftp download failed: %w", err)
		}
		if err := out.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		if err := os.Rename(tmp, destPath); err != nil {
			return "", err
		}

	case "s3":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		emit(fmt.Sprintf("Downloading %s from %s (s3)…", rf.Name, t.Name))
		body, err := newS3Client(t).getObject(ctx, rf.Path)
		if err != nil {
			return "", fmt.Errorf("s3 download failed: %w", err)
		}
		defer body.Close()
		tmp := destPath + ".partial"
		out, err := os.Create(tmp)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, body); err != nil {
			out.Close()
			_ = os.Remove(tmp)
			return "", fmt.Errorf("s3 download failed: %w", err)
		}
		if err := out.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		if err := os.Rename(tmp, destPath); err != nil {
			return "", err
		}

	case "prestoback":
		ctx, cancel := context.WithTimeout(context.Background(), remoteOpTimeout)
		defer cancel()
		if err := prestobackChallenge(ctx, t); err != nil {
			return "", err
		}
		// rf.Path carries "appID/name" for this kind — RemoteFile.Path is
		// documented as "whatever the backend needs to locate the file",
		// and every other kind already uses it that way (sftp: the remote
		// path; mount: the local-ish full path); a composite appID/name
		// key is this kind's equivalent, since the receive-side API is
		// organized by app.
		appID := rf.Path
		if idx := strings.Index(rf.Path, "/"); idx >= 0 {
			appID = rf.Path[:idx]
		}
		emit(fmt.Sprintf("Downloading %s from %s (prestoback)…", rf.Name, t.Name))
		body, err := prestobackOpenDownload(ctx, appID, rf.Name, t)
		if err != nil {
			return "", fmt.Errorf("prestoback download failed: %w", err)
		}
		defer body.Close()
		tmp := destPath + ".partial"
		out, err := os.Create(tmp)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, body); err != nil {
			out.Close()
			_ = os.Remove(tmp)
			return "", fmt.Errorf("prestoback download failed: %w", err)
		}
		if err := out.Close(); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
		if err := os.Rename(tmp, destPath); err != nil {
			return "", err
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

// sftpJoin builds a remote SFTP path from parts, always using "/" (SFTP
// paths are POSIX-style regardless of what OS the client runs on — using
// filepath.Join here would be wrong on a Windows build of this binary).
func sftpJoin(parts ...string) string {
	var clean []string
	for _, p := range parts {
		p = strings.Trim(p, "/")
		if p != "" {
			clean = append(clean, p)
		}
	}
	return strings.Join(clean, "/")
}

// s3Join builds an S3 object key from parts the same way sftpJoin does —
// S3 keys are always "/"-delimited strings, not filesystem paths.
func s3Join(parts ...string) string {
	return sftpJoin(parts...)
}
