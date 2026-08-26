package api

// remotepairing_handlers.go — HTTP surface for PrestoBack-to-PrestoBack
// remote pairing. The actual cryptographic protocol lives in
// internal/config/nodeidentity.go and remotepairing.go; this file is
// just the transport around it, matching every other *_handlers-style
// split in this codebase (auth.go is the same relationship to the JWT/
// bcrypt logic it wraps).
//
// Two very different trust models sit side by side in this one file —
// worth being explicit about which is which:
//
//   - The public endpoints (handleRemotePairingClaim, Challenge,
//     and the three handleRemoteReceive* endpoints) are called by ANOTHER
//     PrestoBack instance's backend, not a logged-in browser. They can't
//     go through the normal session/API-key auth (the caller has no
//     session here — it IS a separate instance), so each has its own
//     credential check instead: a one-time pairing secret, a signature
//     challenge, or a push credential.
//   - The admin-authenticated endpoints (handleRemotePairingStart,
//     handleRemotePairAsPusher, handleRemotePushers*) are normal
//     browser-facing settings actions, gated by adminForWrites like
//     every other mutating endpoint in this codebase.

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/config"
	"github.com/pi/prestoback/internal/notify"
)

// ── Receiver side: public, instance-to-instance ─────────────────────────────

func (s *Server) handleRemotePairingClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	var req config.RemotePairingClaimRequest
	if err := parseJSON(r, &req); err != nil {
		errOut(w, 400, "invalid JSON: "+err.Error())
		return
	}
	resp, err := s.cfg.RespondToRemotePairing(req)
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	if _, err := s.cfg.AddRemotePusher("", req.PusherNodeID, req.PusherPublicKey, resp.PushCredential); err != nil {
		errOut(w, 500, "pairing succeeded but could not save the pusher record: "+err.Error())
		return
	}
	respond(w, 200, resp)
}

func (s *Server) handleRemotePairingChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	var req config.RemoteChallengeRequest
	if err := parseJSON(r, &req); err != nil {
		errOut(w, 400, "invalid JSON: "+err.Error())
		return
	}
	resp, err := s.cfg.RespondToRemoteChallenge(req.Nonce)
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}
	respond(w, 200, resp)
}

// authenticateRemotePush checks the X-Push-Credential header against the
// registered pusher list, returning the matching RemotePusher or writing
// a 401 itself. Shared by all three handleRemoteReceive* endpoints.
func (s *Server) authenticateRemotePush(w http.ResponseWriter, r *http.Request) (config.RemotePusher, bool) {
	cred := r.Header.Get("X-Push-Credential")
	rp, ok := s.cfg.ValidateRemotePushCredential(cred)
	if !ok {
		time.Sleep(300 * time.Millisecond) // same anti-brute-force delay auth.go uses for a failed password/MFA check
		errOut(w, 401, "invalid or missing push credential")
		return config.RemotePusher{}, false
	}
	s.cfg.TouchRemotePusher(rp.ID)
	return rp, true
}

// sanitizeRemotePathComponent rejects anything that isn't a plain,
// single-segment name — no "..", no "/", not empty. Both appID and name
// on the receive endpoints come from an authenticated-but-still-external
// caller, so this gets the same defensive treatment
// extractTarGz's "suspicious path" guard already applies to archive
// entries (engine.go) — authenticated doesn't mean trusted to hand back
// arbitrary paths.
func sanitizeRemotePathComponent(s string) (string, error) {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("invalid path component %q", s)
	}
	return s, nil
}

// receivedDir is where pushed backups from a given pusher+app land —
// namespaced by pusher ID so two different paired instances can never
// collide with or overwrite each other's archives even if they happen to
// use the same appID.
func (s *Server) receivedDir(pusherID, appID string) string {
	return filepath.Join(s.cfg.DataDir, "received", pusherID, appID)
}

// minReceiveFreeSpaceBytes is the safety margin kept free on top of the
// incoming upload's own size — mirrors the same "don't run a disk
// completely dry" caution the low-disk-space warning elsewhere in this
// codebase applies, just enforced at the point of accepting someone
// else's data rather than just warning about it.
const minReceiveFreeSpaceBytes = 500 * 1024 * 1024 // 500MB

// defaultReceivedRetain is how many archives are kept per (pusher, app)
// directory before older ones are pruned — see pruneReceivedBackups.
const defaultReceivedRetain = 10

// diskUsageFunc is a package-level indirection over diskUsage so tests
// can simulate a low-disk-space condition without needing to genuinely
// exhaust real disk space (not practical to do safely in a test). Only
// tests ever reassign this; production code always goes through the real
// diskUsage.
var diskUsageFunc = diskUsage

func (s *Server) handleRemoteReceiveBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	rp, ok := s.authenticateRemotePush(w, r)
	if !ok {
		return
	}
	appID, err := sanitizeRemotePathComponent(r.URL.Query().Get("app"))
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	name, err := sanitizeRemotePathComponent(r.URL.Query().Get("name"))
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, "_manifest.json") {
		errOut(w, 400, "unexpected file type — only backup archives and manifests are accepted")
		return
	}

	dir := s.receivedDir(rp.ID, appID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		errOut(w, 500, "could not create storage directory: "+err.Error())
		return
	}

	// Disk-space check BEFORE accepting the write — an unbounded incoming
	// push (buggy or malicious pusher) shouldn't be able to run this
	// instance's disk dry. Checked against whatever's actually declared in
	// Content-Length; a request with no declared length still has to clear
	// the flat safety margin on its own, so this can't be trivially
	// bypassed by omitting the header.
	if stat, statErr := diskUsageFunc(dir); statErr == nil {
		needed := int64(minReceiveFreeSpaceBytes)
		if r.ContentLength > 0 {
			needed += r.ContentLength
		}
		if stat.free < uint64(needed) {
			s.dispatchNotify(notify.Event{
				Kind: "remote_receive_fail", IsError: true,
				AppName: appID,
				Detail:  fmt.Sprintf("rejected push from %s — insufficient disk space (%d MB free)", rp.Name, stat.free/1024/1024),
			})
			errOut(w, 507, fmt.Sprintf("insufficient disk space on receiver (%d MB free, need ~%d MB)", stat.free/1024/1024, needed/1024/1024))
			return
		}
	}
	// If diskUsage itself failed (statErr != nil), we deliberately still
	// proceed rather than block the push — a stat failure is far more
	// likely to mean "unexpected filesystem type" than "definitely out of
	// space," and refusing every push because of a diagnostic that
	// couldn't run would be a worse failure mode than occasionally
	// skipping the check.

	destPath := filepath.Join(dir, name)
	tmp := destPath + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		errOut(w, 500, "could not create destination file: "+err.Error())
		return
	}
	written, err := io.Copy(out, r.Body)
	out.Close()
	if err != nil {
		os.Remove(tmp)
		s.dispatchNotify(notify.Event{Kind: "remote_receive_fail", IsError: true, AppName: appID, Detail: "write failed: " + err.Error()})
		errOut(w, 500, "write failed: "+err.Error())
		return
	}
	if r.ContentLength > 0 && written != r.ContentLength {
		os.Remove(tmp)
		errOut(w, 400, fmt.Sprintf("incomplete upload: expected %d bytes, got %d", r.ContentLength, written))
		return
	}
	if err := os.Rename(tmp, destPath); err != nil {
		os.Remove(tmp)
		errOut(w, 500, "could not finalize upload: "+err.Error())
		return
	}

	// Manifests are small and never counted against retention on their
	// own (see pruneReceivedBackups) — only archives trigger a prune pass,
	// keeping a manifest push itself cheap and side-effect-light.
	if strings.HasSuffix(name, ".tar.gz") {
		if rp.AppendOnly {
			// Append-only pushers (see RemotePusher.AppendOnly's doc
			// comment in remotepairing.go) never get pruned on receive —
			// new archives keep landing, nothing already accepted is ever
			// removed by this instance. Retention/cleanup for an
			// append-only pusher is a deliberate, separate, manual action
			// an admin takes here (e.g. via the received-backups list),
			// never an automatic side effect of the next push arriving.
		} else {
			pruneReceivedBackups(dir, defaultReceivedRetain)
		}
		s.dispatchNotify(notify.Event{
			Kind: "remote_receive_success", AppName: appID,
			Detail: fmt.Sprintf("%s pushed %s (%s)", rp.Name, name, humanReceiveBytes(written)),
		})
	}

	respond(w, 200, map[string]any{"path": destPath, "size_bytes": written})
}

// pruneReceivedBackups keeps only the newest `retain` archives (by mtime)
// in dir, deleting older ones along with any manifest that shares the
// same base filename. Deliberately simpler than the local engine's
// PruneBackups (engine.go), which retains per-volume-slug: this retains
// by count across the WHOLE app directory regardless of which volume
// slug each archive belongs to. That's a real simplification, not an
// oversight — the practical goal here is bounding a receiver's disk usage
// from potentially many different pushing instances and volumes, not
// exact parity with whatever retention policy governs the pusher's own
// local copies (which already decided how many versions exist in the
// first place; this is a mirror, not the source of truth for "how many
// versions should exist").
func pruneReceivedBackups(dir string, retain int) {
	if retain <= 0 {
		retain = defaultReceivedRetain
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fileWithTime struct {
		name    string
		modTime time.Time
	}
	var archives []fileWithTime
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		archives = append(archives, fileWithTime{e.Name(), info.ModTime()})
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].modTime.After(archives[j].modTime) })
	if len(archives) <= retain {
		return
	}
	for _, a := range archives[retain:] {
		_ = os.Remove(filepath.Join(dir, a.name))
		manifestName := strings.TrimSuffix(a.name, ".tar.gz") + "_manifest.json"
		_ = os.Remove(filepath.Join(dir, manifestName))
	}
}

func humanReceiveBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (s *Server) handleRemoteReceiveList(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.authenticateRemotePush(w, r)
	if !ok {
		return
	}
	appID, err := sanitizeRemotePathComponent(r.URL.Query().Get("app"))
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	dir := s.receivedDir(rp.ID, appID)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		respond(w, 200, []backup.RemoteFile{})
		return
	}
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}
	var out []backup.RemoteFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backup.RemoteFile{
			Name:      e.Name(),
			Path:      appID + "/" + e.Name(), // composite key — see prestobackremote.go's PullArchive case for how this gets parsed back apart
			SizeBytes: info.Size(),
			ModTime:   info.ModTime(),
		})
	}
	respond(w, 200, out)
}

func (s *Server) handleRemoteReceiveDownload(w http.ResponseWriter, r *http.Request) {
	rp, ok := s.authenticateRemotePush(w, r)
	if !ok {
		return
	}
	appID, err := sanitizeRemotePathComponent(r.URL.Query().Get("app"))
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	name, err := sanitizeRemotePathComponent(r.URL.Query().Get("name"))
	if err != nil {
		errOut(w, 400, err.Error())
		return
	}
	path := filepath.Join(s.receivedDir(rp.ID, appID), name)
	f, err := os.Open(path)
	if err != nil {
		errOut(w, 404, "archive not found")
		return
	}
	defer f.Close()
	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/gzip")
	if info != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	io.Copy(w, f)
}

// ── Pusher side: admin-authenticated ─────────────────────────────────────────

// handleRemoteNodeID is a lightweight, read-only endpoint for displaying
// this instance's own Node ID in the UI — deliberately separate from
// handleRemotePairingStart, which mints a fresh one-time pairing secret
// on every call and would be the wrong thing to hit just to show a label.
func (s *Server) handleRemoteNodeID(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]string{"node_id": s.cfg.NodeID()})
}

// handleRemotePairingStart is called on the RECEIVER, by its own admin —
// mints a pairing session for display as a QR (StartRemotePairing).
func (s *Server) handleRemotePairingStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	session, err := s.cfg.StartRemotePairing()
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}
	respond(w, 200, session)
}

// handleRemotePairAsPusher is called on the PUSHER, by its own admin,
// after scanning/pasting the receiver's QR — completes the pairing
// handshake (outbound HTTP call to the receiver) and, only if the
// receiver's identity verifies against what the QR said to expect, saves
// a new RemoteTarget{Kind: "prestoback"}.
// defaultPairedInstanceName builds a readable fallback for a prestoback
// target's name when the person leaves the name field blank while pairing.
// Previously this fell back to the raw NodeID — a 40+ char hash — which
// then became the PERMANENT display name everywhere: the Settings row,
// history entries, and every Telegram/Discord "Remote push complete"
// notification, since all of those just print target.Name. A hostname is
// meaningfully more useful at a glance than a hash, and unlike the hash it
// isn't itself a security-sensitive value — the name is cosmetic; the
// pinned NodeID (still stored and still shown, truncated, in the UI's
// inspect drawer) is what verification actually depends on.
//
// nodeID's first 4-hex-char chunk is appended as a short disambiguator —
// not the full ID — so two unnamed pairings to hosts sharing a hostname
// (e.g. two "raspberrypi.local" on different subnets, common in a
// homelab) still get distinct rows instead of a silent name collision.
func defaultPairedInstanceName(rawURL, nodeID string) string {
	host := "paired instance"
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	return host + " (" + shortNodeID(nodeID) + ")"
}

// shortNodeID returns just the first 4-hex-char chunk of a chunked NodeID
// (e.g. "8402" from "8402-2338-6865-...") — enough to disambiguate two
// same-named entries at a glance without repeating the full verification
// hash inline everywhere it's used as a display suffix.
func shortNodeID(nodeID string) string {
	if i := strings.IndexByte(nodeID, '-'); i > 0 {
		return nodeID[:i]
	}
	if len(nodeID) > 4 {
		return nodeID[:4]
	}
	return nodeID
}

func (s *Server) handleRemotePairAsPusher(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	var req struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
		NodeID string `json:"node_id"`
	}
	if err := parseJSON(r, &req); err != nil {
		errOut(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if req.URL == "" || req.Secret == "" || req.NodeID == "" {
		errOut(w, 400, "url, secret, and node_id are all required")
		return
	}
	if req.Name == "" {
		req.Name = defaultPairedInstanceName(req.URL, req.NodeID)
	}
	req.URL = strings.TrimRight(req.URL, "/")

	result, err := backup.PairWithPrestoBackRemote(r.Context(), req.URL, req.Secret, req.NodeID, s.cfg)
	if err != nil {
		errOut(w, 400, "pairing failed: "+err.Error())
		return
	}

	rc := s.cfg.GetRemote()
	for _, t := range rc.Targets {
		if t.Name == req.Name {
			errOut(w, 400, fmt.Sprintf("a remote target named %q already exists", req.Name))
			return
		}
	}
	newTarget := config.RemoteTarget{
		Name:                      req.Name,
		Kind:                      "prestoback",
		PrestoBackURL:             req.URL,
		PrestoBackPinnedNodeID:    result.PinnedNodeID,
		PrestoBackPinnedPublicKey: result.PinnedPublicKey,
		PrestoBackPushCredential:  result.PushCredential,
	}
	rc.Targets = append(rc.Targets, newTarget)
	if err := s.cfg.SetRemote(rc); err != nil {
		log.Printf("[remote-pairing] failed to persist new target %q: %v", newTarget.Name, err)
		errOut(w, 500, "pairing succeeded but saving the new target failed — try again: "+err.Error())
		return
	}

	resp := map[string]any{"target": redactRemoteTarget(newTarget)}
	if strings.HasPrefix(req.URL, "http://") {
		// The identity-pinning handshake itself is MITM-resistant
		// regardless of transport (see nodeidentity.go/remotepairing.go) —
		// this warning is about a DIFFERENT property, confidentiality:
		// over plain HTTP, an archive's actual bytes are readable by
		// anyone positioned on the network path, even though they can't
		// forge or redirect the connection. Encrypting archives at rest
		// (Settings → Backup Encryption) closes that gap regardless of
		// transport; a reverse proxy with TLS in front of either instance
		// closes it at the transport layer instead.
		resp["warning"] = "This target uses plain http://, not https://. Pairing itself is still protected against impersonation, but archive contents will be readable to anyone on the network path unless you also enable backup encryption or put a TLS reverse proxy in front of one or both instances."
	}
	respond(w, 200, resp)
}

// RemotePusherView is the redacted shape for GET /api/remote/pushers —
// never echoes CredentialHash back, same "never re-expose a stored
// secret-derived value" posture ListPairedKeys' HTTP handler already
// applies for PairedKey.KeyHash.
type RemotePusherView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	PusherNodeID string     `json:"pusher_node_id"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsed     *time.Time `json:"last_used,omitempty"`
}

func (s *Server) handleRemotePushers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	pushers := s.cfg.ListRemotePushers()
	out := make([]RemotePusherView, len(pushers))
	for i, rp := range pushers {
		lastUsed := rp.LastUsed
		if fileTime := s.newestReceivedFileTime(rp.ID); fileTime != nil && (lastUsed == nil || fileTime.After(*lastUsed)) {
			lastUsed = fileTime
		}
		out[i] = RemotePusherView{ID: rp.ID, Name: rp.Name, PusherNodeID: rp.PusherNodeID, CreatedAt: rp.CreatedAt, LastUsed: lastUsed}
	}
	respond(w, 200, out)
}

// newestReceivedFileTime scans every app subdirectory this pusher has ever
// sent to and returns the newest file's mtime across all of them — the
// actual, persisted answer to "when did a backup from this pusher last
// really land on disk", independent of TouchRemotePusher's in-memory-only
// bookkeeping (see its own doc comment for why that field alone reverts
// to null on every restart even when real pushes happened before it).
func (s *Server) newestReceivedFileTime(pusherID string) *time.Time {
	return newestFileTimeInDir(filepath.Join(s.cfg.DataDir, "received", pusherID))
}

// newestFileTimeInDir is newestReceivedFileTime's pure half — split out so
// it's testable without a full Server/Config. Walks dir/{app}/*.tar.gz two
// levels deep and returns the newest mtime found. Returns nil if dir
// doesn't exist, is empty, or contains no archives — best-effort, same
// posture the rest of this file already takes toward filesystem scans
// backing purely informational UI.
func newestFileTimeInDir(dir string) *time.Time {
	appDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var newest time.Time
	for _, appDir := range appDirs {
		if !appDir.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, appDir.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".tar.gz") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	if newest.IsZero() {
		return nil
	}
	return &newest
}

func (s *Server) handleRemotePusherByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/remote/pushers/")
	if id == "" {
		errOut(w, 400, "missing pusher id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name       string `json:"name"`
			AppendOnly *bool  `json:"append_only,omitempty"` // pointer — nil means "not included in this request", not "set to false"; lets a rename-only PUT leave the flag untouched
		}
		if err := parseJSON(r, &req); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		if req.Name != "" {
			if err := s.cfg.RenameRemotePusher(id, req.Name); err != nil {
				errOut(w, 400, err.Error())
				return
			}
		}
		if req.AppendOnly != nil {
			if err := s.cfg.SetRemotePusherAppendOnly(id, *req.AppendOnly); err != nil {
				errOut(w, 400, err.Error())
				return
			}
		}
		respond(w, 200, map[string]string{"status": "updated"})

	case http.MethodDelete:
		if err := s.cfg.DeleteRemotePusher(id); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		purged := false
		// ?purge=true additionally wipes every backup this pusher ever
		// sent, across all its apps — the actual answer to "this pairing
		// is dead (rebuilt/replaced with a new identity), get rid of its
		// leftovers" rather than just leaving them to sit under an
		// orphaned "(revoked)" label forever. Revoke-only (the default)
		// stays non-destructive to received data, matching how revoking a
		// paired KEY elsewhere in this codebase never deletes anything it
		// was used for.
		if r.URL.Query().Get("purge") == "true" {
			dir := filepath.Join(s.cfg.DataDir, "received", id)
			if err := os.RemoveAll(dir); err != nil {
				log.Printf("[remote-pairing] purge of %s failed: %v", dir, err)
				errOut(w, 500, "revoked, but deleting its received backups failed: "+err.Error())
				return
			}
			purged = true
		}
		respond(w, 200, map[string]any{"status": "revoked", "purged": purged})

	default:
		errOut(w, 405, "method not allowed")
	}
}

// ReceivedBackupGroup is one pusher+app directory's worth of received
// archives, for the admin-facing browse/manage view.
type ReceivedBackupGroup struct {
	PusherID   string             `json:"pusher_id"`
	PusherName string             `json:"pusher_name"`
	AppID      string             `json:"app_id"`
	Files      []ReceivedFileInfo `json:"files"`
}

type ReceivedFileInfo struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	ModTime   time.Time `json:"mod_time"`
}

// handleReceivedBackupsList lists everything currently stored under
// DataDir/received/, grouped by pusher and app — the admin's view into
// what's actually accumulating on disk from paired instances, since
// there's otherwise no visibility into this at all beyond SSHing into the
// box and looking.
func (s *Server) handleReceivedBackupsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	pusherNames := map[string]string{}
	for _, rp := range s.cfg.ListRemotePushers() {
		name := rp.Name
		if name == "" {
			name = rp.PusherNodeID
		}
		pusherNames[rp.ID] = name
	}

	root := filepath.Join(s.cfg.DataDir, "received")
	var groups []ReceivedBackupGroup
	pusherDirs, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		respond(w, 200, []ReceivedBackupGroup{})
		return
	}
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}
	for _, pd := range pusherDirs {
		if !pd.IsDir() {
			continue
		}
		pusherID := pd.Name()
		appDirs, err := os.ReadDir(filepath.Join(root, pusherID))
		if err != nil {
			continue
		}
		for _, ad := range appDirs {
			if !ad.IsDir() {
				continue
			}
			appID := ad.Name()
			entries, err := os.ReadDir(filepath.Join(root, pusherID, appID))
			if err != nil {
				continue
			}
			var files []ReceivedFileInfo
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				files = append(files, ReceivedFileInfo{Name: e.Name(), SizeBytes: info.Size(), ModTime: info.ModTime()})
			}
			if len(files) == 0 {
				continue
			}
			sort.Slice(files, func(i, j int) bool { return files[i].ModTime.After(files[j].ModTime) })
			name := pusherNames[pusherID]
			if name == "" {
				name = pusherID + " (revoked)"
			}
			groups = append(groups, ReceivedBackupGroup{PusherID: pusherID, PusherName: name, AppID: appID, Files: files})
		}
	}
	respond(w, 200, groups)
}

// handleReceivedBackupDelete removes received archives at one of two
// granularities, distinguished by path segment count:
//   - /api/remote/received/{pusherID}/{appID}/{filename} — one archive
//     (and its manifest, if any); the counterpart to the automatic
//     pruneReceivedBackups retention pass, for "I want this specific one
//     gone now" rather than waiting on count-based retention.
//   - /api/remote/received/{pusherID}/{appID} — the entire group: every
//     archive a given pusher sent for a given app. Useful for clearing
//     one app's stale history without touching that pusher's other apps
//     (contrast with the pusher-level ?purge=true on DELETE
//     /api/remote/pushers/{id}, which wipes ALL of a pusher's apps at
//     once — this is the finer-grained sibling of that).
func (s *Server) handleReceivedBackupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		errOut(w, 405, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/remote/received/")
	parts := strings.SplitN(rest, "/", 3)

	if len(parts) == 2 {
		pusherID, appID := parts[0], parts[1]
		for _, component := range []string{pusherID, appID} {
			if _, err := sanitizeRemotePathComponent(component); err != nil {
				errOut(w, 400, err.Error())
				return
			}
		}
		dir := s.receivedDir(pusherID, appID)
		if err := os.RemoveAll(dir); err != nil {
			errOut(w, 500, "delete group failed: "+err.Error())
			return
		}
		respond(w, 200, map[string]string{"status": "group deleted"})
		return
	}

	if len(parts) != 3 {
		errOut(w, 400, "expected /api/remote/received/{pusherID}/{appID} or /api/remote/received/{pusherID}/{appID}/{filename}")
		return
	}
	pusherID, appID, name := parts[0], parts[1], parts[2]
	for _, component := range []string{pusherID, appID, name} {
		if _, err := sanitizeRemotePathComponent(component); err != nil {
			errOut(w, 400, err.Error())
			return
		}
	}
	dir := s.receivedDir(pusherID, appID)
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		errOut(w, 404, "file not found")
		return
	}
	if strings.HasSuffix(name, ".tar.gz") {
		_ = os.Remove(filepath.Join(dir, strings.TrimSuffix(name, ".tar.gz")+"_manifest.json"))
	}
	respond(w, 200, map[string]string{"status": "deleted"})
}
