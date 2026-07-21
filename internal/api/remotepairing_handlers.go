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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/config"
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
	respond(w, 200, map[string]any{"path": destPath, "size_bytes": written})
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
		req.Name = req.NodeID
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
	rc.Targets = append(rc.Targets, config.RemoteTarget{
		Name:                      req.Name,
		Kind:                      "prestoback",
		PrestoBackURL:             req.URL,
		PrestoBackPinnedNodeID:    result.PinnedNodeID,
		PrestoBackPinnedPublicKey: result.PinnedPublicKey,
		PrestoBackPushCredential:  result.PushCredential,
	})
	s.cfg.SetRemote(rc)
	respond(w, 200, redactRemoteTarget(rc.Targets[len(rc.Targets)-1]))
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
		out[i] = RemotePusherView{ID: rp.ID, Name: rp.Name, PusherNodeID: rp.PusherNodeID, CreatedAt: rp.CreatedAt, LastUsed: rp.LastUsed}
	}
	respond(w, 200, out)
}

func (s *Server) handleRemotePusherByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/remote/pushers/")
	if id == "" {
		errOut(w, 400, "missing pusher id")
		return
	}
	if r.Method != http.MethodDelete {
		errOut(w, 405, "method not allowed")
		return
	}
	if err := s.cfg.DeleteRemotePusher(id); err != nil {
		errOut(w, 404, err.Error())
		return
	}
	respond(w, 200, map[string]string{"status": "revoked"})
}
