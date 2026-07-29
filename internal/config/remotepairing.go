package config

// remotepairing.go — the actual PrestoBack-to-PrestoBack pairing protocol,
// built on nodeidentity.go's Ed25519 identities. Read that file's package
// comment first for why this exists at all (a QR code alone doesn't
// provide MITM resistance; a pinned identity does).
//
// Roles, to keep the rest of this file's naming straight:
//   - Receiver (R): the instance that will RECEIVE pushed backups (e.g. a
//     NAS). Generates the pairing QR — same "the target shows the code"
//     direction as this codebase's existing device-pairing flow
//     (pairing.go), just for a second instance instead of a second browser.
//   - Pusher (P): the instance that will PUSH backups to R (e.g. the Pi
//     running the main stack). Scans/enters R's QR.
//
// Protocol (one round trip):
//
//  1. R mints a one-time pairing secret (StartRemotePairing) and displays
//     it, alongside its own NodeID, as a QR. This is the out-of-band
//     channel this whole scheme's security rests on — see
//     nodeidentity.go's package comment.
//  2. P's backend (not the browser — this is server-to-server, the same
//     "the backend dials out" pattern remote.go already uses for
//     SFTP/S3 targets) sends R the secret, P's own NodeID/public key, and
//     a fresh random challenge nonce.
//  3. R validates the secret (single-use, rate-limited, same guards
//     ClaimPairing already applies to device pairing), mints a scoped
//     push-only credential, and signs a response binding R's NodeID +
//     P's NodeID + the nonce + the secret together — RespondToRemotePairing.
//  4. P verifies TWO things before trusting anything in that response:
//     the public key it got back actually produces the NodeID from the
//     QR (not just whatever the network handed back), AND the signature
//     over that binding message actually verifies against that public
//     key. Only if BOTH hold does P consider R's identity proven — see
//     VerifyRemotePairingResponse. An attacker who intercepts/redirects
//     the network connection (DNS spoofing, ARP spoofing, a rogue
//     "server" answering in R's place) cannot pass this check without
//     R's actual private key, which never crosses the network in this
//     protocol at all.
//
// After pairing, P has R's NodeID and public key pinned locally (stored
// on the RemoteTarget — see remote.go). Every future push re-runs the
// same challenge-response (RespondToRemoteChallenge / VerifyRemoteChallengeResponse)
// against that PINNED key, not a QR-sourced one — so a MITM that shows up
// only after pairing was done safely is caught too, not just one during
// the initial handshake. If the far end's key ever doesn't match the pin,
// the push must be refused loudly, the same "host key changed" posture
// sftpconn.go's KnownHostsPath already uses.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	remotePairingSecretBytes  = 32              // 256 bits — brute-forcing this over the network is infeasible, same size as GenerateAPIKey
	remotePairingTTL          = 5 * time.Minute // matches pairing.go's device-pairing TTL
	remotePairingClaimRate    = 20              // same brute-force guard pairing.go's pairingClaimRate applies
	remoteChallengeNonceBytes = 32
)

type pendingRemotePairing struct {
	SecretHash string // HashAPIKey(secret) — never store the raw secret at rest, same posture as every other credential in this package
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Attempts   int
	Claimed    bool
}

// RemotePairingSession is what StartRemotePairing returns for display —
// everything needed to build the QR and the human-readable fallback.
type RemotePairingSession struct {
	Secret    string    `json:"secret"`
	NodeID    string    `json:"node_id"`
	PublicKey string    `json:"public_key"` // base64, so a peer can reconstruct raw bytes without a second lookup
	ExpiresAt time.Time `json:"expires_at"`
}

// StartRemotePairing mints a new one-time pairing session on the RECEIVER
// side. Called from an admin-only endpoint.
func (c *Config) StartRemotePairing() (RemotePairingSession, error) {
	secretBytes := make([]byte, remotePairingSecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return RemotePairingSession{}, fmt.Errorf("config: crypto/rand unavailable: %w", err)
	}
	secret := hex.EncodeToString(secretBytes)
	now := time.Now()
	expiresAt := now.Add(remotePairingTTL)

	c.mu.Lock()
	c.sweepExpiredRemotePairings(now)
	c.remotePending[secret] = &pendingRemotePairing{
		SecretHash: HashAPIKey(secret),
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}
	nodeID := ""
	var pubKey []byte
	if c.nodeIdentity != nil {
		nodeID = c.nodeIdentity.NodeID()
		pubKey = c.nodeIdentity.PublicKey
	}
	c.mu.Unlock()

	if nodeID == "" {
		return RemotePairingSession{}, fmt.Errorf("this instance has no node identity yet — restart PrestoBack and try again")
	}
	return RemotePairingSession{
		Secret:    secret,
		NodeID:    nodeID,
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
		ExpiresAt: expiresAt,
	}, nil
}

// sweepExpiredRemotePairings mirrors sweepExpiredPairings/sweepExpiredMFALogins
// — same lazy, entry-point-triggered cleanup. Caller must hold c.mu.
func (c *Config) sweepExpiredRemotePairings(now time.Time) {
	for secret, p := range c.remotePending {
		if now.After(p.ExpiresAt) {
			delete(c.remotePending, secret)
		}
	}
}

// RemotePairingClaimRequest is what the pusher instance sends to the
// receiver's /api/remote-pairing/claim endpoint.
type RemotePairingClaimRequest struct {
	Secret          string `json:"secret"`
	PusherNodeID    string `json:"pusher_node_id"`
	PusherPublicKey string `json:"pusher_public_key"` // base64
	ChallengeNonce  string `json:"challenge_nonce"`   // base64, pusher-generated
}

// RemotePairingClaimResponse is the receiver's answer — everything the
// pusher needs to verify the receiver's identity (see
// VerifyRemotePairingResponse) plus the scoped push credential.
type RemotePairingClaimResponse struct {
	ReceiverNodeID    string `json:"receiver_node_id"`
	ReceiverPublicKey string `json:"receiver_public_key"` // base64
	Signature         string `json:"signature"`           // base64, sign(bindingMessage)
	PushCredential    string `json:"push_credential"`     // shown to the pusher exactly once, like every other issued credential in this package
}

// remotePairingBindingMessage builds the exact byte sequence that gets
// signed and verified — binding the receiver's own NodeID, the pusher's
// claimed NodeID, the pusher's nonce, and the secret together into one
// message. Binding all four (not just signing the nonce alone) matters:
// without it, a signature captured from one pairing exchange could
// potentially be replayed into an unrelated one that happens to reuse the
// same nonce space, or get attributed to the wrong pusher.
func remotePairingBindingMessage(receiverNodeID, pusherNodeID, challengeNonce, secret string) []byte {
	return []byte(receiverNodeID + "|" + pusherNodeID + "|" + challengeNonce + "|" + secret)
}

// RespondToRemotePairing is the RECEIVER's handler logic for a claim
// request: validates the secret (single-use, rate-limited, TTL-bound —
// same guard pattern as pairing.go's ClaimPairing), mints a scoped push
// credential, and signs the binding message so the pusher can verify this
// response really came from the holder of THIS instance's private key.
func (c *Config) RespondToRemotePairing(req RemotePairingClaimRequest) (RemotePairingClaimResponse, error) {
	now := time.Now()
	c.mu.Lock()
	c.sweepExpiredRemotePairings(now)
	p, ok := c.remotePending[req.Secret]
	if !ok {
		c.mu.Unlock()
		return RemotePairingClaimResponse{}, fmt.Errorf("pairing code not found or already expired")
	}
	if p.Claimed {
		c.mu.Unlock()
		return RemotePairingClaimResponse{}, fmt.Errorf("pairing code has already been used")
	}
	p.Attempts++
	if p.Attempts > remotePairingClaimRate {
		delete(c.remotePending, req.Secret)
		c.mu.Unlock()
		return RemotePairingClaimResponse{}, fmt.Errorf("too many attempts for this code — generate a new one")
	}
	if !SecureEquals(HashAPIKey(req.Secret), p.SecretHash) {
		c.mu.Unlock()
		return RemotePairingClaimResponse{}, fmt.Errorf("invalid pairing code")
	}
	if c.nodeIdentity == nil {
		c.mu.Unlock()
		return RemotePairingClaimResponse{}, fmt.Errorf("this instance has no node identity yet")
	}
	p.Claimed = true
	receiverNodeID := c.nodeIdentity.NodeID()
	receiverPubKey := c.nodeIdentity.PublicKey
	identity := c.nodeIdentity
	c.mu.Unlock()

	message := remotePairingBindingMessage(receiverNodeID, req.PusherNodeID, req.ChallengeNonce, req.Secret)
	signature := identity.Sign(message)
	pushCredential := GenerateAPIKey()

	// Persisting the new RemotePusher record (pusher NodeID/public key +
	// hash of pushCredential) is the caller's job (the HTTP handler),
	// same division of responsibility as ClaimPairing leaving config.Save
	// to its own caller — this function's job is the cryptographic
	// exchange, not the storage schema for accepted pushers, which
	// belongs in remote.go alongside RemoteTarget.
	return RemotePairingClaimResponse{
		ReceiverNodeID:    receiverNodeID,
		ReceiverPublicKey: base64.StdEncoding.EncodeToString(receiverPubKey),
		Signature:         base64.StdEncoding.EncodeToString(signature),
		PushCredential:    pushCredential,
	}, nil
}

// VerifyRemotePairingResponse is the PUSHER's half — the actual
// MITM-resistance check. expectedNodeID comes from the QR (the
// out-of-band, human-verified channel); everything else in resp came
// over the network and is NOT trusted until these checks both pass.
func VerifyRemotePairingResponse(resp RemotePairingClaimResponse, expectedNodeID string, pusherNodeID, challengeNonce, secret string) error {
	pubKey, err := base64.StdEncoding.DecodeString(resp.ReceiverPublicKey)
	if err != nil {
		return fmt.Errorf("malformed public key in response: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("malformed signature in response: %w", err)
	}

	// Check 1: does the public key we got back actually produce the NodeID
	// the QR told us to expect? This is the check that catches an
	// attacker substituting their OWN key/identity in the response — they
	// can sign with THEIR key just fine, but they can't make their key
	// hash to the NodeID the real receiver's QR advertised.
	actualNodeID := NodeIDFromPublicKey(pubKey)
	if actualNodeID != expectedNodeID {
		return fmt.Errorf("identity mismatch: response claims NodeID %s, but the paired code was for %s — this could mean the connection was intercepted; do not proceed", actualNodeID, expectedNodeID)
	}
	if resp.ReceiverNodeID != expectedNodeID {
		return fmt.Errorf("identity mismatch: response's stated NodeID doesn't match the paired code")
	}

	// Check 2: does the signature actually verify against that key? This
	// is what an attacker cannot forge without the real receiver's private
	// key, regardless of network position.
	message := remotePairingBindingMessage(expectedNodeID, pusherNodeID, challengeNonce, secret)
	if !VerifyNodeSignature(pubKey, message, signature) {
		return fmt.Errorf("signature verification failed — the response could not be authenticated; do not proceed")
	}
	return nil
}

// ── Post-pairing re-verification (every subsequent push) ───────────────────

// RemoteChallengeRequest/Response are the generic "prove you're still the
// identity I pinned" exchange, reused before every push — not just at
// pairing time. Without this, pairing would only protect the ONE-TIME
// handshake; a network attacker who shows up later (compromising the
// route between pusher and receiver after the fact) would otherwise be
// silently trusted, defeating the whole point of pinning an identity.
type RemoteChallengeRequest struct {
	Nonce string `json:"nonce"` // base64, pusher-generated, fresh every time
}

type RemoteChallengeResponse struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"` // base64
	Signature string `json:"signature"`  // base64, sign(nonce)
}

// RespondToRemoteChallenge is the receiver's handler for a pre-push
// identity check — just signs the nonce. No secret/credential validation
// here (that's the separate push-credential auth on the actual backup
// upload endpoint); this exists purely to let the pusher re-confirm the
// receiver's identity before sending anything.
func (c *Config) RespondToRemoteChallenge(nonce string) (RemoteChallengeResponse, error) {
	c.mu.RLock()
	identity := c.nodeIdentity
	c.mu.RUnlock()
	if identity == nil {
		return RemoteChallengeResponse{}, fmt.Errorf("this instance has no node identity yet")
	}
	sig := identity.Sign([]byte(nonce))
	return RemoteChallengeResponse{
		NodeID:    identity.NodeID(),
		PublicKey: base64.StdEncoding.EncodeToString(identity.PublicKey),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyRemoteChallengeResponse checks a challenge response against a
// PINNED NodeID (from a completed pairing, stored on the RemoteTarget —
// not from a QR this time, since there's no QR involved in an ongoing
// push; the pin itself is now the trust anchor). Returns an error whose
// message is safe to surface directly to the user as a "this remote's
// identity changed" warning — the same posture sftpconn.go's
// KnownHostsPath verifier already takes for a changed SSH host key.
func VerifyRemoteChallengeResponse(resp RemoteChallengeResponse, nonce string, pinnedNodeID string) error {
	pubKey, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return fmt.Errorf("malformed public key in challenge response: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("malformed signature in challenge response: %w", err)
	}
	actualNodeID := NodeIDFromPublicKey(pubKey)
	if actualNodeID != pinnedNodeID || resp.NodeID != pinnedNodeID {
		return fmt.Errorf("remote identity does not match what was pinned at pairing time (expected %s, got %s) — refusing to push; this could mean the remote was reset or the connection is being intercepted. Re-pair only if you're certain this change is expected", pinnedNodeID, actualNodeID)
	}
	if !VerifyNodeSignature(pubKey, []byte(nonce), signature) {
		return fmt.Errorf("signature verification failed on remote challenge — refusing to push")
	}
	return nil
}

// GenerateChallengeNonce is a small helper so callers (the HTTP client
// side of a push) don't each roll their own nonce generation.
func GenerateChallengeNonce() (string, error) {
	b := make([]byte, remoteChallengeNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("config: crypto/rand unavailable: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ── Accepted pusher registry (receiver side) ────────────────────────────────
//
// RemotePusher is the receiver's durable record of one instance that
// successfully completed pairing — the thing an incoming push's
// credential is actually checked against. Distinct from PairedKey
// (pairing.go): a PairedKey grants the SAME admin-equivalent access as
// the master key to a second BROWSER/script on this same account;
// a RemotePusher grants only "may push backups here," to a different
// PrestoBack INSTANCE entirely, and carries that instance's identity
// (NodeID/public key) so a future push can be challenge-verified against
// it, not just bearer-token-authenticated.
type RemotePusher struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"` // user-supplied label, e.g. "Living room Pi" — defaults to the NodeID if blank
	PusherNodeID    string     `json:"pusher_node_id"`
	PusherPublicKey string     `json:"pusher_public_key"` // base64
	CredentialHash  string     `json:"credential_hash"`   // HashAPIKey(credential) — the raw credential is shown to the pusher exactly once, at pairing time, same as every other issued credential in this package
	CreatedAt       time.Time  `json:"created_at"`
	LastUsed        *time.Time `json:"last_used,omitempty"`
}

// shortNodeIDFragment returns just the first 4-hex-char chunk of a chunked
// NodeID (e.g. "8402" from "8402-2338-6865-..."). Used only for a short,
// non-identifying display suffix when a pusher connects without a name —
// the full ID remains available (PusherNodeID) for actual verification.
func shortNodeIDFragment(nodeID string) string {
	if i := strings.IndexByte(nodeID, '-'); i > 0 {
		return nodeID[:i]
	}
	if len(nodeID) > 4 {
		return nodeID[:4]
	}
	return nodeID
}

func generateRemotePusherID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "rp_" + hex.EncodeToString(b)
}

// AddRemotePusher registers a newly-paired pusher instance and persists
// it immediately — called by the /api/remote-pairing/claim handler right
// after RespondToRemotePairing succeeds. Storing only the credential's
// hash (never the raw value) matches every other credential in this
// package; the raw pushCredential returned by RespondToRemotePairing was
// already handed to the pusher in that same response and is never seen
// here again.
func (c *Config) AddRemotePusher(name, pusherNodeID, pusherPublicKeyB64, pushCredential string) (RemotePusher, error) {
	if name == "" {
		// Matches pairing.go's ClaimPairing, which already solved this
		// exact problem for the browser-pairing flow ("Unnamed device")
		// rather than defaulting to a raw credential/ID. Previously this
		// fell back to pusherNodeID itself — a 40+ char hash — which then
		// became the permanent Name shown in the paired-pushers list and
		// anywhere else that prints it. shortNodeIDFragment keeps two
		// unnamed pushers distinguishable without repeating the full
		// verification hash as the primary label.
		name = "Unnamed instance (" + shortNodeIDFragment(pusherNodeID) + ")"
	}
	rp := RemotePusher{
		ID:              generateRemotePusherID(),
		Name:            name,
		PusherNodeID:    pusherNodeID,
		PusherPublicKey: pusherPublicKeyB64,
		CredentialHash:  HashAPIKey(pushCredential),
		CreatedAt:       time.Now(),
	}
	c.mu.Lock()
	c.remotePushers[rp.ID] = rp
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		return RemotePusher{}, fmt.Errorf("save paired pusher: %w", err)
	}
	return rp, nil
}

// ValidateRemotePushCredential checks an incoming push request's
// credential against every registered pusher — linear scan, same
// "a handful at most, not hundreds" reasoning ValidatePairedKey already
// applies — and returns the matching RemotePusher record if found. Uses
// SecureEquals (apikey.go), same constant-time posture as every other
// credential check in this package; a push credential grants real
// capability (writing backup archives to this instance's disk) and gets
// no weaker a guarantee than the master key or a paired key do.
func (c *Config) ValidateRemotePushCredential(credential string) (RemotePusher, bool) {
	if credential == "" {
		return RemotePusher{}, false
	}
	h := HashAPIKey(credential)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, rp := range c.remotePushers {
		if SecureEquals(rp.CredentialHash, h) {
			return rp, true
		}
	}
	return RemotePusher{}, false
}

// TouchRemotePusher updates LastUsed in memory only — same deliberately
// lazy, not-forced-to-disk-every-time posture as TouchPairedKey
// (pairing.go), for the identical reason: a config.json write on every
// single push would be needless wear for a value that's purely
// informational.
func (c *Config) TouchRemotePusher(id string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if rp, ok := c.remotePushers[id]; ok {
		rp.LastUsed = &now
		c.remotePushers[id] = rp
	}
}

// ListRemotePushers returns every accepted pusher, newest first. Includes
// CredentialHash — same contract as ListPairedKeys: it's the HTTP
// handler's job to strip that before it reaches the browser.
func (c *Config) ListRemotePushers() []RemotePusher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]RemotePusher, 0, len(c.remotePushers))
	for _, rp := range c.remotePushers {
		out = append(out, rp)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// DeleteRemotePusher revokes a pusher's access immediately — the very
// next push attempt using its credential fails. Same "nothing else to
// revoke" reasoning DeletePairedKey documents: push credentials aren't
// JWTs, there's no session to separately invalidate.
func (c *Config) DeleteRemotePusher(id string) error {
	c.mu.Lock()
	if _, ok := c.remotePushers[id]; !ok {
		c.mu.Unlock()
		return fmt.Errorf("remote pusher '%s' not found", id)
	}
	delete(c.remotePushers, id)
	c.mu.Unlock()
	return c.Save()
}
