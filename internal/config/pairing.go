package config

// pairing.go — QR/device-pairing flow for issuing additional, independently
// revocable API keys, without ever putting the master key (APIKey()) on a
// second device.
//
// Modeled on the "TV code" pairing pattern used by Plex (plex.tv/link) and
// GitHub CLI's device flow, adapted to this app's simpler needs:
//
//  1. An already-authenticated admin (Device A) calls StartPairing, which
//     mints a short-lived, single-use Code.
//  2. Device A shows that code as a QR (encoding a URL built client-side
//     from window.location.origin, so the server never needs to guess its
//     own reachable address) and polls PairingStatus for it.
//  3. A second device (Device B — phone, NAS, whatever) opens that URL,
//     logs in with a real username/password (this is the actual security
//     boundary — the code alone proves nothing), and calls ClaimPairing.
//  4. ClaimPairing generates a brand-new key, stores only its hash, and
//     returns the raw key ONCE to Device B. Device A's next poll sees the
//     pairing as claimed and refreshes its key list.
//
// The pairing code itself is never treated as a secret with the master
// key's blast radius — it only unlocks "attach a new named key to an
// account that's already logged in," identical in spirit to how Plex's
// short link codes work.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	pairingCodeBytes = 5               // 5 bytes -> 10 hex chars: short enough to type, ~1T possibilities
	pairingTTL       = 5 * time.Minute // matches the login-lockout window's order of magnitude elsewhere in this file
	pairingClaimRate = 20              // max claim attempts per code before it's burned early (brute-force guard)
)

type pendingPairing struct {
	Code        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Attempts    int
	Claimed     bool
	ClaimedName string
}

func generatePairingCode() (string, error) {
	b := make([]byte, pairingCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sweepExpiredPairings drops anything past its TTL. Called lazily from
// every pairing entry point rather than a background goroutine — pairing
// sessions are rare and short-lived, so an unbounded-but-tiny map between
// sweeps is a fine tradeoff for not needing another lifecycle to manage.
// Caller must hold c.mu.
func (c *Config) sweepExpiredPairings(now time.Time) {
	for code, p := range c.pending {
		if now.After(p.ExpiresAt) {
			delete(c.pending, code)
		}
	}
}

// StartPairing mints a new short-lived pairing code. Call from an
// admin-only endpoint (Device A, already logged in).
func (c *Config) StartPairing() (code string, expiresAt time.Time, err error) {
	code, err = generatePairingCode()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expiresAt = now.Add(pairingTTL)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepExpiredPairings(now)
	c.pending[code] = &pendingPairing{
		Code:      code,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	return code, expiresAt, nil
}

// PairingStatus reports the current state of a pairing code for Device A's
// poll loop. status is one of "pending", "claimed", "expired", "not_found".
func (c *Config) PairingStatus(code string) (status string, claimedName string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepExpiredPairings(now)

	p, ok := c.pending[code]
	if !ok {
		return "not_found", ""
	}
	if p.Claimed {
		return "claimed", p.ClaimedName
	}
	if now.After(p.ExpiresAt) {
		return "expired", ""
	}
	return "pending", ""
}

// ClaimPairing is called from Device B once it has authenticated on its own
// (the caller — internal/api/server.go's handler — must already be behind
// admin auth). It validates the code, generates a brand-new API key,
// records only its hash, and returns the raw key exactly once.
func (c *Config) ClaimPairing(code, name string) (apiKey string, err error) {
	if name == "" {
		name = "Unnamed device"
	}
	now := time.Now()

	c.mu.Lock()
	c.sweepExpiredPairings(now)
	p, ok := c.pending[code]
	if !ok {
		c.mu.Unlock()
		return "", fmt.Errorf("pairing code not found or already expired")
	}
	if p.Claimed {
		c.mu.Unlock()
		return "", fmt.Errorf("pairing code has already been used")
	}
	p.Attempts++
	if p.Attempts > pairingClaimRate {
		delete(c.pending, code) // burn it — treat as abuse, not a retryable error
		c.mu.Unlock()
		return "", fmt.Errorf("too many attempts for this code — generate a new one")
	}

	newKey := GenerateAPIKey()
	id := generatePairedKeyID()
	c.pairedKeys[id] = PairedKey{
		ID:        id,
		Name:      name,
		KeyHash:   HashAPIKey(newKey),
		CreatedAt: now,
	}
	p.Claimed = true
	p.ClaimedName = name
	c.mu.Unlock()

	if err := c.Save(); err != nil {
		return "", fmt.Errorf("saved key generation failed: %w", err)
	}
	return newKey, nil
}

func generatePairedKeyID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "pk_" + hex.EncodeToString(b)
}

// ValidatePairedKey checks key against every stored paired key by hash.
// Linear scan is fine here — this app expects a handful of paired keys at
// most, not hundreds. Uses SecureEquals (apikey.go) rather than `==`, same
// as ValidateAPIKey — a paired key grants the same admin-equivalent access
// as the master key (see internal/api/auth.go's authJWT), so it gets the
// same comparison guarantees, not a weaker one just because it's the
// "secondary" credential.
func (c *Config) ValidatePairedKey(key string) (PairedKey, bool) {
	if key == "" {
		return PairedKey{}, false
	}
	h := HashAPIKey(key)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, pk := range c.pairedKeys {
		if SecureEquals(pk.KeyHash, h) {
			return pk, true
		}
	}
	return PairedKey{}, false
}

// TouchPairedKey updates LastUsed in memory only — deliberately not forcing
// a disk write on every authenticated request (that would mean a config.json
// write per API call from every integration, which is needless wear and
// contention for a value that's only ever informational). It'll be picked
// up and persisted the next time Save() runs for any other reason; on
// restart before that, LastUsed just reverts to its last-saved value —
// same acceptable-staleness tradeoff already used for revokedTokens/
// loginAttempts elsewhere in this package.
func (c *Config) TouchPairedKey(id string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if pk, ok := c.pairedKeys[id]; ok {
		pk.LastUsed = &now
		c.pairedKeys[id] = pk
	}
}

// ListPairedKeys returns every paired key, sorted newest-first. Includes
// KeyHash — see PairedKey's doc comment: it's the HTTP handler's job to
// strip that before this ever reaches the browser.
func (c *Config) ListPairedKeys() []PairedKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]PairedKey, 0, len(c.pairedKeys))
	for _, pk := range c.pairedKeys {
		out = append(out, pk)
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

// DeletePairedKey revokes a paired key immediately — the very next request
// using it fails auth. No session/token invalidation needed since paired
// keys aren't JWTs; there's nothing else to revoke.
func (c *Config) DeletePairedKey(id string) error {
	c.mu.Lock()
	if _, ok := c.pairedKeys[id]; !ok {
		c.mu.Unlock()
		return fmt.Errorf("paired key '%s' not found", id)
	}
	delete(c.pairedKeys, id)
	c.mu.Unlock()
	return c.Save()
}
