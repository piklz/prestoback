package config

// nodeidentity.go — every PrestoBack instance's permanent cryptographic
// identity, used ONLY for PrestoBack-to-PrestoBack remote pairing
// (remotepairing.go). This is the piece that makes that pairing flow
// actually MITM-resistant, as opposed to a QR code that just moves a
// shared secret around.
//
// Why a QR code alone isn't enough: a QR code has no cryptographic
// properties of its own — it's a convenient way to move a string from one
// screen to a camera, and its only security value comes from being read
// over a channel an attacker can't intercept (a human looking at a
// screen). If pairing just exchanged a shared secret and trusted whatever
// answered on the network from then on, an attacker already positioned on
// the LAN (ARP spoofing, a rogue AP, a compromised device on the same
// network) could silently sit between the two instances forever after —
// the QR would only have protected the first handshake, not the ongoing
// relationship.
//
// The fix, and the one real prior art in this space (Syncthing) already
// uses: give every instance a permanent identity, and make pairing's job
// be "let each side learn and PIN the other's identity" rather than just
// "exchange a token." After that, every future connection re-proves "I'm
// still talking to the same key I paired with" — trust-on-first-use, the
// same model this codebase already trusts for SFTP host keys
// (sftpconn.go's KnownHostsPath), just applied to a second transport.
//
// NodeID is a public fingerprint (SHA-256 of the public key, hex-encoded,
// chunked for human readability) — safe to display, put in a QR code, or
// read aloud; it's the public half of the keypair, not a secret. The
// private key is the one value in this file that must never leave the
// instance it belongs to.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// NodeIdentity is the persistent keypair PrestoBack generates once, on
// first run, and never changes afterward except by explicit user action
// (RegenerateNodeIdentity — which invalidates every existing remote pair,
// same blast radius as RegenerateAPIKey).
type NodeIdentity struct {
	PublicKey  []byte `json:"public_key"`  // ed25519.PublicKey, 32 bytes
	PrivateKey []byte `json:"private_key"` // ed25519.PrivateKey, 64 bytes — see package comment: this one must never leave the instance
}

// GenerateNodeIdentity creates a fresh Ed25519 keypair. Ed25519 (not RSA
// or ECDSA) specifically: fixed small key/signature sizes (32/64 bytes)
// that fit trivially in a QR code and a JSON field, no parameter choices
// to get wrong (unlike RSA key size or ECDSA curve selection), and
// deterministic signing with no per-signature randomness requirement to
// get right (a broken RNG during ECDSA signing can leak the private key
// entirely — a class of bug Ed25519 doesn't have).
func GenerateNodeIdentity() (*NodeIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return &NodeIdentity{PublicKey: pub, PrivateKey: priv}, nil
}

// NodeID returns this identity's public fingerprint: SHA-256 of the
// public key, hex-encoded and chunked into groups of 4 for readability
// (e.g. "a1b2-c3d4-e5f6-..."), the same cosmetic chunking convention
// pairing codes elsewhere in this package could use, applied here for a
// longer value that's read/compared by a human at least once (verifying
// it matches what a QR code encoded) even though it's mostly
// machine-compared thereafter.
func (n *NodeIdentity) NodeID() string {
	sum := sha256.Sum256(n.PublicKey)
	hexStr := hex.EncodeToString(sum[:])
	var chunks []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		chunks = append(chunks, hexStr[i:end])
	}
	return strings.Join(chunks, "-")
}

// Sign signs message with this identity's private key.
func (n *NodeIdentity) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(n.PrivateKey), message)
}

// VerifyNodeSignature reports whether signature is a valid Ed25519
// signature over message from the holder of the private key matching
// publicKey. This is the actual MITM-resistance check: an attacker who
// intercepted network traffic but never saw the real QR code (and
// therefore never learned the genuine NodeID/public key to compare
// against) cannot produce a signature this function accepts, because
// producing one requires the private key, which never crosses the
// network in any pairing flow in this codebase.
func VerifyNodeSignature(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// NodeIDFromPublicKey computes the same fingerprint NodeID() does, for a
// public key received over the wire (e.g. from a claim response) rather
// than this instance's own — so a caller can compare "the NodeID the QR
// code said to expect" against "the NodeID this public key actually
// produces" without needing a full NodeIdentity struct (which would
// require a private key that isn't ours to have).
func NodeIDFromPublicKey(publicKey []byte) string {
	tmp := &NodeIdentity{PublicKey: publicKey}
	return tmp.NodeID()
}

// ── Config accessors ─────────────────────────────────────────────────────

// NodeID returns this instance's own public fingerprint — safe to display
// in the UI, put in a QR code, or log.
func (c *Config) NodeID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.nodeIdentity == nil {
		return ""
	}
	return c.nodeIdentity.NodeID()
}

// NodePublicKey returns this instance's own public key bytes — the part
// that's safe to hand to a peer during pairing (see remotepairing.go).
func (c *Config) NodePublicKey() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.nodeIdentity == nil {
		return nil
	}
	out := make([]byte, len(c.nodeIdentity.PublicKey))
	copy(out, c.nodeIdentity.PublicKey)
	return out
}

// SignAsNode signs message with this instance's own private key — used to
// answer a peer's pairing challenge (see remotepairing.go). The private
// key itself never leaves this function; only the resulting signature
// does.
func (c *Config) SignAsNode(message []byte) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.nodeIdentity == nil {
		return nil
	}
	return c.nodeIdentity.Sign(message)
}

// RegenerateNodeIdentity replaces this instance's identity with a brand
// new one. This invalidates every existing PrestoBack-to-PrestoBack
// pairing that references the old NodeID — same blast radius as
// RegenerateAPIKey invalidating every session — so this should be a
// deliberate, rare, confirmed action, not something triggered casually.
func (c *Config) RegenerateNodeIdentity() (string, error) {
	identity, err := GenerateNodeIdentity()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.nodeIdentity = identity
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		return "", err
	}
	return identity.NodeID(), nil
}
