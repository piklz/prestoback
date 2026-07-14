package config

// apikey.go — the single source of truth for generating, hashing, and
// comparing every API credential PrestoBack issues: the one legacy/master
// key (Config.APIKey / RegenerateAPIKey) and every independently-revocable
// paired key issued via the QR pairing flow (pairing.go).
//
// Before this file existed, key generation was one 4-line helper
// (generateKey) and the actual "is this the right key?" check was done
// ad hoc at each call site — a plain `==` for the master key in
// internal/api/auth.go, a hash-then-`==` for paired keys in pairing.go.
// Centralizing it here means:
//
//   1. Every credential PrestoBack ever issues — now or in the future
//      (a third kind of paired key, a client-app secret, anything else) —
//      gets the same entropy, storage, and comparison guarantees just by
//      calling these functions, instead of a new ad hoc copy of "make
//      random bytes, hex-encode, compare with ==" appearing somewhere else
//      and quietly missing one of the properties below.
//   2. There is exactly one place to audit or change if any of that ever
//      needs to change (e.g. moving to a longer key, a different KDF, a
//      pepper, etc.) — not N call sites that all need to agree.
//
// Guarantees provided here:
//
//   - Generation: crypto/rand, fixed-width (32 bytes / 256 bits), hex
//     encoded. No metadata is encoded into the key material itself, so
//     nothing about one key's shape narrows down anything about another.
//   - Storage: paired keys are stored ONLY as a SHA-256 hash
//     (PairedKey.KeyHash) — the raw value exists in memory just long
//     enough to hand back to the caller once, at creation time, and is
//     never written to disk. The master key is the one exception (it IS
//     stored raw in config.json, by design — see APIKey()'s doc comment —
//     because it doubles as the HMAC secret for signing JWTs, which
//     requires the raw value, not a one-way hash of it).
//   - Comparison: every comparison against secret material goes through
//     SecureEquals, which is both constant-time AND immune to the
//     "different lengths short-circuit faster" leak that a bare
//     subtle.ConstantTimeCompare still has (see its doc comment below).
//
// Callers outside this package (e.g. internal/api/auth.go) must never
// compare a caller-supplied credential against a stored one with `==`.
// Config.ValidateAPIKey and Config.ValidatePairedKey (pairing.go) are the
// only sanctioned entry points for that check.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// apiKeyBytes is the raw entropy behind every key PrestoBack generates —
// 32 bytes (256 bits), hex-encoded to 64 characters. Used for the master
// API key and every paired key. A future credential type should call
// GenerateAPIKey() rather than picking its own size or encoding.
const apiKeyBytes = 32

// GenerateAPIKey returns a new, cryptographically random API key — 64 hex
// characters, 256 bits of entropy. This is the ONLY place in PrestoBack
// that mints raw key material: the master key (RegenerateAPIKey, and
// first-run in Load) and every paired key (pairing.go's ClaimPairing) both
// call this, so any future caller automatically gets the same entropy and
// format guarantees rather than rolling its own.
func GenerateAPIKey() string {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read only fails if the OS CSPRNG itself is unavailable
		// — a broken-enough machine state that no caller could meaningfully
		// recover from. Panic rather than silently handing back low-entropy
		// or all-zero "random" key material, which would be far worse than
		// a crash.
		panic("config: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// HashAPIKey returns the hex-encoded SHA-256 digest of key. This is the
// ONLY form a paired key is ever written to disk in (PairedKey.KeyHash) —
// the raw key is shown to the user exactly once, at creation time, and is
// never persisted anywhere.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// SecureEquals reports whether a and b are equal, in constant time and
// without leaking their relative lengths.
//
// A bare subtle.ConstantTimeCompare([]byte(a), []byte(b)) is NOT safe to
// call directly on two arbitrary-length secrets: ConstantTimeCompare
// returns 0 immediately — before comparing a single byte — whenever
// len(a) != len(b). That means comparing a correct-length candidate
// against the real secret is measurably slower (it runs the full
// byte-by-byte compare) than comparing a wrong-length candidate (which
// exits instantly on the length check), which is in principle a usable
// timing oracle for probing the secret's length.
//
// Hashing both sides first sidesteps this entirely: SHA-256 fixes both
// inputs at exactly 32 bytes regardless of the original length, so
// ConstantTimeCompare's length check never discriminates on real input —
// every call compares the same amount of data in the same way, and the
// actual equality check still runs in constant time either way.
func SecureEquals(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
