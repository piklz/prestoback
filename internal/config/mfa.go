package config

// mfa.go — optional TOTP-based second factor, with one-time backup codes
// for account recovery if the authenticator app/device is lost. Modeled on
// what every mainstream authenticator app (Google Authenticator, Authy,
// 1Password, Bitwarden) and most serious self-hosted admin tools already
// do — RFC 6238 TOTP plus a set of single-use recovery codes shown once at
// enrollment.
//
// This is deliberately NOT email-based recovery. PrestoBack has no SMTP
// dependency anywhere else in the codebase, and adding one just for
// password/MFA recovery would mean a new external dependency, a new
// verified-address flow, and a new credential (the email account itself)
// with its own blast radius — disproportionate for what is fundamentally a
// single-operator homelab tool. Backup codes give the same "I lost my
// phone" recovery property without any of that: they're generated and
// shown exactly once, at enrollment, and the user is responsible for
// storing them (a password manager, printed, wherever) — the same trust
// model every other MFA-capable service uses backup codes for.
//
// Every credential-shaped value here reuses apikey.go's primitives
// (HashAPIKey, SecureEquals) rather than inventing new hashing/comparison
// logic — same reasoning as pairing.go: a second factor is exactly the
// kind of thing that must not quietly get a weaker guarantee than the
// master key just because it's "only" a backup code.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpSecretBytes = 20 // 160 bits — the de facto standard TOTP secret size (RFC 4226 recommends >=128 bits; this matches what Google Authenticator/Authy generate)
	totpDigits      = 6
	totpStep        = 30 * time.Second
	// totpWindow allows the code from one step before/after the current one
	// to also validate — tolerates ordinary clock drift between the
	// server and the phone generating codes, without materially widening
	// the brute-force window (each step is still a fresh 6-digit space).
	totpWindow = 1

	backupCodeCount = 10 // shown once at enrollment; each is single-use
)

// GenerateTOTPSecret returns a new random TOTP secret, base32-encoded
// (RFC 4648, no padding) — the standard encoding every authenticator app
// expects when scanning an otpauth:// QR code or accepting manual entry.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("config: crypto/rand unavailable: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPProvisioningURI builds the otpauth://totp/... URI that a QR code
// encodes for the authenticator app to scan — same "generate a value,
// render it as a QR client-side" pattern pairing.go already uses for
// device pairing (see index.html's existing qrcode.min.js usage), just a
// different URI scheme. accountName is typically "username@prestoback" so
// multiple PrestoBack instances/accounts are distinguishable in the app's
// list; issuer identifies the app as "PrestoBack".
func TOTPProvisioningURI(secret, accountName, issuer string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(int(totpStep.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// GenerateTOTPCode returns the current TOTP code for secret. Exported as a
// small, legitimate convenience — anyone holding the secret can already
// compute this themselves (TOTP has no asymmetric trick that makes this
// exposure meaningful), so this doesn't weaken anything; it's here so
// tests and any future "show me the current code" tooling don't need to
// reach into totpAt directly.
func GenerateTOTPCode(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// totpAt computes the RFC 6238 TOTP code for secret at time t. Uses
// HMAC-SHA1 as the PRF — this is SHA1 used as a keyed MAC, not for
// collision resistance, which is the property that actually matters for
// hashing; RFC 6238 specifies SHA1 as the default/most broadly compatible
// option and every mainstream authenticator app assumes it unless told
// otherwise. This is the same "SHA1 is fine as a MAC, not as a hash" split
// that HMAC-SHA1 relies on elsewhere in real-world TLS/SSH ciphersuites.
func totpAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret encoding: %w", err)
	}
	counter := uint64(t.Unix()) / uint64(totpStep.Seconds())
	return hotp(key, counter), nil
}

// hotp implements RFC 4226's HOTP algorithm (the counter-based core TOTP
// is built on) — HMAC-SHA1 over the big-endian counter, then the
// "dynamic truncation" step the RFC specifies to fold the 20-byte HMAC
// down into a 6-digit code.
func hotp(key []byte, counter uint64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3): the low 4 bits of the last byte
	// select a 4-byte window to read as a big-endian uint31 (top bit
	// masked off), then reduce mod 10^digits.
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

// VerifyTOTP reports whether code is valid for secret at the current time,
// tolerating +/-totpWindow steps of clock drift. Comparison is via
// SecureEquals (apikey.go) — a 6-digit code is low-entropy enough that
// constant-time comparison alone doesn't make brute-forcing impractical
// (that's what rate-limiting the verify endpoint is for, same as password
// login's existing checkLoginLockout), but there's no reason to accept a
// timing side-channel here just because the code is short-lived.
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	now := time.Now()
	for offset := -totpWindow; offset <= totpWindow; offset++ {
		want, err := totpAt(secret, now.Add(time.Duration(offset)*totpStep))
		if err != nil {
			return false
		}
		if SecureEquals(code, want) {
			return true
		}
	}
	return false
}

// GenerateBackupCodes returns backupCodeCount fresh, human-typeable
// recovery codes (format XXXX-XXXX, Crockford-ish base32 alphabet without
// easily-confused characters like 0/O and 1/I/L, since these are meant to
// be read off a screen and typed back in, possibly from a printed copy).
// Callers must hash each one with HashAPIKey before persisting — these
// raw values are returned to be shown to the user exactly once and must
// never be stored as-is.
func GenerateBackupCodes() ([]string, error) {
	const alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ" // no 0/O/1/I/L
	codes := make([]string, backupCodeCount)
	for i := range codes {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("config: crypto/rand unavailable: %w", err)
		}
		var sb strings.Builder
		for j, by := range b {
			if j == 4 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(by)%len(alphabet)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

// normalizeBackupCode uppercases and strips whitespace so a code typed
// with inconsistent case or an extra space still matches — the hash was
// computed over this normalized form at enrollment time (see
// Config.EnableMFA), so lookups must normalize identically.
func normalizeBackupCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// ── MFA enrollment ──────────────────────────────────────────────────────────
//
// Enrollment is two steps, not one, deliberately: BeginMFAEnrollment
// generates a secret and backup codes and returns them for display (QR +
// codes), but does NOT flip MFAEnabled on yet. ConfirmMFAEnrollment
// requires the user to submit one valid code generated from what they just
// scanned before MFA actually activates. Skipping straight to "enabled"
// on generation alone risks locking someone out immediately if their
// authenticator app never actually synced the secret correctly (wrong QR
// render, typo in manual entry, clock badly off) — confirming first means
// the first successful code IS the proof it's going to keep working.

const mfaPendingLoginTTL = 5 * time.Minute

type pendingMFALogin struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

// BeginMFAEnrollment generates a fresh TOTP secret and backup codes for
// username, WITHOUT enabling MFA yet (see package comment above). Returns
// the secret (for the QR provisioning URI, built by the caller via
// TOTPProvisioningURI) and the raw backup codes — both shown to the user
// exactly once; only their hashes get persisted, and only once
// ConfirmMFAEnrollment succeeds.
func (c *Config) BeginMFAEnrollment(username string) (secret string, backupCodes []string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", nil, err
	}
	backupCodes, err = GenerateBackupCodes()
	if err != nil {
		return "", nil, err
	}

	hashes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hashes[i] = HashAPIKey(normalizeBackupCode(code))
	}

	c.mu.Lock()
	u, ok := c.users[username]
	if !ok {
		c.mu.Unlock()
		return "", nil, fmt.Errorf("user '%s' not found", username)
	}
	u.MFASecret = secret
	u.MFAEnabled = false // not active until ConfirmMFAEnrollment
	u.MFABackupCodeHashes = hashes
	c.users[username] = u
	c.mu.Unlock()

	if err := c.Save(); err != nil {
		return "", nil, fmt.Errorf("save MFA enrollment: %w", err)
	}
	return secret, backupCodes, nil
}

// ConfirmMFAEnrollment validates one code against the secret staged by
// BeginMFAEnrollment and, only if it checks out, flips MFAEnabled on.
func (c *Config) ConfirmMFAEnrollment(username, code string) error {
	c.mu.Lock()
	u, ok := c.users[username]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("user '%s' not found", username)
	}
	if u.MFASecret == "" {
		c.mu.Unlock()
		return fmt.Errorf("no MFA enrollment in progress for this account — call setup first")
	}
	secret := u.MFASecret
	c.mu.Unlock()

	if !VerifyTOTP(secret, code) {
		return fmt.Errorf("invalid code — check your authenticator app and try again")
	}

	c.mu.Lock()
	u = c.users[username]
	u.MFAEnabled = true
	c.users[username] = u
	c.mu.Unlock()
	return c.Save()
}

// DisableMFA turns MFA off and clears the secret and any remaining backup
// codes. Callers (the HTTP handler) are responsible for re-verifying the
// account's password before calling this — MFA is exactly the kind of
// setting where "I'm already logged in" shouldn't be sufficient on its own
// to remove a security control, the same reasoning most services apply to
// disabling 2FA.
func (c *Config) DisableMFA(username string) error {
	c.mu.Lock()
	u, ok := c.users[username]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("user '%s' not found", username)
	}
	u.MFASecret = ""
	u.MFAEnabled = false
	u.MFABackupCodeHashes = nil
	c.users[username] = u
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		return err
	}
	// Trusted-device records only mean anything relative to an MFA
	// requirement that no longer exists — clean them up rather than
	// leaving stale entries a re-enabled MFA setup would otherwise
	// silently start honoring again.
	return c.RevokeAllTrustedDevices(username)
}

// VerifyAndConsumeBackupCode checks code against username's remaining
// backup codes and, if it matches, removes it — single-use, enforced
// atomically under c.mu so two concurrent requests racing to redeem the
// same code cannot both succeed (the second one finds it already gone).
// This whole check-then-remove sequence holds the write lock for its
// entire duration specifically to close that race, rather than checking
// under a read lock and removing separately.
func (c *Config) VerifyAndConsumeBackupCode(username, code string) bool {
	normalized := normalizeBackupCode(code)
	if normalized == "" {
		return false
	}
	target := HashAPIKey(normalized)

	c.mu.Lock()
	u, ok := c.users[username]
	if !ok {
		c.mu.Unlock()
		return false
	}
	consumed := false
	for i, h := range u.MFABackupCodeHashes {
		if SecureEquals(h, target) {
			u.MFABackupCodeHashes = append(u.MFABackupCodeHashes[:i:i], u.MFABackupCodeHashes[i+1:]...)
			c.users[username] = u
			consumed = true
			break
		}
	}
	c.mu.Unlock()

	if !consumed {
		return false
	}
	// Synchronous, not fire-and-forget: a used code must never be able to
	// come back after a crash/restart before this write lands, and two
	// concurrent redemptions both queuing their own async Save() could
	// race each other writing the same file. The Lock/Unlock above already
	// guarantees only one caller ever gets consumed=true for the same
	// code, so this call itself doesn't need to be inside that critical
	// section — Save() takes its own RLock, which would self-deadlock if
	// called while still holding the Lock above (same reasoning AddUser/
	// DeleteUser/ClaimPairing already follow elsewhere in this file).
	if err := c.Save(); err != nil {
		log.Printf("[mfa] warning: backup code consumed but failed to persist: %v", err)
	}
	return true
}

// ── Two-step login (password, then second factor) ──────────────────────────

// sweepExpiredMFALogins mirrors sweepExpiredPairings — same lazy,
// entry-point-triggered cleanup, same reasoning (short-lived by design,
// an unbounded-but-tiny map between sweeps is an acceptable tradeoff).
// Caller must hold c.mu.
func (c *Config) sweepExpiredMFALogins(now time.Time) {
	for token, p := range c.mfaPending {
		if now.After(p.ExpiresAt) {
			delete(c.mfaPending, token)
		}
	}
}

// BeginMFALogin is called once a username+password has already checked
// out (handleAuthLogin) for an account with MFAEnabled — instead of
// issuing the real JWT immediately, it mints a short-lived, single-use
// pending-login token that only CompleteMFALogin can redeem, and only
// after a valid TOTP or backup code is presented. This is what stands
// between "knows the password" and "actually gets a session" for an
// MFA-protected account.
func (c *Config) BeginMFALogin(username, role string) (token string, expiresAt time.Time, err error) {
	token = GenerateAPIKey() // reuse the same 256-bit generator — this token is exactly as sensitive as a short-lived credential
	now := time.Now()
	expiresAt = now.Add(mfaPendingLoginTTL)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepExpiredMFALogins(now)
	c.mfaPending[token] = &pendingMFALogin{Username: username, Role: role, ExpiresAt: expiresAt}
	return token, expiresAt, nil
}

// CompleteMFALogin validates a pending-login token and a second-factor
// code (TOTP first, then falling back to a backup code — same order a
// user would naturally try them in), consuming the pending-login token
// either way so it can't be replayed regardless of outcome. Returns the
// username/role to issue a real JWT for on success.
func (c *Config) CompleteMFALogin(token, code string) (username, role string, err error) {
	now := time.Now()
	c.mu.Lock()
	c.sweepExpiredMFALogins(now)
	p, ok := c.mfaPending[token]
	if ok {
		delete(c.mfaPending, token) // single-use regardless of outcome below
	}
	c.mu.Unlock()

	if !ok {
		return "", "", fmt.Errorf("MFA login session not found or expired — please log in again")
	}

	u, exists := c.GetUser(p.Username)
	if !exists || !u.MFAEnabled {
		return "", "", fmt.Errorf("MFA is no longer enabled for this account — please log in again")
	}

	if VerifyTOTP(u.MFASecret, code) {
		return p.Username, p.Role, nil
	}
	if c.VerifyAndConsumeBackupCode(p.Username, code) {
		return p.Username, p.Role, nil
	}
	return "", "", fmt.Errorf("invalid code")
}

// ── Trusted devices ("remember this device for 30 days") ───────────────────
//
// Without this, an MFA-enabled account gets prompted for a code on EVERY
// login — every JWT expiry (12h, see auth.go's jwtTTL), forever. That's
// meaningfully more friction than mainstream MFA implementations (Google,
// Bitwarden, and most other serious services) actually impose: they
// prompt for the second factor once per device/browser, then trust that
// device for a window (commonly ~30 days), re-prompting only on a new
// device, a cleared cookie, or after the window lapses. This section adds
// the same shape here — NOT "skip login entirely" (a password is always
// still required; see handleAuthLogin), just "skip re-proving the second
// factor on a browser that already proved it recently."
//
// Security posture: a trusted-device token is a real bearer credential —
// anyone holding it can complete a login as this user without a second
// factor for the rest of its 30-day life. So it gets the same treatment
// as every other credential in this package: 256 bits of entropy
// (GenerateAPIKey), stored server-side only as a hash (HashAPIKey),
// compared via SecureEquals, scoped to one username, and independently
// revocable. The raw token itself lives ONLY in an HttpOnly cookie (see
// auth.go) — never reachable from JavaScript, so an XSS bug can't
// exfiltrate it the way it could a value merely stored in localStorage.

const trustedDeviceTTL = 30 * 24 * time.Hour

// TrustedDevice is one browser/device that's completed MFA recently
// enough to be trusted for trustedDeviceTTL without re-prompting.
type TrustedDevice struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	TokenHash  string     `json:"token_hash"`      // HashAPIKey(token) — the raw token is never stored, only ever held by the browser as an HttpOnly cookie
	Label      string     `json:"label,omitempty"` // e.g. a parsed User-Agent summary, for a human to recognize it in a list later
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func generateTrustedDeviceID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "td_" + hex.EncodeToString(b)
}

// IssueTrustedDevice mints a new trusted-device token for username,
// returning the raw token (to be set as an HttpOnly cookie — see
// auth.go's handleAuthMFAVerify) exactly once; only its hash is persisted.
func (c *Config) IssueTrustedDevice(username, label string) (token string, expiresAt time.Time, err error) {
	token = GenerateAPIKey()
	now := time.Now()
	expiresAt = now.Add(trustedDeviceTTL)

	td := TrustedDevice{
		ID: generateTrustedDeviceID(), Username: username,
		TokenHash: HashAPIKey(token), Label: label,
		CreatedAt: now, ExpiresAt: expiresAt,
	}
	c.mu.Lock()
	c.trustedDevices[td.ID] = td
	c.mu.Unlock()

	if err := c.Save(); err != nil {
		return "", time.Time{}, fmt.Errorf("save trusted device: %w", err)
	}
	return token, expiresAt, nil
}

// ValidateTrustedDevice reports whether token is a currently-valid trusted
// device for username specifically — a trusted-device token for one
// account can never be used to skip MFA on a different account, even if
// somehow presented alongside that other account's username/password.
// Updates LastUsedAt (best-effort, not persisted synchronously — same
// lazy posture TouchPairedKey already documents for the identical
// "informational only" tradeoff).
func (c *Config) ValidateTrustedDevice(username, token string) bool {
	if token == "" || username == "" {
		return false
	}
	target := HashAPIKey(token)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	for id, td := range c.trustedDevices {
		if td.Username != username {
			continue
		}
		if !SecureEquals(td.TokenHash, target) {
			continue
		}
		if now.After(td.ExpiresAt) {
			return false // expired — deliberately not deleted here; sweepExpiredTrustedDevices handles cleanup, keeping this a read-only check
		}
		td.LastUsedAt = &now
		c.trustedDevices[id] = td
		return true
	}
	return false
}

// ListTrustedDevices returns every trusted device for username, newest
// first — for a "your trusted devices" settings list. Never includes
// TokenHash's raw counterpart (there isn't one to include — that's the
// point) but does include the hash itself here since this is the
// internal representation; the HTTP handler strips it, same contract
// every other List* method in this package follows.
func (c *Config) ListTrustedDevices(username string) []TrustedDevice {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]TrustedDevice, 0)
	for _, td := range c.trustedDevices {
		if td.Username == username {
			out = append(out, td)
		}
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

// RevokeTrustedDevice removes one trusted device by ID — the next login
// attempt from that browser falls back to a full MFA prompt.
func (c *Config) RevokeTrustedDevice(id string) error {
	c.mu.Lock()
	if _, ok := c.trustedDevices[id]; !ok {
		c.mu.Unlock()
		return fmt.Errorf("trusted device '%s' not found", id)
	}
	delete(c.trustedDevices, id)
	c.mu.Unlock()
	return c.Save()
}

// RevokeAllTrustedDevices removes every trusted device for username —
// called when MFA is disabled (DisableMFA) so stale trust records don't
// linger for a feature that's now off, and available directly for a
// "sign out of all devices" action.
func (c *Config) RevokeAllTrustedDevices(username string) error {
	c.mu.Lock()
	changed := false
	for id, td := range c.trustedDevices {
		if td.Username == username {
			delete(c.trustedDevices, id)
			changed = true
		}
	}
	c.mu.Unlock()
	if !changed {
		return nil
	}
	return c.Save()
}
