package api

// ── PrestoBack Auth System ────────────────────────────────────────────────────
//
// JWT-based browser login + legacy X-API-Key for scripts/automations.
//
// Endpoints (all public — no auth required):
//   GET  /api/auth/status  → {setup_required, version}
//   POST /api/auth/setup   → first-run only: create admin account → JWT
//   POST /api/auth/login   → credentials → JWT
//
// Endpoints (auth required):
//   POST /api/auth/logout  → revokes current token
//   GET  /api/auth/me      → {username, role}
//
// JWT: HS256, 12-hour TTL, signed with HMAC of existing APIKey.
// Password: bcrypt (golang.org/x/crypto/bcrypt), cost 12.
// Token revocation: small in-memory set, cleared on restart
//   (acceptable — tokens expire in 12h anyway).

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pi/prestoback/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtTTL    = 12 * time.Hour
	jwtDomain = "prestoback-auth-v1"
	roleAdmin = "admin"
	// roleViewer can log in and read state, but every mutating endpoint
	// (backup/restore/container/stack control, settings changes) rejects it.
	// See requireAdmin() below — this is intentionally a single coarse
	// read/write boundary, not a granular permission matrix.
	roleViewer = "viewer"
)

// ── Login lockout ──────────────────────────────────────────────────────────────
//
// Previously the only brute-force mitigation was a flat 400ms sleep on every
// failed attempt — no counter, no lockout. That caps an attacker at roughly
// 2.5 guesses/sec indefinitely, which is fine only as long as this is never
// reachable from anywhere but a trusted LAN. Since some setups do forward the
// UI port for remote access, this adds a real (if simple) lockout: after
// maxLoginAttempts failures for a given username, further attempts are
// rejected outright for lockoutDuration — no bcrypt run at all during the
// lockout window, so it also cheaply avoids the CPU cost of hashing during
// a sustained attack.
//
// Deliberately in-memory, not persisted: a restart clearing lockout state is
// an acceptable tradeoff for a single-operator homelab tool, matching the
// existing revokedTokens design (see config.go — same reasoning: tokens
// expire in 12h anyway, lockouts reset in minutes anyway).
var (
	loginAttemptsMu sync.Mutex
	loginAttempts   = map[string]*loginState{}
)

type loginState struct {
	failures    int
	lockedUntil time.Time
}

const (
	maxLoginAttempts = 5
	lockoutDuration  = 5 * time.Minute
)

// checkLoginLockout returns a non-empty message if username is currently
// locked out. Case-insensitive key match, same normalization as GetUser.
func checkLoginLockout(username string) string {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	st, ok := loginAttempts[strings.ToLower(username)]
	if !ok {
		return ""
	}
	if time.Now().Before(st.lockedUntil) {
		remaining := time.Until(st.lockedUntil).Round(time.Second)
		return fmt.Sprintf("too many failed attempts — try again in %s", remaining)
	}
	return ""
}

// recordLoginFailure increments the failure count for username and locks it
// out once maxLoginAttempts is reached.
func recordLoginFailure(username string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	key := strings.ToLower(username)
	st, ok := loginAttempts[key]
	if !ok {
		st = &loginState{}
		loginAttempts[key] = st
	}
	st.failures++
	if st.failures >= maxLoginAttempts {
		st.lockedUntil = time.Now().Add(lockoutDuration)
	}
}

// recordLoginSuccess clears any failure history for username.
func recordLoginSuccess(username string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, strings.ToLower(username))
}

// ── JWT (HS256, pure stdlib) ──────────────────────────────────────────────────

type jwtClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat"`
}

func jwtSecret(apiKey string) []byte {
	h := sha256.New()
	h.Write([]byte(jwtDomain + ":" + apiKey))
	return h.Sum(nil)
}

func jwtSign(claims jwtClaims, secret []byte) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig
}

func jwtVerify(token string, secret []byte) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	body := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return nil, fmt.Errorf("invalid signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if time.Now().Unix() > c.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &c, nil
}

// ── Middleware ────────────────────────────────────────────────────────────────

// requireAdmin wraps a handler that's already behind authJWT and additionally
// rejects any request whose X-Auth-Role isn't admin. Use this on every
// mutating endpoint (backup/restore/delete, container/stack control, settings
// changes); leave plain authJWT on read-only (GET) endpoints so a viewer
// account can still see everything, just not change anything.
//
// This is a coarse read/write boundary, not a granular permission system —
// deliberately so. A homelab tool with one operator plus maybe one or two
// people who just want to check status doesn't need per-endpoint ACLs; it
// needs "can look" vs "can touch," and that's what this gives.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Role") != roleAdmin {
			errOut(w, 403, "this action requires an admin account")
			return
		}
		next(w, r)
	}
}

// adminForWrites wraps authJWT(next) and additionally requires an admin role
// for any non-GET request, while any authenticated role (including viewer)
// can still GET. This lets a single route/handler serve both a read (e.g.
// "list backups") and a write (e.g. "delete backup") — which almost every
// handler in this file does via internal r.Method dispatch — without having
// to split each one into two separate handlers or duplicate routing. Routes
// that are exclusively mutating (no GET case at all) are simply always
// admin-only under this wrapper, which is correct for them too.
func (s *Server) adminForWrites(next http.HandlerFunc) http.HandlerFunc {
	return s.authJWT(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-Auth-Role") != roleAdmin {
			errOut(w, 403, "this action requires an admin account")
			return
		}
		next(w, r)
	})
}

// authJWT replaces the old auth() middleware. Accepts:
//  1. Legacy X-API-Key header or ?api_key= query param (for scripts)
//  2. Authorization: Bearer <jwt> header (normal fetch()-based API calls —
//     always preferred whenever the caller can set custom headers)
//  3. ?token=<jwt> query param — ONLY as a fallback for clients that
//     genuinely cannot set custom headers, such as EventSource (used by the
//     SSE live-activity stream). Query-string tokens are a weaker posture
//     than a header (they can end up in browser history and server access
//     logs), so this exists for parity with the ?api_key= fallback already
//     used the same way, not as a general-purpose alternative — callers
//     that CAN use fetch()/XHR should always send the Authorization header
//     instead. Previously each caller (e.g. handleSSE) reimplemented this
//     check independently, which is how it ended up out of sync with this
//     function; now there is exactly one place that decides what counts as
//     valid auth, and every route — including SSE — goes through it.
func (s *Server) authJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Legacy API key (backwards compat for scripts / automations)
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key != "" {
			if key == s.cfg.APIKey() {
				r.Header.Set("X-Auth-User", "api-key")
				r.Header.Set("X-Auth-Role", roleAdmin)
				next(w, r)
				return
			}
			// Paired keys (see pairing.go): independently issued and
			// independently revocable, but grant the same admin-equivalent
			// access as the legacy key — same trust level, just not the
			// same shared secret. TouchPairedKey is best-effort and never
			// blocks the request on its own.
			if pk, ok := s.cfg.ValidatePairedKey(key); ok {
				s.cfg.TouchPairedKey(pk.ID)
				r.Header.Set("X-Auth-User", "paired:"+pk.Name)
				r.Header.Set("X-Auth-Role", roleAdmin)
				next(w, r)
				return
			}
		}

		// JWT — prefer the Authorization header; fall back to ?token= only
		// when no valid Bearer header was present at all.
		var token string
		if bearer := r.Header.Get("Authorization"); strings.HasPrefix(bearer, "Bearer ") {
			token = strings.TrimPrefix(bearer, "Bearer ")
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != "" {
			if s.cfg.IsTokenRevoked(token) {
				errOut(w, 401, "token has been revoked — please log in again")
				return
			}
			claims, err := jwtVerify(token, jwtSecret(s.cfg.APIKey()))
			if err != nil {
				errOut(w, 401, "invalid or expired token")
				return
			}
			r.Header.Set("X-Auth-User", claims.Sub)
			r.Header.Set("X-Auth-Role", claims.Role)
			next(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="PrestoBack"`)
		errOut(w, 401, "authentication required — use /api/auth/login")
	}
}

// ── Public auth handlers ──────────────────────────────────────────────────────

// GET /api/auth/status — UI calls this on load to decide: show login or setup.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]any{
		"setup_required": !s.cfg.HasUsers(),
		"version":        config.Version,
	})
}

// POST /api/auth/setup — first-run only. Creates admin + returns JWT.
func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	if s.cfg.HasUsers() {
		errOut(w, 409, "setup already complete — use /api/auth/login")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := parseJSON(r, &req); err != nil {
		errOut(w, 400, "invalid JSON: "+err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 2 {
		errOut(w, 400, "username must be at least 2 characters")
		return
	}
	if len(req.Password) < 8 {
		errOut(w, 400, "password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		errOut(w, 500, "failed to hash password")
		return
	}
	if err := s.cfg.AddUser(config.User{
		Username: req.Username,
		Hash:     string(hash),
		Role:     roleAdmin,
	}); err != nil {
		errOut(w, 500, "failed to save user: "+err.Error())
		return
	}
	token := s.issueToken(req.Username, roleAdmin)
	respond(w, 201, map[string]any{
		"token":    token,
		"username": req.Username,
		"role":     roleAdmin,
		"expires":  time.Now().Add(jwtTTL).Unix(),
	})
}

// POST /api/auth/login — validate credentials, return JWT.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := parseJSON(r, &req); err != nil {
		errOut(w, 400, "invalid JSON: "+err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	if msg := checkLoginLockout(req.Username); msg != "" {
		errOut(w, 429, msg)
		return
	}

	user, ok := s.cfg.GetUser(req.Username)
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(req.Password)) != nil {
		time.Sleep(400 * time.Millisecond) // constant-time-ish to prevent enumeration
		recordLoginFailure(req.Username)
		errOut(w, 401, "invalid username or password")
		return
	}
	recordLoginSuccess(req.Username)
	token := s.issueToken(user.Username, user.Role)
	respond(w, 200, map[string]any{
		"token":    token,
		"username": user.Username,
		"role":     user.Role,
		"expires":  time.Now().Add(jwtTTL).Unix(),
	})
}

// ── Protected auth handlers ───────────────────────────────────────────────────

// POST /api/auth/logout — revoke current token.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	bearer := r.Header.Get("Authorization")
	if strings.HasPrefix(bearer, "Bearer ") {
		s.cfg.RevokeToken(strings.TrimPrefix(bearer, "Bearer "))
	}
	respond(w, 200, map[string]string{"status": "logged out"})
}

// GET /api/auth/me — returns the authenticated user's info.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]string{
		"username": r.Header.Get("X-Auth-User"),
		"role":     r.Header.Get("X-Auth-Role"),
	})
}

// GET/POST/DELETE /api/users — manage additional accounts. Admin-only for
// writes via adminForWrites; GET is available to any authenticated role so a
// viewer can at least see who else has access (but not the password hashes —
// those are stripped before serializing, see the anonymous struct below).
//
//	GET    → list all accounts (username + role only)
//	POST   → {username, password, role: "admin"|"viewer"} create an account
//	DELETE → ?username=<name> remove an account (refuses to remove the last one)
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users := s.cfg.ListUsers()
		out := make([]map[string]string, len(users))
		for i, u := range users {
			out[i] = map[string]string{"username": u.Username, "role": u.Role}
		}
		respond(w, 200, out)

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := parseJSON(r, &req); err != nil {
			errOut(w, 400, "invalid JSON: "+err.Error())
			return
		}
		req.Username = strings.TrimSpace(req.Username)
		if len(req.Username) < 2 {
			errOut(w, 400, "username must be at least 2 characters")
			return
		}
		if len(req.Password) < 8 {
			errOut(w, 400, "password must be at least 8 characters")
			return
		}
		if req.Role != roleAdmin && req.Role != roleViewer {
			errOut(w, 400, fmt.Sprintf("role must be %q or %q", roleAdmin, roleViewer))
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		if err != nil {
			errOut(w, 500, "failed to hash password")
			return
		}
		if err := s.cfg.AddUser(config.User{
			Username: req.Username,
			Hash:     string(hash),
			Role:     req.Role,
		}); err != nil {
			errOut(w, 409, err.Error())
			return
		}
		respond(w, 201, map[string]string{"username": req.Username, "role": req.Role})

	case http.MethodDelete:
		username := strings.TrimSpace(r.URL.Query().Get("username"))
		if username == "" {
			errOut(w, 400, "username query param required")
			return
		}
		// Refuse self-deletion via this endpoint — forces the operator to log
		// in as a different account first, avoiding an accidental self-lockout
		// where the only remaining session is the one that just deleted itself.
		if username == r.Header.Get("X-Auth-User") {
			errOut(w, 400, "cannot delete your own account while logged in as it — log in as another admin first")
			return
		}
		if err := s.cfg.DeleteUser(username); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]string{"status": "deleted"})

	default:
		errOut(w, 405, "method not allowed")
	}
}

// ── Helper ────────────────────────────────────────────────────────────────────

func (s *Server) issueToken(username, role string) string {
	now := time.Now()
	return jwtSign(jwtClaims{
		Sub:  username,
		Role: role,
		Iat:  now.Unix(),
		Exp:  now.Add(jwtTTL).Unix(),
	}, jwtSecret(s.cfg.APIKey()))
}
