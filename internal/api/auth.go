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
	"time"

	"github.com/pi/prestoback/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtTTL    = 12 * time.Hour
	jwtDomain = "prestoback-auth-v1"
	roleAdmin = "admin"
)

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
		if key != "" && key == s.cfg.APIKey() {
			r.Header.Set("X-Auth-User", "api-key")
			r.Header.Set("X-Auth-Role", roleAdmin)
			next(w, r)
			return
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
	user, ok := s.cfg.GetUser(strings.TrimSpace(req.Username))
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(req.Password)) != nil {
		time.Sleep(400 * time.Millisecond) // constant-time-ish to prevent enumeration
		errOut(w, 401, "invalid username or password")
		return
	}
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
