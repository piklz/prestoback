package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/config"
	"github.com/pi/prestoback/internal/history"
	"github.com/pi/prestoback/internal/notify"
	"github.com/pi/prestoback/internal/scheduler"
	"github.com/pi/prestoback/web"
)

type Server struct {
	cfg      *config.Config
	engine   *backup.Engine
	hist     *history.Log
	sched    *scheduler.Scheduler
	mux      *http.ServeMux
	image    string
	selfName string

	sseClients map[chan backup.JobUpdate]struct{}
	sseMu      sync.Mutex

	// Disk monitoring — guards diskWarnLow and diskWarnSent.
	// diskWarnSent is debounced: once sent, won't fire again until space recovers.
	stateMu      sync.Mutex
	diskWarnLow  bool
	diskWarnSent bool

	// Maintenance mode — schedules are skipped while time.Now() < maintUntil.
	// Resets on container restart (intentional — a stuck maintenance window after
	// a crash would be worse than a missed one).
	maintUntil time.Time

	// Pending update tracking — populated by updateCheckLoop, read by the UI
	// (/api/status) and the Telegram notifier. Guarded by stateMu.
	pendingUpdates       []string          // app names with an image update available — dashboard-facing, unchanged shape
	pendingUpdateDetails []AppUpdateReport // per-image detail behind pendingUpdates — Telegram-report-facing, see updatecheck.go
	updateAlertSent      map[string]bool   // debounce: app name -> already alerted

	// updateMu serializes ALL container recreate operations (UpdateContainer /
	// standaloneRecreate, via /update, /update all, the update-check button,
	// and /stack pull). Without this, two overlapping update runs can race
	// the same container through docker stop/rename/create — the loser's
	// "docker rename" fails, it falls back to restarting the OLD container,
	// and the winner's later "docker rm <bak>" then fails too (target is
	// running, no -f used) — leaving the old container orphaned and still
	// attached to its original network endpoint under its old short ID
	// (visible as "<shortID>_<name>" in "docker network inspect"). This is
	// a hard global lock, not per-app: a stack-wide /stack pull and a
	// single-app /update must never overlap either, since FindContainers can
	// resolve the same container from two different app entries.
	updateMu      sync.Mutex
	updateRunning bool
}

func NewServer(cfg *config.Config, image, selfName string) *Server {
	hist, _ := history.Load(cfg.HistoryFile())
	sched := scheduler.New()

	s := &Server{
		cfg:             cfg,
		engine:          backup.NewEngine(cfg.BackupDir()),
		hist:            hist,
		sched:           sched,
		mux:             http.NewServeMux(),
		image:           image,
		selfName:        selfName,
		sseClients:      make(map[chan backup.JobUpdate]struct{}),
		updateAlertSent: make(map[string]bool),
	}
	s.routes()
	s.loadSchedules()
	go s.broadcastUpdates()
	go s.runTelegramBot()
	go s.diskMonitorLoop()
	go s.updateCheckLoop()
	return s
}

func (s *Server) Run(port int) error {
	key := s.cfg.APIKey()
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("  PrestoBack v%s  —  port %d", config.Version, port)
	masked := key[:8] + "..." + key[len(key)-4:]
	log.Printf("  API Key: %s (full key in /data/config.json — use for external integrations)", masked)
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return http.ListenAndServe(fmt.Sprintf(":%d", port), s.mux)
}

// ── Routes ────────────────────────────────────────────────────────────────────

func (s *Server) routes() {
	// Public
	s.mux.Handle("/", http.FileServer(http.FS(web.StaticFS())))
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("/api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/api/events", s.authJWT(s.handleSSE))

	// Auth-required — read-only for any authenticated role (including viewer)
	s.mux.HandleFunc("/api/auth/logout", s.authJWT(s.handleAuthLogout)) // self-service, not privilege-gated
	s.mux.HandleFunc("/api/auth/me", s.authJWT(s.handleAuthMe))
	s.mux.HandleFunc("/api/volumes", s.authJWT(s.handleListVolumes))
	s.mux.HandleFunc("/api/discover", s.authJWT(s.handleDiscover))
	s.mux.HandleFunc("/api/suggest-excludes", s.authJWT(s.handleSuggestExcludes))
	s.mux.HandleFunc("/api/validate-path", s.authJWT(s.handleValidatePath))
	s.mux.HandleFunc("/api/dir-size", s.authJWT(s.handleDirSize))
	s.mux.HandleFunc("/api/container-health", s.authJWT(s.handleContainerHealth))
	s.mux.HandleFunc("/api/history", s.authJWT(s.handleHistory))
	s.mux.HandleFunc("/api/apikey", s.authJWT(s.handleAPIKey)) // masked fingerprint only, never the live key
	s.mux.HandleFunc("/api/update/check", s.authJWT(s.handleUpdateCheck))
	s.mux.HandleFunc("/api/cron/preview", s.authJWT(s.handleCronPreview))

	// Auth-required — admin-only for any write (GET still allowed for viewer);
	// see adminForWrites doc comment for why these aren't split into separate
	// read/write handlers.
	s.mux.HandleFunc("/api/apps", s.adminForWrites(s.handleApps))
	s.mux.HandleFunc("/api/apps/", s.adminForWrites(s.handleApp))
	s.mux.HandleFunc("/api/backups/", s.adminForWrites(s.handleBackups))
	s.mux.HandleFunc("/api/backups-orphans/", s.adminForWrites(s.handleOrphans))
	s.mux.HandleFunc("/api/backups-orphans", s.adminForWrites(s.handleOrphans))
	s.mux.HandleFunc("/api/backups-import", s.adminForWrites(s.handleBackupsImport))
	s.mux.HandleFunc("/api/notify", s.adminForWrites(s.handleNotify))
	s.mux.HandleFunc("/api/notify/test", s.adminForWrites(s.handleNotifyTest))
	s.mux.HandleFunc("/api/apikey/regenerate", s.adminForWrites(s.handleRegenKey))
	s.mux.HandleFunc("/api/update/apply", s.adminForWrites(s.handleUpdateApply))
	s.mux.HandleFunc("/api/maintenance", s.adminForWrites(s.handleMaintenance))
	s.mux.HandleFunc("/api/users", s.adminForWrites(s.handleUsers))
}

// ── SSE ───────────────────────────────────────────────────────────────────────

// handleSSE streams live job progress. Auth is handled entirely by the
// authJWT middleware wrapping this route (see routes()) — including its
// ?token= query-param fallback for EventSource, which cannot set custom
// headers. This used to duplicate that check inline with its own goto-based
// logic; that duplication is exactly how it drifted out of sync with
// authJWT's actual rules. One source of truth now.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// No Access-Control-Allow-Origin: same-origin requests (the only
	// legitimate caller — this app's own frontend) never need CORS headers
	// at all. A wildcard here only helps a DIFFERENT origin's JavaScript read
	// this live activity stream, which is not a use case this app has —
	// unnecessary attack surface for zero functional benefit, especially
	// combined with the ?token= query-param auth fallback this route accepts.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	ch := make(chan backup.JobUpdate, 32)
	s.sseMu.Lock()
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()
	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
	}()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case u, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(u)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) broadcastUpdates() {
	for u := range s.engine.Updates() {
		s.sseMu.Lock()
		for ch := range s.sseClients {
			select {
			case ch <- u:
			default:
			}
		}
		s.sseMu.Unlock()
	}
}

// ── Health ────────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]string{"status": "ok", "version": config.Version})
}

// ── Status ────────────────────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	builtAt := ""
	if s.image != "" {
		if out, err := exec.Command("docker", "image", "inspect",
			"--format={{.Created}}", s.image).Output(); err == nil {
			builtAt = strings.TrimSpace(string(out))
		}
	}
	var diskFreeBytes, diskTotalBytes uint64
	diskLowPct := 0 // 0 means OK; >0 means disk is below threshold (value = % free)
	if stat, err := diskUsage(s.cfg.BackupDir()); err == nil {
		diskFreeBytes = stat.free
		diskTotalBytes = stat.total
		if stat.total > 0 {
			freePct := int(100 * stat.free / stat.total)
			if freePct < diskWarnThresholdPct {
				diskLowPct = freePct
			}
		}
	}
	nextRuns := s.sched.NextRuns()
	s.stateMu.Lock()
	maintUntil := s.maintUntil
	pendingUpdates := append([]string{}, s.pendingUpdates...) // copy under lock
	s.stateMu.Unlock()
	var maintUntilStr string
	if !maintUntil.IsZero() && time.Now().Before(maintUntil) {
		maintUntilStr = maintUntil.UTC().Format(time.RFC3339)
	}
	respond(w, 200, map[string]any{
		"version":           config.Version,
		"app_count":         s.cfg.AppCount(),
		"volumes_dir":       s.cfg.VolumesDir,
		"backup_dir":        s.cfg.BackupDir(),
		"image":             s.image,
		"self_name":         s.selfName,
		"built_at":          builtAt,
		"time":              time.Now().UTC(),
		"disk_free_bytes":   diskFreeBytes,
		"disk_total_bytes":  diskTotalBytes,
		"disk_low_pct":      diskLowPct,        // non-zero = warning; value = % free
		"maintenance_until": maintUntilStr,     // RFC3339 or "" if not in maintenance
		"compose_file":      s.cfg.ComposeFile, // "" if /update auto-restart not configured
		"pending_updates":   pendingUpdates,    // app names with an image update available
		"next_runs":         nextRuns,
	})
}

// ── History ───────────────────────────────────────────────────────────────────

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, s.hist.List(100))
}

// ── Notifications ─────────────────────────────────────────────────────────────

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, 200, s.cfg.GetNotify())
	case http.MethodPut:
		var n config.NotifyConfig
		if err := parseJSON(r, &n); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		s.cfg.SetNotify(n)
		respond(w, 200, n)
	default:
		errOut(w, 405, "method not allowed")
	}
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	nc := s.cfg.GetNotify()
	ev := notify.Event{Kind: "backup_success", AppName: "test-app", Detail: "PrestoBack test notification ✓"}
	var errs []string
	if nc.TelegramEnabled && nc.TelegramToken != "" {
		if err := notify.SendTelegram(notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}, ev); err != nil {
			errs = append(errs, "telegram: "+err.Error())
		}
	}
	if nc.DiscordEnabled && nc.DiscordURL != "" {
		if err := notify.SendWebhook(nc.DiscordURL, ev); err != nil {
			errs = append(errs, "discord: "+err.Error())
		}
	}
	if nc.NtfyEnabled && nc.NtfyURL != "" {
		if err := notify.SendWebhook(nc.NtfyURL, ev); err != nil {
			errs = append(errs, "ntfy: "+err.Error())
		}
	}
	if nc.WebhookEnabled && nc.WebhookURL != "" {
		if err := notify.SendWebhook(nc.WebhookURL, ev); err != nil {
			errs = append(errs, "webhook: "+err.Error())
		}
	}
	if len(errs) > 0 {
		respond(w, 200, map[string]any{"ok": false, "errors": errs})
	} else {
		respond(w, 200, map[string]any{"ok": true})
	}
}

// ── API key regen ─────────────────────────────────────────────────────────────

// POST /api/apikey/regenerate — generates a new key and returns it ONCE in full.
// The UI must prompt the user to copy it immediately; subsequent GET /api/apikey
// will only show the masked version.
func (s *Server) handleRegenKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	newKey := s.cfg.RegenerateAPIKey()
	respond(w, 200, map[string]any{
		"api_key": newKey,
		"warning": "Copy this key now — it will not be shown again. Use it as the X-API-Key header for external integrations.",
	})
}

// ── Volumes ───────────────────────────────────────────────────────────────────

func (s *Server) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VolumesDir == "" {
		respond(w, 200, []any{})
		return
	}
	entries, err := os.ReadDir(s.cfg.VolumesDir)
	if os.IsNotExist(err) {
		respond(w, 200, []any{})
		return
	}
	if err != nil {
		errOut(w, 500, "cannot read volumes dir: "+err.Error())
		return
	}
	type vol struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	var vols []vol
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		vols = append(vols, vol{
			Name: e.Name(),
			Path: filepath.Join(s.cfg.VolumesDir, e.Name()),
		})
	}
	respond(w, 200, vols)
}

func (s *Server) handleSuggestExcludes(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	patterns := backup.SuggestExcludes(image)
	if patterns == nil {
		patterns = []string{}
	}
	respond(w, 200, map[string]any{
		"image":    image,
		"patterns": patterns,
	})
}

// ContainerHealth is what the frontend receives per app.
type ContainerHealth struct {
	AppID    string `json:"app_id"`
	Name     string `json:"name"`   // container name
	State    string `json:"state"`  // "running" | "exited" | "paused" | "unknown"
	Health   string `json:"health"` // "healthy" | "unhealthy" | "starting" | "" (no healthcheck)
	ExitCode int    `json:"exit_code,omitempty"`
}

// GET /api/container-health — returns live container state for every registered
// app. Called periodically by the frontend to show inline status in the app list.
// Uses the same FindContainers matching as the backup pipeline so the displayed
// container is always the one that would actually be stopped/paused on backup.
func (s *Server) handleContainerHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	apps := s.cfg.ListApps()
	result := make([]ContainerHealth, 0, len(apps))
	for _, a := range apps {
		containers := backup.FindContainers(a.ID)
		if len(containers) == 0 {
			result = append(result, ContainerHealth{AppID: a.ID, State: "unknown"})
			continue
		}
		// Use the first matched container (primary one for this app).
		c := containers[0]
		h := ContainerHealth{AppID: a.ID, Name: c.Name, State: c.Status}
		// Try to get health check status from docker inspect.
		out, err := exec.Command("docker", "inspect",
			"--format={{.State.Health.Status}}:{{.State.ExitCode}}", c.ID).Output()
		if err == nil {
			parts := strings.SplitN(strings.TrimSpace(string(out)), ":", 2)
			healthStr := parts[0]
			// Docker returns "<nil>" when there is no healthcheck configured.
			if healthStr != "" && healthStr != "<nil>" {
				h.Health = healthStr
			}
			if len(parts) == 2 {
				if code, err := strconv.Atoi(parts[1]); err == nil && code != 0 {
					h.ExitCode = code
				}
			}
		}
		result = append(result, h)
	}
	respond(w, 200, result)
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	// path → registered app name (empty string = not registered)
	registeredPaths := map[string]string{}
	for _, a := range s.cfg.ListApps() {
		for _, v := range a.Volumes {
			registeredPaths[v.Path] = a.Name
		}
	}
	candidates := backup.DiscoverApps(s.selfName, s.cfg.VolumesDir, registeredPaths)
	if candidates == nil {
		candidates = []backup.DiscoveredApp{}
	}
	respond(w, 200, candidates)
}

// handleDirSize estimates the archived size of one or more directories,
// respecting exclude patterns — this is what powers the backup/restore size
// warnings, so it deliberately reuses backup.MatchesExclude (the same logic
// tarGz uses) rather than a second, potentially-divergent copy of it.
//
// GET /api/dir-size?path=A&path=B&exclude=Cache/&exclude=*.log
func (s *Server) handleDirSize(w http.ResponseWriter, r *http.Request) {
	paths := r.URL.Query()["path"]
	if len(paths) == 0 {
		errOut(w, 400, "at least one path required")
		return
	}
	excludes := r.URL.Query()["exclude"]

	var totalBytes int64
	fileCount := 0
	for _, path := range paths {
		_ = filepath.Walk(path, func(walked string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info == nil || walked == path {
				return nil
			}
			rel, relErr := filepath.Rel(path, walked)
			if relErr != nil {
				return nil
			}
			if info.IsDir() {
				if len(excludes) > 0 && backup.MatchesExclude(rel, excludes) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Mode().IsRegular() {
				if len(excludes) > 0 && backup.MatchesExclude(rel, excludes) {
					return nil
				}
				totalBytes += info.Size()
				fileCount++
			}
			return nil
		})
	}
	respond(w, 200, map[string]any{
		"paths":      paths,
		"bytes":      totalBytes,
		"file_count": fileCount,
		"human":      humanBytes(totalBytes),
	})
}

func humanBytes(b int64) string {
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

// formatDurationMs formats a millisecond duration as a compact human string.
// e.g. 45000 → "45s", 90000 → "1m 30s", 3700000 → "1h 1m"
func formatDurationMs(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return fmt.Sprintf("%dms", ms)
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// formatDuration formats a time.Duration as a compact human string for display.
// e.g. 90m → "1h 30m", 25h → "1d 1h"
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, h)
}

// ── Maintenance mode ──────────────────────────────────────────────────────────

const diskWarnThresholdPct = 10 // alert when backup dir has < 10% free space

func (s *Server) inMaintenance() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return !s.maintUntil.IsZero() && time.Now().Before(s.maintUntil)
}

func (s *Server) getMaintUntil() time.Time {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.maintUntil
}

// handleMaintenance exposes the same maintenance-mode state the Telegram
// /maintenance command controls, so the dashboard can display and manage it
// too — previously this was Telegram-only, so the "Edit Application" modal
// (and the rest of the UI) had no way to know a global maintenance window
// was active, even though it fully overrides each app's own Pinned setting.
//
//	GET  /api/maintenance         → {active, until, remaining_seconds}
//	POST /api/maintenance         → {duration: "2h"|"1d"|"1w"|"on"|"off"}
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		until := s.getMaintUntil()
		active := !until.IsZero() && time.Now().Before(until)
		resp := map[string]any{"active": active}
		if active {
			resp["until"] = until.UTC().Format(time.RFC3339)
			resp["remaining_seconds"] = int(time.Until(until).Seconds())
		}
		respond(w, 200, resp)

	case http.MethodPost:
		var req struct {
			Duration string `json:"duration"`
		}
		if err := parseJSON(r, &req); err != nil {
			errOut(w, 400, "invalid JSON: "+err.Error())
			return
		}
		lower := strings.ToLower(strings.TrimSpace(req.Duration))
		if lower == "" || lower == "off" {
			s.stateMu.Lock()
			s.maintUntil = time.Time{}
			s.stateMu.Unlock()
			respond(w, 200, map[string]any{"active": false})
			return
		}
		dur, ok := parseMaintDuration(lower)
		if !ok {
			errOut(w, 400, "invalid duration — use e.g. \"2h\", \"1d\", \"1w\", or \"on\"")
			return
		}
		until := time.Now().Add(dur)
		s.stateMu.Lock()
		s.maintUntil = until
		s.stateMu.Unlock()
		respond(w, 200, map[string]any{
			"active":            true,
			"until":             until.UTC().Format(time.RFC3339),
			"remaining_seconds": int(dur.Seconds()),
		})

	default:
		errOut(w, 405, "method not allowed")
	}
}

// parseMaintDuration parses duration strings like "2h", "1d", "2day", "1w",
// "1week" or the special keyword "on" (treated as ~1 year / indefinite).
func parseMaintDuration(arg string) (time.Duration, bool) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	if arg == "on" {
		return 365 * 24 * time.Hour, true
	}
	type suffix struct {
		s string
		u time.Duration
	}
	// Longest first so "days" is tried before "d"
	suffixes := []suffix{
		{"weeks", 7 * 24 * time.Hour},
		{"week", 7 * 24 * time.Hour},
		{"days", 24 * time.Hour},
		{"day", 24 * time.Hour},
		{"hours", time.Hour},
		{"hour", time.Hour},
		{"w", 7 * 24 * time.Hour},
		{"d", 24 * time.Hour},
		{"h", time.Hour},
	}
	for _, su := range suffixes {
		if strings.HasSuffix(arg, su.s) {
			nStr := strings.TrimSpace(strings.TrimSuffix(arg, su.s))
			n, err := strconv.Atoi(nStr)
			if err == nil && n > 0 {
				return time.Duration(n) * su.u, true
			}
		}
	}
	return 0, false
}

// ── Update availability checking ──────────────────────────────────────────────
//
// Checks every running app's container(s) against their registries via an
// actual "docker pull" per unique image (see CheckImageUpdate doc comment for
// why manifest-digest comparison was abandoned — it produced false positives
// on every multi-arch image). A pull costs a small registry round-trip even
// when nothing changed, and real bandwidth only when a layer actually changed
// — this is why the interval defaults to 24h rather than something tighter.
// Use /check at any time to trigger an immediate on-demand check.
//
// Notifies via Telegram with a one-tap Update button the first time an app is
// found to have a pending update; debounced per-app so it won't repeat until
// either the update is applied or the set of pending apps changes.

const updateCheckInterval = 24 * time.Hour

func (s *Server) updateCheckLoop() {
	time.Sleep(2 * time.Minute) // let startup settle, avoid racing the disk/SSE goroutines
	for {
		s.checkForUpdates(true)
		time.Sleep(updateCheckInterval)
	}
}

// checkForUpdates is implemented in updatecheck.go — it now checks every
// running container's image against its registry directly (HEAD-based
// digest comparison, no `docker pull`) and groups results under their real
// owning app so a container matched by more than one app's fuzzy name isn't
// checked and reported twice. See updatecheck.go for the full explanation.

// diskMonitorLoop checks backup disk space every 30 minutes and fires a
// Telegram alert (with action buttons) when free space drops below the threshold.
// The alert is debounced: once sent, it won't fire again until space recovers
// above the threshold — preventing spam during a long fill-up.
func (s *Server) diskMonitorLoop() {
	time.Sleep(60 * time.Second) // let startup settle before first check
	for {
		s.checkDiskAndAlert()
		time.Sleep(30 * time.Minute)
	}
}

func (s *Server) checkDiskAndAlert() {
	stat, err := diskUsage(s.cfg.BackupDir())
	if err != nil || stat.total == 0 {
		return
	}
	freePct := int(100 * stat.free / stat.total)
	isLow := freePct < diskWarnThresholdPct

	s.stateMu.Lock()
	wasLow := s.diskWarnLow
	warnSent := s.diskWarnSent
	s.diskWarnLow = isLow
	if !isLow {
		s.diskWarnSent = false // reset debounce when space recovers
	}
	s.stateMu.Unlock()

	if isLow && !warnSent {
		s.stateMu.Lock()
		s.diskWarnSent = true
		s.stateMu.Unlock()

		nc := s.cfg.GetNotify()
		if !nc.TelegramEnabled || nc.TelegramToken == "" || nc.TelegramChatID == "" {
			return
		}
		used := stat.total - stat.free
		tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
		bar := strings.Repeat("█", (100-freePct)/10) + strings.Repeat("░", freePct/10)
		msg := fmt.Sprintf(
			"⚠️ *Backup disk space low* — only *%d%%* free\\!\n\n"+
				"💾 Used: `%s`\n"+
				"🆓 Free: `%s`\n"+
				"📦 Total: `%s`\n"+
				"`%s`\n\n"+
				"What would you like to do?",
			freePct,
			notify.EscapeMD(humanBytes(int64(used))),
			notify.EscapeMD(humanBytes(int64(stat.free))),
			notify.EscapeMD(humanBytes(int64(stat.total))),
			bar,
		)
		btns := []notify.ButtonAction{
			{Label: "🗑 Prune old backup archives", Data: "disk:prune"},
			{Label: "🐳 Prune dangling Docker images", Data: "disk:docker_prune"},
			{Label: "❌ Dismiss (re-alert if worse)", Data: "disk:dismiss"},
		}
		_ = notify.SendRawWithButtons(tgCfg, msg, btns)
		log.Printf("[disk] low space alert sent (%d%% free)", freePct)
		_ = wasLow // silence unused variable warning
	}
}

// runPruneAll removes backups beyond each app's retain count and reports results.
func (s *Server) runPruneAll(tgCfg notify.TelegramConfig) {
	apps := s.cfg.ListApps()
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	var sb strings.Builder
	sb.WriteString("*Prune Results*\n\n")
	totalRemoved := 0
	for _, app := range apps {
		before, _ := s.engine.ListBackups(app.ID)
		if err := s.engine.PruneBackups(app.ID, app.Retain); err != nil {
			sb.WriteString(fmt.Sprintf("❌ `%s`: %s\n", notify.EscapeMD(app.Name), notify.EscapeMD(err.Error())))
			continue
		}
		after, _ := s.engine.ListBackups(app.ID)
		removed := len(before) - len(after)
		if removed > 0 {
			totalRemoved += removed
			sb.WriteString(fmt.Sprintf("✅ `%s` — removed %d archive\\(s\\)\n", notify.EscapeMD(app.Name), removed))
		}
	}
	if totalRemoved == 0 {
		sb.WriteString("Nothing to prune — all apps are within their retain limits\\.")
	} else {
		sb.WriteString(fmt.Sprintf("\n🗑 Total: *%d* archive\\(s\\) deleted", totalRemoved))
	}
	_ = notify.SendRaw(tgCfg, sb.String())
}

// runContainerUpdates is the public entry point for all update operations
// (/update, /update all, the update-check notification button). It acquires
// the global updateMu lock so overlapping update runs can never race the
// same container through recreate — see the updateMu doc comment on the
// Server struct for exactly what goes wrong if they do. If an update is
// already in progress, this sends a friendly "already running" message and
// returns immediately rather than queuing or racing.
func (s *Server) runContainerUpdates(tgCfg notify.TelegramConfig, apps []config.AppConfig) {
	s.stateMu.Lock()
	if s.updateRunning {
		s.stateMu.Unlock()
		_ = notify.SendRaw(tgCfg, "⏳ An update is already in progress — please wait for it to finish before starting another\\.")
		return
	}
	s.updateRunning = true
	s.stateMu.Unlock()

	s.updateMu.Lock()
	defer func() {
		s.updateMu.Unlock()
		s.stateMu.Lock()
		s.updateRunning = false
		s.stateMu.Unlock()
	}()

	s.runContainerUpdatesLocked(tgCfg, apps)
}

// runContainerUpdatesLocked pulls + recreates containers for each app,
// streaming a timed summary back to Telegram when all work is done.
// Must only be called while holding s.updateMu — use runContainerUpdates.
func (s *Server) runContainerUpdatesLocked(tgCfg notify.TelegramConfig, apps []config.AppConfig) {
	// Belt-and-suspenders: a panic in a goroutine would crash the bot loop.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[update] PANIC in runContainerUpdatesLocked: %v", r)
			_ = notify.SendRaw(tgCfg, "❌ Internal error during update — check container logs\\.")
		}
	}()

	if ok, errMsg := backup.DockerReachable(); !ok {
		log.Printf("[update] aborting — Docker daemon unreachable: %s", errMsg)
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"⚠️ Can't reach Docker right now \\(daemon may be restarting\\) — nothing was checked or updated\\. Try again in a moment\\.\n\n`%s`",
			notify.EscapeMD(errMsg)))
		return
	}

	type cResult struct {
		name         string
		res          backup.ContainerUpdate
		dur          time.Duration
		timedOut     bool
		timeoutAfter time.Duration
	}
	type aResult struct {
		appName      string
		noContainers bool
		containers   []cResult
		dur          time.Duration
	}
	allRestarted := func(ar aResult) bool {
		if len(ar.containers) == 0 {
			return false
		}
		for _, cr := range ar.containers {
			if !cr.res.Restarted {
				return false
			}
		}
		return true
	}
	anyRolled := func(ar aResult) bool {
		for _, cr := range ar.containers {
			if cr.res.Rolled {
				return true
			}
		}
		return false
	}
	anyErr := func(ar aResult) bool {
		for _, cr := range ar.containers {
			if cr.res.Err != "" || cr.timedOut {
				return true
			}
		}
		return false
	}

	overallStart := time.Now()
	results := make([]aResult, 0, len(apps))

	for _, app := range apps {
		log.Printf("[update] processing app %s (id: %s)", app.Name, app.ID)
		appStart := time.Now()

		// emit streams each step to SSE so the browser live-log panel shows
		// progress exactly like a backup job does.
		appID := app.ID
		appName := app.Name
		emit := func(msg string) {
			log.Printf("[update:%s] %s", appName, msg)
			s.engine.EmitLog(appID, msg)
		}
		emit(fmt.Sprintf("━━━ Update started: %s ━━━", appName))

		containers := backup.DedupeContainers(backup.FindContainers(app.ID))
		if len(containers) == 0 {
			log.Printf("[update] no containers found for app %s", app.ID)
			emit(fmt.Sprintf("⚠  No containers found for %s", appName))
			results = append(results, aResult{appName: app.Name, noContainers: true, dur: time.Since(appStart)})
			continue
		}
		ar := aResult{appName: app.Name}
		for _, c := range containers {
			type res struct{ r backup.ContainerUpdate }
			ch := make(chan res, 1)
			cStart := time.Now()
			go func(ci backup.ContainerInfo) {
				ch <- res{r: backup.UpdateContainer(ci, s.cfg.ComposeFile, emit)}
			}(c)

			var cr cResult
			cr.name = c.Name
			// Size the wait to agree with what UpdateContainer is actually
			// doing internally (see ContainerPullTimeout/pullTimeoutFor) —
			// this used to be a flat 11 minutes regardless of image size,
			// which fired and abandoned the real pull before its own
			// (correctly larger) internal timeout ever got a chance to. The
			// +5m buffer covers the stop→rename→create→start→health-check
			// steps that run after the pull itself.
			watchdog := backup.ContainerPullTimeout(c) + 5*time.Minute
			select {
			case r := <-ch:
				cr.res = r.r
			case <-time.After(watchdog):
				cr.timedOut = true
				cr.timeoutAfter = watchdog
				emit(fmt.Sprintf("✗ %s timed out (no response after %s)", c.Name, formatDuration(watchdog)))
			}
			cr.dur = time.Since(cStart)
			log.Printf("[update] container %s done in %s: err=%q restarted=%v upToDate=%v timedOut=%v",
				c.Name, cr.dur.Round(time.Second), cr.res.Err, cr.res.Restarted, cr.res.AlreadyUpToDate, cr.timedOut)
			ar.containers = append(ar.containers, cr)
		}
		ar.dur = time.Since(appStart)

		// Emit SSE footer for this app
		switch {
		case allRestarted(ar):
			emit(fmt.Sprintf("━━━ Update complete: %s (%s) ━━━", appName, formatDuration(ar.dur)))
		case anyRolled(ar):
			emit(fmt.Sprintf("━━━ Update rolled back: %s (%s) ━━━", appName, formatDuration(ar.dur)))
		case anyErr(ar):
			emit(fmt.Sprintf("━━━ Update failed: %s (%s) ━━━", appName, formatDuration(ar.dur)))
		default:
			emit(fmt.Sprintf("━━━ Update finished: %s (%s) ━━━", appName, formatDuration(ar.dur)))
		}

		results = append(results, ar)
	}

	totalDur := time.Since(overallStart)
	isSingle := len(apps) == 1

	var sb strings.Builder
	if isSingle && len(results) > 0 {
		sb.WriteString(fmt.Sprintf("*Update — %s*\n\n", notify.EscapeMD(results[0].appName)))
	} else {
		sb.WriteString(fmt.Sprintf("*Update Results* — %d app\\(s\\) in %s\n\n",
			len(apps), notify.EscapeMD(formatDuration(totalDur))))
	}

	for _, ar := range results {
		if ar.noContainers {
			sb.WriteString(fmt.Sprintf("⚠️ *%s* — no containers found\n\n", notify.EscapeMD(ar.appName)))
			continue
		}
		if !isSingle {
			sb.WriteString(fmt.Sprintf("*%s* _%s_\n", notify.EscapeMD(ar.appName), notify.EscapeMD(formatDuration(ar.dur))))
		}
		for _, cr := range ar.containers {
			// Truncate error messages — Docker output can include long stack traces
			// and spinner characters that trip MarkdownV2 length limits.
			errMsg := cr.res.Err
			if len(errMsg) > 300 {
				errMsg = errMsg[:300] + "…"
			}
			switch {
			case cr.timedOut:
				sb.WriteString(fmt.Sprintf("  ❌ `%s` — timed out \\(no response after %s\\)\n",
					notify.EscapeMD(cr.name), notify.EscapeMD(formatDuration(cr.timeoutAfter))))
			case cr.res.Rolled:
				sb.WriteString(fmt.Sprintf("  ⚠️ `%s` — new container failed health check, rolled back _%s_\n",
					notify.EscapeMD(cr.name), notify.EscapeMD(formatDuration(cr.dur))))
				if errMsg != "" {
					sb.WriteString(fmt.Sprintf("     `%s`\n", notify.EscapeMD(errMsg)))
				}
			case errMsg != "":
				sb.WriteString(fmt.Sprintf("  ❌ `%s` — %s\n", notify.EscapeMD(cr.name), notify.EscapeMD(errMsg)))
			case cr.res.AlreadyUpToDate:
				sb.WriteString(fmt.Sprintf("  ✔ `%s` — already up to date _%s_\n",
					notify.EscapeMD(cr.name), notify.EscapeMD(formatDuration(cr.dur))))
			case cr.res.Restarted:
				sb.WriteString(fmt.Sprintf("  ✅ `%s` — pulled \\+ recreated _%s_\n",
					notify.EscapeMD(cr.name), notify.EscapeMD(formatDuration(cr.dur))))
			default:
				sb.WriteString(fmt.Sprintf("  ❓ `%s` — unknown result\n", notify.EscapeMD(cr.name)))
			}
			if cr.res.Image != "" && !cr.res.AlreadyUpToDate && errMsg == "" && !cr.res.Rolled {
				sb.WriteString(fmt.Sprintf("     📦 `%s`\n", notify.EscapeMD(cr.res.Image)))
			}
		}
		if !isSingle {
			sb.WriteString("\n")
		}
	}

	if isSingle {
		sb.WriteString(fmt.Sprintf("\n⏱ _%s_", notify.EscapeMD(formatDuration(totalDur))))
	}

	msg := sb.String()
	if err := notify.SendRaw(tgCfg, msg); err != nil {
		// MarkdownV2 parse failure — Docker error output can contain characters
		// that trip Telegram even after EscapeMD (e.g. Unicode spinner frames).
		// Fall back to a plain summary so the user always gets a response.
		log.Printf("[update] SendRaw failed (%v) — sending plain fallback", err)
		plain := fmt.Sprintf("Update finished in %s — full results in container logs (docker logs prestoback).", formatDuration(totalDur))
		for _, ar := range results {
			for _, cr := range ar.containers {
				if cr.timedOut {
					plain += fmt.Sprintf("\n⚠️ %s: timed out", cr.name)
				} else if cr.res.Rolled {
					plain += fmt.Sprintf("\n⚠️ %s: health check failed, rolled back", cr.name)
				} else if cr.res.Err != "" {
					plain += fmt.Sprintf("\n❌ %s: failed", cr.name)
				} else if cr.res.Restarted {
					plain += fmt.Sprintf("\n✅ %s: updated", cr.name)
				} else if cr.res.AlreadyUpToDate {
					plain += fmt.Sprintf("\n✔ %s: already up to date", cr.name)
				}
			}
		}
		// SendRaw with no parse_mode for the fallback
		if err2 := notify.SendRawPlain(tgCfg, plain); err2 != nil {
			log.Printf("[update] plain fallback also failed: %v", err2)
		}
	}
}

func (s *Server) handleValidatePath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		errOut(w, 400, "path query param required")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		respond(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, 200, map[string]any{
		"ok":       true,
		"is_dir":   info.IsDir(),
		"readable": true,
	})
}

// ── Apps ──────────────────────────────────────────────────────────────────────

// GET /api/apps        → []AppConfig
// POST /api/apps       → create app (body: AppConfig with Volumes[])
//
// POST /api/apps also accepts a legacy body with a single `path` field for
// backwards compat with any existing scripts; it is promoted to a Volumes entry.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, 200, s.cfg.ListApps())
	case http.MethodPost:
		var a config.AppConfig
		if err := parseJSON(r, &a); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		if a.Name == "" {
			errOut(w, 400, "name is required")
			return
		}
		// Derive ID early so slug derivation can avoid a collision with it
		if a.ID == "" {
			a.ID = sanitizeID(a.Name)
		}
		// Legacy single-path promotion
		if len(a.Volumes) == 0 && a.Path != "" {
			slug := slugFromPathForID(a.Path, a.ID)
			a.Volumes = []config.VolumeConfig{{
				Slug:     slug,
				Path:     a.Path,
				Label:    slug,
				Excludes: a.Excludes,
				Enabled:  true,
			}}
			a.Path = ""
			a.Excludes = nil
		}
		if len(a.Volumes) == 0 {
			errOut(w, 400, "at least one volume is required")
			return
		}
		for _, v := range a.Volumes {
			if dupID, dupName, found := s.cfg.PathInUse(v.Path, a.ID); found {
				errOut(w, 409, fmt.Sprintf("path %q is already backed up under app %q (id: %s) — pick a different path, or use that app instead", v.Path, dupName, dupID))
				return
			}
		}
		if err := s.cfg.AddApp(a); err != nil {
			errOut(w, 409, err.Error())
			return
		}
		_ = s.cfg.Save()
		s.syncSchedule(a)
		respond(w, 201, a)
	default:
		errOut(w, 405, "method not allowed")
	}
}

// handleApp routes sub-paths under /api/apps/{id}/...
//
//	GET    /api/apps/{id}                  → AppConfig
//	PUT    /api/apps/{id}                  → update AppConfig
//	DELETE /api/apps/{id}[?purge=1]        → remove app; purge=1 also deletes backup dir
//	POST   /api/apps/{id}/backup           → trigger backup of all enabled volumes
//	POST   /api/apps/{id}/restore/{backupID} → restore a single volume archive
//	POST   /api/apps/{id}/volumes          → add a volume to an existing app
//	DELETE /api/apps/{id}/volumes/{slug}   → remove a volume from an app
func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/apps/")
	parts := strings.SplitN(tail, "/", 4)
	appID := parts[0]

	// POST /api/apps/{id}/backup
	if len(parts) == 2 && parts[1] == "backup" && r.Method == http.MethodPost {
		s.handleTriggerBackup(w, r, appID)
		return
	}
	// POST /api/apps/{id}/restore/{backupID}
	if len(parts) == 3 && parts[1] == "restore" && r.Method == http.MethodPost {
		s.handleRestore(w, r, appID, parts[2])
		return
	}
	// POST /api/apps/{id}/volumes  — add volume to existing app
	if len(parts) == 2 && parts[1] == "volumes" && r.Method == http.MethodPost {
		s.handleAddVolume(w, r, appID)
		return
	}
	// DELETE /api/apps/{id}/volumes/{slug}  — remove volume from app
	if len(parts) == 3 && parts[1] == "volumes" && r.Method == http.MethodDelete {
		s.handleRemoveVolume(w, r, appID, parts[2])
		return
	}
	// GET /api/apps/{id}/linked-containers — detect compose depends_on for this app
	if len(parts) == 2 && parts[1] == "linked-containers" && r.Method == http.MethodGet {
		s.handleLinkedContainers(w, r, appID)
		return
	}
	// POST /api/apps/{id}/lifecycle — start/stop/restart/pause/unpause, the
	// web dashboard's equivalent of the Telegram bot's lifecycle commands.
	if len(parts) == 2 && parts[1] == "lifecycle" && r.Method == http.MethodPost {
		s.handleAppLifecycle(w, r, appID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		a, ok := s.cfg.GetApp(appID)
		if !ok {
			errOut(w, 404, "app not found")
			return
		}
		respond(w, 200, a)

	case http.MethodPut:
		var a config.AppConfig
		if err := parseJSON(r, &a); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		a.ID = appID
		// Legacy single-path promotion on PUT too
		if len(a.Volumes) == 0 && a.Path != "" {
			slug := slugFromPathForID(a.Path, a.ID)
			a.Volumes = []config.VolumeConfig{{
				Slug:     slug,
				Path:     a.Path,
				Label:    slug,
				Excludes: a.Excludes,
				Enabled:  true,
			}}
			a.Path = ""
			a.Excludes = nil
		}
		// Mirror UpdateApp's own single-volume path-promotion here so the
		// collision check below sees the path that will actually be saved
		// (UpdateApp will harmlessly re-apply this — it's idempotent).
		if a.Path != "" && len(a.Volumes) == 1 && a.Path != a.Volumes[0].Path {
			a.Volumes[0].Path = a.Path
		}
		for _, v := range a.Volumes {
			if dupID, dupName, found := s.cfg.PathInUse(v.Path, a.ID); found {
				errOut(w, 409, fmt.Sprintf("path %q is already backed up under app %q (id: %s) — pick a different path, or use that app instead", v.Path, dupName, dupID))
				return
			}
		}
		if err := s.cfg.UpdateApp(a); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		_ = s.cfg.Save()
		s.syncSchedule(a)
		respond(w, 200, a)

	case http.MethodDelete:
		// ?purge=1 also removes the backup directory
		purge := r.URL.Query().Get("purge") == "1"
		if err := s.cfg.DeleteApp(appID); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		_ = s.cfg.Save()
		s.sched.Remove(appID)
		if purge {
			if err := s.engine.DeleteAppBackups(appID); err != nil {
				log.Printf("[delete] could not purge backup dir for %s: %v", appID, err)
			}
		}
		respond(w, 200, map[string]any{"deleted": appID, "purged": purge})

	default:
		errOut(w, 405, "method not allowed")
	}
}

// LinkedContainerCandidate is one compose-detected dependency surfaced to the
// Edit App UI, for the user to confirm (or not) as part of the pause/stop pipeline.
type LinkedContainerCandidate struct {
	ServiceName   string `json:"service_name"`             // as declared in depends_on, e.g. "database"
	ContainerName string `json:"container_name,omitempty"` // resolved sibling container name, if found
	Status        string `json:"status,omitempty"`
	Found         bool   `json:"found"`          // false if the service name didn't resolve to a live container
	AlreadyLinked bool   `json:"already_linked"` // true if this app's config already includes it
}

// GET /api/apps/{id}/linked-containers — detects compose depends_on for the
// app's currently matched container(s), so the Edit App UI can show "this
// app depends on: X, Y" and let the user opt these into the pause/stop
// pipeline. We only ever read the matched container's OWN depends_on label —
// never a reverse proxy's or anything else's — see ComposeDependencies.
func (s *Server) handleLinkedContainers(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}
	alreadyLinked := map[string]bool{}
	for _, n := range app.LinkedContainers {
		alreadyLinked[n] = true
	}

	containers := backup.FindContainers(appID)
	seen := map[string]bool{} // dedupe by service name, in case of multiple replicas
	var candidates []LinkedContainerCandidate
	for _, c := range containers {
		for _, link := range backup.ComposeDependencies(c.ID) {
			if seen[link.ServiceName] {
				continue
			}
			seen[link.ServiceName] = true
			cand := LinkedContainerCandidate{ServiceName: link.ServiceName}
			if link.Container != nil {
				cand.Found = true
				cand.ContainerName = link.Container.Name
				cand.Status = link.Container.Status
				cand.AlreadyLinked = alreadyLinked[link.Container.Name]
			}
			candidates = append(candidates, cand)
		}
	}
	if candidates == nil {
		candidates = []LinkedContainerCandidate{}
	}
	respond(w, 200, map[string]any{
		"detected":              candidates,
		"linked_containers_set": app.LinkedContainersSet,
	})
}

// handleAddVolume adds a new VolumeConfig to an existing app.
// Body: {"path": "/volumes/mosquitto/log", "label": "log", "excludes": []}
func (s *Server) handleAddVolume(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}
	var v config.VolumeConfig
	if err := parseJSON(r, &v); err != nil {
		errOut(w, 400, err.Error())
		return
	}
	if v.Path == "" {
		errOut(w, 400, "path is required")
		return
	}
	if v.Slug == "" {
		v.Slug = slugFromPath(v.Path)
	}
	if v.Label == "" {
		v.Label = v.Slug
	}
	v.Enabled = true
	// Check for duplicate slug within this app
	for _, existing := range app.Volumes {
		if existing.Slug == v.Slug {
			errOut(w, 409, fmt.Sprintf("volume slug '%s' already exists in app '%s'", v.Slug, appID))
			return
		}
	}
	app.Volumes = append(app.Volumes, v)
	if err := s.cfg.UpdateApp(app); err != nil {
		errOut(w, 500, err.Error())
		return
	}
	_ = s.cfg.Save()
	respond(w, 201, app)
}

// handleRemoveVolume removes a volume by slug from an app.
// The backup archives for that volume are NOT deleted automatically (use the
// backups endpoint to tidy up). The UI can offer a "also delete backups" checkbox.
func (s *Server) handleRemoveVolume(w http.ResponseWriter, r *http.Request, appID, slug string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}
	found := false
	filtered := app.Volumes[:0]
	for _, v := range app.Volumes {
		if v.Slug == slug {
			found = true
		} else {
			filtered = append(filtered, v)
		}
	}
	if !found {
		errOut(w, 404, fmt.Sprintf("volume slug '%s' not found in app '%s'", slug, appID))
		return
	}
	app.Volumes = filtered
	if err := s.cfg.UpdateApp(app); err != nil {
		errOut(w, 500, err.Error())
		return
	}
	_ = s.cfg.Save()
	respond(w, 200, app)
}

// ── Backup ────────────────────────────────────────────────────────────────────

func (s *Server) handleTriggerBackup(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}
	if s.engine.IsRunning(appID) {
		errOut(w, 409, "a job is already running for this app")
		return
	}
	respond(w, 202, map[string]string{"status": "accepted", "app_id": appID})
	go s.runBackup(app, false)
}

func (s *Server) runBackup(app config.AppConfig, scheduled bool) {
	// Refuse to run alongside an update/stack operation — QuiesceContainers
	// (stop/pause) racing standaloneRecreate's stop→rename→create→start
	// sequence on the same container is the same class of bug that produces
	// orphaned containers with stale network endpoints. A skipped scheduled
	// backup will simply run at its next scheduled time; a manual backup
	// can be retried once the update finishes.
	s.stateMu.Lock()
	busy := s.updateRunning
	s.stateMu.Unlock()
	if busy {
		s.engine.EmitLog(app.ID, "⏳ Skipped — an update or stack operation is currently in progress")
		log.Printf("[backup] skipping %s — update/stack operation in progress", app.ID)
		return
	}

	start := time.Now()
	emit := func(msg string) { s.engine.EmitLog(app.ID, msg) }

	prefix := "Manual"
	if scheduled {
		prefix = "Scheduled"
	}
	emit(fmt.Sprintf("━━━ %s backup started: %s ━━━", prefix, app.Name))

	vols := app.EnabledVolumes()
	if len(vols) == 0 {
		emit("⚠  No enabled volumes — nothing to back up")
		return
	}
	emit(fmt.Sprintf("Backing up %d volume(s): %s", len(vols), volumeNames(vols)))

	// Build VolumeTarget list early — needed for pre-flight checks before stopping containers.
	targets := make([]backup.VolumeTarget, len(vols))
	for i, v := range vols {
		targets[i] = backup.VolumeTarget{
			Slug:     v.Slug,
			Path:     v.Path,
			Excludes: v.Excludes,
		}
	}

	// ── Pre-flight: disk space check BEFORE stopping any containers ───────────
	// Stopping containers then discovering we're out of space causes unnecessary
	// downtime. We check all volumes up-front.
	if spaceErr := s.engine.CheckAllDiskSpace(app.ID, targets, emit); spaceErr != nil {
		emit("✗ Backup aborted (disk space): " + spaceErr.Error())
		s.hist.Append(history.Entry{
			Event:      history.EventBackupFail,
			AppID:      app.ID,
			AppName:    app.Name,
			Detail:     "disk space check failed: " + spaceErr.Error(),
			DurationMs: time.Since(start).Milliseconds(),
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name,
			Detail: "Insufficient disk space: " + spaceErr.Error(), IsError: true})
		return
	}

	// (Pre-backup command feature removed — no longer executed even if an
	// old config.json still has pre_backup_cmd set from before this was
	// removed from the UI. The field stays defined in AppConfig purely so
	// existing saved configs still parse without error; it's just inert.)

	containers := backup.FindContainers(app.ID)
	containers = append(containers, backup.ContainersByName(app.LinkedContainers)...)
	containers = backup.DedupeContainers(containers)
	if len(containers) == 0 {
		emit("⚠  No running containers found — backing up live files")
	}
	toResume, _ := backup.QuiesceContainers(containers, app.ContainerStrategy, emit)

	// Isolated in a closure so resume is guaranteed (via defer) the instant
	// BackupVolumes returns OR panics — same timing as before on the happy
	// path (no added downtime), but a panic here no longer (a) strands the
	// containers stopped/paused, or (b) crashes the entire PrestoBack process.
	var metas []backup.BackupMeta
	var err error
	func() {
		defer backup.ResumeContainers(toResume, app.ContainerStrategy, emit)
		defer func() {
			if rec := recover(); rec != nil {
				err = fmt.Errorf("internal error during backup: %v", rec)
				emit(fmt.Sprintf("✗ Internal error during backup: %v", rec))
				log.Printf("[backup] panic recovered for app %s: %v", app.ID, rec)
			}
		}()
		metas, err = s.engine.BackupVolumes(app.ID, app.Name, targets)
	}()

	dur := time.Since(start).Milliseconds()

	if err != nil {
		// Partial failure: some volumes may have succeeded
		failedSlugs := []string{}
		var totalSize int64
		for _, m := range metas {
			if m.Status == backup.StatusFailed {
				failedSlugs = append(failedSlugs, m.VolumeSlug)
			} else {
				totalSize += m.SizeBytes
			}
		}
		detail := fmt.Sprintf("failed volumes: %s", strings.Join(failedSlugs, ", "))
		emit("✗ Backup partially failed: " + detail)
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: detail, DurationMs: dur,
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: detail, IsError: true})
		// Still prune what succeeded
		_ = s.engine.PruneBackups(app.ID, app.Retain)
	} else {
		var totalSize int64
		for _, m := range metas {
			totalSize += m.SizeBytes
		}
		detail := fmt.Sprintf("%d volume(s), %.1f MB total, %dms", len(metas), float64(totalSize)/1e6, dur)
		s.hist.Append(history.Entry{
			Event: history.EventBackupSuccess, AppID: app.ID, AppName: app.Name,
			Detail: detail, SizeBytes: totalSize, DurationMs: dur,
		})
		s.dispatchNotify(notify.Event{Kind: "backup_success", AppName: app.Name, Detail: detail})
		_ = s.engine.PruneBackups(app.ID, app.Retain)
	}

	// ── Manifest ────────────────────────────────────────────────────────────
	// Written regardless of partial/full success — records exactly what we
	// have on disk for this run (files, sizes, hashes, duration).
	if manifestPath, mErr := s.engine.WriteManifest(app.ID, app.Name, metas, dur); mErr != nil {
		emit("⚠  Could not write backup manifest: " + mErr.Error())
	} else {
		emit("✓ Manifest written: " + filepath.Base(manifestPath))
	}

	emit("━━━ Backup complete ━━━")
}

// volumeNames returns a comma-separated list of volume slugs for logging.
func volumeNames(vols []config.VolumeConfig) string {
	names := make([]string, len(vols))
	for i, v := range vols {
		names[i] = v.Slug
	}
	return strings.Join(names, ", ")
}

// ── Restore ───────────────────────────────────────────────────────────────────
//
// POST /api/apps/{id}/restore/{backupID}
//
// The backupID encodes both volume and timestamp:
//   mosquitto_config_20250615_120000
//
// We look up the app, find which volume the archive belongs to (by slug),
// and restore into that volume's path.

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request, appID, backupID string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}
	if s.engine.IsRunning(appID) {
		errOut(w, 409, "a job is already running for this app")
		return
	}
	archivePath := filepath.Join(s.cfg.BackupDir(), appID, backupID+".tar.gz")
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		errOut(w, 404, "backup archive not found")
		return
	}

	// Determine which volume this archive belongs to, and thus its restore path.
	// backupID format: {appID}_{volumeSlug}_{timestamp}[_prerestore]
	volumeSlug := volumeSlugFromBackupID(appID, backupID)
	destPath := ""

	// Pass 1: exact slug match
	for _, v := range app.Volumes {
		if v.Slug == volumeSlug {
			destPath = v.Path
			break
		}
	}

	// Pass 2: if no exact slug match (common after adopt-at-parent-path where
	// the registered slug is "caddy" but the archive slug is "caddy_data"),
	// read the manifest to get the original source_path and use that instead —
	// the user told us where they want things to go during adopt, so
	// we pick the volume whose registered path is the best parent match for
	// the manifest's source_path.
	if destPath == "" {
		manifestPath := filepath.Join(s.cfg.BackupDir(), appID, backupID+"_manifest.json")
		if manifestData, err := os.ReadFile(manifestPath); err == nil {
			var mf backup.Manifest
			if err := json.Unmarshal(manifestData, &mf); err == nil {
				for _, ent := range mf.Entries {
					if ent.VolumeSlug == volumeSlug && ent.SourcePath != "" {
						// Find the registered volume whose path is the best
						// match — either an exact match, or is a parent of the
						// original source path (e.g. registered=/volumes/caddy,
						// source=/volumes/caddy/caddy_data → use /volumes/caddy).
						bestLen := -1
						for _, v := range app.Volumes {
							vClean := filepath.Clean(v.Path)
							sClean := filepath.Clean(ent.SourcePath)
							if vClean == sClean || strings.HasPrefix(sClean, vClean+"/") {
								if len(vClean) > bestLen {
									bestLen = len(vClean)
									destPath = v.Path
								}
							}
						}
						break
					}
				}
			}
		}
	}

	// Pass 3: single-volume app — just use the one registered path regardless
	// of slug. Handles the case where slug naming drifted from what was archived
	// (e.g. app renamed, or parent-path adoption changed the derived slug).
	if destPath == "" && len(app.Volumes) == 1 {
		destPath = app.Volumes[0].Path
		log.Printf("[restore] slug %q not matched, using single-volume fallback path %s", volumeSlug, destPath)
	}

	if destPath == "" {
		// Last resort: let the caller supply ?path=
		destPath = r.URL.Query().Get("path")
		if destPath == "" {
			errOut(w, 400, fmt.Sprintf(
				"cannot determine restore path for volume slug %q — no matching volume in app config, and no manifest source_path available. Add ?path=/volumes/... to override",
				volumeSlug))
			return
		}
	}

	respond(w, 202, map[string]string{"status": "accepted", "backup_id": backupID, "volume": volumeSlug, "dest": destPath})

	go func() {
		start := time.Now()
		emit := func(msg string) { s.engine.EmitLog(app.ID, msg) }
		emit(fmt.Sprintf("━━━ Restore started: %s [%s → %s] ━━━", app.Name, backupID, destPath))

		containers := backup.FindContainers(app.ID)
		containers = append(containers, backup.ContainersByName(app.LinkedContainers)...)
		containers = backup.DedupeContainers(containers)
		if len(containers) == 0 {
			emit("⚠  No running containers found")
		}
		toResume, _ := backup.QuiesceContainers(containers, app.ContainerStrategy, emit)

		var err error
		func() {
			defer backup.ResumeContainers(toResume, app.ContainerStrategy, emit)
			defer func() {
				if rec := recover(); rec != nil {
					err = fmt.Errorf("internal error during restore: %v", rec)
					emit(fmt.Sprintf("✗ Internal error during restore: %v", rec))
					log.Printf("[restore] panic recovered for app %s: %v", app.ID, rec)
				}
			}()
			err = s.engine.RestoreVolume(app.ID, app.Name, volumeSlug, archivePath, destPath)
		}()

		dur := time.Since(start).Milliseconds()
		if err != nil {
			emit("✗ Restore failed: " + err.Error())
			s.hist.Append(history.Entry{
				Event: history.EventRestoreFail, AppID: app.ID, AppName: app.Name,
				Detail: err.Error(), DurationMs: dur,
			})
			s.dispatchNotify(notify.Event{Kind: "restore_fail", AppName: app.Name, Detail: err.Error(), IsError: true})
			return
		}
		detail := fmt.Sprintf("Restored %s from %s (%dms)", volumeSlug, backupID, dur)
		s.hist.Append(history.Entry{
			Event: history.EventRestoreSuccess, AppID: app.ID, AppName: app.Name,
			Detail: detail, DurationMs: dur,
		})
		s.dispatchNotify(notify.Event{Kind: "restore_success", AppName: app.Name, Detail: detail})
		emit("━━━ Restore complete ━━━")
	}()
}

// volumeSlugFromBackupID extracts the slug from a backup ID.
// "mosquitto_config_20250615_120000"            → "config"
// "mosquitto_config_20250615_120000_prerestore"  → "config"
func volumeSlugFromBackupID(appID, backupID string) string {
	prefix := appID + "_"
	if !strings.HasPrefix(backupID, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(backupID, prefix)
	rest = strings.TrimSuffix(rest, "_prerestore")
	// Strip trailing _YYYYMMDD_HHMMSS (two underscore-separated segments)
	parts := strings.Split(rest, "_")
	if len(parts) < 3 {
		if len(parts) >= 1 {
			return parts[0]
		}
		return rest
	}
	slugParts := parts[:len(parts)-2]
	return strings.Join(slugParts, "_")
}

// ── Backups ───────────────────────────────────────────────────────────────────
//
// GET    /api/backups/{appID}                    → list archives (all volumes)
// DELETE /api/backups/{appID}/{backupID}         → delete one archive

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/backups/"), "/", 3)
	appID := parts[0]
	if appID == "" {
		errOut(w, 400, "app ID required")
		return
	}
	// Defense-in-depth: appID here comes straight from a URL path segment.
	// Go's http.ServeMux already collapses literal ".." before dispatch, and
	// SplitN naturally caps how much of the path can land in one segment, so
	// this was never practically exploitable beyond one directory level up —
	// but "provably low risk after testing" isn't the same as "intentionally
	// safe." This makes it safe by construction instead.
	if !appIDCharset.MatchString(appID) {
		errOut(w, 400, "invalid app ID")
		return
	}

	// GET /api/backups/{appID}/{backupID}/download — serve the archive file
	if len(parts) == 3 && parts[2] == "download" && r.Method == http.MethodGet {
		s.handleBackupDownload(w, r, appID, parts[1])
		return
	}

	switch r.Method {
	case http.MethodGet:
		metas, err := s.engine.ListBackups(appID)
		if err != nil {
			errOut(w, 500, err.Error())
			return
		}
		respond(w, 200, metas)
	case http.MethodDelete:
		if len(parts) < 2 || parts[1] == "" {
			errOut(w, 400, "backup ID required")
			return
		}
		archivePath := filepath.Join(s.cfg.BackupDir(), appID, parts[1]+".tar.gz")
		if err := s.engine.DeleteBackup(archivePath); err != nil {
			errOut(w, 500, err.Error())
			return
		}
		respond(w, 200, map[string]string{"deleted": parts[1]})
	default:
		errOut(w, 405, "method not allowed")
	}
}

// GET /api/backups/{appID}/{backupID}/download — serves the archive as a
// browser download. Works from any device: mobile browser, laptop, desktop.
// The file is streamed directly from disk — no memory buffering.
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request, appID, backupID string) {
	if backupID == "" {
		errOut(w, 400, "backup ID required")
		return
	}
	filename := backupID + ".tar.gz"
	archivePath := filepath.Join(s.cfg.BackupDir(), appID, filename)

	f, err := os.Open(archivePath)
	if err != nil {
		if os.IsNotExist(err) {
			errOut(w, 404, "backup archive not found")
			return
		}
		errOut(w, 500, err.Error())
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		errOut(w, 500, err.Error())
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, stat.ModTime(), f)
}

// ── Import a loose backup archive file ─────────────────────────────────────────
//
// POST /api/backups-import  (multipart: file=<.tar.gz>, app_id=<claimed owner>)
//
// This is for the "I only have one stray .tar.gz, not the whole backups/
// directory" case. PrestoBack's own archive names are unambiguous to verify
// against a CLAIMED app_id (filename must start with "{app_id}_" and match
// the full naming pattern) — but they are NOT safely splittable from
// scratch, because both the app_id and volume_slug segments use the same
// charset and either can contain underscores. So this endpoint trusts the
// app_id the client asked for, but independently verifies the filename is
// actually consistent with it before accepting — it never blindly believes
// an unverified claim. The client (see frontend) is responsible for
// proposing that app_id, either by matching it against already-registered
// apps, or via the Adopt Orphan flow for a brand new one.
//
// Character class includes '-' as well as '_': volume slugs are frequently
// derived directly from Docker volume/folder names (e.g. "homebox-data",
// "immich-postgres"), which commonly use hyphens. Every archive PrestoBack
// legitimately produces for such a volume was being permanently rejected by
// this endpoint before the hyphen was added here — e.g.
// "homebox_homebox-data_20260702_102658.tar.gz" failed validation even
// though it's a perfectly normal, correctly-named archive; nothing on the
// writing side was ever wrong, this check just hadn't caught up to what
// real volume names look like.
// appIDCharset matches a real PrestoBack app ID — exactly what sanitizeID
// produces (see config.go): lowercase letters, digits, underscore only. Used
// to explicitly validate any app_id arriving from a client (URL path segment
// or form field) before it's used in any filesystem path construction, so
// path-traversal safety doesn't depend on incidental interaction with other
// checks (see handleBackupsImport and handleBackups for where this closes
// that gap).
var appIDCharset = regexp.MustCompile(`^[a-z0-9_]+$`)

var backupArchiveNamePattern = regexp.MustCompile(`^[a-z0-9_-]+_[a-z0-9_-]+_\d{8}_\d{6}(_prerestore)?\.tar\.gz$`)

func (s *Server) handleBackupsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil { // 64MB memory threshold; larger files spill to disk automatically
		errOut(w, 400, "could not parse upload: "+err.Error())
		return
	}
	appID := strings.TrimSpace(r.FormValue("app_id"))
	if appID == "" {
		errOut(w, 400, "app_id required")
		return
	}
	// Explicit validation, not just reliance on the filename-prefix check
	// below happening to constrain it: app_id arrives as a raw multipart
	// form field with no inherent shape. Real app IDs are always produced by
	// sanitizeID (a-z, 0-9, underscore only — see config.go) — a hyphen or
	// any other character here means this isn't a real app_id at all, and
	// definitely isn't one PrestoBack would ever have generated. Checking
	// this up front means the safety of this endpoint no longer depends on
	// the filename-pattern check below happening to compose correctly with
	// it — it's correct by construction, not as a side effect.
	if !appIDCharset.MatchString(appID) {
		errOut(w, 400, "app_id contains invalid characters — expected only a-z, 0-9, and underscore")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		errOut(w, 400, "file required: "+err.Error())
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)
	if !backupArchiveNamePattern.MatchString(filename) {
		errOut(w, 400, "filename doesn't match PrestoBack's backup naming pattern (appid_volumeslug_YYYYMMDD_HHMMSS.tar.gz) — only PrestoBack's own archives can be smart-imported this way")
		return
	}
	if !strings.HasPrefix(filename, appID+"_") {
		errOut(w, 400, fmt.Sprintf("filename %q doesn't start with %q — it doesn't look like it belongs to this app", filename, appID+"_"))
		return
	}

	destDir := filepath.Join(s.cfg.BackupDir(), appID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		errOut(w, 500, "could not create backup directory: "+err.Error())
		return
	}
	destPath := filepath.Join(destDir, filename)
	if _, err := os.Stat(destPath); err == nil {
		errOut(w, 409, "a backup with this exact filename already exists for this app — nothing to do")
		return
	}

	out, err := os.Create(destPath)
	if err != nil {
		errOut(w, 500, "could not save file: "+err.Error())
		return
	}
	defer out.Close()
	written, err := io.Copy(out, file)
	if err != nil {
		out.Close()
		os.Remove(destPath) // don't leave a truncated, half-written archive lying around
		errOut(w, 500, "upload failed partway through: "+err.Error())
		return
	}

	_, isRegistered := s.cfg.GetApp(appID)
	respond(w, 200, map[string]any{
		"status":         "imported",
		"app_id":         appID,
		"filename":       filename,
		"size_bytes":     written,
		"app_registered": isRegistered,
	})
}

// ── Orphan backup directories ─────────────────────────────────────────────────
//
// GET    /api/backups-orphans                 → list dir names with no registered app
// GET    /api/backups-orphans/{dir}/inspect   → recover app_id/name/volume slugs from manifests, for the Adopt flow
// DELETE /api/backups-orphans/{dir}            → remove an orphaned backup directory

func (s *Server) handleOrphans(w http.ResponseWriter, r *http.Request) {
	// Build set of registered app IDs
	registered := map[string]bool{}
	for _, a := range s.cfg.ListApps() {
		registered[a.ID] = true
	}

	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/backups-orphans"), "/")

	switch r.Method {
	case http.MethodGet:
		if rest == "" {
			orphans, err := s.engine.OrphanedBackupDirs(registered)
			if err != nil {
				errOut(w, 500, err.Error())
				return
			}
			// Enrich with size info
			type orphanInfo struct {
				DirName   string `json:"dir_name"`
				SizeBytes int64  `json:"size_bytes"`
				Human     string `json:"human"`
			}
			var result []orphanInfo
			for _, name := range orphans {
				dir := filepath.Join(s.cfg.BackupDir(), name)
				var size int64
				_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
					if err == nil && info != nil && info.Mode().IsRegular() {
						size += info.Size()
					}
					return nil
				})
				result = append(result, orphanInfo{DirName: name, SizeBytes: size, Human: humanBytes(size)})
			}
			if result == nil {
				result = []orphanInfo{}
			}
			respond(w, 200, result)
			return
		}

		// GET /api/backups-orphans/{dir}/inspect
		parts := strings.SplitN(rest, "/", 2)
		dirName := parts[0]
		if len(parts) != 2 || parts[1] != "inspect" {
			errOut(w, 404, "not found")
			return
		}
		// Same reasoning as handleBackups: validate before any filesystem use
		// rather than rely on os.ReadDir simply failing harmlessly for a
		// malformed path. The DELETE branch below already guards this via a
		// resolved-path prefix check; this makes the GET branch consistent.
		if !appIDCharset.MatchString(dirName) {
			errOut(w, 400, "invalid directory name")
			return
		}
		if registered[dirName] {
			errOut(w, 409, fmt.Sprintf("'%s' is already a registered app", dirName))
			return
		}
		insp, err := s.engine.InspectOrphan(dirName)
		if err != nil {
			errOut(w, 404, err.Error())
			return
		}
		respond(w, 200, insp)

	case http.MethodDelete:
		// DELETE /api/backups-orphans/{dirName}
		dirName := rest
		if dirName == "" {
			errOut(w, 400, "dir name required")
			return
		}
		// Safety: must be orphaned
		if registered[dirName] {
			errOut(w, 409, fmt.Sprintf("'%s' is a registered app — use DELETE /api/apps/{id}?purge=1 instead", dirName))
			return
		}
		// Safety: must not escape backup dir
		target := filepath.Join(s.cfg.BackupDir(), dirName)
		if !strings.HasPrefix(target, s.cfg.BackupDir()) {
			errOut(w, 400, "invalid directory name")
			return
		}
		if err := os.RemoveAll(target); err != nil {
			errOut(w, 500, err.Error())
			return
		}
		respond(w, 200, map[string]string{"deleted": dirName})

	default:
		errOut(w, 405, "method not allowed")
	}
}

// ── API Key ───────────────────────────────────────────────────────────────────
//
// maskAPIKey returns a display-safe fingerprint of a key — enough to
// recognize "yes, that's my key" without revealing anything brute-forceable.
// Keys are 64-char hex (32 random bytes), so leaking 8 of 64 chars gives no
// meaningful advantage to an attacker.
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("•", len(key))
	}
	return key[:4] + strings.Repeat("•", 12) + key[len(key)-4:]
}

// GET /api/apikey → returns a masked fingerprint ONLY. The full key is
// returned exactly once, at regeneration time (see handleRegenKey below) —
// this endpoint must never hand the live key back out on a routine page
// load, since the API key also doubles as the JWT signing secret.
func (s *Server) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	respond(w, 200, map[string]any{
		"masked":       maskAPIKey(s.cfg.APIKey()),
		"usage_header": "X-API-Key",
		"usage_param":  "api_key",
	})
}

// ── Self-update ───────────────────────────────────────────────────────────────

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.image == "" {
		respond(w, 200, map[string]any{"available": false, "reason": "PRESTOBACK_IMAGE not set"})
		return
	}
	hasUpdate, local, remote, err := backup.ForceCheckForUpdate(s.image)
	if err != nil {
		respond(w, 200, map[string]any{"available": false, "error": err.Error()})
		return
	}
	respond(w, 200, map[string]any{
		"available":     hasUpdate,
		"local_digest":  local,
		"remote_digest": remote,
		"image":         s.image,
		"locally_built": local == "local-build",
	})
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	if s.image == "" || s.selfName == "" {
		errOut(w, 400, "PRESTOBACK_IMAGE and PRESTOBACK_CONTAINER must be set")
		return
	}
	respond(w, 202, map[string]string{"status": "update started"})
	go func() {
		if err := backup.SelfUpdate(s.image, s.selfName, s.engine.AnyRunning, s.engine.EmitUpdate); err != nil {
			log.Printf("self-update error: %v", err)
			s.engine.EmitUpdate(backup.UpdateResult{Stage: "error", Message: "Update failed", Error: err.Error()})
		}
	}()
}

// ── Cron preview ──────────────────────────────────────────────────────────────

func (s *Server) handleCronPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	expr := r.URL.Query().Get("expr")
	if expr == "" {
		errOut(w, 400, "missing cron expression")
		return
	}

	description := scheduler.DescribeCron(expr)
	nextRuns := scheduler.NextRunsForExpr(expr, 5, time.Now())

	respond(w, 200, map[string]interface{}{
		"description": description,
		"next_runs":   nextRuns,
	})
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

func (s *Server) loadSchedules() {
	for _, app := range s.cfg.ListApps() {
		s.syncSchedule(app)
	}
}

func (s *Server) syncSchedule(app config.AppConfig) {
	if !app.Schedule.Enabled || app.Pinned || app.Schedule.CronExpr == "" {
		s.sched.Remove(app.ID)
		return
	}
	a := app
	s.sched.Upsert(scheduler.Job{
		ID:       app.ID,
		CronExpr: app.Schedule.CronExpr,
		Fn: func() {
			// Respect maintenance mode — skip this run silently.
			if s.inMaintenance() {
				log.Printf("[scheduler] skipping %s — maintenance mode active until %s", a.ID, s.getMaintUntil().Format(time.RFC3339))
				return
			}
			current, ok := s.cfg.GetApp(a.ID)
			if !ok || current.Pinned || !current.Schedule.Enabled {
				return
			}
			if s.engine.IsRunning(current.ID) {
				log.Printf("[scheduler] skipping %s — job already running", current.ID)
				return
			}
			s.runBackup(current, true)
		},
	})
}

// ── Telegram bot ──────────────────────────────────────────────────────────────

// prestoBackBotCommands returns the full list of bot commands registered with
// Telegram's setMyCommands API. This is what populates the "/" autocomplete
// picker in every Telegram client. Command names must be lowercase, no slash.
func prestoBackBotCommands() []notify.BotCommand {
	return []notify.BotCommand{
		{Command: "status", Description: "All apps with paths, schedules, and backup retain counts"},
		{Command: "apps", Description: "Compact app overview with readable schedule descriptions"},
		{Command: "backup", Description: "Trigger a backup — /backup <name> or pick from list"},
		{Command: "history", Description: "Last 10 events — or /history <name> to filter by app"},
		{Command: "logs", Description: "Detailed recent backups for one app — /logs <name>"},
		{Command: "disk", Description: "Backup directory disk usage (free / used / total)"},
		{Command: "next", Description: "Upcoming scheduled backup times across all apps"},
		{Command: "check", Description: "Check for image updates now (registry check, no downloads)"},
		{Command: "start", Description: "Start a stopped container — /start <name>"},
		{Command: "stop", Description: "Stop a running container — /stop <name>"},
		{Command: "restart", Description: "Restart a container — /restart <name>"},
		{Command: "pause", Description: "Freeze a container (SIGSTOP) — /pause <name>"},
		{Command: "unpause", Description: "Resume a frozen container — /unpause <name>"},
		{Command: "stack", Description: "Whole-stack control — /stack up|down|restart|pull|ps"},
		{Command: "schedpause", Description: "Disable an app's backup schedule — /schedpause <name>"},
		{Command: "schedresume", Description: "Re-enable a backup schedule — /schedresume <name>"},
		{Command: "maintenance", Description: "Freeze all schedules — /maintenance 2h / 1d / 1w / on / off"},
		{Command: "update", Description: "Pull + recreate a container — /update <name> or /update all"},
		{Command: "settings", Description: "Show current notification and app configuration"},
		{Command: "selfupdate", Description: "Check for a new PrestoBack image and apply it"},
		{Command: "help", Description: "Show all available commands"},
	}
}

func (s *Server) runTelegramBot() {
	// Send a startup notification so the user knows PrestoBack is online —
	// especially useful after a /selfupdate restart where the user is waiting
	// to know the new version came up cleanly.
	go func() {
		time.Sleep(3 * time.Second) // wait for initial config to load
		nc := s.cfg.GetNotify()
		if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
			_ = notify.SendRaw(
				notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID},
				fmt.Sprintf("🟢 *PrestoBack online* — v%s\nType /help for available commands\\.", notify.EscapeMD(config.Version)),
			)
		}
	}()

	// Register commands with Telegram so the "/" autocomplete picker is populated.
	// Runs after the startup notification so the token is confirmed working first.
	go func() {
		time.Sleep(5 * time.Second)
		nc := s.cfg.GetNotify()
		if nc.TelegramEnabled && nc.TelegramToken != "" {
			cmds := prestoBackBotCommands()
			if err := notify.SetMyCommands(nc.TelegramToken, cmds); err != nil {
				log.Printf("[bot] setMyCommands: %v", err)
			} else {
				log.Printf("[bot] registered %d commands with Telegram autocomplete", len(cmds))
			}
		}
	}()

	offset := 0
	for {
		nc := s.cfg.GetNotify()
		if !nc.TelegramEnabled || nc.TelegramToken == "" {
			time.Sleep(30 * time.Second)
			continue
		}
		updates, err := notify.GetUpdates(nc.TelegramToken, offset)
		if err != nil {
			time.Sleep(15 * time.Second)
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			if u.Message != nil {
				s.handleTelegramCommand(nc, u.Message)
			}
			if u.CallbackQuery != nil {
				s.handleTelegramCallback(nc, u.CallbackQuery)
			}
		}
		if len(updates) == 0 {
			time.Sleep(2 * time.Second)
		}
	}
}

func (s *Server) handleTelegramCommand(nc config.NotifyConfig, msg *notify.TelegramMessage) {
	tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}

	// Security: verify BOTH the chat the message came from AND the sender's
	// user ID match the configured chat ID. This prevents two attack vectors:
	// 1. Messages from strangers in direct chat (Chat.ID check)
	// 2. Messages from other members in a group chat where the bot is a member
	//    but only the admin's user ID should be able to run commands (From.ID check)
	chatIDStr := fmt.Sprintf("%d", msg.Chat.ID)
	fromIDStr := fmt.Sprintf("%d", msg.From.ID)
	if chatIDStr != nc.TelegramChatID && fromIDStr != nc.TelegramChatID {
		// Neither the chat nor the sender matches — silently ignore.
		// No response: telling strangers the bot exists is itself a security leak.
		log.Printf("[bot] rejected message from chat=%s from=%s (not authorised)", chatIDStr, fromIDStr)
		return
	}

	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}
	// Strip bot@username suffix that Telegram adds in group chats: /backup@MyBot → /backup
	parts := strings.SplitN(text, " ", 2)
	cmd := strings.SplitN(parts[0], "@", 2)[0]
	arg := ""
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}

	switch cmd {
	case "/status":
		apps := s.cfg.ListApps()
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("*PrestoBack v%s*\n🐳 *%d apps*\n\n", notify.EscapeMD(config.Version), len(apps)))
		for _, a := range apps {
			badges := ""
			if a.Pinned {
				badges += " 📌"
			}
			if s.engine.IsRunning(a.ID) {
				badges += " ⏳"
			}
			schedInfo := "manual"
			if a.Schedule.Enabled {
				schedInfo = notify.EscapeMD(a.Schedule.CronExpr)
			}
			sb.WriteString(fmt.Sprintf("• `%s`%s\n  📁 `%s`\n  🗓 `%s` · retain %d\n\n",
				notify.EscapeMD(a.Name), badges,
				notify.EscapeMD(a.PrimaryPath()),
				schedInfo, a.Retain))
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send status: %v", err)
		}

	case "/backup":
		if arg == "" {
			s.sendTelegramAppList(tgCfg, "backup")
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ App not found: `%s`", notify.EscapeMD(arg)))
			return
		}
		if s.engine.IsRunning(app.ID) {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⏳ `%s` — a job is already running", notify.EscapeMD(app.Name)))
			return
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("▶ Backup started for `%s`", notify.EscapeMD(app.Name)))
		go s.runBackup(*app, false)

	case "/history":
		// /history           → last 10 events across all apps
		// /history <name>    → last 10 events for that specific app
		allEntries := s.hist.List(50)
		var entries []history.Entry
		if arg == "" {
			if len(allEntries) > 10 {
				entries = allEntries[:10]
			} else {
				entries = allEntries
			}
		} else {
			lower := strings.ToLower(arg)
			for _, e := range allEntries {
				if strings.Contains(strings.ToLower(e.AppName), lower) || strings.Contains(strings.ToLower(e.AppID), lower) {
					entries = append(entries, e)
					if len(entries) == 10 {
						break
					}
				}
			}
		}
		var sb strings.Builder
		if arg == "" {
			sb.WriteString("*Recent history \\(last 10\\)*\n\n")
		} else {
			sb.WriteString(fmt.Sprintf("*History — %s \\(last 10\\)*\n\n", notify.EscapeMD(arg)))
		}
		for _, e := range entries {
			icon := "✅"
			if strings.Contains(string(e.Event), "fail") {
				icon = "❌"
			}
			sb.WriteString(fmt.Sprintf("%s `%s` — %s\n_%s_\n\n",
				icon,
				notify.EscapeMD(e.AppName),
				notify.EscapeMD(string(e.Event)),
				notify.EscapeMD(e.Time.Format("02 Jan 15:04")),
			))
		}
		if len(entries) == 0 {
			sb.WriteString("No history yet\\.")
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send history: %v", err)
		}

	case "/settings":
		n := s.cfg.GetNotify()
		apps := s.cfg.ListApps()
		scheduledCount := 0
		for _, a := range apps {
			if a.Schedule.Enabled {
				scheduledCount++
			}
		}
		var sb strings.Builder
		sb.WriteString("*PrestoBack Settings*\n\n")
		sb.WriteString(fmt.Sprintf("🐳 *Apps:* `%d` \\(%d scheduled\\)\n", len(apps), scheduledCount))
		sb.WriteString(fmt.Sprintf("🔔 *Telegram:* `%s`\n", boolStr(n.TelegramEnabled)))
		sb.WriteString(fmt.Sprintf("💬 *Discord:* `%s`\n", boolStr(n.DiscordEnabled)))
		sb.WriteString(fmt.Sprintf("📣 *Ntfy:* `%s`\n", boolStr(n.NtfyEnabled)))
		sb.WriteString(fmt.Sprintf("🔗 *Webhook:* `%s`\n", boolStr(n.WebhookEnabled)))
		sb.WriteString("\n*Notify on:*\n")
		sb.WriteString(fmt.Sprintf("  ✅ Backup success: `%s`\n", boolStr(n.OnBackupSuccess)))
		sb.WriteString(fmt.Sprintf("  ❌ Backup fail: `%s`\n", boolStr(n.OnBackupFail)))
		sb.WriteString(fmt.Sprintf("  ✅ Restore success: `%s`\n", boolStr(n.OnRestoreSuccess)))
		sb.WriteString(fmt.Sprintf("  ❌ Restore fail: `%s`\n", boolStr(n.OnRestoreFail)))
		if s.image != "" {
			sb.WriteString(fmt.Sprintf("\n🐋 *Image:* `%s`\n", notify.EscapeMD(s.image)))
		}
		sb.WriteString(fmt.Sprintf("📦 *Version:* `%s`\n", notify.EscapeMD(config.Version)))
		// /update compose config
		if s.cfg.ComposeFile != "" {
			sb.WriteString(fmt.Sprintf("🔄 *Compose file:* `%s`\n", notify.EscapeMD(s.cfg.ComposeFile)))
		} else {
			sb.WriteString("🔄 *Compose file:* _not set_ \\(/update help for setup\\)\n")
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send settings: %v", err)
		}

	case "/selfupdate":
		if s.image == "" || s.selfName == "" {
			_ = notify.SendRaw(tgCfg, "❌ Self\\-update not available: `PRESTOBACK_IMAGE` and `PRESTOBACK_CONTAINER` must be set in your compose config\\.")
			return
		}
		_ = notify.SendRaw(tgCfg, "🔍 Checking for updates\\.\\.\\.")
		hasUpdate, local, remote, err := backup.ForceCheckForUpdate(s.image)
		if err != nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Update check failed: `%s`", notify.EscapeMD(err.Error())))
			return
		}
		localShort := local
		if len(localShort) > 12 {
			localShort = localShort[:12]
		}
		remoteShort := remote
		if len(remoteShort) > 12 {
			remoteShort = remoteShort[:12]
		}
		if !hasUpdate {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("✅ Already up to date\\.\nDigest: `%s`", notify.EscapeMD(localShort)))
			return
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"🆕 Update available\\!\n📦 Local: `%s`\n🌐 Remote: `%s`\n\nPulling and restarting now\\. PrestoBack will briefly go offline — you'll get backup notifications once it's back\\.",
			notify.EscapeMD(localShort),
			notify.EscapeMD(remoteShort),
		))
		go func() {
			if err := backup.SelfUpdate(s.image, s.selfName, s.engine.AnyRunning, s.engine.EmitUpdate); err != nil {
				log.Printf("[bot] selfupdate: %v", err)
				_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Self\\-update failed: `%s`", notify.EscapeMD(err.Error())))
			}
			// If SelfUpdate succeeds, the container is replaced — this goroutine
			// will never reach here. The "back online" message must be sent
			// on startup instead (see the startup notification in runTelegramBot).
		}()

	case "/apps":
		// Compact overview: name, badges, human schedule, volume count, retain
		apps := s.cfg.ListApps()
		nextRunMap := map[string]time.Time{}
		for _, nr := range s.sched.NextRuns() {
			nextRunMap[nr.AppID] = nr.NextRun
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("*Apps \\(%d\\)*\n\n", len(apps)))
		for _, a := range apps {
			// Badges
			badges := ""
			if a.Pinned {
				badges += " 📌"
			}
			if s.engine.IsRunning(a.ID) {
				badges += " ⏳"
			}
			if a.Schedule.Enabled && a.Schedule.CronExpr != "" {
				badges += " 🗓"
			}

			// Schedule description
			schedLine := "manual"
			if a.Schedule.Enabled && a.Schedule.CronExpr != "" {
				schedLine = scheduler.DescribeCron(a.Schedule.CronExpr)
				if nr, ok := nextRunMap[a.ID]; ok {
					schedLine += fmt.Sprintf(" \\(next: %s\\)", notify.EscapeMD(nr.Format("02 Jan 15:04")))
				}
			} else if !a.Schedule.Enabled && a.Schedule.CronExpr != "" {
				schedLine = "⏸ paused"
			}

			// Volume count
			volCount := len(a.EnabledVolumes())
			volLabel := "vol"
			if volCount != 1 {
				volLabel = "vols"
			}

			sb.WriteString(fmt.Sprintf("• *%s*%s\n  🗓 %s\n  📦 %d %s · retain %d\n\n",
				notify.EscapeMD(a.Name), badges,
				notify.EscapeMD(schedLine),
				volCount, volLabel, a.Retain,
			))
		}
		if len(apps) == 0 {
			sb.WriteString("No apps registered yet\\.")
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send apps: %v", err)
		}

	case "/disk":
		stat, err := diskUsage(s.cfg.BackupDir())
		if err != nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Could not read disk: `%s`", notify.EscapeMD(err.Error())))
			return
		}
		used := stat.total - stat.free
		pct := 0
		if stat.total > 0 {
			pct = int(100 * used / stat.total)
		}
		// Build a simple 10-char bar
		filled := pct / 10
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 10-filled)
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"*Backup Disk Usage*\n\n"+
				"📁 `%s`\n"+
				"💾 Used: `%s`\n"+
				"🆓 Free: `%s`\n"+
				"📦 Total: `%s`\n"+
				"`%s` %d%%",
			notify.EscapeMD(s.cfg.BackupDir()),
			notify.EscapeMD(humanBytes(int64(used))),
			notify.EscapeMD(humanBytes(int64(stat.free))),
			notify.EscapeMD(humanBytes(int64(stat.total))),
			bar, pct,
		))

	case "/next":
		nextRuns := s.sched.NextRuns()
		if len(nextRuns) == 0 {
			_ = notify.SendRaw(tgCfg, "📭 No scheduled backups configured\\.")
			return
		}
		// Sort by next run time
		sorted := make([]scheduler.NextRunInfo, len(nextRuns))
		copy(sorted, nextRuns)
		for i := 1; i < len(sorted); i++ {
			for j := i; j > 0 && sorted[j].NextRun.Before(sorted[j-1].NextRun); j-- {
				sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
			}
		}
		now := time.Now()
		var sb strings.Builder
		sb.WriteString("*Upcoming Backups*\n\n")
		for _, nr := range sorted {
			app, ok := s.cfg.GetApp(nr.AppID)
			name := nr.AppID
			if ok {
				name = app.Name
			}
			diff := nr.NextRun.Sub(now)
			var countdown string
			switch {
			case diff < time.Minute:
				countdown = "< 1 min"
			case diff < time.Hour:
				countdown = fmt.Sprintf("%d min", int(diff.Minutes()))
			case diff < 24*time.Hour:
				h := int(diff.Hours())
				m := int(diff.Minutes()) % 60
				if m > 0 {
					countdown = fmt.Sprintf("%dh %dm", h, m)
				} else {
					countdown = fmt.Sprintf("%dh", h)
				}
			default:
				countdown = fmt.Sprintf("%dd %dh", int(diff.Hours())/24, int(diff.Hours())%24)
			}
			sb.WriteString(fmt.Sprintf("⏰ *%s*\n   %s _\\(%s\\)_\n\n",
				notify.EscapeMD(name),
				notify.EscapeMD(nr.NextRun.Format("02 Jan 15:04")),
				notify.EscapeMD(countdown),
			))
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send next: %v", err)
		}

	case "/check":
		_ = notify.SendRaw(tgCfg, "🔍 Checking for image updates \\(registry check — no downloads\\)\\.\\.\\.")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[bot] PANIC in /check: %v", r)
				}
			}()
			reports, dockerOK := s.checkForUpdates(false) // false: we send our own message below, not the debounced alert
			if !dockerOK {
				_ = notify.SendRaw(tgCfg, "⚠️ Can't reach Docker right now \\(daemon may be restarting\\) — nothing was checked\\. Try again in a moment\\.")
				return
			}
			if len(reports) == 0 {
				_ = notify.SendRaw(tgCfg, "✅ Everything is up to date\\.")
				return
			}
			text, btns := buildUpdateReportMessage(reports)
			_ = notify.SendRawWithButtons(tgCfg, text, btns)
		}()

	case "/logs":
		if arg == "" {
			_ = notify.SendRaw(tgCfg, "Usage: `/logs \\<app name\\>`")
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ App not found: `%s`", notify.EscapeMD(arg)))
			return
		}
		all := s.hist.List(200)
		var entries []history.Entry
		for _, e := range all {
			if e.AppID == app.ID {
				entries = append(entries, e)
				if len(entries) == 5 {
					break
				}
			}
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("*Logs — %s*\n\n", notify.EscapeMD(app.Name)))
		if len(entries) == 0 {
			sb.WriteString("No history for this app yet\\.")
		}
		for _, e := range entries {
			icon := "✅"
			if strings.Contains(string(e.Event), "fail") {
				icon = "❌"
			}
			sb.WriteString(fmt.Sprintf("%s *%s*\n", icon, notify.EscapeMD(string(e.Event))))
			sb.WriteString(fmt.Sprintf("   🕐 _%s_\n", notify.EscapeMD(e.Time.Format("02 Jan 2006 15:04"))))
			if e.Detail != "" {
				sb.WriteString(fmt.Sprintf("   📋 `%s`\n", notify.EscapeMD(e.Detail)))
			}
			if e.SizeBytes > 0 {
				sb.WriteString(fmt.Sprintf("   💾 %s\n", notify.EscapeMD(humanBytes(e.SizeBytes))))
			}
			if e.DurationMs > 0 {
				sb.WriteString(fmt.Sprintf("   ⏱ %s\n", notify.EscapeMD(formatDurationMs(e.DurationMs))))
			}
			sb.WriteString("\n")
		}
		if err := notify.SendRaw(tgCfg, sb.String()); err != nil {
			log.Printf("[bot] send logs: %v", err)
		}

	case "/schedpause":
		if arg == "" {
			_ = notify.SendRaw(tgCfg, "Usage: `/schedpause \\<app name\\>`")
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ App not found: `%s`", notify.EscapeMD(arg)))
			return
		}
		if !app.Schedule.Enabled {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⚠️ `%s` schedule is already paused", notify.EscapeMD(app.Name)))
			return
		}
		app.Schedule.Enabled = false
		if err := s.cfg.UpdateApp(*app); err != nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Failed to update: `%s`", notify.EscapeMD(err.Error())))
			return
		}
		_ = s.cfg.Save()
		s.syncSchedule(*app) // removes the job from the scheduler
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("⏸ *%s* — schedule paused\nUse /schedresume %s to re\\-enable\\.",
			notify.EscapeMD(app.Name), notify.EscapeMD(app.Name)))

	case "/schedresume":
		if arg == "" {
			_ = notify.SendRaw(tgCfg, "Usage: `/schedresume \\<app name\\>`")
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ App not found: `%s`", notify.EscapeMD(arg)))
			return
		}
		if app.Schedule.CronExpr == "" {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⚠️ `%s` has no cron expression configured — edit the app first", notify.EscapeMD(app.Name)))
			return
		}
		if app.Schedule.Enabled {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⚠️ `%s` schedule is already active \\(%s\\)",
				notify.EscapeMD(app.Name), notify.EscapeMD(scheduler.DescribeCron(app.Schedule.CronExpr))))
			return
		}
		app.Schedule.Enabled = true
		if err := s.cfg.UpdateApp(*app); err != nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Failed to update: `%s`", notify.EscapeMD(err.Error())))
			return
		}
		_ = s.cfg.Save()
		s.syncSchedule(*app) // re-upserts the job into the scheduler
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("▶ *%s* — schedule resumed\n🗓 %s",
			notify.EscapeMD(app.Name),
			notify.EscapeMD(scheduler.DescribeCron(app.Schedule.CronExpr))))

	case "/start":
		s.handleContainerLifecycle(tgCfg, arg, "start")

	case "/stop":
		s.handleContainerLifecycle(tgCfg, arg, "stop")

	case "/restart":
		s.handleContainerLifecycle(tgCfg, arg, "restart")

	case "/pause":
		s.handleContainerLifecycle(tgCfg, arg, "pause")

	case "/unpause":
		s.handleContainerLifecycle(tgCfg, arg, "unpause")

	case "/stack":
		s.handleStackCommand(tgCfg, strings.ToLower(strings.TrimSpace(arg)))

	case "/maintenance":
		lower := strings.ToLower(strings.TrimSpace(arg))
		if lower == "" {
			// Show current status
			s.stateMu.Lock()
			until := s.maintUntil
			s.stateMu.Unlock()
			if until.IsZero() || time.Now().After(until) {
				_ = notify.SendRaw(tgCfg,
					"🟢 *Maintenance mode off* — schedules running normally\\.\n\n"+
						"Usage: `/maintenance 2h` `/maintenance 1d` `/maintenance 1w` `/maintenance on` `/maintenance off`")
			} else {
				remaining := time.Until(until)
				_ = notify.SendRaw(tgCfg, fmt.Sprintf(
					"🔧 *Maintenance mode active*\n⏰ Expires: %s \\(%s remaining\\)\n\nUse `/maintenance off` to end early\\.",
					notify.EscapeMD(until.Local().Format("02 Jan 15:04")),
					notify.EscapeMD(formatDuration(remaining)),
				))
			}
			return
		}
		if lower == "off" {
			s.stateMu.Lock()
			s.maintUntil = time.Time{}
			s.stateMu.Unlock()
			_ = notify.SendRaw(tgCfg, "🟢 *Maintenance mode off* — all enabled schedules will run at their next time\\.")
			return
		}
		dur, ok := parseMaintDuration(lower)
		if !ok {
			_ = notify.SendRaw(tgCfg, "❌ Unknown duration\\. Examples:\n`/maintenance 2h` — 2 hours\n`/maintenance 1d` — 1 day\n`/maintenance 1w` — 1 week\n`/maintenance on` — indefinite\n`/maintenance off` — cancel")
			return
		}
		until := time.Now().Add(dur)
		s.stateMu.Lock()
		s.maintUntil = until
		s.stateMu.Unlock()
		// Count how many scheduled apps are affected
		affected := 0
		for _, a := range s.cfg.ListApps() {
			if a.Schedule.Enabled && !a.Pinned {
				affected++
			}
		}
		if lower == "on" {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"🔧 *Maintenance mode on* — %d scheduled app\\(s\\) paused indefinitely\\.\n\nNote: resets on container restart\\. Use `/maintenance off` to end early\\.",
				affected,
			))
		} else {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"🔧 *Maintenance mode on*\n⏰ Auto\\-resumes at %s \\(%s\\)\n🐳 %d scheduled app\\(s\\) paused\n\nUse `/maintenance off` to end early\\.",
				notify.EscapeMD(until.Local().Format("02 Jan 15:04")),
				notify.EscapeMD(formatDuration(dur)),
				affected,
			))
			// Goroutine fires a Telegram notification when maintenance expires.
			go func(resumeAt time.Time) {
				time.Sleep(time.Until(resumeAt))
				s.stateMu.Lock()
				stillSet := s.maintUntil.Equal(resumeAt)
				if stillSet {
					s.maintUntil = time.Time{}
				}
				s.stateMu.Unlock()
				if !stillSet {
					return // user changed it in the meantime
				}
				nc := s.cfg.GetNotify()
				if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
					cfg2 := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
					_ = notify.SendRaw(cfg2, "🟢 *Maintenance window ended* — scheduled backups have resumed\\.")
				}
			}(until)
		}

	case "/update":
		lower := strings.ToLower(strings.TrimSpace(arg))
		if lower == "" {
			// No arg — show app picker with an "Update ALL" option at top
			s.sendTelegramAppList(tgCfg, "update")
			return
		}
		if lower == "help" {
			composeStatus := "not set \\(standalone recreate active\\)"
			if s.cfg.ComposeFile != "" {
				composeStatus = fmt.Sprintf("✅ `%s`", notify.EscapeMD(s.cfg.ComposeFile))
			}
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"*\\/update — how it works*\n\n"+
					"*Compose file:* %s\n\n"+
					"*Default \\(no compose file needed\\):*\n"+
					"PrestoBack reads the full container config from the Docker socket, "+
					"pulls the new image, stops the old container, and recreates it with "+
					"identical volumes, ports, networks, env vars, and restart policy\\. "+
					"If the new container fails its health check within 30s, the old one "+
					"is automatically restarted \\(rollback\\)\\.\n\n"+
					"*Optional — compose file \\(tried first, falls back automatically\\):*\n"+
					"If `PRESTOBACK\\_COMPOSE\\_FILE` is set, `/update` tries compose first and "+
					"silently falls back to standalone recreate on any failure \\(including a "+
					"partially\\-mounted project directory\\) — so it's safe to set even if your "+
					"mount isn't complete\\. `/stack` commands have no such fallback and require the "+
					"*entire* project directory mounted \\(not just the compose file\\) so `\\.env` and "+
					"per\\-service `env\\_file:` references resolve correctly:\n"+
					"```yaml\n"+
					"environment:\n"+
					"  PRESTOBACK_COMPOSE_FILE: ${PWD}/docker-compose.yml\n"+
					"volumes:\n"+
					"  - ${PWD}:${PWD}:ro\n"+
					"```\n"+
					"Use `/selfupdate` to update PrestoBack itself\\.",
				composeStatus,
			))
			return
		}
		if lower == "all" {
			targets := s.cfg.ListApps()
			sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
			if len(targets) == 0 {
				_ = notify.SendRaw(tgCfg, "❌ No apps registered\\.")
				return
			}
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"🔄 Pulling latest images for *%d* app\\(s\\)\\. Results incoming when complete\\.\\.\\.",
				len(targets),
			))
			go s.runContainerUpdates(tgCfg, targets)
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"❌ App not found: `%s`\nUse /update with no args to pick from list\\.",
				notify.EscapeMD(arg),
			))
			return
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("🔄 Pulling `%s`\\.\\.\\.", notify.EscapeMD(app.Name)))
		go s.runContainerUpdates(tgCfg, []config.AppConfig{*app})

	case "/help":
		// NOTE: every special MarkdownV2 character in this literal must be escaped with \.
		// Reserved chars: _ * [ ] ( ) ~ ` > # + - = | { } . !
		// The | in <name|all> and () throughout are the most common sources of 400 errors.
		help := "*PrestoBack Bot Commands*\n\n" +
			"*Backups*\n" +
			"📊 /status — all apps with paths, cron, retain counts\n" +
			"📱 /apps — compact overview with readable schedules\n" +
			"▶ /backup \\<name\\> — trigger a backup \\(or pick from list\\)\n" +
			"📜 /history — last 10 events \\(or /history \\<name\\> to filter\\)\n" +
			"🔍 /logs \\<name\\> — detailed recent backups for one app\n" +
			"💾 /disk — backup directory disk usage\n" +
			"⏰ /next — upcoming scheduled backup times\n" +
			"🔍 /check — check for image updates now \\(registry check, no downloads\\)\n" +
			"⏸ /schedpause \\<name\\> — disable an app's backup schedule\n" +
			"▶ /schedresume \\<name\\> — re\\-enable an app's backup schedule\n" +
			"🔧 /maintenance \\<2h/1d/1w/on/off\\> — freeze all schedules temporarily\n\n" +
			"*Containers*\n" +
			"🟢 /start \\<name\\> — start a stopped container\n" +
			"🔴 /stop \\<name\\> — stop a running container\n" +
			"🔁 /restart \\<name\\> — restart a container\n" +
			"⏸ /pause \\<name\\> — freeze a container \\(SIGSTOP\\)\n" +
			"▶ /unpause \\<name\\> — resume a frozen container\n" +
			"🔄 /update \\<name\\|all\\> — pull \\+ recreate container\\(s\\)\n\n" +
			"*Stack*\n" +
			"📚 /stack up — start all stack services\n" +
			"📚 /stack down — stop \\+ remove all \\(volumes kept\\)\n" +
			"📚 /stack restart — restart all running services\n" +
			"📚 /stack pull — update the whole stack at once\n" +
			"📚 /stack ps — show status of every service\n\n" +
			"*System*\n" +
			"⚙️ /settings — notification and app configuration\n" +
			"🔃 /selfupdate — check for a new PrestoBack image and apply\n" +
			"❓ /help — this message"
		if err := notify.SendRaw(tgCfg, help); err != nil {
			log.Printf("[bot] send help: %v", err)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func (s *Server) handleTelegramCallback(nc config.NotifyConfig, cb *notify.TelegramCallbackQuery) {
	tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}

	// Security: verify the callback came from the configured chat/user.
	// Without this, ANY Telegram user who somehow obtains your bot link can
	// trigger backups by sending callback_query events (e.g. from a forwarded
	// button message). Chat.ID on a callback_query is the chat where the
	// original button message was sent; From.ID is the user who tapped it.
	chatIDStr := fmt.Sprintf("%d", cb.Message.Chat.ID)
	fromIDStr := fmt.Sprintf("%d", cb.From.ID)
	if chatIDStr != nc.TelegramChatID && fromIDStr != nc.TelegramChatID {
		log.Printf("[bot] rejected callback from chat=%s from=%s (not authorised)", chatIDStr, fromIDStr)
		_ = notify.AnswerCallbackQuery(nc.TelegramToken, cb.ID, "Not authorised")
		return
	}

	_ = notify.AnswerCallbackQuery(nc.TelegramToken, cb.ID, "Processing…")
	parts := strings.SplitN(cb.Data, ":", 3)
	if len(parts) < 2 {
		return
	}
	switch parts[0] {
	case "disk":
		if len(parts) < 2 {
			return
		}
		switch parts[1] {
		case "prune":
			_ = notify.SendRaw(tgCfg, "🗑 Pruning old backup archives\\.\\.\\.")
			go s.runPruneAll(tgCfg)
		case "docker_prune":
			go func() {
				_ = notify.SendRaw(tgCfg, "🐳 Running `docker image prune \\-f`\\.\\.\\.")
				out, err := exec.Command("docker", "image", "prune", "-f").CombinedOutput()
				if err != nil {
					_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Docker prune failed: `%s`", notify.EscapeMD(strings.TrimSpace(string(out)))))
					return
				}
				result := strings.TrimSpace(string(out))
				if result == "" {
					result = "No dangling images to remove"
				}
				_ = notify.SendRaw(tgCfg, fmt.Sprintf("✅ *Docker images pruned*\n```\n%s\n```", notify.EscapeMD(result)))
			}()
		case "dismiss":
			// Reset the debounce so they'll get another alert if it gets worse
			s.stateMu.Lock()
			s.diskWarnSent = false
			s.stateMu.Unlock()
			_ = notify.SendRaw(tgCfg, "OK\\. I'll re\\-alert if disk space drops further\\.")
		}

	case "backup":
		app, ok := s.cfg.GetApp(parts[1])
		if !ok {
			return
		}
		if s.engine.IsRunning(app.ID) {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⏳ `%s` — already running", notify.EscapeMD(app.Name)))
			return
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("▶ Backup started for `%s`", notify.EscapeMD(app.Name)))
		go s.runBackup(app, false)

	case "update":
		if parts[1] == "all" {
			targets := s.cfg.ListApps()
			sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"🔄 Pulling latest images for *%d* app\\(s\\)\\. Results incoming when complete\\.\\.\\.",
				len(targets),
			))
			go s.runContainerUpdates(tgCfg, targets)
		} else {
			app, ok := s.cfg.GetApp(parts[1])
			if !ok {
				return
			}
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("🔄 Pulling `%s`\\.\\.\\.", notify.EscapeMD(app.Name)))
			go s.runContainerUpdates(tgCfg, []config.AppConfig{app})
		}

	case "start", "stop", "restart", "pause", "unpause":
		app, ok := s.cfg.GetApp(parts[1])
		if !ok {
			return
		}
		s.runContainerLifecycle(tgCfg, app, parts[0])

	case "stackdown":
		if len(parts) < 2 {
			return
		}
		switch parts[1] {
		case "confirm":
			_ = notify.SendRaw(tgCfg, "📚 Taking the stack down\\.\\.\\.")
			go s.runStackOp(tgCfg, s.cfg.ComposeFile, "down")
		case "cancel":
			_ = notify.SendRaw(tgCfg, "Cancelled \\— stack left running\\.")
		}

	case "updatecheck":
		if len(parts) >= 2 && parts[1] == "dismiss" {
			_ = notify.SendRaw(tgCfg, "OK — I'll remind you again if it's still pending at the next check\\.")
		}
	}
}

// handleContainerLifecycle implements /start, /stop, /restart, /pause, /unpause.
// No-arg shows an app picker for that action; with an arg, finds the app's
// containers and runs the operation, streaming progress to SSE + Telegram.
func (s *Server) handleContainerLifecycle(tgCfg notify.TelegramConfig, arg, action string) {
	if strings.TrimSpace(arg) == "" {
		s.sendTelegramAppList(tgCfg, action)
		return
	}
	app := s.findAppByNameFragment(arg)
	if app == nil {
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"❌ App not found: `%s`\nUse /%s with no args to pick from list\\.",
			notify.EscapeMD(arg), action,
		))
		return
	}
	s.runContainerLifecycle(tgCfg, *app, action)
}

// runLifecycleAction runs action ("start"/"stop"/"restart"/"pause"/"unpause")
// against every container in containers, using the exact same backup.*OneContainer
// functions and same-status guards regardless of caller. This is the one place
// both the Telegram bot (runContainerLifecycle) and the web dashboard's
// container controls (handleAppLifecycle) actually perform the action — the
// two control surfaces read/write the same underlying state through the same
// code path, so they can't drift apart the way a duplicated implementation
// eventually would.
func (s *Server) runLifecycleAction(containers []backup.ContainerInfo, action string, emit func(string)) []string {
	var failed []string
	for _, c := range containers {
		var err error
		switch action {
		case "start":
			if c.Status == "running" {
				emit(fmt.Sprintf("%s already running — skipping", c.Name))
				continue
			}
			err = backup.StartOneContainer(c, emit)
		case "stop":
			if c.Status != "running" {
				emit(fmt.Sprintf("%s already %s — skipping", c.Name, c.Status))
				continue
			}
			err = backup.StopOneContainer(c, emit)
		case "restart":
			err = backup.RestartOneContainer(c, emit)
		case "pause":
			if c.Status != "running" {
				emit(fmt.Sprintf("%s is %s, not running — cannot pause", c.Name, c.Status))
				continue
			}
			err = backup.PauseOneContainer(c, emit)
		case "unpause":
			err = backup.UnpauseOneContainer(c, emit)
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", c.Name, err))
			emit(fmt.Sprintf("✗ %s failed: %v", c.Name, err))
		}
	}
	return failed
}

// validLifecycleActions is shared by the HTTP and Telegram entry points so
// both reject the same set of unknown actions.
var validLifecycleActions = map[string]bool{
	"start": true, "stop": true, "restart": true, "pause": true, "unpause": true,
}

// handleAppLifecycle is the web dashboard's equivalent of the Telegram
// /start /stop /restart /pause /unpause commands — same runLifecycleAction
// call as Telegram uses, same updateMu busy-check, same containers. Without
// this, a container paused via Telegram (or the reverse) had no way to be
// acted on from the dashboard even though the dashboard could already see
// and display its "paused" state — a control surface that could show truth
// it couldn't act on.
func (s *Server) handleAppLifecycle(w http.ResponseWriter, r *http.Request, appID string) {
	app, ok := s.cfg.GetApp(appID)
	if !ok {
		errOut(w, 404, "app not found")
		return
	}

	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errOut(w, 400, "invalid request body")
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))
	if !validLifecycleActions[action] {
		errOut(w, 400, "unknown action: "+action)
		return
	}

	// Same guard runContainerLifecycle uses — refuse to race a manual
	// start/stop/pause against the stop→rename→create→start sequence inside
	// an in-progress update. See updateMu's doc comment.
	s.stateMu.Lock()
	busy := s.updateRunning
	s.stateMu.Unlock()
	if busy {
		errOut(w, 409, "an update or stack operation is in progress — please wait for it to finish first")
		return
	}

	if ok, errMsg := backup.DockerReachable(); !ok {
		errOut(w, 503, "Docker isn't reachable right now (daemon may be restarting): "+errMsg)
		return
	}

	containers := backup.DedupeContainers(backup.FindContainers(app.ID))
	if len(containers) == 0 {
		errOut(w, 404, "no containers found for "+app.Name)
		return
	}

	emit := func(msg string) {
		log.Printf("[lifecycle:%s] %s", app.Name, msg)
		s.engine.EmitLog(app.ID, msg)
	}
	emit(fmt.Sprintf("━━━ %s (from dashboard): %s ━━━", action, app.Name))
	start := time.Now()
	failed := s.runLifecycleAction(containers, action, emit)
	dur := time.Since(start)
	emit(fmt.Sprintf("━━━ %s %s: %s (%s) ━━━", action, map[bool]string{true: "complete", false: "failed"}[len(failed) == 0], app.Name, formatDuration(dur)))

	respond(w, 200, map[string]any{
		"app":         app.Name,
		"action":      action,
		"success":     len(failed) == 0,
		"failed":      failed,
		"duration_ms": dur.Milliseconds(),
	})
}

// runContainerLifecycle does the actual work for a resolved app — shared by
// both the slash-command path and the inline-button callback path.
func (s *Server) runContainerLifecycle(tgCfg notify.TelegramConfig, app config.AppConfig, action string) {
	// Refuse to run alongside an update/stack operation — a manual stop/start/
	// restart racing the stop→rename→create→start sequence inside
	// standaloneRecreate is the same class of bug that produces orphaned
	// containers with stale network endpoints. See updateMu's doc comment.
	s.stateMu.Lock()
	busy := s.updateRunning
	s.stateMu.Unlock()
	if busy {
		_ = notify.SendRaw(tgCfg, "⏳ An update or stack operation is in progress — please wait for it to finish first\\.")
		return
	}

	verbs := map[string]string{
		"start": "Starting", "stop": "Stopping", "restart": "Restarting",
		"pause": "Pausing", "unpause": "Unpausing",
	}
	verb := verbs[action]
	if verb == "" {
		verb = "Processing"
	}
	_ = notify.SendRaw(tgCfg, fmt.Sprintf("%s `%s`\\.\\.\\.", verb, notify.EscapeMD(app.Name)))

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[lifecycle] PANIC in runContainerLifecycle: %v", r)
				_ = notify.SendRaw(tgCfg, "❌ Internal error — check container logs\\.")
			}
		}()

		emit := func(msg string) {
			log.Printf("[lifecycle:%s] %s", app.Name, msg)
			s.engine.EmitLog(app.ID, msg)
		}

		if ok, errMsg := backup.DockerReachable(); !ok {
			log.Printf("[lifecycle] aborting — Docker daemon unreachable: %s", errMsg)
			_ = notify.SendRaw(tgCfg, "⚠️ Can't reach Docker right now \\(daemon may be restarting\\) — try again in a moment\\.")
			return
		}

		containers := backup.DedupeContainers(backup.FindContainers(app.ID))
		if len(containers) == 0 {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("⚠️ No containers found for `%s`", notify.EscapeMD(app.Name)))
			return
		}

		emit(fmt.Sprintf("━━━ %s: %s ━━━", verb, app.Name))
		start := time.Now()
		failed := s.runLifecycleAction(containers, action, emit)
		dur := time.Since(start)

		if len(failed) == 0 {
			emit(fmt.Sprintf("━━━ %s complete: %s (%s) ━━━", verb, app.Name, formatDuration(dur)))
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("✅ *%s* — %s complete _%s_",
				notify.EscapeMD(app.Name), strings.ToLower(verb), notify.EscapeMD(formatDuration(dur))))
		} else {
			emit(fmt.Sprintf("━━━ %s failed: %s (%s) ━━━", verb, app.Name, formatDuration(dur)))
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("❌ *%s* — %s failed\n", notify.EscapeMD(app.Name), strings.ToLower(verb)))
			for _, f := range failed {
				sb.WriteString(fmt.Sprintf("  `%s`\n", notify.EscapeMD(f)))
			}
			_ = notify.SendRaw(tgCfg, sb.String())
		}
	}()
}

// handleStackCommand implements /stack up|down|restart|pull|ps.
func (s *Server) handleStackCommand(tgCfg notify.TelegramConfig, sub string) {
	composeFile := s.cfg.ComposeFile
	projectDir := filepath.Dir(composeFile)

	if composeFile == "" {
		_ = notify.SendRaw(tgCfg,
			"❌ *No compose file configured*\n\n"+
				"`/stack` commands operate on your whole docker\\-compose\\.yml \\(and everything it "+
				"references — `\\.env`, per\\-service `env\\_file:` entries, etc\\.\\), so PrestoBack "+
				"needs the *entire project directory* mounted, not just the one file\\. Add to your "+
				"prestoback service:\n\n"+
				"```yaml\n"+
				"environment:\n"+
				"  PRESTOBACK_COMPOSE_FILE: ${PWD}/docker-compose.yml\n"+
				"volumes:\n"+
				"  - ${PWD}:${PWD}:ro\n"+
				"```\n\n"+
				"_Note: compose\\-managed containers also need this for `/update` — only fully standalone, non\\-compose containers can update without it\\._")
		return
	}
	if _, statErr := os.Stat(composeFile); statErr != nil {
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"❌ *Compose file not accessible*\n\n"+
				"`PRESTOBACK_COMPOSE_FILE` is set to `%s` but that path doesn't exist *inside this container*\\.\n\n"+
				"Mount the *entire project directory* \\(not just the one file\\) — your stack likely "+
				"references `\\.env` and per\\-service `env\\_file:` paths that also need to resolve "+
				"correctly inside this container:\n\n"+
				"```yaml\n"+
				"volumes:\n"+
				"  - %s:%s:ro\n"+
				"```",
			notify.EscapeMD(composeFile), projectDir, projectDir,
		))
		return
	}
	// Soft warning (not a hard stop): catches the case where only
	// docker-compose.yml (+ maybe top-level .env) is mounted, but the
	// services/<app>/<app>.env tree referenced by env_file: entries isn't.
	// See backup.ProjectDirIssue for the full layout assumption this checks.
	if issue := backup.ProjectDirIssue(composeFile); issue != "" {
		log.Printf("[stack] warning: %s", issue)
	}

	switch sub {
	case "", "help":
		_ = notify.SendRaw(tgCfg,
			"*\\/stack — whole\\-stack control*\n\n"+
				"📚 `/stack up` — start all stack services\n"+
				"📚 `/stack down` — stop \\+ remove all \\(volumes kept\\)\n"+
				"📚 `/stack restart` — restart all running services\n"+
				"📚 `/stack pull` — pull \\+ recreate the entire stack\n"+
				"📚 `/stack ps` — show status of every service")
		return

	case "ps":
		out, err := backup.StackPs(composeFile)
		if err != nil {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ `%s`", notify.EscapeMD(err.Error())))
			return
		}
		trimmed := strings.TrimSpace(out)
		if len(trimmed) > 3500 {
			trimmed = trimmed[:3500] + "\n…"
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("*Stack Status*\n```\n%s\n```", notify.EscapeMD(trimmed)))
		return

	case "up", "down", "restart", "pull":
		// destructive-ish ops get a confirm step via callback for "down"
		if sub == "down" {
			_ = notify.SendRawWithButtons(tgCfg,
				"⚠️ *Stack Down*\nThis stops and removes every container EXCEPT PrestoBack itself \\(named volumes are preserved\\)\\. PrestoBack stays running so you can `/stack up` again from anywhere\\. Continue?",
				[]notify.ButtonAction{
					{Label: "✅ Yes, take the stack down", Data: "stackdown:confirm"},
					{Label: "❌ Cancel", Data: "stackdown:cancel"},
				})
			return
		}

		verbMap := map[string]string{"up": "Starting", "restart": "Restarting", "pull": "Updating"}
		// Send the acknowledgement BEFORE launching the goroutine so Telegram
		// always shows an immediate reply — avoids the "stuck / no response"
		// appearance when Docker is slow to respond or the compose project lock
		// is briefly held by a concurrent operation.
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("📚 %s the stack\\.\\.\\.", verbMap[sub]))
		go s.runStackOp(tgCfg, composeFile, sub)
		return

	default:
		_ = notify.SendRaw(tgCfg, fmt.Sprintf(
			"❌ Unknown subcommand: `%s`\nUse `/stack` with no args for usage\\.", notify.EscapeMD(sub)))
	}
}

// runStackOp is the public entry point for all stack-mutating operations
// (/stack up, down, restart, pull). It shares the SAME global updateMu lock
// as runContainerUpdates — a per-app /update racing a /stack down (or
// another /stack op) against the same container is exactly the class of bug
// that produces orphaned containers with stale network endpoints. See the
// updateMu doc comment on the Server struct for the full mechanism.
func (s *Server) runStackOp(tgCfg notify.TelegramConfig, composeFile, op string) {
	s.stateMu.Lock()
	if s.updateRunning {
		s.stateMu.Unlock()
		_ = notify.SendRaw(tgCfg, "⏳ An update or stack operation is already in progress — please wait for it to finish\\.")
		return
	}
	s.updateRunning = true
	s.stateMu.Unlock()

	s.updateMu.Lock()
	defer func() {
		s.updateMu.Unlock()
		s.stateMu.Lock()
		s.updateRunning = false
		s.stateMu.Unlock()
	}()

	s.runStackOpLocked(tgCfg, composeFile, op)
}

// runStackOpLocked executes one stack-level compose operation, streaming
// progress to SSE under the synthetic "_stack" app ID and reporting the
// result to Telegram. Must only be called while holding s.updateMu — use
// runStackOp.
func (s *Server) runStackOpLocked(tgCfg notify.TelegramConfig, composeFile, op string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[stack] PANIC in runStackOpLocked(%s): %v", op, r)
			_ = notify.SendRaw(tgCfg, "❌ Internal error during stack operation — check container logs\\.")
		}
	}()

	emit := func(msg string) {
		log.Printf("[stack:%s] %s", op, msg)
		s.engine.EmitLog("_stack", msg)
	}

	start := time.Now()
	var err error
	switch op {
	case "up":
		// selfName excludes PrestoBack's own container from the recreate
		// target list — see StackUp's doc comment for why this is required.
		err = backup.StackUp(composeFile, s.selfName, emit)
	case "down":
		// selfName excludes PrestoBack's own container — see StackDown's doc
		// comment for why the management tool must survive its own "down".
		err = backup.StackDown(composeFile, s.selfName, emit)
	case "restart":
		err = backup.StackRestart(composeFile, s.selfName, emit)
	case "pull":
		err = backup.StackPull(composeFile, s.selfName, emit)
	}
	dur := time.Since(start)

	if err != nil {
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ *Stack %s failed* _%s_\n`%s`",
			notify.EscapeMD(op), notify.EscapeMD(formatDuration(dur)), notify.EscapeMD(err.Error())))
		return
	}
	_ = notify.SendRaw(tgCfg, fmt.Sprintf("✅ *Stack %s complete* _%s_",
		notify.EscapeMD(op), notify.EscapeMD(formatDuration(dur))))
}

// sendTelegramAppList sends a button menu with one app per row, sorted
// alphabetically.
//
// Container-lifecycle actions (start/stop/restart/pause/unpause) are filtered
// to only show apps whose container Docker actually knows about. Apps that are
// registered in PrestoBack but have no corresponding Docker container (e.g.
// a backup-only app with no running service, or a stale registration) are
// silently excluded from those menus — showing them would produce the
// confusing "No containers found for X" error on every button tap.
//
// Backup and update actions always show all registered apps regardless of
// container status, since both can meaningfully operate on stopped services.
func (s *Server) sendTelegramAppList(tgCfg notify.TelegramConfig, action string) {
	allApps := s.cfg.ListApps()
	if len(allApps) == 0 {
		_ = notify.SendRaw(tgCfg, "❌ No apps registered yet\\.")
		return
	}

	// Actions that require a real running/stopped container in Docker.
	// For these we filter out apps with no discoverable container.
	containerActions := map[string]bool{
		"start": true, "stop": true, "restart": true,
		"pause": true, "unpause": true,
	}

	var apps []config.AppConfig
	if containerActions[action] {
		for _, a := range allApps {
			// Check if Docker knows any container for this app.
			// FindContainers uses docker ps -a so it catches stopped containers too.
			containers := backup.FindContainers(a.ID)
			// Also check ContainerName if set explicitly.
			if len(containers) == 0 && a.ContainerName != "" {
				containers = backup.ContainersByName([]string{a.ContainerName})
			}
			if len(containers) > 0 {
				apps = append(apps, a)
			}
		}
		if len(apps) == 0 {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf(
				"❌ No containers found for any registered app\\. Use `/stack up` to start the stack\\.",
			))
			return
		}
	} else {
		apps = allApps
	}

	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })

	var btns []notify.ButtonAction
	// Prepend a bulk-action button for update so users can choose All without typing.
	if action == "update" {
		btns = append(btns, notify.ButtonAction{
			Label: fmt.Sprintf("⬆️ Update ALL %d apps", len(apps)),
			Data:  "update:all",
		})
	}
	for _, a := range apps {
		btns = append(btns, notify.ButtonAction{Label: a.Name, Data: action + ":" + a.ID})
	}
	_ = notify.SendRawWithButtons(tgCfg,
		fmt.Sprintf("Choose an app to *%s*:", notify.EscapeMD(action)),
		btns,
	)
}

func (s *Server) findAppByNameFragment(fragment string) *config.AppConfig {
	lower := strings.ToLower(fragment)
	for _, a := range s.cfg.ListApps() {
		if strings.Contains(strings.ToLower(a.Name), lower) || strings.Contains(strings.ToLower(a.ID), lower) {
			cp := a
			return &cp
		}
	}
	return nil
}

// ── Notify dispatch ───────────────────────────────────────────────────────────

func (s *Server) dispatchNotify(ev notify.Event) {
	nc := s.cfg.GetNotify()
	notify.Dispatch(notify.Config{
		TelegramToken:    nc.TelegramToken,
		TelegramChatID:   nc.TelegramChatID,
		TelegramEnabled:  nc.TelegramEnabled,
		DiscordURL:       nc.DiscordURL,
		DiscordEnabled:   nc.DiscordEnabled,
		NtfyURL:          nc.NtfyURL,
		NtfyToken:        nc.NtfyToken,
		NtfyEnabled:      nc.NtfyEnabled,
		WebhookURL:       nc.WebhookURL,
		WebhookEnabled:   nc.WebhookEnabled,
		OnBackupSuccess:  nc.OnBackupSuccess,
		OnBackupFail:     nc.OnBackupFail,
		OnRestoreSuccess: nc.OnRestoreSuccess,
		OnRestoreFail:    nc.OnRestoreFail,
	}, ev)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func parseJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func errOut(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}

func sanitizeID(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	id := b.String()
	for strings.Contains(id, "__") {
		id = strings.ReplaceAll(id, "__", "_") // collapse runs of underscores
	}
	return strings.Trim(id, "_")
}

// slugFromPath mirrors the config package helper (avoids import cycle).
func slugFromPath(p string) string {
	return slugFromPathForID(p, "")
}

func slugFromPathForID(p, appID string) string {
	base := filepath.Base(filepath.Clean(p))
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" || (appID != "" && s == appID) {
		return "data"
	}
	return s
}
