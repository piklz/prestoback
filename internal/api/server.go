package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
}

func NewServer(cfg *config.Config, image, selfName string) *Server {
	hist, _ := history.Load(cfg.HistoryFile())
	sched := scheduler.New()

	s := &Server{
		cfg:        cfg,
		engine:     backup.NewEngine(cfg.BackupDir()),
		hist:       hist,
		sched:      sched,
		mux:        http.NewServeMux(),
		image:      image,
		selfName:   selfName,
		sseClients: make(map[chan backup.JobUpdate]struct{}),
	}
	s.routes()
	s.loadSchedules()
	sched.Start()
	go s.broadcastUpdates()
	go s.runTelegramBot()
	return s
}

func (s *Server) Run(port int) error {
	key := s.cfg.APIKey()
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("  PrestoBack v%s  —  port %d", config.Version, port)
	log.Printf("  API Key: %s", key)
	log.Printf("  Add header: X-API-Key: %s", key)
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return http.ListenAndServe(fmt.Sprintf(":%d", port), s.mux)
}

// ── Routes ────────────────────────────────────────────────────────────────────

func (s *Server) routes() {
	// Public — no auth (healthcheck, auth flow, status)
	s.mux.Handle("/", http.FileServer(http.FS(web.StaticFS())))
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/status", s.handleStatus)          // public — used by UI before login & Docker healthcheck
	s.mux.HandleFunc("/api/auth/status", s.handleAuthStatus) // {setup_required, version}
	s.mux.HandleFunc("/api/auth/setup", s.handleAuthSetup)   // first-run setup
	s.mux.HandleFunc("/api/auth/login", s.handleAuthLogin)   // credential login → JWT
	s.mux.HandleFunc("/api/events", s.handleSSE)             // SSE — auth via query param

	// Auth-required API (JWT or legacy X-API-Key)
	s.mux.HandleFunc("/api/auth/logout", s.authJWT(s.handleAuthLogout))
	s.mux.HandleFunc("/api/auth/me", s.authJWT(s.handleAuthMe))
	s.mux.HandleFunc("/api/volumes", s.authJWT(s.handleListVolumes))
	s.mux.HandleFunc("/api/discover", s.authJWT(s.handleDiscover))
	s.mux.HandleFunc("/api/validate-path", s.authJWT(s.handleValidatePath))
	s.mux.HandleFunc("/api/apps", s.authJWT(s.handleApps))
	s.mux.HandleFunc("/api/apps/", s.authJWT(s.handleApp))
	s.mux.HandleFunc("/api/backups/", s.authJWT(s.handleBackups))
	s.mux.HandleFunc("/api/remotes", s.authJWT(s.handleRemotes))
	s.mux.HandleFunc("/api/remotes/", s.authJWT(s.handleRemote))
	s.mux.HandleFunc("/api/history", s.authJWT(s.handleHistory))
	s.mux.HandleFunc("/api/notify", s.authJWT(s.handleNotify))
	s.mux.HandleFunc("/api/notify/test", s.authJWT(s.handleNotifyTest))
	s.mux.HandleFunc("/api/apikey/regenerate", s.authJWT(s.handleRegenKey))
	s.mux.HandleFunc("/api/update/check", s.authJWT(s.handleUpdateCheck))
	s.mux.HandleFunc("/api/update/apply", s.authJWT(s.handleUpdateApply))
}

// ── Auth middleware ───────────────────────────────────────────────────────────

// SSE uses query param auth so EventSource (no custom headers) works.
// Accepts ?token=<jwt> or legacy ?api_key=<apikey>
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	// JWT token param
	token := r.URL.Query().Get("token")
	if token != "" {
		if !s.cfg.IsTokenRevoked(token) {
			if _, err := jwtVerify(token, jwtSecret(s.cfg.APIKey())); err == nil {
				goto authorized
			}
		}
		http.Error(w, "unauthorized", 401)
		return
	}
	// Legacy API key param
	if key := r.URL.Query().Get("api_key"); key == s.cfg.APIKey() {
		goto authorized
	}
	http.Error(w, "unauthorized", 401)
	return

authorized:
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
	respond(w, 200, map[string]any{
		"version":      config.Version,
		"app_count":    s.cfg.AppCount(),
		"remote_count": len(s.cfg.ListRemotes()),
		"volumes_dir":  s.cfg.VolumesDir,
		"backup_dir":   s.cfg.BackupDir(),
		"image":        s.image,
		"self_name":    s.selfName,
		"time":         time.Now().UTC(),
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

func (s *Server) handleRegenKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	newKey := s.cfg.RegenerateAPIKey()
	respond(w, 200, map[string]string{"api_key": newKey})
}

// ── Volumes ───────────────────────────────────────────────────────────────────

func (s *Server) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	// VolumesDir is optional — users with non-standard setups add apps manually
	// via the custom path field. Return empty list gracefully if not set/mounted.
	if s.cfg.VolumesDir == "" {
		respond(w, 200, []any{})
		return
	}
	entries, err := os.ReadDir(s.cfg.VolumesDir)
	if os.IsNotExist(err) {
		// Not mounted — not an error, just no auto-discovery available
		respond(w, 200, []any{})
		return
	}
	if err != nil {
		errOut(w, 500, "cannot read volumes dir: "+err.Error())
		return
	}
	type vol struct {
		Name string `json:"name"`
		Path string `json:"path"` // path inside the container (use this for backup)
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

// handleDiscover returns candidate apps discovered via Docker socket + volumes dir.
// Replaces the old flat-dir-only /api/volumes discovery with Docker-aware discovery.
func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	// Build set of already-registered paths so we can filter them out
	alreadyRegistered := map[string]bool{}
	for _, a := range s.cfg.ListApps() {
		alreadyRegistered[a.Path] = true
	}
	candidates := backup.DiscoverApps(s.cfg.VolumesDir, alreadyRegistered)
	if candidates == nil {
		candidates = []backup.DiscoveredApp{}
	}
	respond(w, 200, candidates)
}

// handleValidatePath checks whether an arbitrary path is readable inside the container.
// Used by the UI when the user types a custom path.
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
		if a.Name == "" || a.Path == "" {
			errOut(w, 400, "name and path are required")
			return
		}
		if a.ID == "" {
			a.ID = sanitizeID(a.Name)
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

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/apps/")
	parts := strings.SplitN(tail, "/", 3)
	appID := parts[0]

	if len(parts) == 2 && parts[1] == "backup" && r.Method == http.MethodPost {
		s.handleTriggerBackup(w, r, appID)
		return
	}
	if len(parts) == 3 && parts[1] == "restore" && r.Method == http.MethodPost {
		s.handleRestore(w, r, appID, parts[2])
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
		if err := s.cfg.UpdateApp(a); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		_ = s.cfg.Save()
		s.syncSchedule(a)
		respond(w, 200, a)
	case http.MethodDelete:
		if err := s.cfg.DeleteApp(appID); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		_ = s.cfg.Save()
		s.sched.Remove(appID)
		respond(w, 200, map[string]string{"deleted": appID})
	default:
		errOut(w, 405, "method not allowed")
	}
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
	remoteID := r.URL.Query().Get("remote")
	respond(w, 202, map[string]string{"status": "accepted", "app_id": appID})
	go s.runBackup(app, remoteID, false)
}

func (s *Server) runBackup(app config.AppConfig, remoteID string, scheduled bool) {
	start := time.Now()
	emit := func(msg string) { s.engine.EmitLog(app.ID, msg) }

	prefix := "Manual"
	if scheduled {
		prefix = "Scheduled"
	}
	emit(fmt.Sprintf("━━━ %s backup started: %s ━━━", prefix, app.Name))

	// ── Pre-flight: validate path before touching Docker or the tar engine ─
	if app.Path == "" {
		msg := "backup aborted: no path configured for this app"
		emit("✗ " + msg)
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: msg, DurationMs: time.Since(start).Milliseconds(),
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: msg, IsError: true})
		return
	}
	if isDangerousPath(app.Path) {
		msg := fmt.Sprintf("backup aborted: refusing to back up dangerous path %q — this would tar the entire filesystem", app.Path)
		emit("✗ " + msg)
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: msg, DurationMs: time.Since(start).Milliseconds(),
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: msg, IsError: true})
		return
	}
	if info, err := os.Stat(app.Path); err != nil {
		msg := fmt.Sprintf("backup aborted: path %q is not accessible inside this container: %v", app.Path, err)
		emit("✗ " + msg)
		emit("  Tip: the path must be mounted into prestoback, not just exist on the host.")
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: msg, DurationMs: time.Since(start).Milliseconds(),
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: msg, IsError: true})
		return
	} else if !info.IsDir() {
		msg := fmt.Sprintf("backup aborted: path %q is not a directory", app.Path)
		emit("✗ " + msg)
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: msg, DurationMs: time.Since(start).Milliseconds(),
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: msg, IsError: true})
		return
	}
	// ── End pre-flight ─────────────────────────────────────────────────────

	// Use the real Docker container name when available (set by discovery).
	// Manually-added apps don't have this, so fall back to the app ID.
	containerLookup := app.ContainerName
	if containerLookup == "" {
		containerLookup = app.ID
	}
	containers := backup.FindContainers(containerLookup)
	if len(containers) == 0 {
		emit("⚠  No running containers found — backing up live files")
	}
	toRestart, _ := backup.StopContainers(containers, emit)

	meta, err := s.engine.BackupApp(app.ID, app.Name, app.Path)
	backup.StartContainers(toRestart, emit)

	dur := time.Since(start).Milliseconds()

	if err != nil {
		emit("✗ Backup failed: " + err.Error())
		s.hist.Append(history.Entry{
			Event: history.EventBackupFail, AppID: app.ID, AppName: app.Name,
			Detail: err.Error(), DurationMs: dur,
		})
		s.dispatchNotify(notify.Event{Kind: "backup_fail", AppName: app.Name, Detail: err.Error(), IsError: true})
		return
	}

	_ = s.engine.PruneBackups(app.ID, app.Retain)
	detail := fmt.Sprintf("%s (%.1f MB, %dms)", meta.ID, float64(meta.SizeBytes)/1e6, dur)
	s.hist.Append(history.Entry{
		Event: history.EventBackupSuccess, AppID: app.ID, AppName: app.Name,
		Detail: detail, SizeBytes: meta.SizeBytes, DurationMs: dur,
	})
	s.dispatchNotify(notify.Event{Kind: "backup_success", AppName: app.Name, Detail: detail})

	if remoteID != "" {
		for _, rem := range s.cfg.ListRemotes() {
			if rem.ID == remoteID {
				emit("Pushing to remote: " + rem.Label)
				if pushErr := backup.PushToRemote(meta.FilePath, rem); pushErr != nil {
					emit("✗ Push failed: " + pushErr.Error())
					s.dispatchNotify(notify.Event{Kind: "push_fail", AppName: app.Name, Detail: pushErr.Error(), IsError: true})
				} else {
					emit("✓ Remote push complete: " + rem.Label)
					s.dispatchNotify(notify.Event{Kind: "push_success", AppName: app.Name, Detail: rem.Label})
				}
				break
			}
		}
	}
	emit("━━━ Backup complete ━━━")
}

// ── Restore ───────────────────────────────────────────────────────────────────

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
	respond(w, 202, map[string]string{"status": "accepted", "backup_id": backupID})

	go func() {
		start := time.Now()
		emit := func(msg string) { s.engine.EmitLog(app.ID, msg) }
		emit("━━━ Restore started: " + app.Name + " [" + backupID + "] ━━━")

		containerLookup := app.ContainerName
		if containerLookup == "" {
			containerLookup = app.ID
		}
		containers := backup.FindContainers(containerLookup)
		if len(containers) == 0 {
			emit("⚠  No running containers found")
		}
		toRestart, _ := backup.StopContainers(containers, emit)
		err := s.engine.RestoreApp(app.ID, app.Name, archivePath, app.Path)
		backup.StartContainers(toRestart, emit)

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
		detail := fmt.Sprintf("Restored from %s (%dms)", backupID, dur)
		s.hist.Append(history.Entry{
			Event: history.EventRestoreSuccess, AppID: app.ID, AppName: app.Name,
			Detail: detail, DurationMs: dur,
		})
		s.dispatchNotify(notify.Event{Kind: "restore_success", AppName: app.Name, Detail: detail})
		emit("━━━ Restore complete ━━━")
	}()
}

// ── Backups ───────────────────────────────────────────────────────────────────

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/backups/"), "/", 3)
	appID := parts[0]
	if appID == "" {
		errOut(w, 400, "app ID required")
		return
	}

	// POST /api/backups/{appID}/{backupID}/push?remote=
	if r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "push" {
		backupID := parts[1]
		remoteID := r.URL.Query().Get("remote")
		if remoteID == "" {
			errOut(w, 400, "remote query param required")
			return
		}
		archivePath := filepath.Join(s.cfg.BackupDir(), appID, backupID+".tar.gz")
		if _, err := os.Stat(archivePath); os.IsNotExist(err) {
			errOut(w, 404, "backup not found")
			return
		}
		var found *config.RemoteTarget
		for _, rem := range s.cfg.ListRemotes() {
			if rem.ID == remoteID {
				cp := rem
				found = &cp
				break
			}
		}
		if found == nil {
			errOut(w, 404, "remote not found")
			return
		}
		app, _ := s.cfg.GetApp(appID)
		respond(w, 202, map[string]string{"status": "accepted"})
		go func() {
			emit := func(msg string) { s.engine.EmitLog(appID, msg) }
			emit("Pushing " + backupID + " → " + found.Label + "…")
			if err := backup.PushToRemote(archivePath, *found); err != nil {
				emit("✗ Push failed: " + err.Error())
				s.dispatchNotify(notify.Event{Kind: "push_fail", AppName: app.Name, Detail: err.Error(), IsError: true})
			} else {
				emit("✓ Push complete: " + found.Label)
				s.dispatchNotify(notify.Event{Kind: "push_success", AppName: app.Name, Detail: found.Label})
			}
		}()
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

// ── Remotes ───────────────────────────────────────────────────────────────────

func (s *Server) handleRemotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respond(w, 200, s.cfg.ListRemotes())
	case http.MethodPost:
		var rem config.RemoteTarget
		if err := parseJSON(r, &rem); err != nil {
			errOut(w, 400, err.Error())
			return
		}
		if rem.Label == "" || rem.Host == "" {
			errOut(w, 400, "label and host are required")
			return
		}
		if rem.ID == "" {
			rem.ID = sanitizeID(rem.Label)
		}
		if err := s.cfg.AddRemote(rem); err != nil {
			errOut(w, 409, err.Error())
			return
		}
		_ = s.cfg.Save()
		respond(w, 201, rem)
	default:
		errOut(w, 405, "method not allowed")
	}
}

func (s *Server) handleRemote(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/remotes/")
	if r.Method == http.MethodPost && strings.HasSuffix(tail, "/test") {
		remID := strings.TrimSuffix(tail, "/test")
		for _, rem := range s.cfg.ListRemotes() {
			if rem.ID == remID {
				err := backup.TestRemoteConnection(rem)
				if err != nil {
					respond(w, 200, map[string]any{"ok": false, "error": err.Error()})
				} else {
					respond(w, 200, map[string]any{"ok": true})
				}
				return
			}
		}
		errOut(w, 404, "remote not found")
		return
	}
	if r.Method == http.MethodDelete {
		if err := s.cfg.DeleteRemote(tail); err != nil {
			errOut(w, 404, err.Error())
			return
		}
		_ = s.cfg.Save()
		respond(w, 200, map[string]string{"deleted": tail})
		return
	}
	errOut(w, 405, "method not allowed")
}

// ── Self-update ───────────────────────────────────────────────────────────────

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.image == "" {
		respond(w, 200, map[string]any{"available": false, "reason": "PRESTOBACK_IMAGE not set"})
		return
	}
	hasUpdate, local, remote, err := backup.CheckForUpdate(s.image)
	if err != nil {
		respond(w, 200, map[string]any{"available": false, "error": err.Error()})
		return
	}
	respond(w, 200, map[string]any{
		"available":     hasUpdate,
		"local_digest":  safeSlice(local, 19),
		"remote_digest": safeSlice(remote, 19),
		"image":         s.image,
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
	a := app // capture
	s.sched.Upsert(scheduler.Job{
		ID:       app.ID,
		CronExpr: app.Schedule.CronExpr,
		Fn: func() {
			current, ok := s.cfg.GetApp(a.ID)
			if !ok || current.Pinned || !current.Schedule.Enabled {
				return
			}
			if s.engine.IsRunning(current.ID) {
				log.Printf("[scheduler] skipping %s — job already running", current.ID)
				return
			}
			s.runBackup(current, "", true)
		},
	})
}

// ── Telegram bot ──────────────────────────────────────────────────────────────

func (s *Server) runTelegramBot() {
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
	// Only respond to the configured chat ID
	if fmt.Sprintf("%d", msg.Chat.ID) != nc.TelegramChatID {
		return
	}

	text := strings.TrimSpace(msg.Text)
	cmd := strings.SplitN(text, " ", 2)[0]
	arg := ""
	if len(strings.SplitN(text, " ", 2)) > 1 {
		arg = strings.TrimSpace(strings.SplitN(text, " ", 2)[1])
	}

	switch cmd {
	case "/status":
		apps := s.cfg.ListApps()
		reply := fmt.Sprintf("*PrestoBack v%s*\n🐳 Apps: %d\n\n", config.Version, len(apps))
		for _, a := range apps {
			pin := ""
			if a.Pinned {
				pin = " 📌"
			}
			running := ""
			if s.engine.IsRunning(a.ID) {
				running = " ⏳"
			}
			reply += fmt.Sprintf("• `%s`%s%s\n  `%s`\n", a.Name, pin, running, a.Path)
		}
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: "PrestoBack", Detail: reply})

	case "/backup":
		if arg == "" {
			s.sendTelegramAppList(tgCfg, "backup")
			return
		}
		app := s.findAppByNameFragment(arg)
		if app == nil {
			_ = notify.SendTelegram(tgCfg, notify.Event{AppName: "PrestoBack", Detail: "App not found: " + arg, IsError: true})
			return
		}
		if s.engine.IsRunning(app.ID) {
			_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "A job is already running for this app", IsError: true})
			return
		}
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "Backup started ⏳"})
		go s.runBackup(*app, "", false)

	case "/history":
		entries := s.hist.List(10)
		reply := "*Recent history (last 10)*\n\n"
		for _, e := range entries {
			icon := "✅"
			if strings.Contains(string(e.Event), "fail") {
				icon = "❌"
			}
			reply += fmt.Sprintf("%s `%s` — %s\n_%s_\n\n", icon, e.AppName, e.Event, e.Time.Format("02 Jan 15:04"))
		}
		if len(entries) == 0 {
			reply = "No history yet."
		}
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: "PrestoBack", Detail: reply})

	case "/help":
		help := "*PrestoBack Bot Commands*\n\n" +
			"/status — list all apps\n" +
			"/backup \\<name\\> — backup an app\n" +
			"/history — last 10 events\n" +
			"/help — this message"
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: "PrestoBack", Detail: help})
	}
}

func (s *Server) handleTelegramCallback(nc config.NotifyConfig, cb *notify.TelegramCallbackQuery) {
	tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
	_ = notify.AnswerCallbackQuery(nc.TelegramToken, cb.ID, "Processing…")

	// callback_data format: "backup:{appID}" or "restore:{appID}:{backupID}"
	parts := strings.SplitN(cb.Data, ":", 3)
	if len(parts) < 2 {
		return
	}
	switch parts[0] {
	case "backup":
		app, ok := s.cfg.GetApp(parts[1])
		if !ok {
			return
		}
		if s.engine.IsRunning(app.ID) {
			_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "Already running", IsError: true})
			return
		}
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "Backup started ⏳"})
		go s.runBackup(app, "", false)
	}
}

func (s *Server) sendTelegramAppList(tgCfg notify.TelegramConfig, action string) {
	apps := s.cfg.ListApps()
	actions := make(map[string]string, len(apps))
	for _, a := range apps {
		actions[a.Name] = action + ":" + a.ID
	}
	ev := notify.Event{AppName: "PrestoBack", Detail: "Choose an app to " + action + ":"}
	_ = notify.SendTelegramWithButtons(tgCfg, ev, actions)
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
	r := strings.NewReplacer(" ", "_", "/", "_", ".", "_", "-", "_")
	id := strings.ToLower(r.Replace(strings.TrimSpace(name)))
	for strings.Contains(id, "__") {
		id = strings.ReplaceAll(id, "__", "_")
	}
	return strings.Trim(id, "_")
}

func safeSlice(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isDangerousPath returns true for paths that must never be backed up because
// tarring them would capture the entire OS or a critical system tree.
func isDangerousPath(path string) bool {
	// Trim trailing slashes so "/" and "//" both match.
	p := strings.TrimRight(path, "/")
	if p == "" {
		return true // bare root
	}
	blocked := []string{
		"/proc", "/sys", "/dev", "/run", "/tmp",
		"/var/run", "/usr", "/bin", "/sbin", "/lib",
		"/boot", "/lost+found", "/etc",
	}
	for _, b := range blocked {
		if p == b || strings.HasPrefix(p, b+"/") {
			return true
		}
	}
	return false
}
