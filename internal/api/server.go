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
	go s.broadcastUpdates()
	go s.runTelegramBot()
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
	s.mux.HandleFunc("/api/events", s.handleSSE)

	// Auth-required
	s.mux.HandleFunc("/api/auth/logout", s.authJWT(s.handleAuthLogout))
	s.mux.HandleFunc("/api/auth/me", s.authJWT(s.handleAuthMe))
	s.mux.HandleFunc("/api/volumes", s.authJWT(s.handleListVolumes))
	s.mux.HandleFunc("/api/discover", s.authJWT(s.handleDiscover))
	s.mux.HandleFunc("/api/suggest-excludes", s.authJWT(s.handleSuggestExcludes))
	s.mux.HandleFunc("/api/validate-path", s.authJWT(s.handleValidatePath))
	s.mux.HandleFunc("/api/dir-size", s.authJWT(s.handleDirSize))
	s.mux.HandleFunc("/api/apps", s.authJWT(s.handleApps))
	s.mux.HandleFunc("/api/apps/", s.authJWT(s.handleApp))
	s.mux.HandleFunc("/api/backups/", s.authJWT(s.handleBackups))
	s.mux.HandleFunc("/api/backups-orphans/", s.authJWT(s.handleOrphans))
	s.mux.HandleFunc("/api/backups-orphans", s.authJWT(s.handleOrphans))
	s.mux.HandleFunc("/api/backups-import", s.authJWT(s.handleBackupsImport))
	s.mux.HandleFunc("/api/history", s.authJWT(s.handleHistory))
	s.mux.HandleFunc("/api/notify", s.authJWT(s.handleNotify))
	s.mux.HandleFunc("/api/notify/test", s.authJWT(s.handleNotifyTest))
	s.mux.HandleFunc("/api/apikey", s.authJWT(s.handleAPIKey))
	s.mux.HandleFunc("/api/apikey/regenerate", s.authJWT(s.handleRegenKey))
	s.mux.HandleFunc("/api/update/check", s.authJWT(s.handleUpdateCheck))
	s.mux.HandleFunc("/api/update/apply", s.authJWT(s.handleUpdateApply))
	s.mux.HandleFunc("/api/cron/preview", s.authJWT(s.handleCronPreview))
}

// ── SSE ───────────────────────────────────────────────────────────────────────

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
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
	builtAt := ""
	if s.image != "" {
		if out, err := exec.Command("docker", "image", "inspect",
			"--format={{.Created}}", s.image).Output(); err == nil {
			builtAt = strings.TrimSpace(string(out))
		}
	}
	var diskFreeBytes, diskTotalBytes uint64
	if stat, err := diskUsage(s.cfg.BackupDir()); err == nil {
		diskFreeBytes = stat.free
		diskTotalBytes = stat.total
	}
	nextRuns := s.sched.NextRuns()
	respond(w, 200, map[string]any{
		"version":          config.Version,
		"app_count":        s.cfg.AppCount(),
		"volumes_dir":      s.cfg.VolumesDir,
		"backup_dir":       s.cfg.BackupDir(),
		"image":            s.image,
		"self_name":        s.selfName,
		"built_at":         builtAt,
		"time":             time.Now().UTC(),
		"disk_free_bytes":  diskFreeBytes,
		"disk_total_bytes": diskTotalBytes,
		"next_runs":        nextRuns,
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

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	alreadyRegistered := map[string]bool{}
	for _, a := range s.cfg.ListApps() {
		for _, v := range a.Volumes {
			alreadyRegistered[v.Path] = true
		}
	}
	candidates := backup.DiscoverApps(s.selfName, s.cfg.VolumesDir, alreadyRegistered)
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
		// Legacy single-path promotion
		if len(a.Volumes) == 0 && a.Path != "" {
			slug := slugFromPath(a.Path)
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
		if a.ID == "" {
			a.ID = sanitizeID(a.Name)
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
			slug := slugFromPath(a.Path)
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
	respond(w, 200, map[string]any{"detected": candidates})
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

	// ── Pre-backup hook ───────────────────────────────────────────────────────
	// Run any pre-backup command (e.g. pg_dump, sqlite3 .backup) while containers
	// are still running so databases are accessible.
	if app.PreBackupCmd != "" {
		emit(fmt.Sprintf("→ Running pre-backup hook: %s", app.PreBackupCmd))
		if err := s.engine.RunPreBackupCmd(app.ID, app.PreBackupCmd, emit); err != nil {
			emit(fmt.Sprintf("⚠  Pre-backup hook failed: %v — continuing anyway", err))
		} else {
			emit("✓ Pre-backup hook completed")
		}
	}

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
	for _, v := range app.Volumes {
		if v.Slug == volumeSlug {
			destPath = v.Path
			break
		}
	}
	if destPath == "" {
		// Fallback: if we can't identify the volume, let the caller supply ?path=
		destPath = r.URL.Query().Get("path")
		if destPath == "" {
			errOut(w, 400, fmt.Sprintf(
				"cannot determine restore path for volume slug '%s' — volume not found in app config. Add ?path=/volumes/... to override",
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
var backupArchiveNamePattern = regexp.MustCompile(`^[a-z0-9_]+_[a-z0-9_]+_\d{8}_\d{6}(_prerestore)?\.tar\.gz$`)

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
// GET /api/apikey  → returns the full API key for use with external integrations.

func (s *Server) handleAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errOut(w, 405, "method not allowed")
		return
	}
	key := s.cfg.APIKey()
	respond(w, 200, map[string]any{
		"key":          key,
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
			reply += fmt.Sprintf("• `%s`%s%s — %d volume(s)\n", a.Name, pin, running, len(a.Volumes))
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
			_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "A job is already running", IsError: true})
			return
		}
		_ = notify.SendTelegram(tgCfg, notify.Event{AppName: app.Name, Detail: "Backup started ⏳"})
		go s.runBackup(*app, false)

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
		go s.runBackup(app, false)
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
	if s == "" {
		return "vol"
	}
	return s
}