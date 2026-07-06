package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pi/prestoback/internal/api"
	"github.com/pi/prestoback/internal/config"
)

func main() {
	port := flag.Int("port", 8765, "HTTP server port")
	dataDir := flag.String("data", "/data", "PrestoBack data directory")
	volumesDir := flag.String("volumes", "/volumes", "Presto volumes directory")
	composeFile := flag.String("compose-file", "", "Path inside this container to your docker-compose.yml (enables /update auto-restart). E.g. /compose/docker-compose.yml")
	flag.Parse()

	image := envOr("PRESTOBACK_IMAGE", "")
	selfName := envOr("PRESTOBACK_CONTAINER", "prestoback")

	fmt.Printf("PrestoBack v%s\n", config.Version)

	// Restart-reason detection: was this process started fresh, or did the
	// previous instance get stopped by something external (host reboot,
	// `docker restart`, the Docker daemon restarting) rather than by its own
	// /update or /selfupdate flow? Purely additive — there was no signal
	// handling here before, so SIGTERM just killed the process immediately;
	// this does the same thing (a few-millisecond marker write, then
	// os.Exit), it just leaves a note for the next startup to find.
	restartNote := checkPreviousShutdown(*dataDir)
	installShutdownMarker(*dataDir)

	cfg, err := config.Load(*dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.VolumesDir = *volumesDir
	cfg.DataDir = *dataDir

	// Compose file: flag takes precedence over env var.
	cfg.ComposeFile = *composeFile
	if cfg.ComposeFile == "" {
		cfg.ComposeFile = envOr("PRESTOBACK_COMPOSE_FILE", "")
	}
	if cfg.ComposeFile != "" {
		if _, err := os.Stat(cfg.ComposeFile); err != nil {
			log.Printf("[warn] PRESTOBACK_COMPOSE_FILE=%q is NOT accessible inside this container: %v", cfg.ComposeFile, err)
			log.Printf("[warn] /update will fall back to 'manual restart needed'")
			log.Printf("[warn] Fix: mount at the exact host path, e.g.:")
			log.Printf("[warn]   volumes: - ${PWD}/docker-compose.yml:${PWD}/docker-compose.yml:ro")
			log.Printf("[warn]   environment: PRESTOBACK_COMPOSE_FILE: ${PWD}/docker-compose.yml")
		} else {
			log.Printf("[compose] file OK: %s", cfg.ComposeFile)
		}
	}

	if err := os.MkdirAll(cfg.BackupDir(), 0755); err != nil {
		log.Fatalf("mkdir backup dir: %v", err)
	}

	// Save immediately to persist auto-generated API key on first run
	if err := cfg.Save(); err != nil {
		log.Fatalf("config save: %v", err)
	}

	// Clean up any leftover updater helper container from a previous self-update.
	// Runs silently — if the container doesn't exist this is a no-op.
	_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()

	srv := api.NewServer(cfg, image, selfName, restartNote)
	if err := srv.Run(*port); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Restart-reason detection ─────────────────────────────────────────────────
//
// Distinguishes "PrestoBack restarted itself" (e.g. /update, /selfupdate —
// those flows already know why they're restarting) from "something external
// stopped this container" (host reboot, `docker restart`, the Docker daemon
// restarting) — the latter is otherwise invisible: the next startup looks
// identical either way. A small marker file bridges the one process's death
// to the next process's start.

type shutdownMarker struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

func shutdownMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, ".last_shutdown.json")
}

// checkPreviousShutdown reads and clears any marker left by a previous
// process's signal handler below, returning a note for the startup message
// if one is found. Returns "" for a normal start — first run, a crash, or a
// previous process that was SIGKILLed before it could write the marker (a
// slow shutdown handler forcibly killed after Docker's stop-grace-period —
// not this one, which just does a fast file write).
func checkPreviousShutdown(dataDir string) string {
	path := shutdownMarkerPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	_ = os.Remove(path) // best-effort — a leftover marker just means this note repeats once more, harmless
	var m shutdownMarker
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	reason := m.Reason
	if reason == "" {
		reason = "an external stop signal"
	}
	return fmt.Sprintf(
		"Restart followed %s — e.g. a host reboot, docker restart, or the Docker daemon restarting. PrestoBack did not restart itself.",
		reason,
	)
}

// installShutdownMarker traps SIGTERM/SIGINT and writes the marker above
// before exiting. Before this, the process had no signal handling at all —
// SIGTERM's default Go behavior is immediate termination — so this
// preserves that exact behavior (os.Exit right after the write) rather than
// attempting a slower graceful HTTP drain, which isn't something this
// process had before either and isn't worth the added risk to add blind.
func installShutdownMarker(dataDir string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		sigName := "SIGTERM"
		if sig == syscall.SIGINT {
			sigName = "SIGINT"
		}
		reason := fmt.Sprintf("an external stop signal (%s)", sigName)
		m := shutdownMarker{Reason: reason, At: time.Now().UTC()}
		if data, err := json.Marshal(m); err == nil {
			_ = os.WriteFile(shutdownMarkerPath(dataDir), data, 0644)
		}
		os.Exit(0)
	}()
}
