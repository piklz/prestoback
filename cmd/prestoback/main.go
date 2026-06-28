package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

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

	srv := api.NewServer(cfg, image, selfName)
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
