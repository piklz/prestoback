package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pi/prestoback/internal/api"
	"github.com/pi/prestoback/internal/config"
)

func main() {
	port       := flag.Int("port", 8765, "HTTP server port")
	dataDir    := flag.String("data", "/data", "PrestoBack data directory")
	volumesDir := flag.String("volumes", "/volumes", "Presto volumes directory")
	flag.Parse()

	image    := envOr("PRESTOBACK_IMAGE", "")
	selfName := envOr("PRESTOBACK_CONTAINER", "prestoback")

	fmt.Printf("PrestoBack v%s\n", config.Version)

	cfg, err := config.Load(*dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.VolumesDir = *volumesDir
	cfg.DataDir    = *dataDir

	if err := os.MkdirAll(cfg.BackupDir(), 0755); err != nil {
		log.Fatalf("mkdir backup dir: %v", err)
	}

	// Save immediately to persist auto-generated API key on first run
	if err := cfg.Save(); err != nil {
		log.Fatalf("config save: %v", err)
	}

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
