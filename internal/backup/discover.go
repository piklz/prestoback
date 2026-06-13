package backup

// discover.go — finds running containers and their bind-mount paths via the
// Docker socket. This lets PrestoBack work with any directory layout, not
// just a flat /volumes tree.
//
// Two discovery sources, merged and deduplicated:
//   1. Docker socket  — queries running containers for bind mounts
//   2. VolumesDir scan — existing flat-directory fallback (optional)
//
// Label convention (same pattern as offen/docker-volume-backup):
//   com.prestoback.backup=true   — include this container in discovery
//   com.prestoback.path=/data    — override which bind mount to back up
//   com.prestoback.name=MyApp   — friendly name override

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DiscoveredApp is a candidate app found via Docker socket or volumes dir.
type DiscoveredApp struct {
	Name          string `json:"name"`
	Path          string `json:"path"`           // path inside prestoback container
	ContainerName string `json:"container_name"` // source Docker container (if any)
	Image         string `json:"image"`          // container image (informational)
	Running       bool   `json:"running"`
	LabelHinted   bool   `json:"label_hinted"`   // had explicit prestoback label
	Source        string `json:"source"`         // "docker" | "volumes_dir"
}

// dockerContainer is the subset of docker inspect we care about.
type dockerContainer struct {
	Name   string `json:"Name"`
	State  struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Binds []string `json:"Binds"` // "hostpath:containerpath[:options]"
	} `json:"HostConfig"`
}

// DiscoverApps queries the Docker socket for running containers and returns
// candidate apps for the user to confirm and import.
//
// volumesDir is the optional flat-directory mount (legacy / your setup).
// Pass "" to skip the directory scan.
//
// alreadyRegistered is a set of paths already in the prestoback config —
// these are filtered out so the UI only shows new candidates.
func DiscoverApps(volumesDir string, alreadyRegistered map[string]bool) []DiscoveredApp {
	var results []DiscoveredApp
	seen := map[string]bool{}

	// ── Source 1: Docker socket ──────────────────────────────────────────────
	dockerResults := discoverFromDocker(alreadyRegistered, seen)
	results = append(results, dockerResults...)

	// ── Source 2: VolumesDir flat scan (fallback / legacy) ──────────────────
	if volumesDir != "" {
		dirResults := discoverFromDir(volumesDir, alreadyRegistered, seen)
		results = append(results, dirResults...)
	}

	return results
}

// discoverFromDocker queries `docker ps -a` then inspects each container.
func discoverFromDocker(alreadyRegistered map[string]bool, seen map[string]bool) []DiscoveredApp {
	// Get all container IDs (running + stopped so user can see everything)
	out, err := exec.Command("docker", "ps", "-a", "--format={{.ID}}").Output()
	if err != nil {
		log.Printf("[discover] docker ps failed: %v — is Docker socket mounted?", err)
		return nil
	}

	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}

	// Inspect all containers in one call
	args := append([]string{"inspect"}, ids...)
	raw, err := exec.Command("docker", args...).Output()
	if err != nil {
		log.Printf("[discover] docker inspect failed: %v", err)
		return nil
	}

	var containers []dockerContainer
	if err := json.Unmarshal(raw, &containers); err != nil {
		log.Printf("[discover] inspect parse failed: %v", err)
		return nil
	}

	var results []DiscoveredApp
	for _, c := range containers {
		// Clean container name (docker prefixes with /)
		name := strings.TrimPrefix(c.Name, "/")

		// Skip prestoback itself and its updater helper
		if name == "prestoback" || name == "prestoback-updater" {
			continue
		}

		labels := c.Config.Labels

		// Check for explicit opt-out label
		if labels["com.prestoback.ignore"] == "true" {
			continue
		}

		// Friendly name — label override or container name
		friendlyName := labels["com.prestoback.name"]
		if friendlyName == "" {
			friendlyName = cleanContainerName(name)
		}

		// Explicit path label — highest priority
		if explicitPath := labels["com.prestoback.path"]; explicitPath != "" {
			if !alreadyRegistered[explicitPath] && !seen[explicitPath] {
				seen[explicitPath] = true
				results = append(results, DiscoveredApp{
					Name:          friendlyName,
					Path:          explicitPath,
					ContainerName: name,
					Image:         c.Config.Image,
					Running:       c.State.Running,
					LabelHinted:   true,
					Source:        "docker",
				})
			}
			continue // explicit path set — don't also scan bind mounts
		}

		// Scan bind mounts for useful data directories
		for _, bind := range c.HostConfig.Binds {
			hostPath, containerPath := parseBindMount(bind)
			if hostPath == "" || containerPath == "" {
				continue
			}

			// Skip system/socket mounts
			if isSystemPath(hostPath) || isSystemPath(containerPath) {
				continue
			}

			// The path prestoback uses is the HOST path as seen inside our
			// container. If the user mounted /home/pi/stacks:/stacks into
			// prestoback, then hostPath "/home/pi/stacks/plex/config" is
			// accessible inside prestoback as "/stacks/plex/config".
			// We can't know the mapping, so we present both and let the user
			// confirm via validate-path.
			if alreadyRegistered[hostPath] || seen[hostPath] {
				continue
			}

			// Only include if com.prestoback.backup=true label is set,
			// OR if no label set (show everything, user can filter)
			labelBacked := labels["com.prestoback.backup"] == "true"

			seen[hostPath] = true
			results = append(results, DiscoveredApp{
				Name:          friendlyName + " (" + filepath.Base(containerPath) + ")",
				Path:          hostPath,
				ContainerName: name,
				Image:         c.Config.Image,
				Running:       c.State.Running,
				LabelHinted:   labelBacked,
				Source:        "docker",
			})
		}
	}
	return results
}

// discoverFromDir scans a flat directory (the legacy /volumes approach).
func discoverFromDir(dir string, alreadyRegistered map[string]bool, seen map[string]bool) []DiscoveredApp {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		log.Printf("[discover] read volumes dir %s: %v", dir, err)
		return nil
	}

	var results []DiscoveredApp
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if alreadyRegistered[path] || seen[path] {
			continue
		}
		seen[path] = true
		results = append(results, DiscoveredApp{
			Name:   e.Name(),
			Path:   path,
			Source: "volumes_dir",
		})
	}
	return results
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseBindMount splits "hostpath:containerpath:options" into its parts.
func parseBindMount(bind string) (hostPath, containerPath string) {
	parts := strings.SplitN(bind, ":", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// isSystemPath returns true for paths that are never useful to back up.
func isSystemPath(path string) bool {
	systemPrefixes := []string{
		"/proc", "/sys", "/dev", "/run", "/tmp",
		"/var/run/docker.sock",
		"/etc/localtime", "/etc/timezone",
		"/usr/", "/bin/", "/sbin/", "/lib/",
	}
	for _, prefix := range systemPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// cleanContainerName turns "presto-plex-1" or "presto_plex_1" into "plex".
func cleanContainerName(name string) string {
	// Strip common compose prefix patterns: "projectname-service-N" or "projectname_service_N"
	name = strings.ReplaceAll(name, "_", "-")
	parts := strings.Split(name, "-")

	// If last part is a number (replica index), drop it
	if len(parts) > 1 {
		last := parts[len(parts)-1]
		allDigits := true
		for _, c := range last {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			parts = parts[:len(parts)-1]
		}
	}

	// If more than 2 parts, drop the first (project name)
	if len(parts) > 2 {
		parts = parts[1:]
	}

	result := strings.Join(parts, "-")
	if result == "" {
		return name
	}
	// Title case first letter
	return strings.ToUpper(result[:1]) + result[1:]
}
