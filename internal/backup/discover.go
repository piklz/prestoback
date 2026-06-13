package backup

// discover.go — finds running containers and their bind-mount paths via the
// Docker socket, translating host paths into paths accessible inside the
// prestoback container via its own volume mounts.

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
	Path          string `json:"path"` // path INSIDE prestoback container
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	Running       bool   `json:"running"`
	LabelHinted   bool   `json:"label_hinted"`
	Source        string `json:"source"`     // "docker" | "volumes_dir"
	Accessible    bool   `json:"accessible"` // can prestoback actually reach this path?
}

type dockerContainer struct {
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Binds []string `json:"Binds"`
	} `json:"HostConfig"`
}

// DiscoverApps queries the Docker socket for running containers and returns
// candidate apps the user can confirm and import.
//
// selfName is the prestoback container name — used to read its own mounts
// so we can translate host paths into container-internal paths.
// volumesDir is the optional flat-directory mount fallback.
// alreadyRegistered is a set of paths already in config (filtered out).
func DiscoverApps(selfName, volumesDir string, alreadyRegistered map[string]bool) []DiscoveredApp {
	// ── Step 1: learn prestoback's own host→container path mappings ──────────
	// e.g. /home/pi/presto/volumes → /volumes
	//      /data → /data
	hostToContainer := inspectSelfMounts(selfName)
	log.Printf("[discover] own mounts: %v", hostToContainer)

	var results []DiscoveredApp
	seen := map[string]bool{}

	// ── Step 2: Docker socket discovery ──────────────────────────────────────
	dockerResults := discoverFromDocker(selfName, hostToContainer, alreadyRegistered, seen)
	results = append(results, dockerResults...)

	// ── Step 3: VolumesDir flat scan (fallback) ───────────────────────────────
	if volumesDir != "" {
		dirResults := discoverFromDir(volumesDir, alreadyRegistered, seen)
		results = append(results, dirResults...)
	}

	return results
}

// inspectSelfMounts returns a map of hostPath→containerPath for the prestoback
// container itself, so we can translate other containers' host paths.
func inspectSelfMounts(selfName string) map[string]string {
	result := map[string]string{}
	if selfName == "" {
		return result
	}
	raw, err := exec.Command("docker", "container", "inspect", selfName).Output()
	if err != nil {
		log.Printf("[discover] could not inspect self (%s): %v", selfName, err)
		return result
	}
	var arr []dockerContainer
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return result
	}
	for _, bind := range arr[0].HostConfig.Binds {
		hostPath, containerPath, _ := parseBindMount(bind)
		if hostPath != "" && containerPath != "" && !isSystemPath(hostPath) {
			result[filepath.Clean(hostPath)] = filepath.Clean(containerPath)
		}
	}
	return result
}

// translateHostPath converts a host path to a path accessible inside the
// prestoback container using its known mount mappings.
// Returns ("", false) if the path is not accessible.
func translateHostPath(hostPath string, hostToContainer map[string]string) (string, bool) {
	hostPath = filepath.Clean(hostPath)

	// Direct match
	if cp, ok := hostToContainer[hostPath]; ok {
		return cp, true
	}

	// Check if hostPath is under any of our mounted host dirs
	// e.g. hostPath=/home/pi/presto/volumes/plex, mount=/home/pi/presto/volumes→/volumes
	// result = /volumes/plex
	for hostMount, containerMount := range hostToContainer {
		if strings.HasPrefix(hostPath, hostMount+"/") {
			rel := strings.TrimPrefix(hostPath, hostMount)
			return filepath.Join(containerMount, rel), true
		}
	}
	return "", false
}

func discoverFromDocker(selfName string, hostToContainer map[string]string, alreadyRegistered map[string]bool, seen map[string]bool) []DiscoveredApp {
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
		name := strings.TrimPrefix(c.Name, "/")

		// Skip prestoback itself and its helper
		if name == selfName || name == "prestoback" || name == "prestoback-updater" {
			continue
		}

		labels := c.Config.Labels
		if labels["com.prestoback.ignore"] == "true" {
			continue
		}

		friendlyName := labels["com.prestoback.name"]
		if friendlyName == "" {
			friendlyName = cleanContainerName(name)
		}

		// Explicit path label — translate from host path if needed
		if explicitPath := labels["com.prestoback.path"]; explicitPath != "" {
			containerPath, accessible := translateHostPath(explicitPath, hostToContainer)
			if !accessible {
				// Try using it directly (might already be a container-internal path)
				containerPath = explicitPath
				accessible = pathAccessible(explicitPath)
			}
			key := containerPath
			if !alreadyRegistered[key] && !seen[key] {
				seen[key] = true
				results = append(results, DiscoveredApp{
					Name: friendlyName, Path: containerPath,
					ContainerName: name, Image: c.Config.Image,
					Running: c.State.Running, LabelHinted: true,
					Source: "docker", Accessible: accessible,
				})
			}
			continue
		}

		// Scan bind mounts
		for _, bind := range c.HostConfig.Binds {
			hostPath, _, _ := parseBindMount(bind)
			if hostPath == "" {
				continue
			}
			if isSystemPath(hostPath) {
				continue
			}

			// Translate host path → container-internal path
			containerPath, accessible := translateHostPath(hostPath, hostToContainer)
			if !accessible {
				// Not mounted into prestoback — skip, can't back it up
				log.Printf("[discover] skipping %s bind %s — not accessible inside prestoback", name, hostPath)
				continue
			}

			if alreadyRegistered[containerPath] || seen[containerPath] {
				continue
			}

			labelBacked := labels["com.prestoback.backup"] == "true"
			seen[containerPath] = true
			results = append(results, DiscoveredApp{
				Name:          friendlyName,
				Path:          containerPath,
				ContainerName: name,
				Image:         c.Config.Image,
				Running:       c.State.Running,
				LabelHinted:   labelBacked,
				Source:        "docker",
				Accessible:    true,
			})
		}
	}
	return results
}

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
			Name: e.Name(), Path: path,
			Source: "volumes_dir", Accessible: true,
		})
	}
	return results
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseBindMount(bind string) (hostPath, containerPath, options string) {
	parts := strings.SplitN(bind, ":", 3)
	if len(parts) < 2 {
		return "", "", ""
	}
	if len(parts) == 3 {
		return parts[0], parts[1], parts[2]
	}
	return parts[0], parts[1], ""
}

func isSystemPath(path string) bool {
	// Exact matches for things that should never be backed up
	systemExact := []string{
		"/", "/proc", "/sys", "/dev", "/run", "/tmp",
		"/var/run/docker.sock", "/etc/localtime", "/etc/timezone",
	}
	for _, p := range systemExact {
		if path == p {
			return true
		}
	}
	// Prefix matches
	systemPrefixes := []string{
		"/proc/", "/sys/", "/dev/", "/run/",
		"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func pathAccessible(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cleanContainerName(name string) string {
	name = strings.ReplaceAll(name, "_", "-")
	parts := strings.Split(name, "-")
	// Drop trailing replica number
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
	// Drop leading project name if 3+ parts
	if len(parts) > 2 {
		parts = parts[1:]
	}
	result := strings.Join(parts, "-")
	if result == "" {
		return name
	}
	return strings.ToUpper(result[:1]) + result[1:]
}
