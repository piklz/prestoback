package backup

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// ContainerInfo holds what we need about a matched container.
type ContainerInfo struct {
	ID     string
	Name   string
	Status string // "running", "exited", etc.
}

// FindContainers returns ALL containers (running or stopped) that look like
// they belong to the given appID. We try several strategies so that
// standard docker-compose naming (presto-plex-1, presto_plex_1, plex, etc.)
// all get matched.
//
// Returns multiple matches in case of replica sets; the caller should use all of them.
func FindContainers(appID string) []ContainerInfo {
	// Normalise: "homepage_3044" → base name is the part before the first underscore+digits suffix
	// e.g. homepage_3044 → "homepage", plex_1234 → "plex"
	baseName := stripIDSuffix(appID)

	// Build candidate name fragments to try (most specific first)
	candidates := dedupe([]string{
		appID,
		baseName,
		strings.ReplaceAll(appID, "_", "-"),
		strings.ReplaceAll(baseName, "_", "-"),
	})

	seen := map[string]bool{}
	var results []ContainerInfo

	for _, name := range candidates {
		// docker ps -a so we also catch already-stopped containers
		out, err := exec.Command(
			"docker", "ps", "-a",
			"--filter", "name="+name,
			"--format", `{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}"}`,
		).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var ci ContainerInfo
			if err := json.Unmarshal([]byte(line), &ci); err != nil {
				continue
			}
			// Docker --filter name= is a substring match, so verify the
			// container name actually contains our candidate as a word segment.
			nameLower := strings.ToLower(ci.Name)
			if !nameContains(nameLower, strings.ToLower(name)) {
				continue
			}
			if seen[ci.ID] {
				continue
			}
			seen[ci.ID] = true
			ci.Status = containerState(ci.ID)
			results = append(results, ci)
			log.Printf("[docker] matched container %s (%s) for app %s", ci.Name, ci.ID, appID)
		}
	}

	// Also try by label (works if containers were tagged with com.presto.app)
	for _, labelVal := range dedupe([]string{appID, baseName}) {
		out, err := exec.Command(
			"docker", "ps", "-a",
			"--filter", "label=com.presto.app="+labelVal,
			"--format", `{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}"}`,
		).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var ci ContainerInfo
			if err := json.Unmarshal([]byte(line), &ci); err != nil {
				continue
			}
			if seen[ci.ID] {
				continue
			}
			seen[ci.ID] = true
			ci.Status = containerState(ci.ID)
			results = append(results, ci)
		}
	}

	if len(results) == 0 {
		log.Printf("[docker] no containers found for app %s (tried: %v) — will proceed without stop/start", appID, candidates)
	}
	return results
}

// StopContainers stops all given containers, returning a map of id→wasRunning
// so the caller knows which ones to restart.
func StopContainers(containers []ContainerInfo, emitFn func(string)) ([]ContainerInfo, error) {
	var toRestart []ContainerInfo
	for _, c := range containers {
		if c.Status != "running" {
			log.Printf("[docker] container %s is already %s — skipping stop", c.Name, c.Status)
			continue
		}
		emitFn(fmt.Sprintf("Stopping container %s…", c.Name))
		out, err := exec.Command("docker", "stop", "-t", "30", c.ID).CombinedOutput()
		if err != nil {
			return toRestart, fmt.Errorf("docker stop %s: %w\n%s", c.Name, err, out)
		}
		log.Printf("[docker] stopped %s", c.Name)
		toRestart = append(toRestart, c)
	}
	return toRestart, nil
}

// StartContainers starts each container and waits up to 15s for it to reach
// "running" state, emitting progress via emitFn.
func StartContainers(containers []ContainerInfo, emitFn func(string)) {
	for _, c := range containers {
		emitFn(fmt.Sprintf("Starting container %s…", c.Name))
		time.Sleep(300 * time.Millisecond) // let filesystem settle
		out, err := exec.Command("docker", "start", c.ID).CombinedOutput()
		if err != nil {
			emitFn(fmt.Sprintf("ERROR: could not start %s — %s", c.Name, strings.TrimSpace(string(out))))
			log.Printf("[docker] start error for %s: %v", c.Name, err)
			continue
		}
		// Poll for healthy/running state
		if err := waitRunning(c.ID, c.Name, 15*time.Second, emitFn); err != nil {
			emitFn(fmt.Sprintf("Warning: %s started but may not be healthy: %v", c.Name, err))
		} else {
			emitFn(fmt.Sprintf("Container %s is running ✓", c.Name))
		}
	}
}

// waitRunning polls docker inspect until the container is "running" or timeout.
func waitRunning(id, name string, timeout time.Duration, emitFn func(string)) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state := containerState(id)
		switch state {
		case "running":
			return nil
		case "exited", "dead":
			// Get the exit code + last log lines for a useful error message
			out, _ := exec.Command("docker", "logs", "--tail=5", id).CombinedOutput()
			return fmt.Errorf("container exited immediately. Last logs:\n%s", out)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to reach running state", name)
}

// containerState returns the low-level State.Status from docker inspect.
func containerState(id string) string {
	out, err := exec.Command("docker", "inspect", "--format={{.State.Status}}", id).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// stripIDSuffix removes a trailing _NNNN suffix that PrestoBack appends to app IDs.
// "homepage_3044" → "homepage", "radarr" → "radarr"
func stripIDSuffix(id string) string {
	parts := strings.Split(id, "_")
	if len(parts) < 2 {
		return id
	}
	// If the last segment is all digits, drop it
	last := parts[len(parts)-1]
	allDigits := true
	for _, c := range last {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits && len(last) >= 3 {
		return strings.Join(parts[:len(parts)-1], "_")
	}
	return id
}

func nameContains(haystack, needle string) bool {
	// Check if needle appears as a word/segment in haystack
	// e.g. "presto-plex-1" contains "plex" ✓, but "complexplex" contains "plex" which we allow too
	return strings.Contains(haystack, needle)
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	out := ss[:0]
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
