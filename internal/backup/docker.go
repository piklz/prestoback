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
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // "running", "exited", etc.
}

// ── Compose dependency discovery ──────────────────────────────────────────────
//
// Docker Compose stamps every container it creates with labels recording
// which compose project/service it belongs to, and — crucially — what its
// own `depends_on:` entry in the compose file listed. We read that straight
// off the container; no compose file parsing needed.
//
// IMPORTANT — direction matters: we only ever read a container's OWN
// depends_on label, never anyone else's. A reverse proxy that depends_on
// your app (e.g. Caddy → Vaultwarden) is irrelevant to backing up the app —
// we only care what the app ITSELF depends on (e.g. immich-server →
// postgres, redis), since that's where its actual data dependencies live.

const (
	composeProjectLabel   = "com.docker.compose.project"
	composeServiceLabel   = "com.docker.compose.service"
	composeDependsOnLabel = "com.docker.compose.depends_on"
)

// ComposeLink describes one compose-declared dependency, resolved to an
// actual sibling container where possible.
type ComposeLink struct {
	ServiceName string         `json:"service_name"`        // as named in depends_on, e.g. "database"
	Container   *ContainerInfo `json:"container,omitempty"` // resolved sibling, nil if not found
}

// ComposeDependencies reads a container's own com.docker.compose.depends_on
// label and resolves each entry to its actual sibling container within the
// same compose project. Returns nil if the container isn't compose-managed
// or has no declared dependencies (e.g. it's the thing other things depend
// on, not the other way around).
func ComposeDependencies(containerID string) []ComposeLink {
	labels := inspectLabels(containerID)
	if labels == nil {
		return nil
	}
	project := labels[composeProjectLabel]
	depsRaw := labels[composeDependsOnLabel]
	if project == "" || depsRaw == "" {
		return nil
	}

	var links []ComposeLink
	for _, entry := range strings.Split(depsRaw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Format is "service:condition:required" — we only need the service name,
		// and we parse defensively in case the exact format varies by Compose version.
		serviceName := strings.SplitN(entry, ":", 2)[0]
		if serviceName == "" {
			continue
		}
		link := ComposeLink{ServiceName: serviceName}
		if ci := findComposeService(project, serviceName); ci != nil {
			link.Container = ci
		}
		links = append(links, link)
	}
	return links
}

// inspectLabels returns a container's labels, or nil on any failure.
func inspectLabels(containerID string) map[string]string {
	out, err := exec.Command("docker", "inspect", "--format={{json .Config.Labels}}", containerID).Output()
	if err != nil {
		return nil
	}
	var labels map[string]string
	if err := json.Unmarshal(out, &labels); err != nil {
		return nil
	}
	return labels
}

// findComposeService locates the container for a given compose project +
// service name pair, regardless of running state. If a service has multiple
// replicas, the first match is returned.
func findComposeService(project, service string) *ContainerInfo {
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "label="+composeProjectLabel+"="+project,
		"--filter", "label="+composeServiceLabel+"="+service,
		"--format", `{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}"}`,
	).Output()
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil
	}
	first := strings.SplitN(line, "\n", 2)[0]
	var ci ContainerInfo
	if err := json.Unmarshal([]byte(first), &ci); err != nil {
		return nil
	}
	ci.Status = containerState(ci.ID)
	return &ci
}

// ContainersByName resolves explicit, user-configured container names (e.g.
// AppConfig.LinkedContainers) to their current ContainerInfo. Unlike
// FindContainers, this does an exact-name lookup — no fuzzy matching — since
// the user (or auto-detection) already pinned down the precise name.
func ContainersByName(names []string) []ContainerInfo {
	var out []ContainerInfo
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		raw, err := exec.Command("docker", "ps", "-a",
			"--filter", "name=^/"+name+"$",
			"--format", `{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}"}`,
		).Output()
		if err != nil {
			continue
		}
		line := strings.TrimSpace(string(raw))
		if line == "" {
			log.Printf("[docker] linked container %q not found", name)
			continue
		}
		var ci ContainerInfo
		if err := json.Unmarshal([]byte(strings.SplitN(line, "\n", 2)[0]), &ci); err != nil {
			continue
		}
		ci.Status = containerState(ci.ID)
		out = append(out, ci)
	}
	return out
}

// DedupeContainers removes duplicate entries by ID — relevant when a linked
// container happens to also be matched by FindContainers' name heuristics.
func DedupeContainers(cs []ContainerInfo) []ContainerInfo {
	seen := map[string]bool{}
	var out []ContainerInfo
	for _, c := range cs {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out
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

// PauseContainers freezes all running containers via SIGSTOP (docker pause),
// returning the set that was actually paused so the caller knows what to
// resume afterward. Unlike StopContainers, nothing exits and nothing is
// asked to flush — the container's filesystem state is simply frozen exactly
// where it stood. This is crash-consistent (the same guarantee LVM/ZFS
// snapshots give), not clean-shutdown-consistent — fine for apps with proper
// WAL/journaling (SQLite, Postgres, MySQL), but skip it for anything that
// writes raw/unjournaled state across multiple files.
func PauseContainers(containers []ContainerInfo, emitFn func(string)) ([]ContainerInfo, error) {
	var toUnpause []ContainerInfo
	for _, c := range containers {
		if c.Status != "running" {
			log.Printf("[docker] container %s is already %s — skipping pause", c.Name, c.Status)
			continue
		}
		emitFn(fmt.Sprintf("Pausing container %s…", c.Name))
		out, err := exec.Command("docker", "pause", c.ID).CombinedOutput()
		if err != nil {
			return toUnpause, fmt.Errorf("docker pause %s: %w\n%s", c.Name, err, out)
		}
		log.Printf("[docker] paused %s", c.Name)
		toUnpause = append(toUnpause, c)
	}
	return toUnpause, nil
}

// UnpauseContainers resumes containers previously frozen by PauseContainers.
// Resuming is near-instant (no health-check wait needed — the process never
// stopped running, it just picks back up where it left off).
func UnpauseContainers(containers []ContainerInfo, emitFn func(string)) {
	for _, c := range containers {
		emitFn(fmt.Sprintf("Resuming container %s…", c.Name))
		out, err := exec.Command("docker", "unpause", c.ID).CombinedOutput()
		if err != nil {
			emitFn(fmt.Sprintf("ERROR: could not unpause %s — %s", c.Name, strings.TrimSpace(string(out))))
			log.Printf("[docker] unpause error for %s: %v", c.Name, err)
			continue
		}
		emitFn(fmt.Sprintf("Container %s resumed ✓", c.Name))
	}
}

// QuiesceContainers stops, pauses, or leaves containers alone depending on
// strategy, returning whatever must be passed to ResumeContainers afterward.
// Empty/unrecognized strategy defaults to "stop" (the safest option) so
// existing configs with no container_strategy set behave exactly as before.
func QuiesceContainers(containers []ContainerInfo, strategy string, emitFn func(string)) ([]ContainerInfo, error) {
	switch strategy {
	case "none":
		return nil, nil
	case "pause":
		return PauseContainers(containers, emitFn)
	default:
		return StopContainers(containers, emitFn)
	}
}

// ResumeContainers is the inverse of QuiesceContainers — call with the same
// strategy and the containers it returned.
func ResumeContainers(containers []ContainerInfo, strategy string, emitFn func(string)) {
	if strategy == "pause" {
		UnpauseContainers(containers, emitFn)
		return
	}
	StartContainers(containers, emitFn)
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

// ── Container update ──────────────────────────────────────────────────────────

// ContainerUpdate holds the result of pulling and recreating one container.
type ContainerUpdate struct {
	ContainerName string
	Image         string
	Pulled        bool   // image was pulled from registry
	Restarted     bool   // container was recreated via compose up -d
	NeedsManual   bool   // pulled OK but no compose info — user must recreate
	Err           string // non-empty on failure
}

// UpdateContainer pulls the latest image for c and, if the container is
// compose-managed (has com.docker.compose.project.working_dir label), recreates
// it via "docker compose up -d --no-deps <service>".
//
// Important: this does NOT back up the container's data first. Callers should
// run a backup (or accept the risk) before calling this.
func UpdateContainer(c ContainerInfo) ContainerUpdate {
	res := ContainerUpdate{ContainerName: c.Name}

	// Resolve the image name from the live container config.
	out, err := exec.Command("docker", "inspect", "--format={{.Config.Image}}", c.ID).Output()
	if err != nil {
		res.Err = "inspect failed: " + err.Error()
		return res
	}
	res.Image = strings.TrimSpace(string(out))
	if res.Image == "" {
		res.Err = "could not determine image name"
		return res
	}

	// Pull the latest digest for this image.
	pullOut, err := exec.Command("docker", "pull", res.Image).CombinedOutput()
	if err != nil {
		res.Err = "pull failed: " + strings.TrimSpace(string(pullOut))
		return res
	}
	res.Pulled = true

	// Re-create via compose if we know the project working directory.
	// Compose reads its own compose.yml / docker-compose.yml from that dir,
	// so we don't need to guess the filename.
	labels := inspectLabels(c.ID)
	wd := labels["com.docker.compose.project.working_dir"]
	service := labels["com.docker.compose.service"]
	if wd != "" && service != "" {
		upOut, err := exec.Command("docker", "compose",
			"--project-directory", wd,
			"up", "-d", "--no-deps", service,
		).CombinedOutput()
		if err != nil {
			res.Err = "compose up failed: " + strings.TrimSpace(string(upOut))
			return res
		}
		res.Restarted = true
		return res
	}

	// No compose metadata — we pulled the image but cannot auto-recreate.
	// The user must stop + rm + docker run (or docker compose up) themselves.
	res.NeedsManual = true
	return res
}
