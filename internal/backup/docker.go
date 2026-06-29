package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
//
// Strategy: read the full HostConfig from the running container via the Docker
// socket and recreate the container directly — no compose file needed.
//
// This is the same approach as Docksentry: inspect → pull → stop → rename →
// create (with identical HostConfig + new image) → start → verify → rm old.
// Compose is tried first if configured (PRESTOBACK_COMPOSE_FILE), but the
// standalone recreate is the reliable fallback that always works.
//
// Rollback: if the new container fails to reach "running" within 30s, the
// old container is renamed back and restarted automatically.

// ContainerUpdate holds the result of pulling and recreating one container.
type ContainerUpdate struct {
	ContainerName   string
	Image           string
	Pulled          bool   // image was pulled from registry
	AlreadyUpToDate bool   // pull succeeded but image was already current
	Restarted       bool   // container recreated successfully
	Rolled          bool   // new container failed health check — rolled back to previous
	NeedsManual     bool   // pulled OK but socket operations failed unexpectedly
	Err             string // non-empty on failure
}

// fullInspect holds the container configuration needed to recreate a container.
// Fields not present in older Docker versions default to zero values and are
// handled gracefully in buildCreateArgs.
type fullInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image      string            `json:"Image"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
		Labels     map[string]string `json:"Labels"`
		User       string            `json:"User"`
		WorkingDir string            `json:"WorkingDir"`
	} `json:"Config"`
	HostConfig struct {
		Binds         []string `json:"Binds"`
		NetworkMode   string   `json:"NetworkMode"`
		RestartPolicy struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
		Privileged bool     `json:"Privileged"`
		CapAdd     []string `json:"CapAdd"`
		CapDrop    []string `json:"CapDrop"`
		ExtraHosts []string `json:"ExtraHosts"`
		Dns        []string `json:"Dns"`
		GroupAdd   []string `json:"GroupAdd"`
		IpcMode    string   `json:"IpcMode"`
		PidMode    string   `json:"PidMode"`
		ShmSize    int64    `json:"ShmSize"`
		Runtime    string   `json:"Runtime"`
		Devices    []struct {
			PathOnHost        string `json:"PathOnHost"`
			PathInContainer   string `json:"PathInContainer"`
			CgroupPermissions string `json:"CgroupPermissions"`
		} `json:"Devices"`
		Sysctls map[string]string `json:"Sysctls"`
		Ulimits []struct {
			Name string `json:"Name"`
			Soft int64  `json:"Soft"`
			Hard int64  `json:"Hard"`
		} `json:"Ulimits"`
		VolumesFrom []string          `json:"VolumesFrom"`
		Tmpfs       map[string]string `json:"Tmpfs"`
		LogConfig   struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			NetworkID string   `json:"NetworkID"`
			Aliases   []string `json:"Aliases"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`   // non-empty for named volumes
		Source      string `json:"Source"` // host path (bind) or volume name
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// buildCreateArgs converts a fullInspect into a "docker create" argument list.
// The new image is substituted for the old one; everything else is preserved.
func buildCreateArgs(name string, insp fullInspect, newImage string) []string {
	var args []string
	args = append(args, "create", "--name", name)

	// Restart policy
	switch rp := insp.HostConfig.RestartPolicy; rp.Name {
	case "always", "unless-stopped":
		args = append(args, "--restart", rp.Name)
	case "on-failure":
		if rp.MaximumRetryCount > 0 {
			args = append(args, "--restart", fmt.Sprintf("on-failure:%d", rp.MaximumRetryCount))
		} else {
			args = append(args, "--restart", "on-failure")
		}
	}

	// Environment variables
	for _, e := range insp.Config.Env {
		args = append(args, "-e", e)
	}

	// Labels — preserve all (including compose labels so compose still recognises the container)
	for k, v := range insp.Config.Labels {
		args = append(args, "--label", k+"="+v)
	}

	// Mounts: bind mounts + named volumes (from Mounts, which is more reliable
	// than HostConfig.Binds for named volumes)
	for _, m := range insp.Mounts {
		switch m.Type {
		case "bind":
			mode := m.Mode
			if mode == "" {
				if m.RW {
					mode = "rw"
				} else {
					mode = "ro"
				}
			}
			args = append(args, "-v", m.Source+":"+m.Destination+":"+mode)
		case "volume":
			ref := m.Source
			if m.Name != "" {
				ref = m.Name
			}
			mode := m.Mode
			if mode == "" {
				if m.RW {
					mode = "rw"
				} else {
					mode = "ro"
				}
			}
			args = append(args, "-v", ref+":"+m.Destination+":"+mode)
		}
	}

	// Tmpfs
	for target, opts := range insp.HostConfig.Tmpfs {
		if opts != "" {
			args = append(args, "--tmpfs", target+":"+opts)
		} else {
			args = append(args, "--tmpfs", target)
		}
	}

	// Port bindings
	for containerPort, bindings := range insp.HostConfig.PortBindings {
		for _, hb := range bindings {
			switch {
			case hb.HostIP != "" && hb.HostIP != "0.0.0.0":
				args = append(args, "-p", hb.HostIP+":"+hb.HostPort+":"+containerPort)
			case hb.HostPort != "":
				args = append(args, "-p", hb.HostPort+":"+containerPort)
			default:
				args = append(args, "-p", containerPort)
			}
		}
	}

	// Primary network — additional networks are connected after create
	nm := insp.HostConfig.NetworkMode
	if nm == "" || nm == "default" {
		nm = "bridge"
	}
	args = append(args, "--network", nm)

	// Privileged
	if insp.HostConfig.Privileged {
		args = append(args, "--privileged")
	}

	// User
	if insp.Config.User != "" {
		args = append(args, "--user", insp.Config.User)
	}

	// Working directory
	if insp.Config.WorkingDir != "" {
		args = append(args, "--workdir", insp.Config.WorkingDir)
	}

	// IPC mode (skip Docker defaults)
	if ipc := insp.HostConfig.IpcMode; ipc != "" && ipc != "private" && ipc != "shareable" {
		args = append(args, "--ipc", ipc)
	}

	// PID mode
	if pid := insp.HostConfig.PidMode; pid != "" && pid != "private" {
		args = append(args, "--pid", pid)
	}

	// SHM size (skip default 64 MiB)
	const defaultShmSize = 67108864
	if insp.HostConfig.ShmSize > 0 && insp.HostConfig.ShmSize != defaultShmSize {
		args = append(args, fmt.Sprintf("--shm-size=%d", insp.HostConfig.ShmSize))
	}

	// Extra hosts
	for _, h := range insp.HostConfig.ExtraHosts {
		args = append(args, "--add-host", h)
	}

	// DNS
	for _, d := range insp.HostConfig.Dns {
		args = append(args, "--dns", d)
	}

	// Supplemental groups
	for _, g := range insp.HostConfig.GroupAdd {
		args = append(args, "--group-add", g)
	}

	// Capabilities
	for _, cap := range insp.HostConfig.CapAdd {
		args = append(args, "--cap-add", cap)
	}
	for _, cap := range insp.HostConfig.CapDrop {
		args = append(args, "--cap-drop", cap)
	}

	// Devices
	for _, dev := range insp.HostConfig.Devices {
		arg := dev.PathOnHost + ":" + dev.PathInContainer
		if dev.CgroupPermissions != "" && dev.CgroupPermissions != "rwm" {
			arg += ":" + dev.CgroupPermissions
		}
		args = append(args, "--device", arg)
	}

	// Sysctls
	for k, v := range insp.HostConfig.Sysctls {
		args = append(args, "--sysctl", k+"="+v)
	}

	// Ulimits
	for _, ul := range insp.HostConfig.Ulimits {
		args = append(args, "--ulimit", fmt.Sprintf("%s=%d:%d", ul.Name, ul.Soft, ul.Hard))
	}

	// Volumes from other containers
	for _, vf := range insp.HostConfig.VolumesFrom {
		args = append(args, "--volumes-from", vf)
	}

	// Log driver (only if non-default)
	if lc := insp.HostConfig.LogConfig; lc.Type != "" && lc.Type != "json-file" {
		args = append(args, "--log-driver", lc.Type)
		for k, v := range lc.Config {
			args = append(args, "--log-opt", k+"="+v)
		}
	}

	// Runtime (only if non-default)
	if rt := insp.HostConfig.Runtime; rt != "" && rt != "runc" {
		args = append(args, "--runtime", rt)
	}

	// Entrypoint (first element only — --entrypoint takes a single string)
	if len(insp.Config.Entrypoint) > 0 {
		args = append(args, "--entrypoint", insp.Config.Entrypoint[0])
	}

	// Image (the new one)
	args = append(args, newImage)

	// Cmd: if entrypoint has extra elements, they become the first cmd args
	if len(insp.Config.Entrypoint) > 1 {
		args = append(args, insp.Config.Entrypoint[1:]...)
	}
	args = append(args, insp.Config.Cmd...)

	return args
}

// standaloneRecreate stops the container, renames it to a _prestoback_bak
// backup, creates a new container from the same HostConfig + new image,
// starts it, verifies it reaches "running", then removes the old one.
//
// If the new container fails the health check within 30s it automatically
// renames the backup back and restarts the original — full rollback.
//
// This requires no compose file — only the Docker socket.
func standaloneRecreate(c ContainerInfo, newImage string) (rolled bool, err error) {
	// Full inspect of the running container
	raw, inspErr := exec.Command("docker", "inspect", c.ID).Output()
	if inspErr != nil {
		return false, fmt.Errorf("inspect failed: %w", inspErr)
	}
	var inspects []fullInspect
	if jsonErr := json.Unmarshal(raw, &inspects); jsonErr != nil || len(inspects) == 0 {
		return false, fmt.Errorf("inspect parse failed: %w", jsonErr)
	}
	insp := inspects[0]
	name := strings.TrimPrefix(insp.Name, "/")
	bakName := name + "_prestoback_bak"

	// Remove any leftover backup container from a previous failed update
	_ = exec.Command("docker", "rm", "-f", bakName).Run()

	// Stop the current container gracefully
	log.Printf("[recreate] stopping %s", name)
	if out, stopErr := exec.Command("docker", "stop", "-t", "30", c.ID).CombinedOutput(); stopErr != nil {
		return false, fmt.Errorf("stop failed: %s", stripDockerOutput(string(out)))
	}

	// Rename old container so we can reclaim the name
	log.Printf("[recreate] renaming %s → %s", name, bakName)
	if out, renErr := exec.Command("docker", "rename", c.ID, bakName).CombinedOutput(); renErr != nil {
		_ = exec.Command("docker", "start", c.ID).Run() // restore original
		return false, fmt.Errorf("rename failed: %s", stripDockerOutput(string(out)))
	}

	// rollback restores the old container on any subsequent failure
	rollback := func(reason error) (bool, error) {
		log.Printf("[recreate] rollback %s: %v", name, reason)
		_ = exec.Command("docker", "rename", bakName, name).Run()
		if startErr := exec.Command("docker", "start", c.ID).Run(); startErr != nil {
			log.Printf("[recreate] WARNING: rollback start failed for %s: %v", name, startErr)
		}
		return true, fmt.Errorf("%w", reason)
	}

	// Create new container from identical HostConfig + new image
	createArgs := buildCreateArgs(name, insp, newImage)
	log.Printf("[recreate] docker create %s (image: %s)", name, newImage)
	createOut, createErr := exec.Command("docker", createArgs...).CombinedOutput()
	if createErr != nil {
		return rollback(fmt.Errorf("create failed: %s", stripDockerOutput(string(createOut))))
	}
	newID := strings.TrimSpace(string(createOut))

	// Connect to additional networks (compose projects often have several)
	primaryNet := insp.HostConfig.NetworkMode
	if primaryNet == "" || primaryNet == "default" {
		primaryNet = "bridge"
	}
	for netName, netInfo := range insp.NetworkSettings.Networks {
		if netName == primaryNet {
			continue
		}
		// Skip built-in Docker networks already handled by --network
		if netName == "bridge" || netName == "host" || netName == "none" {
			continue
		}
		log.Printf("[recreate] connecting %s to network %s", name, netName)
		connectArgs := []string{"network", "connect"}
		for _, alias := range netInfo.Aliases {
			connectArgs = append(connectArgs, "--alias", alias)
		}
		connectArgs = append(connectArgs, netName, newID)
		if out, connErr := exec.Command("docker", connectArgs...).CombinedOutput(); connErr != nil {
			log.Printf("[recreate] warning: could not connect %s to %s: %s", name, netName, stripDockerOutput(string(out)))
		}
	}

	// Start the new container
	log.Printf("[recreate] starting %s (new id: %.12s)", name, newID)
	if out, startErr := exec.Command("docker", "start", newID).CombinedOutput(); startErr != nil {
		_ = exec.Command("docker", "rm", newID).Run()
		return rollback(fmt.Errorf("start failed: %s", stripDockerOutput(string(out))))
	}

	// Wait up to 30s for the container to reach running state
	if waitErr := waitRunning(newID, name, 30*time.Second, func(s string) {
		log.Printf("[recreate] %s", s)
	}); waitErr != nil {
		_ = exec.Command("docker", "stop", newID).Run()
		_ = exec.Command("docker", "rm", newID).Run()
		return rollback(fmt.Errorf("health check: %v", waitErr))
	}

	// Success — clean up backup
	log.Printf("[recreate] %s updated OK — removing old container %s", name, bakName)
	if out, rmErr := exec.Command("docker", "rm", bakName).CombinedOutput(); rmErr != nil {
		// Not fatal — old container is stopped, new one is running
		log.Printf("[recreate] warning: could not remove backup %s: %s", bakName, stripDockerOutput(string(out)))
	}
	return false, nil
}

// ansiEscape matches ANSI/VT100 terminal escape sequences that docker CLI
// writes to output even when stdout is a pipe. These corrupt MarkdownV2.
var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-9;]*[a-zA-Z]|\][^\x07]*\x07|[()][AB012])`)

// stripDockerOutput removes ANSI escape sequences, Unicode Braille spinner
// frames (U+2800–U+28FF), and keeps only the last 8 lines — making Docker
// output safe to embed verbatim in Telegram MarkdownV2 messages.
func stripDockerOutput(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r >= 0x2800 && r <= 0x28FF { // Braille block — CLI spinners
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	const maxLines = 8
	lines := strings.Split(out, "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// initCompose / composeCmd: used by the optional compose Strategy 3a.
// Detects V2 plugin vs V1 binary once at first call.
var (
	composeOnce sync.Once
	composeBin  []string
	composeIsV2 bool
)

func initCompose() {
	composeOnce.Do(func() {
		out, err := exec.Command("docker", "compose", "version").CombinedOutput()
		s := string(out)
		if err == nil && !strings.Contains(s, "--tlskey") && !strings.Contains(s, "Usage:  docker") {
			composeBin = []string{"docker", "compose"}
			composeIsV2 = true
			log.Printf("[docker] compose: V2 detected — %s", strings.TrimSpace(s))
			return
		}
		log.Printf("[docker] compose: V2 not available (%v) — trying docker-compose V1", err)
		if out2, err2 := exec.Command("docker-compose", "--version").CombinedOutput(); err2 == nil {
			composeBin = []string{"docker-compose"}
			log.Printf("[docker] compose: V1 detected — %s", strings.TrimSpace(string(out2)))
			return
		}
		composeBin = []string{"docker", "compose"} // last resort; caller sees error
		log.Printf("[docker] compose: WARNING — no compose binary found in PATH")
	})
}

func composeCmd(ctx context.Context, fileArgs []string, subcmd ...string) *exec.Cmd {
	initCompose()
	bin := composeBin[0]
	var args []string
	if len(composeBin) > 1 {
		args = append(args, composeBin[1:]...)
	}
	args = append(args, fileArgs...)
	if composeIsV2 {
		args = append(args, "--progress", "plain")
	}
	args = append(args, subcmd...)
	return exec.CommandContext(ctx, bin, args...)
}

const pullTimeout = 10 * time.Minute

// UpdateContainer pulls the latest image for c and recreates the container.
//
// Recreation strategy (in order):
//  1. docker compose (if PRESTOBACK_COMPOSE_FILE is set and the file exists)
//  2. Standalone recreate via HostConfig read from Docker socket — works for
//     all containers, no compose file needed. Includes automatic rollback if
//     the new container fails its health check.
//  3. NeedsManual — only if both strategies fail unexpectedly.
func UpdateContainer(c ContainerInfo, composeFile string) ContainerUpdate {
	res := ContainerUpdate{ContainerName: c.Name}

	// ── Step 1: resolve the current image name ────────────────────────────────
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

	// ── Step 2: pull latest image ─────────────────────────────────────────────
	ctx, cancel := context.WithTimeout(context.Background(), pullTimeout)
	defer cancel()
	pullOut, err := exec.CommandContext(ctx, "docker", "pull", res.Image).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Err = fmt.Sprintf("pull timed out after %s", pullTimeout)
		} else {
			res.Err = "pull failed: " + stripDockerOutput(string(pullOut))
		}
		return res
	}
	res.Pulled = true
	res.AlreadyUpToDate = strings.Contains(string(pullOut), "up to date")
	if res.AlreadyUpToDate {
		// Image unchanged — no need to recreate the container.
		return res
	}

	// ── Step 3a: compose recreation (optional, if file is configured) ─────────
	labels := inspectLabels(c.ID)
	service := labels["com.docker.compose.service"]
	const composeUpTimeout = 5 * time.Minute

	if service != "" && composeFile != "" {
		if _, statErr := os.Stat(composeFile); statErr == nil {
			upCtx, upCancel := context.WithTimeout(context.Background(), composeUpTimeout)
			defer upCancel()
			fileArgs := []string{"-f", composeFile}
			envFile := filepath.Join(filepath.Dir(composeFile), ".env")
			if _, envErr := os.Stat(envFile); envErr == nil {
				fileArgs = append(fileArgs, "--env-file", envFile)
				log.Printf("[docker] compose up: using env-file %s", envFile)
			}
			upOut, upErr := composeCmd(upCtx, fileArgs, "up", "-d", "--no-deps", service).CombinedOutput()
			if upErr == nil {
				res.Restarted = true
				return res
			}
			// Compose failed — log and fall through to standalone recreate
			log.Printf("[docker] compose up failed for %s (%s): %s — falling back to standalone recreate",
				c.Name, service, stripDockerOutput(string(upOut)))
		} else {
			log.Printf("[docker] composeFile %q not accessible inside container — using standalone recreate", composeFile)
		}
	}

	// ── Step 3b: standalone HostConfig-based recreate (always available) ──────
	rolled, recreateErr := standaloneRecreate(c, res.Image)
	if recreateErr != nil {
		res.Err = recreateErr.Error()
		res.Rolled = rolled
		return res
	}
	res.Restarted = true
	return res
}
