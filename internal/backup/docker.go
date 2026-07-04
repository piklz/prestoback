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
	"syscall"
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
// disconnectAllNetworks explicitly disconnects a container from every
// network it's attached to, ignoring errors for networks it's already off.
// This is defense-in-depth against Docker's known stale-endpoint behavior:
// "docker rm" is supposed to clean up network endpoints automatically, but
// if rm fails or races another operation, the endpoint can be left behind —
// visible later as a ghost "<shortID>_<name>" entry in
// "docker network inspect <network>" even though the container itself is
// long gone from "docker ps -a". Calling this before removal guarantees
// clean endpoint teardown regardless of what state rm leaves things in.
func disconnectAllNetworks(containerID string) {
	out, err := exec.Command("docker", "inspect",
		"--format={{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", containerID).Output()
	if err != nil {
		return // container may already be gone — nothing to disconnect
	}
	for _, netName := range strings.Fields(string(out)) {
		_ = exec.Command("docker", "network", "disconnect", "-f", netName, containerID).Run()
	}
}

// safeRemove stops (if running) then removes a container WITHOUT using
// "docker rm -f" on a potentially-running container — force-removing a
// running container is a documented source of stale network endpoints in
// Docker's bridge driver. Disconnects all networks explicitly first as
// defense-in-depth. Retries the final rm once after a short delay since
// network teardown can occasionally lag the stop by a few hundred ms.
func safeRemove(containerID string) error {
	state, err := exec.Command("docker", "inspect", "--format={{.State.Status}}", containerID).Output()
	if err != nil {
		return nil // container doesn't exist — nothing to do
	}
	if strings.TrimSpace(string(state)) == "running" {
		_ = exec.Command("docker", "stop", "-t", "10", containerID).Run()
	}
	disconnectAllNetworks(containerID)

	if out, rmErr := exec.Command("docker", "rm", containerID).CombinedOutput(); rmErr != nil {
		log.Printf("[recreate] rm %s failed (%s), retrying once after backoff", containerID, stripDockerOutput(string(out)))
		time.Sleep(1 * time.Second)
		disconnectAllNetworks(containerID) // in case the first attempt raced teardown
		if out2, rmErr2 := exec.Command("docker", "rm", containerID).CombinedOutput(); rmErr2 != nil {
			return fmt.Errorf("%s", stripDockerOutput(string(out2)))
		}
	}
	return nil
}

func standaloneRecreate(c ContainerInfo, newImage string, emit func(string)) (rolled bool, err error) {
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

	// Remove any leftover backup container from a previous failed update.
	// Resolved by name first (not blindly force-removed) so we never force-kill
	// a container that turns out to still be running — see safeRemove's doc
	// comment for why "rm -f" on a running container is unsafe here.
	if bakID, lookupErr := exec.Command("docker", "inspect", "--format={{.Id}}", bakName).Output(); lookupErr == nil {
		if rmErr := safeRemove(strings.TrimSpace(string(bakID))); rmErr != nil {
			log.Printf("[recreate] warning: could not clean up leftover %s: %v", bakName, rmErr)
		}
	}

	// Stop the current container gracefully
	emit(fmt.Sprintf("Stopping %s…", name))
	if out, stopErr := exec.Command("docker", "stop", "-t", "30", c.ID).CombinedOutput(); stopErr != nil {
		return false, fmt.Errorf("stop failed: %s", stripDockerOutput(string(out)))
	}
	emit(fmt.Sprintf("Stopped %s ✓", name))

	// Rename old container so we can reclaim the name
	if out, renErr := exec.Command("docker", "rename", c.ID, bakName).CombinedOutput(); renErr != nil {
		_ = exec.Command("docker", "start", c.ID).Run() // restore original
		return false, fmt.Errorf("rename failed: %s", stripDockerOutput(string(out)))
	}

	// rollback restores the old container on any subsequent failure
	rollback := func(reason error) (bool, error) {
		emit(fmt.Sprintf("⚠  Health check failed — rolling back %s…", name))
		_ = exec.Command("docker", "rename", bakName, name).Run()
		if startErr := exec.Command("docker", "start", c.ID).Run(); startErr != nil {
			log.Printf("[recreate] WARNING: rollback start failed for %s: %v", name, startErr)
			emit(fmt.Sprintf("✗ Rollback start failed for %s — check manually", name))
		} else {
			emit(fmt.Sprintf("↩  %s rolled back to previous image", name))
		}
		return true, fmt.Errorf("%w", reason)
	}

	// Create new container from identical HostConfig + new image
	emit(fmt.Sprintf("Creating %s with new image…", name))
	createArgs := buildCreateArgs(name, insp, newImage)
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
		if netName == "bridge" || netName == "host" || netName == "none" {
			continue
		}
		emit(fmt.Sprintf("Connecting %s to network %s…", name, netName))
		connectArgs := []string{"network", "connect"}
		for _, alias := range netInfo.Aliases {
			connectArgs = append(connectArgs, "--alias", alias)
		}
		connectArgs = append(connectArgs, netName, newID)
		if out, connErr := exec.Command("docker", connectArgs...).CombinedOutput(); connErr != nil {
			emit(fmt.Sprintf("⚠  Could not connect to %s: %s", netName, stripDockerOutput(string(out))))
		}
	}

	// Start the new container
	emit(fmt.Sprintf("Starting %s…", name))
	if out, startErr := exec.Command("docker", "start", newID).CombinedOutput(); startErr != nil {
		if rmErr := safeRemove(newID); rmErr != nil {
			log.Printf("[recreate] warning: could not clean up failed-start container %s: %v", newID, rmErr)
		}
		return rollback(fmt.Errorf("start failed: %s", stripDockerOutput(string(out))))
	}

	// Wait up to 30s for the container to reach running state
	if waitErr := waitRunning(newID, name, 30*time.Second, emit); waitErr != nil {
		if rmErr := safeRemove(newID); rmErr != nil {
			log.Printf("[recreate] warning: could not clean up unhealthy container %s: %v", newID, rmErr)
		}
		return rollback(fmt.Errorf("health check: %v", waitErr))
	}

	emit(fmt.Sprintf("Container %s is running ✓", name))

	// Success — clean up backup. safeRemove handles the case where this
	// container ended up running for any reason (it shouldn't, but defense
	// in depth costs nothing) and guarantees network endpoints are released.
	if rmErr := safeRemove(bakName); rmErr != nil {
		emit(fmt.Sprintf("⚠  Could not remove old container %s: %v", bakName, rmErr))
		log.Printf("[recreate] warning: could not remove backup %s after retries: %v", bakName, rmErr)
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

// composeCmd builds an exec.Cmd for a compose operation.
//
// PROCESS GROUP KILL:
// exec.CommandContext sends SIGKILL only to the direct child on ctx cancel.
// docker compose V2 (and docker-compose V1) internally exec helper processes
// that inherit the stdout/stderr pipes — those grandchildren are NOT killed,
// so CombinedOutput() blocks indefinitely even after the context deadline.
// This caused /stack commands to hang forever with no Telegram response.
//
// Fix: Setpgid puts the child in its own process group; the Cancel hook
// sends SIGKILL to the whole group (negative PID) so every descended
// process is killed and pipes are closed when the deadline fires.
func composeCmd(ctx context.Context, fileArgs []string, subcmd ...string) *exec.Cmd {
	initCompose()
	bin := composeBin[0]
	var args []string
	if len(composeBin) > 1 {
		args = append(args, composeBin[1:]...)
	}
	args = append(args, fileArgs...)
	if composeIsV2 {
		// --progress plain: suppress ANSI/TUI output that corrupts Telegram messages.
		args = append(args, "--progress", "plain")
	}
	args = append(args, subcmd...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return cmd
}

// pullTimeout is the floor used when we can't determine a size up front
// (registry lookup failed, or the image is digest-pinned). See
// pullTimeoutFor for the size-scaled timeout actually used by UpdateContainer.
const pullTimeout = 10 * time.Minute

// estimateDownloadSize does a best-effort, cheap registry lookup (the same
// HEAD-digest + manifest machinery the /check command uses) to size the pull
// timeout before a real `docker pull` starts. Returns 0 on any failure —
// callers fall back to the flat pullTimeout floor, so a registry hiccup here
// never blocks the actual update.
func estimateDownloadSize(image string) int64 {
	if strings.Contains(image, "@sha256:") {
		return 0
	}
	registry, repository, _ := parseImageRef(image)
	_, _, remoteDigest, err := ForceCheckForUpdate(image)
	if err != nil || remoteDigest == "" {
		return 0
	}
	size, _, err := fetchImageDetails(registry, repository, remoteDigest)
	if err != nil {
		return 0
	}
	return size
}

// pullTimeoutFor scales the pull timeout with the actual download size
// instead of a flat cutoff that fails identically on a 50MB and a 500MB
// image. The per-MB rate is deliberately conservative (~0.5 MB/s effective)
// since this runs on Pi-class hardware/SD storage and often contended home
// upload/download — better to wait longer than to false-timeout a real
// in-progress pull. Capped so a genuinely stuck pull still gets killed
// eventually rather than hanging the update lock indefinitely.
func pullTimeoutFor(sizeBytes int64) time.Duration {
	const perMB = 2 * time.Second
	const cap = 40 * time.Minute
	if sizeBytes <= 0 {
		return pullTimeout
	}
	extra := time.Duration(sizeBytes/(1024*1024)) * perMB
	total := pullTimeout + extra
	if total > cap {
		return cap
	}
	return total
}

// UpdateContainer pulls the latest image for c and recreates the container.
//
// Recreation strategy (in order):
//  1. docker compose (if PRESTOBACK_COMPOSE_FILE is set and the file exists)
//  2. Standalone recreate via HostConfig read from Docker socket — works for
//     all containers, no compose file needed. Includes automatic rollback if
//     the new container fails its health check.
//  3. NeedsManual — only if both strategies fail unexpectedly.
func UpdateContainer(c ContainerInfo, composeFile string, emit func(string)) ContainerUpdate {
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
	sizeBytes := estimateDownloadSize(res.Image)
	timeout := pullTimeoutFor(sizeBytes)
	if sizeBytes > 0 {
		emit(fmt.Sprintf("Pulling %s… (~%s, timeout %s)", res.Image, humanBytes(sizeBytes), timeout))
	} else {
		emit(fmt.Sprintf("Pulling %s… (timeout %s)", res.Image, timeout))
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pullOut, err := exec.CommandContext(ctx, "docker", "pull", res.Image).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Err = fmt.Sprintf("pull timed out after %s", timeout)
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

	// ── Step 3: recreate the container ───────────────────────────────────────
	//
	// Strategy depends on whether this container is compose-managed:
	//
	//   Compose-managed (com.docker.compose.service label is set):
	//     ALWAYS use "docker compose up -d --no-deps <service>".
	//     NEVER fall through to standaloneRecreate — doing so renames the old
	//     container to "{id}_{name}" and creates a new one outside compose's
	//     project tracking. Compose then sees TWO containers for the same
	//     service on the next "up" and renames the one it didn't create to a
	//     hash-prefixed orphan name. This is the root cause of the
	//     "ae5f67985bd9_immich_postgres" orphan storm seen after mixed updates.
	//
	//   Not compose-managed (no service label, or no compose file configured):
	//     Use standaloneRecreate which reads HostConfig from the Docker socket
	//     and does a stop → rename → create → start → health-check cycle with
	//     automatic rollback. Safe because compose doesn't own these containers.
	labels := inspectLabels(c.ID)
	service := labels["com.docker.compose.service"]
	// 10 minutes — long enough for a single heavy service (e.g. immich_server)
	// to pull-recreate without our own timeout killing compose mid-sequence.
	const composeUpTimeout = 10 * time.Minute

	if service != "" {
		// This is a compose-managed container. Only compose may recreate it.
		if composeFile == "" {
			res.Err = fmt.Sprintf(
				"container %s is managed by compose (service=%s) but PRESTOBACK_COMPOSE_FILE is not set — "+
					"set it to your docker-compose.yml path so /update can recreate this container correctly",
				c.Name, service)
			return res
		}
		if _, statErr := os.Stat(composeFile); statErr != nil {
			res.Err = fmt.Sprintf(
				"compose file %q is not accessible inside this container — "+
					"mount the project directory at the same host path so /update can reach it",
				composeFile)
			return res
		}
		// Soft pre-flight: warn (don't block) if only the compose file is mounted
		// rather than the whole presto project directory — see ProjectDirIssue.
		// This turns a cryptic "empty section between colons" compose failure
		// into a clear, actionable message before we even try.
		if issue := ProjectDirIssue(composeFile); issue != "" {
			log.Printf("[docker] update %s: %s", c.Name, issue)
		}
		emit(fmt.Sprintf("Recreating %s via compose (service: %s)…", c.Name, service))
		upCtx, upCancel := context.WithTimeout(context.Background(), composeUpTimeout)
		defer upCancel()
		// stackFileArgs uses --project-directory so this single-container
		// update sees the exact same project context as /stack commands and
		// as a manual "cd ~/presto && docker compose up -d" — same .env
		// loading, same env_file resolution, same config hash.
		fileArgs := stackFileArgs(composeFile)
		// --force-recreate: recreate even if config hash looks unchanged — after
		// a pull the image digest changed but compose's config hash may not have,
		// causing it to leave the old container running. Docksentry uses this too.
		// --no-deps: only recreate THIS service, not its dependencies.
		upOut, upErr := composeCmd(upCtx, fileArgs,
			"up", "-d", "--no-deps", "--force-recreate", service,
		).CombinedOutput()
		if upErr != nil {
			res.Err = fmt.Sprintf("compose up failed for %s: %s", service, stripDockerOutput(string(upOut)))
			return res
		}
		res.Restarted = true
		return res
	}

	// Not compose-managed: use standalone HostConfig-based recreate.
	// Safe to use here because compose doesn't track this container and won't
	// produce orphan conflicts from it.
	rolled, recreateErr := standaloneRecreate(c, res.Image, emit)
	if recreateErr != nil {
		res.Err = recreateErr.Error()
		res.Rolled = rolled
		return res
	}
	res.Restarted = true
	return res
}

// ── Single-container lifecycle (Docksentry-style) ─────────────────────────────
//
// These are simple, direct wrappers — no recreate, no rollback — used by
// /start, /stop, /restart, /pause, /unpause. UpdateContainer (above) is the
// only operation that recreates a container; these just change run state.

// StopOneContainer stops a single running container with a 30s graceful timeout.
func StopOneContainer(c ContainerInfo, emit func(string)) error {
	emit(fmt.Sprintf("Stopping %s…", c.Name))
	out, err := exec.Command("docker", "stop", "-t", "30", c.ID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	emit(fmt.Sprintf("Container %s stopped ✓", c.Name))
	return nil
}

// StartOneContainer starts a single stopped container and waits for it to
// reach "running" (15s timeout), reusing the same health-check used by updates.
func StartOneContainer(c ContainerInfo, emit func(string)) error {
	emit(fmt.Sprintf("Starting %s…", c.Name))
	out, err := exec.Command("docker", "start", c.ID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	if err := waitRunning(c.ID, c.Name, 15*time.Second, emit); err != nil {
		return err
	}
	emit(fmt.Sprintf("Container %s is running ✓", c.Name))
	return nil
}

// RestartOneContainer stops then starts a single container.
func RestartOneContainer(c ContainerInfo, emit func(string)) error {
	if c.Status == "running" {
		if err := StopOneContainer(c, emit); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
	}
	if err := StartOneContainer(c, emit); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return nil
}

// PauseOneContainer freezes a container via SIGSTOP (docker pause). The
// filesystem/process state is frozen exactly where it stood — crash-consistent
// but not clean-shutdown-consistent. See PauseContainers doc comment for the
// same caveat (fine for SQLite/Postgres/MySQL, risky for raw unjournaled state).
func PauseOneContainer(c ContainerInfo, emit func(string)) error {
	emit(fmt.Sprintf("Pausing %s…", c.Name))
	out, err := exec.Command("docker", "pause", c.ID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	emit(fmt.Sprintf("Container %s paused ✓", c.Name))
	return nil
}

// UnpauseOneContainer resumes a container frozen by PauseOneContainer.
func UnpauseOneContainer(c ContainerInfo, emit func(string)) error {
	emit(fmt.Sprintf("Unpausing %s…", c.Name))
	out, err := exec.Command("docker", "unpause", c.ID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	emit(fmt.Sprintf("Container %s resumed ✓", c.Name))
	return nil
}

// ── Whole-stack operations ──────────────────────────────────────────────────
//
// Operates on the entire docker-compose.yml at once via PRESTOBACK_COMPOSE_FILE.
// Unlike UpdateContainer's per-container standalone recreate, these genuinely
// require the compose file — there's no HostConfig equivalent for "the whole
// stack" since compose itself owns project-level concerns (network creation,
// service dependency order, etc.).

// StackPs returns "docker compose ps" output for the configured stack.
// composeServiceNames returns every service name defined in the compose
// file, using "docker compose config --services" (fast, no side effects).
func composeServiceNames(composeFile string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := composeCmd(ctx, stackFileArgs(composeFile), "config", "--services").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if n := strings.TrimSpace(line); n != "" {
			names = append(names, n)
		}
	}
	return names, nil
}

// servicesExcluding returns every service name EXCEPT selfService. Used so
// bulk stack operations that recreate or restart containers never target
// PrestoBack's own container — see the detailed explanation on StackUp.
func servicesExcluding(all []string, selfService string) []string {
	if selfService == "" {
		return all
	}
	var out []string
	for _, n := range all {
		if n != selfService {
			out = append(out, n)
		}
	}
	return out
}

func StackPs(composeFile string) (string, error) {
	if composeFile == "" {
		return "", fmt.Errorf("no compose file configured (PRESTOBACK_COMPOSE_FILE)")
	}
	if _, err := os.Stat(composeFile); err != nil {
		return "", fmt.Errorf("compose file not accessible: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := composeCmd(ctx, stackFileArgs(composeFile), "ps", "-a").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	return string(out), nil
}

// StackUp runs "docker compose up -d" for the whole stack — creates/starts
// any service that isn't running, leaves running services untouched.
//
// selfName is PrestoBack's own container/service name (PRESTOBACK_CONTAINER).
// It is ALWAYS excluded from the target service list — see the detailed
// explanation below for why this is not optional.
func StackUp(composeFile, selfName string, emit func(string)) error {
	if composeFile == "" {
		return fmt.Errorf("no compose file configured (PRESTOBACK_COMPOSE_FILE)")
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Errorf("compose file not accessible inside this container: %w", err)
	}
	// Self-heal: clean up any containers stranded by a previous interrupted
	// recreate before starting a new one — see CleanupStaleRenames doc comment.
	CleanupStaleRenames(emit)

	// ── Why PrestoBack must exclude itself from "up -d" ─────────────────────
	// PrestoBack's own container is a service in this same compose file. If
	// "up -d" runs with no explicit service list, Compose eventually reaches
	// the prestoback service and tries to stop/recreate it — but that
	// container is the one CURRENTLY RUNNING this exact "docker compose"
	// invocation. Stopping it kills the compose CLI process itself mid-run,
	// aborting the ENTIRE "up" for every service compose hadn't reached yet.
	// This is exactly what produced "only prestoback ends up running,
	// everything else stays stopped, and prestoback itself gets orphaned" —
	// the operation was decapitating itself partway through.
	//
	// Fix: explicitly list every service EXCEPT prestoback. PrestoBack's own
	// lifecycle is handled separately by SelfUpdate (via /selfupdate), which
	// uses a detached helper container specifically so it survives
	// prestoback stopping/restarting.
	services, svcErr := composeServiceNames(composeFile)
	if svcErr != nil {
		return fmt.Errorf("could not list compose services: %w", svcErr)
	}
	targets := servicesExcluding(services, selfName)
	if len(targets) == 0 {
		return fmt.Errorf("no services to bring up (compose file only contains %q)", selfName)
	}
	emit(fmt.Sprintf("Running: docker compose up -d (%d services, excluding %s)…", len(targets), selfName))

	// 20 minutes — a multi-service stack (esp. with immich-sized images) can
	// legitimately take this long to recreate everything. The old 5-minute
	// timeout was firing mid-recreate and killing compose between its
	// internal rename-old/create-new/remove-old steps, which is what produced
	// the {id}_{name} orphans in the first place — killing compose too early
	// is worse than waiting longer.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	// No --remove-orphans here by design: with --project-directory giving
	// Compose the exact same view of the project it always has, it correctly
	// recognizes every existing container as its own and only touches what
	// actually changed — there's nothing spurious left over to remove.
	upArgs := append([]string{"up", "-d"}, targets...)
	out, err := composeCmd(ctx, stackFileArgs(composeFile), upArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	// Second cleanup pass: catches any containers compose renamed during THIS
	// run but failed to remove.
	CleanupStaleRenames(emit)
	emit("Stack up ✓")
	return nil
}

// StackDown runs "docker compose down" — stops and removes all stack
// containers (and the project's default network). Named volumes are NOT
// removed (compose down does not remove volumes unless -v is passed, and we
// deliberately never pass -v here — that would be data loss).
// StackDown stops and removes every service EXCEPT PrestoBack's own
// container.
//
// This intentionally does NOT run "docker compose down" — that command
// always operates on the WHOLE project with no way to exclude a single
// service. Instead it uses "docker compose rm -f -s <services>" against an
// explicit list (every service except selfName), which stops and removes
// only those targets while leaving PrestoBack — and the shared network —
// alive.
//
// Why exclude self here, same as StackUp/StackRestart/StackPull: if a full
// "docker compose down" also took PrestoBack down, the Telegram bot and
// dashboard would die along with the rest of the stack, and there would be
// no way to bring anything back up without physically going to the Pi and
// running a compose command by hand — defeating the entire point of a
// remote management tool. Keeping PrestoBack alive means /stack up can
// always be run immediately afterward to restore everything, from
// anywhere.
func StackDown(composeFile, selfName string, emit func(string)) error {
	if composeFile == "" {
		return fmt.Errorf("no compose file configured (PRESTOBACK_COMPOSE_FILE)")
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Errorf("compose file not accessible inside this container: %w", err)
	}
	services, svcErr := composeServiceNames(composeFile)
	if svcErr != nil {
		return fmt.Errorf("could not list compose services: %w", svcErr)
	}
	targets := servicesExcluding(services, selfName)
	if len(targets) == 0 {
		return fmt.Errorf("no services to take down (compose file only contains %q)", selfName)
	}
	emit(fmt.Sprintf("Running: docker compose rm -f -s (%d services, excluding %s)…", len(targets), selfName))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rmArgs := append([]string{"rm", "-f", "-s"}, targets...)
	out, err := composeCmd(ctx, stackFileArgs(composeFile), rmArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	emit(fmt.Sprintf("Stack down ✓ — %d containers stopped and removed (volumes preserved, %s left running so you can /stack up again)", len(targets), selfName))
	return nil
}

// StackRestart runs "docker compose restart" — restarts every running
// service in place without recreating containers.
//
// selfName is excluded here too: "restart" stops then starts the SAME
// container, and since that container is running this very compose CLI
// invocation, restarting it kills the process reporting the operation's
// result mid-run (docker's restart:unless-stopped policy would bring it
// back, but the "Stack restart ✓" confirmation would never arrive).
func StackRestart(composeFile, selfName string, emit func(string)) error {
	if composeFile == "" {
		return fmt.Errorf("no compose file configured (PRESTOBACK_COMPOSE_FILE)")
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Errorf("compose file not accessible inside this container: %w", err)
	}
	services, svcErr := composeServiceNames(composeFile)
	if svcErr != nil {
		return fmt.Errorf("could not list compose services: %w", svcErr)
	}
	targets := servicesExcluding(services, selfName)
	emit(fmt.Sprintf("Running: docker compose restart (%d services, excluding %s)…", len(targets), selfName))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	restartArgs := append([]string{"restart"}, targets...)
	out, err := composeCmd(ctx, stackFileArgs(composeFile), restartArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", stripDockerOutput(string(out)))
	}
	emit("Stack restart ✓")
	return nil
}

// StackPull runs "docker compose pull" for every service in the stack, then
// "docker compose up -d" to recreate any containers whose image changed.
// This is the compose-native equivalent of /update all, and is tried as a
// single atomic operation rather than looping UpdateContainer per-service —
// faster for stacks with many services since compose pulls in parallel.
//
// selfName is excluded from the recreate ("up -d") phase for the same
// self-decapitation reason as StackUp — pulling the prestoback image is
// harmless (no container is touched), but recreating it here would still
// kill this process mid-run. Self-updates go through /selfupdate instead.
func StackPull(composeFile, selfName string, emit func(string)) error {
	if composeFile == "" {
		return fmt.Errorf("no compose file configured (PRESTOBACK_COMPOSE_FILE)")
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Errorf("compose file not accessible inside this container: %w", err)
	}
	// Self-heal before doing anything — see CleanupStaleRenames doc comment.
	CleanupStaleRenames(emit)
	fileArgs := stackFileArgs(composeFile)

	emit("Pulling latest images for all services…")
	pullCtx, pullCancel := context.WithTimeout(context.Background(), pullTimeout)
	defer pullCancel()
	pullOut, pullErr := composeCmd(pullCtx, fileArgs, "pull").CombinedOutput()
	if pullErr != nil {
		return fmt.Errorf("pull failed: %s", stripDockerOutput(string(pullOut)))
	}
	emit("Pull complete — recreating changed containers…")

	services, svcErr := composeServiceNames(composeFile)
	if svcErr != nil {
		return fmt.Errorf("could not list compose services: %w", svcErr)
	}
	targets := servicesExcluding(services, selfName)

	// 20 minutes for the same reason as StackUp: killing compose mid-recreate
	// is what produces {id}_{name} orphans, so it's better to wait it out.
	upCtx, upCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer upCancel()
	upArgs := append([]string{"up", "-d"}, targets...)
	upOut, upErr := composeCmd(upCtx, fileArgs, upArgs...).CombinedOutput()
	if upErr != nil {
		return fmt.Errorf("up failed: %s", stripDockerOutput(string(upOut)))
	}
	// Second cleanup pass — same reasoning as StackUp.
	CleanupStaleRenames(emit)
	emit("Stack updated ✓")
	return nil
}

// stackFileArgs builds the compose invocation args using --project-directory.
//
// THE FIX — why --project-directory and nothing else:
// Running "docker compose up -d" manually from the project's own working
// directory (cd ~/presto && docker compose up -d) NEVER produces orphans,
// because Compose:
//  1. Loads .env automatically from the current directory
//  2. Resolves every per-service "env_file: ./services/<app>/<app>.env"
//     path relative to that same directory
//  3. Computes the exact same project name and config hash it always has
//     for this stack, so it sees zero unexpected changes and recreates
//     nothing that hasn't actually changed
//
// Every previous approach here (manually passing -f with an absolute path,
// forcing -p from a detected label, merging env files into a synthetic
// temp file, adding --remove-orphans as a cleanup band-aid) was working
// around symptoms of the same root problem: none of those reproduce cwd
// semantics, so Compose's computed config differs slightly from what it
// used originally, some services look "changed" when they aren't, and a
// recreate gets triggered where none was needed — which is what produces
// {container_id}_{service} orphans when anything interrupts it.
//
// --project-directory <dir> makes Compose behave EXACTLY as if invoked
// from inside that directory — same .env loading, same env_file
// resolution, same project name, same config hash — without needing a
// real shell or actually changing this process's working directory. This
// is the single correct fix; everything else in this list becomes
// unnecessary once it's in place.
func stackFileArgs(composeFile string) []string {
	return []string{"--project-directory", filepath.Dir(composeFile), "-f", composeFile}
}

// CleanupStaleRenames finds and removes containers left over from a
// docker compose recreate sequence that was interrupted mid-flight (e.g. by
// a timeout firing while compose was between its internal "rename old
// container out of the way" and "remove old container" steps).
//
// Compose's own recreate sequence is: rename old container to
// "{old_container_id}_{service_name}" -> create new container with the
// proper name -> start it -> remove the old renamed one. That rename is
// normally invisible — it exists for a fraction of a second. If our process
// is killed (e.g. our own timeout enforcement) at exactly the wrong moment,
// the renamed-but-never-removed old container is left behind permanently,
// with a name like "a68df191956f_homebox".
//
// This is safe to run automatically before every stack up/pull: a container
// is only removed if (a) its name matches the {hex12}_{anything} pattern AND
// (b) a different, properly-named, RUNNING container already exists for the
// same compose project+service labels — i.e. the recreate actually
// succeeded and this is provably the abandoned leftover, not a container
// that's still mid-recreate.
func CleanupStaleRenames(emit func(string)) {
	out, err := exec.Command("docker", "ps", "-a",
		"--format", `{"id":"{{.ID}}","name":"{{.Names}}","labels":"{{.Labels}}"}`,
	).Output()
	if err != nil {
		return
	}

	type psEntry struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Labels string `json:"labels"`
	}
	var all []psEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e psEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			all = append(all, e)
		}
	}

	// Build a set of (project, service) pairs that have a normally-named,
	// currently-running container — i.e. a confirmed-successful recreate.
	healthyServices := map[string]bool{}
	for _, e := range all {
		if staleRenamePattern.MatchString(e.Name) {
			continue // this one IS a candidate orphan, not a healthy reference
		}
		project := labelValue(e.Labels, "com.docker.compose.project")
		service := labelValue(e.Labels, "com.docker.compose.service")
		if project != "" && service != "" {
			healthyServices[project+"/"+service] = true
		}
	}

	for _, e := range all {
		if !staleRenamePattern.MatchString(e.Name) {
			continue
		}
		project := labelValue(e.Labels, "com.docker.compose.project")
		service := labelValue(e.Labels, "com.docker.compose.service")
		if project == "" || service == "" {
			continue // not a compose container — leave it alone, not ours to touch
		}
		if !healthyServices[project+"/"+service] {
			// No confirmed-healthy replacement exists yet — this might still be
			// mid-recreate. Don't touch it; a future cleanup pass will catch it
			// once the replacement is confirmed running.
			continue
		}
		if emit != nil {
			emit(fmt.Sprintf("Removing stale interrupted-recreate container %s…", e.Name))
		}
		log.Printf("[docker] CleanupStaleRenames: removing %s (%s) — confirmed replaced by a running container for %s/%s",
			e.Name, e.ID, project, service)
		_ = exec.Command("docker", "rm", "-f", e.ID).Run()
	}
}

// staleRenamePattern matches container names left behind by an interrupted
// compose recreate: a 12-character hex container ID followed by an
// underscore and the original name, e.g. "a68df191956f_homebox".
var staleRenamePattern = regexp.MustCompile(`^[a-f0-9]{12}_`)

// IsOrphanName reports whether name looks like a stale compose-recreate
// orphan. Exported so pickers in server.go can filter them without importing
// the regex directly.
func IsOrphanName(name string) bool { return staleRenamePattern.MatchString(name) }

// labelValue extracts a single label's value from Docker CLI's
// comma-separated "--format {{.Labels}}" output (e.g. "a=1,b=2,c=3").
func labelValue(labels, key string) string {
	for _, kv := range strings.Split(labels, ",") {
		if idx := strings.Index(kv, "="); idx > 0 && kv[:idx] == key {
			return kv[idx+1:]
		}
	}
	return ""
}

// ProjectDirIssue checks whether the presto project directory is fully
// reachable inside this container — not just docker-compose.yml itself.
//
// Expected layout (the assumption this whole update system is built on):
//
//	~/presto/docker-compose.yml
//	~/presto/.env                          (top-level vars)
//	~/presto/volumes/<app>/...             (app data/config)
//	~/presto/services/<app>/<app>.env      (per-service env_file: refs)
//
// Compose resolves every env_file: path in the YAML relative to the project
// directory AT PARSE TIME, from inside whichever container runs the compose
// CLI. If only docker-compose.yml (and maybe the top .env) are mounted —
// not the services/ subtree — those per-service env files silently don't
// exist, their variables resolve to empty strings, and compose fails with
// a confusing "empty section between colons" or similar deep in a volume
// spec, with no indication the real cause is an incomplete mount.
//
// Returns "" if everything looks reachable, otherwise a human-readable
// explanation suitable for sending straight to Telegram/SSE.
func ProjectDirIssue(composeFile string) string {
	if composeFile == "" {
		return "no compose file configured (PRESTOBACK_COMPOSE_FILE)"
	}
	if _, err := os.Stat(composeFile); err != nil {
		return fmt.Sprintf("compose file %q is not accessible inside this container — mount the project directory at the same host path", composeFile)
	}
	projectDir := filepath.Dir(composeFile)

	// services/ subtree is the layout-specific check: if docker-compose.yml
	// references ./services/<app>/<app>.env via env_file: and that directory
	// isn't reachable, every such service will fail to recreate with an
	// opaque compose error. Only warn (don't hard-fail) since not every stack
	// uses per-service env files — but the message is actionable either way.
	servicesDir := filepath.Join(projectDir, "services")
	if _, err := os.Stat(servicesDir); err != nil {
		return fmt.Sprintf(
			"only %s is mounted, not the whole project directory — if any service uses "+
				"env_file: ./services/<app>/<app>.env, those variables will silently resolve "+
				"empty and compose will fail. Mount the whole %s directory at the same host path, not just docker-compose.yml.",
			composeFile, projectDir)
	}
	return ""
}

// ── Update availability checking ──────────────────────────────────────────────
//
// IMPORTANT — why this pulls the image rather than comparing manifests:
//
// An earlier version compared "docker manifest inspect" (the registry's
// multi-arch MANIFEST LIST digest) against the locally stored RepoDigest
// (the PLATFORM-SPECIFIC image digest — e.g. arm64 on a Raspberry Pi).
// These are structurally different digests for any multi-arch image and
// will essentially never match, causing false-positive "update available"
// alerts on nearly every image, every check. That approach is removed.
//
// The reliable method — and what tools like Watchtower actually do — is to
// run "docker pull" and read whether it reports "Image is up to date" or
// downloaded new layers. This costs a small registry round-trip (a few KB
// for the manifest) even when nothing changed; it only transfers real data
// when a layer has actually changed. This is why the background check
// interval defaults to 24h rather than something more frequent.

// ImageUpdateStatus describes whether a running container's image has a
// newer version available in its registry.
type ImageUpdateStatus struct {
	ContainerName   string
	Image           string
	UpdateAvailable bool
	Err             string // non-empty if the check itself failed (e.g. registry unreachable)
}

const imageCheckTimeout = 2 * time.Minute

// CheckImageUpdate pulls c's image and reports whether the pull resulted in
// new layers (i.e. an update was available and has now been cached locally
// — NOT applied to any running container; the container itself is untouched).
//
// pullCache deduplicates repeated checks of the same image within one check
// cycle — e.g. a stack with several services sharing 2-3 base images only
// needs each unique image pulled once, not once per container.
func CheckImageUpdate(c ContainerInfo, pullCache map[string]ImageUpdateStatus) ImageUpdateStatus {
	out, err := exec.Command("docker", "inspect", "--format={{.Config.Image}}", c.ID).Output()
	if err != nil {
		return ImageUpdateStatus{ContainerName: c.Name, Err: "inspect failed: " + err.Error()}
	}
	image := strings.TrimSpace(string(out))
	if image == "" {
		return ImageUpdateStatus{ContainerName: c.Name, Err: "could not determine image name"}
	}

	if cached, ok := pullCache[image]; ok {
		cached.ContainerName = c.Name // keep per-container name, reuse the pull result
		return cached
	}

	ctx, cancel := context.WithTimeout(context.Background(), imageCheckTimeout)
	defer cancel()
	pullOut, pullErr := exec.CommandContext(ctx, "docker", "pull", image).CombinedOutput()

	res := ImageUpdateStatus{ContainerName: c.Name, Image: image}
	if pullErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Err = fmt.Sprintf("pull timed out after %s", imageCheckTimeout)
		} else {
			res.Err = "pull failed: " + stripDockerOutput(string(pullOut))
		}
		pullCache[image] = res
		return res
	}
	// Same detection string used by UpdateContainer's AlreadyUpToDate field.
	res.UpdateAvailable = !strings.Contains(string(pullOut), "up to date")
	pullCache[image] = res
	return res
}
