package backup

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// UpdateResult is sent over SSE during a self-update.
type UpdateResult struct {
	Stage   string `json:"stage"`   // pulling | stopping | starting | done | error
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// SelfUpdate performs a safe in-place update of the prestoback container:
//
//  1. Pull the new image
//  2. Drain: wait for any running backup/restore jobs to finish (up to 60s)
//  3. Spawn a detached "updater helper" alpine container that:
//     a. Sleeps 2s (lets prestoback respond 202 to the UI first)
//     b. docker stop prestoback
//     c. docker rm prestoback
//     d. docker run ... (same flags, new image)
//  4. prestoback returns — the helper takes over from here
//
// Why the helper container? A process cannot restart itself after docker stop.
// The helper sidesteps this by running outside prestoback's own container
// with access to the Docker socket. This is the same pattern used by
// Watchtower and Dockge.
//
// image: e.g. "yourdockerhubuser/prestoback:latest"
// selfName: the container name of THIS container (e.g. "prestoback")
func SelfUpdate(image, selfName string, isRunning func() bool, emit func(UpdateResult)) error {
	emit(UpdateResult{Stage: "pulling", Message: "Pulling " + image + "…"})

	// Step 1 — pull new image
	out, err := exec.Command("docker", "pull", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull failed: %w\n%s", err, out)
	}
	emit(UpdateResult{Stage: "pulling", Message: "Image pulled ✓"})

	// Step 2 — drain running jobs (max 60s)
	emit(UpdateResult{Stage: "draining", Message: "Waiting for active jobs to finish…"})
	deadline := time.Now().Add(60 * time.Second)
	for isRunning() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
	}
	if isRunning() {
		emit(UpdateResult{Stage: "draining", Message: "Warning: jobs still running after 60s — proceeding anyway"})
	} else {
		emit(UpdateResult{Stage: "draining", Message: "No active jobs ✓"})
	}

	// Step 3 — inspect current container to replay its run flags
	flags, err := inspectRunFlags(selfName, image)
	if err != nil {
		return fmt.Errorf("could not read current container config: %w", err)
	}

	emit(UpdateResult{Stage: "stopping", Message: "Spawning update helper…"})

	// Step 4 — spawn detached helper
	// We use alpine + sh because it's always available and has no deps.
	// The helper waits 3s so prestoback can send the final SSE event to the
	// browser before the connection drops.
	stopCmd := fmt.Sprintf(
		"sleep 3 && docker stop %s && docker rm %s && docker run -d %s && echo update-ok",
		selfName, selfName, flags,
	)

	helperArgs := []string{
		"run", "--rm", "-d",
		"--name", "prestoback-updater",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"alpine",
		"sh", "-c",
		"apk add --no-cache docker-cli -q && " + stopCmd,
	}

	log.Printf("[updater] spawning helper: docker %s", strings.Join(helperArgs, " "))
	out2, err := exec.Command("docker", helperArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start update helper: %w\n%s", err, out2)
	}

	emit(UpdateResult{Stage: "done", Message: "Update helper running — PrestoBack will restart in ~5 seconds. Reconnecting…"})
	return nil
}

// inspectRunFlags reads the current container's configuration and returns
// the docker run flags needed to recreate it with the new image.
// We reconstruct: name, ports, volumes, env, restart policy, labels.
func inspectRunFlags(containerName, newImage string) (string, error) {
	// Use Go templates to extract what we need
	out, err := exec.Command("docker", "inspect", "--format",
		`{{json .}}`, containerName).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", containerName, err)
	}

	flags := buildRunFlags(out, containerName, newImage)
	return flags, nil
}

// buildRunFlags parses docker inspect JSON and reconstructs -p, -v, -e, --restart flags.
func buildRunFlags(inspectJSON []byte, name, image string) string {
	// We parse just what we need manually to avoid importing encoding/json in a cycle.
	// For a self-hosted tool this is fine — the config is controlled and predictable.
	raw := string(inspectJSON)
	var parts []string

	parts = append(parts, "--name "+name)
	parts = append(parts, "--restart unless-stopped")

	// Ports — look for "8765/tcp" patterns
	if portSection := between(raw, `"PortBindings":{`, `}`); portSection != "" {
		// Extract "8765/tcp":[{"HostIp":"","HostPort":"8765"}]
		for _, chunk := range strings.Split(portSection, `"/tcp"`) {
			if idx := strings.LastIndex(chunk, `"`); idx >= 0 {
				containerPort := chunk[idx+1:]
				hostPort := between(chunk+`"/tcp"`, `"HostPort":"`, `"`)
				if containerPort != "" && hostPort != "" {
					parts = append(parts, fmt.Sprintf("-p %s:%s", hostPort, containerPort))
				}
			}
		}
	}

	// Volumes — Binds section
	if bindSection := between(raw, `"Binds":[`, `]`); bindSection != "" {
		for _, bind := range splitJSONArray(bindSection) {
			if bind != "" {
				parts = append(parts, "-v "+bind)
			}
		}
	}

	// Env
	if envSection := between(raw, `"Env":[`, `]`); envSection != "" {
		for _, e := range splitJSONArray(envSection) {
			// Skip internal Docker env vars
			if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "HOSTNAME=") && !strings.HasPrefix(e, "HOME=") {
				parts = append(parts, "-e "+shellQuote(e))
			}
		}
	}

	// Labels
	if labelSection := between(raw, `"Labels":{`, `}`); labelSection != "" {
		for _, pair := range strings.Split(labelSection, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 {
				k := strings.Trim(kv[0], `"`)
				v := strings.Trim(kv[1], `"`)
				if !strings.HasPrefix(k, "com.docker.") {
					parts = append(parts, fmt.Sprintf("-l %s=%s", k, v))
				}
			}
		}
	}

	parts = append(parts, image)
	return strings.Join(parts, " ")
}

// CheckForUpdate compares the local image digest against the registry.
// Returns (hasUpdate bool, currentDigest, remoteDigest string).
func CheckForUpdate(image string) (bool, string, string, error) {
	// Get local image ID
	localOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	if err != nil {
		return false, "", "", fmt.Errorf("local image not found: %w", err)
	}
	localDigest := strings.TrimSpace(string(localOut))

	// Pull manifest without downloading (--dry-run not universally available,
	// so we pull latest to a temp tag and compare)
	tmpTag := image + "-prestoback-check-" + fmt.Sprintf("%d", os.Getpid())
	pullOut, err := exec.Command("docker", "pull", "-q", image).CombinedOutput()
	if err != nil {
		return false, localDigest, "", fmt.Errorf("pull check failed: %w\n%s", err, pullOut)
	}
	remoteOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", tmpTag).Output()
	_ = exec.Command("docker", "rmi", tmpTag).Run()
	if err != nil {
		// Fall back: just pulled successfully, compare freshly-pulled digest
		remoteOut, _ = exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	}
	remoteDigest := strings.TrimSpace(string(remoteOut))
	return localDigest != remoteDigest, localDigest, remoteDigest, nil
}

// ── string parsing helpers (no external deps) ────────────────────────────────

func between(s, start, end string) string {
	si := strings.Index(s, start)
	if si < 0 {
		return ""
	}
	s = s[si+len(start):]
	ei := strings.Index(s, end)
	if ei < 0 {
		return s
	}
	return s[:ei]
}

func splitJSONArray(s string) []string {
	var out []string
	for _, part := range strings.Split(s, `","`) {
		part = strings.Trim(part, `" `)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\$`!") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
