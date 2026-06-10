package backup

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// UpdateResult is sent over SSE during a self-update.
type UpdateResult struct {
	Stage   string `json:"stage"`   // pulling | draining | stopping | done | error
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// SelfUpdate performs a safe in-place update of the prestoback container:
//
//  1. Pull the new image
//  2. Drain: wait for running backup/restore jobs to finish (max 60s)
//  3. Inspect the current container to replay its run flags
//  4. Spawn a detached "updater helper" alpine container that:
//     a. Installs docker-cli (cached on most systems)
//     b. Sleeps 3s so prestoback can finish the SSE response
//     c. docker stop prestoback && docker rm prestoback
//     d. docker run … (same flags, new image)
//
// Why the helper? A process cannot restart itself once docker-stop is called.
// The helper sidesteps this by running outside prestoback's own container
// with access to the Docker socket — same pattern as Watchtower / Dockge.
func SelfUpdate(image, selfName string, isRunning func() bool, emit func(UpdateResult)) error {
	emit(UpdateResult{Stage: "pulling", Message: "Pulling " + image + "…"})

	// ── Step 1: pull ──────────────────────────────────────────────────────────
	out, err := exec.Command("docker", "pull", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull failed: %w\n%s", err, out)
	}
	emit(UpdateResult{Stage: "pulling", Message: "Image pulled ✓"})

	// ── Step 2: drain ─────────────────────────────────────────────────────────
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

	// ── Step 3: inspect current container ────────────────────────────────────
	flags, err := inspectRunFlags(selfName, image)
	if err != nil {
		return fmt.Errorf("could not read current container config: %w", err)
	}

	emit(UpdateResult{Stage: "stopping", Message: "Spawning update helper…"})

	// ── Step 4: spawn detached helper ─────────────────────────────────────────
	//
	// The helper runs outside this container (via the Docker socket) so it can
	// stop and recreate us. We use newline-separated commands instead of &&
	// chaining so a slow/partial docker stop doesn't abort the docker run.
	// The sleep gives prestoback time to flush the SSE "done" event before
	// the socket disappears.
	//
	// docker:27-cli is a versioned multi-arch image (amd64+arm64) with docker
	// CLI pre-installed — no apk install step, ready in ~1s on a Pi.
	stopCmd := fmt.Sprintf(
		"sleep 3\ndocker stop -t 15 %s || true\ndocker rm -f %s || true\ndocker run -d %s\necho 'prestoback-update-ok'",
		selfName, selfName, flags,
	)

	helperArgs := []string{
		"run", "--rm", "-d",
		"--name", "prestoback-updater",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"docker:27-cli",
		"sh", "-c", stopCmd,
	}

	log.Printf("[updater] spawning helper: docker %s", strings.Join(helperArgs, " "))
	out2, err := exec.Command("docker", helperArgs...).CombinedOutput()
	if err != nil {
		// Fallback: alpine + apk install if docker:27-cli isn't available
		log.Printf("[updater] docker:27-cli helper failed (%v), falling back to alpine+apk", err)
		alpineStopCmd := fmt.Sprintf(
			"apk add --no-cache docker-cli -q\nsleep 3\ndocker stop -t 15 %s || true\ndocker rm -f %s || true\ndocker run -d %s\necho 'prestoback-update-ok'",
			selfName, selfName, flags,
		)
		alpineArgs := []string{
			"run", "--rm", "-d",
			"--name", "prestoback-updater",
			"-v", "/var/run/docker.sock:/var/run/docker.sock",
			"alpine",
			"sh", "-c", alpineStopCmd,
		}
		log.Printf("[updater] fallback: docker %s", strings.Join(alpineArgs, " "))
		out2, err = exec.Command("docker", alpineArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start update helper: %w\n%s", err, out2)
		}
	}

	helperID := strings.TrimSpace(string(out2))
	log.Printf("[updater] helper container started: %s", helperID)
	emit(UpdateResult{Stage: "done", Message: "Update helper running (ID: " + helperID[:min(12, len(helperID))] + ") — PrestoBack will restart in ~5s. Refresh in ~20s."})
	return nil
}

// inspectRunFlags reads the current container's config and returns
// the docker run flags needed to recreate it with the new image.
func inspectRunFlags(containerName, newImage string) (string, error) {
	out, err := exec.Command("docker", "inspect", "--format", `{{json .}}`, containerName).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", containerName, err)
	}
	return buildRunFlags(out, containerName, newImage), nil
}

// buildRunFlags parses docker inspect JSON and reconstructs -p, -v, -e, --restart flags.
// We parse manually to avoid circular imports — the config is controlled and predictable.
func buildRunFlags(inspectJSON []byte, name, image string) string {
	raw := string(inspectJSON)
	var parts []string

	parts = append(parts, "--name "+name)
	parts = append(parts, "--restart unless-stopped")

	// ── Ports ─────────────────────────────────────────────────────────────────
	// Format in inspect JSON: "PortBindings":{"8765/tcp":[{"HostIp":"","HostPort":"8765"}]}
	if portSection := between(raw, `"PortBindings":{`, `}`); portSection != "" {
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

	// ── Networks ──────────────────────────────────────────────────────────────
	// Format: "Networks":{"presto_default":{...},"prestoback-net":{...}}
	// Skip the built-in "bridge" network — docker adds it automatically and
	// attaching to it explicitly alongside named networks causes an error.
	if netSection := between(raw, `"Networks":{`, `}`); netSection != "" {
		for _, chunk := range strings.Split(netSection, `":{`) {
			if idx := strings.LastIndex(chunk, `"`); idx >= 0 {
				netName := chunk[idx+1:]
				if netName != "" && netName != "bridge" {
					parts = append(parts, "--network "+netName)
				}
			}
		}
	}

	// ── Volumes / Binds ───────────────────────────────────────────────────────
	if bindSection := between(raw, `"Binds":[`, `]`); bindSection != "" {
		for _, bind := range splitJSONArray(bindSection) {
			if bind != "" {
				parts = append(parts, "-v "+bind)
			}
		}
	}

	// ── Environment variables ─────────────────────────────────────────────────
	if envSection := between(raw, `"Env":[`, `]`); envSection != "" {
		for _, e := range splitJSONArray(envSection) {
			// Skip Docker-internal env vars
			if !strings.HasPrefix(e, "PATH=") &&
				!strings.HasPrefix(e, "HOSTNAME=") &&
				!strings.HasPrefix(e, "HOME=") &&
				!strings.HasPrefix(e, "GOPATH=") {
				parts = append(parts, "-e "+shellQuote(e))
			}
		}
	}

	// ── Labels (skip Docker-managed ones) ────────────────────────────────────
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
				if !strings.HasPrefix(k, "com.docker.") && !strings.HasPrefix(k, "org.opencontainers.") {
					parts = append(parts, fmt.Sprintf("-l %s=%s", k, v))
				}
			}
		}
	}

	parts = append(parts, image)
	return strings.Join(parts, " ")
}

// CheckForUpdate compares the local image digest against the registry.
// Returns (hasUpdate bool, currentDigest, remoteDigest string, error).
//
// Strategy: pull the image quietly (docker pull is idempotent and cheap when
// already up to date), then compare the resulting image ID with the one
// currently running. This avoids the need for registry API auth tokens.
func CheckForUpdate(image string) (bool, string, string, error) {
	// Local digest of currently-running image
	localOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	if err != nil {
		return false, "", "", fmt.Errorf("local image not found: %w", err)
	}
	localDigest := strings.TrimSpace(string(localOut))

	// Pull latest — docker will report "Status: Image is up to date" if unchanged.
	// We capture the new digest after pull.
	pullOut, err := exec.Command("docker", "pull", "-q", image).CombinedOutput()
	if err != nil {
		return false, localDigest, "", fmt.Errorf("pull check failed: %w\n%s", err, pullOut)
	}

	remoteOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	if err != nil {
		return false, localDigest, "", fmt.Errorf("post-pull inspect failed: %w", err)
	}
	remoteDigest := strings.TrimSpace(string(remoteOut))

	return localDigest != remoteDigest, localDigest, remoteDigest, nil
}

// ── string parsing helpers ────────────────────────────────────────────────────

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
