package backup

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// UpdateResult is sent over SSE during a self-update.
type UpdateResult struct {
	Stage   string `json:"stage"` // pulling | draining | stopping | done | error
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// SelfUpdate performs a safe in-place update of the prestoback container.
//
// Strategy (same as Portainer / Dockge):
//  1. Pull the new image
//  2. Drain: wait for running backup/restore jobs to finish (max 60s)
//  3. Inspect the running container to find its compose file + service name
//  4. Spawn a detached helper container that:
//     a. Sleeps 3s so prestoback can flush the SSE "done" event
//     b. Runs: docker compose -f <file> up -d --pull always <service>
//     — compose handles stop/rm/recreate atomically with the right networks,
//     volumes, labels, and env vars. No fragile flag reconstruction needed.
//
// Falls back to bare "docker run" (reconstructed flags) if the container was
// not started by compose (e.g. during development / manual docker run).
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

	// ── Step 3: inspect — prefer compose path, fall back to raw flags ─────────
	composeFile, serviceName, inspectErr := inspectComposeInfo(selfName)

	var restartCmd string
	if inspectErr == nil && composeFile != "" {
		// Compose path: atomically stops, removes, recreates with correct config
		restartCmd = fmt.Sprintf(
			"docker compose -f %s up -d --pull always %s",
			composeFile, serviceName,
		)
		emit(UpdateResult{Stage: "stopping", Message: fmt.Sprintf(
			"Using compose: %s (service: %s)", composeFile, serviceName,
		)})
	} else {
		// Fallback: reconstruct docker run flags from inspect
		log.Printf("[updater] compose info unavailable (%v), falling back to docker run", inspectErr)
		flags, err := inspectRunFlags(selfName, image)
		if err != nil {
			return fmt.Errorf("could not read current container config: %w", err)
		}
		runArgs := buildRunArgList(flags)
		restartCmd = fmt.Sprintf(
			"docker stop -t 15 %s || true; docker rm -f %s || true; docker run %s",
			selfName, selfName, strings.Join(runArgs, " "),
		)
		emit(UpdateResult{Stage: "stopping", Message: "No compose config found — using docker run fallback"})
	}

	emit(UpdateResult{Stage: "stopping", Message: "Spawning update helper…"})

	// ── Step 4: spawn detached helper ─────────────────────────────────────────
	//
	// Pre-clean any leftover helper from a previous failed attempt.
	_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()

	// The helper is NOT --rm so it stays after exit — inspect its logs with:
	//   docker logs prestoback-updater
	// if the update appears to fail.
	helperScript := fmt.Sprintf("sleep 3; %s; echo prestoback-update-ok", restartCmd)
	log.Printf("[updater] helper script: %s", helperScript)

	helperArgs := []string{
		"run", "-d",
		"--name", "prestoback-updater",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
	}

	// Mount the compose file directory so docker compose can resolve relative
	// paths (e.g. .env files, named volumes defined in the compose file).
	if composeFile != "" {
		dir := composeFileDir(composeFile)
		helperArgs = append(helperArgs, "-v", dir+":"+dir, "-w", dir)
	}

	helperArgs = append(helperArgs,
		"docker:27-cli",
		"sh", "-c", helperScript,
	)

	out2, err := exec.Command("docker", helperArgs...).CombinedOutput()
	if err != nil {
		// Fallback to alpine if docker:27-cli isn't cached on this host
		log.Printf("[updater] docker:27-cli failed (%v), trying alpine+apk", err)
		_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()

		alpineScript := fmt.Sprintf(
			"apk add --no-cache docker-cli docker-cli-compose -q; sleep 3; %s; echo prestoback-update-ok",
			restartCmd,
		)
		alpineArgs := []string{
			"run", "-d",
			"--name", "prestoback-updater",
			"-v", "/var/run/docker.sock:/var/run/docker.sock",
		}
		if composeFile != "" {
			dir := composeFileDir(composeFile)
			alpineArgs = append(alpineArgs, "-v", dir+":"+dir, "-w", dir)
		}
		alpineArgs = append(alpineArgs, "alpine", "sh", "-c", alpineScript)

		log.Printf("[updater] alpine fallback script: %s", alpineScript)
		out2, err = exec.Command("docker", alpineArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start update helper: %w\n%s", err, out2)
		}
	}

	helperID := strings.TrimSpace(string(out2))
	log.Printf("[updater] helper started: %s", helperID)
	emit(UpdateResult{
		Stage: "done",
		Message: fmt.Sprintf(
			"Update helper running (ID: %s) — PrestoBack will restart in ~5s. "+
				"If it doesn't come back, check: docker logs prestoback-updater",
			helperID[:min(12, len(helperID))],
		),
	})
	return nil
}

// ── Inspect helpers ───────────────────────────────────────────────────────────

// containerInspect holds the fields we care about from docker inspect.
type containerInspect struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Binds        []string `json:"Binds"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
	Name string `json:"Name"`
}

// inspectComposeInfo returns the compose file path and service name for the
// given container, by reading com.docker.compose.* labels set by compose.
func inspectComposeInfo(containerName string) (composeFile, service string, err error) {
	raw, err := exec.Command("docker", "inspect", "--format={{json .}}", containerName).Output()
	if err != nil {
		return "", "", fmt.Errorf("docker inspect: %w", err)
	}

	// docker inspect returns an array
	var arr []containerInspect
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return "", "", fmt.Errorf("parse inspect: %w", err)
	}
	c := arr[0]

	composeFile = c.Config.Labels["com.docker.compose.project.config_files"]
	service = c.Config.Labels["com.docker.compose.service"]

	if composeFile == "" {
		return "", "", fmt.Errorf("container was not started by compose (no config_files label)")
	}
	return composeFile, service, nil
}

// inspectRunFlags reads the current container's config and returns
// the docker run flags needed to recreate it with the new image.
// Used only when compose info is unavailable.
func inspectRunFlags(containerName, newImage string) (string, error) {
	raw, err := exec.Command("docker", "inspect", "--format={{json .}}", containerName).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", containerName, err)
	}
	var arr []containerInspect
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return "", fmt.Errorf("parse inspect: %w", err)
	}
	return buildRunFlags(arr[0], containerName, newImage), nil
}

// buildRunFlags reconstructs docker run flags from a parsed inspect struct.
func buildRunFlags(c containerInspect, name, image string) string {
	var parts []string
	parts = append(parts, "-d")
	parts = append(parts, "--name", name)
	parts = append(parts, "--restart", c.HostConfig.RestartPolicy.Name)

	for portProto, bindings := range c.HostConfig.PortBindings {
		containerPort := strings.TrimSuffix(portProto, "/tcp")
		for _, b := range bindings {
			if b.HostPort != "" {
				parts = append(parts, "-p", b.HostPort+":"+containerPort)
			}
		}
	}

	for netName := range c.NetworkSettings.Networks {
		if netName != "bridge" {
			parts = append(parts, "--network", netName)
		}
	}

	for _, bind := range c.HostConfig.Binds {
		parts = append(parts, "-v", bind)
	}

	skipEnv := map[string]bool{"PATH": true, "HOSTNAME": true, "HOME": true, "GOPATH": true}
	for _, env := range c.Config.Env {
		key := strings.SplitN(env, "=", 2)[0]
		if !skipEnv[key] {
			parts = append(parts, "-e", shellQuote(env))
		}
	}

	parts = append(parts, image)
	return strings.Join(parts, " ")
}

// composeFileDir returns the directory containing the compose file.
func composeFileDir(composeFile string) string {
	idx := strings.LastIndex(composeFile, "/")
	if idx < 0 {
		return "."
	}
	return composeFile[:idx]
}

// CheckForUpdate compares the local image digest against the registry.
func CheckForUpdate(image string) (bool, string, string, error) {
	localOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	if err != nil {
		return false, "", "", fmt.Errorf("local image not found: %w", err)
	}
	localDigest := strings.TrimSpace(string(localOut))

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

// ── string helpers ────────────────────────────────────────────────────────────

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\$`!") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// buildRunArgList splits a quoted flags string into a []string arg list.
func buildRunArgList(flags string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(flags); i++ {
		c := flags[i]
		switch {
		case c == '"' && !inQuote:
			inQuote = true
		case c == '"' && inQuote:
			inQuote = false
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
