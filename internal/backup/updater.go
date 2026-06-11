package backup

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
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

	// Invalidate the update cache so when prestoback comes back up the UI
	// correctly shows "up to date" rather than stale "update available".
	InvalidateUpdateCache(image)

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

// ── Update check cache ────────────────────────────────────────────────────────

// UpdateCheckTTL is how long a successful check result is reused before the
// registry is contacted again. Override in tests or via an env-driven init().
var UpdateCheckTTL = 1 * time.Hour

type updateCacheEntry struct {
	hasUpdate    bool
	localDigest  string
	remoteDigest string
	err          error
	checkedAt    time.Time
}

var (
	updateCacheMu sync.Mutex
	updateCache   = map[string]*updateCacheEntry{}
)

// CheckForUpdate compares the local image digest against the registry.
//
// Results are cached for UpdateCheckTTL (default 1 h) so repeated calls —
// e.g. from a polling UI — never hammer the registry. The cache is
// invalidated automatically when the TTL expires.
//
// The remote digest is fetched via a direct HTTPS call to the registry API
// (a single HEAD request returning only metadata — no image layers downloaded).
// Use ForceCheckForUpdate to bypass the cache (e.g. for a "check now" button).
func CheckForUpdate(image string) (bool, string, string, error) {
	return checkForUpdate(image, false)
}

// ForceCheckForUpdate bypasses the cache and always contacts the registry.
// Use this for explicit user-initiated checks; prefer CheckForUpdate for
// background polling.
func ForceCheckForUpdate(image string) (bool, string, string, error) {
	return checkForUpdate(image, true)
}

func checkForUpdate(image string, force bool) (hasUpdate bool, localDigest, remoteDigest string, err error) {
	updateCacheMu.Lock()
	entry, ok := updateCache[image]
	if ok && !force && time.Since(entry.checkedAt) < UpdateCheckTTL {
		updateCacheMu.Unlock()
		log.Printf("[updater] check result served from cache (age: %s)", time.Since(entry.checkedAt).Round(time.Second))
		return entry.hasUpdate, entry.localDigest, entry.remoteDigest, entry.err
	}
	updateCacheMu.Unlock()

	// Fetch fresh — outside the lock so we don't block other goroutines.
	hasUpdate, localDigest, remoteDigest, err = doCheckForUpdate(image)

	updateCacheMu.Lock()
	updateCache[image] = &updateCacheEntry{
		hasUpdate:    hasUpdate,
		localDigest:  localDigest,
		remoteDigest: remoteDigest,
		err:          err,
		checkedAt:    time.Now(),
	}
	updateCacheMu.Unlock()

	return
}

// InvalidateUpdateCache removes the cached result for the given image so the
// next CheckForUpdate call always hits the registry. Call this after a
// successful SelfUpdate so the UI reflects the new state immediately.
func InvalidateUpdateCache(image string) {
	updateCacheMu.Lock()
	delete(updateCache, image)
	updateCacheMu.Unlock()
}

// doCheckForUpdate is the uncached implementation of CheckForUpdate.
//
// Two-phase approach (same as Watchtower):
//  1. HEAD request to registry → get remote manifest digest (no download)
//  2. Compare against local RepoDigests from docker inspect
//
// Key insight: docker inspect RepoDigests stores the manifest digest as
// "image@sha256:..." — this is the SAME digest the registry returns via
// Docker-Content-Digest on a HEAD /v2/<repo>/manifests/<tag> request.
// This is different from inspect .Id (config digest) which never matches.
//
// For multi-arch images the registry returns the manifest LIST digest.
// RepoDigests also stores the manifest list digest after a pull.
// So they match correctly.
func doCheckForUpdate(image string) (bool, string, string, error) {
	// ── Step 1: local digest from RepoDigests ────────────────────────────────
	// Use "docker image inspect" which returns a JSON array reliably.
	// (plain "docker inspect" on an image tag can return an object or array
	// depending on Docker version — "docker image inspect" is always an array.)
	type imageInfo struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	localOut, err := exec.Command("docker", "image", "inspect", image).Output()
	if err != nil {
		return false, "", "", fmt.Errorf("local image not found: %w", err)
	}
	var arr []imageInfo
	if err := json.Unmarshal(localOut, &arr); err != nil || len(arr) == 0 {
		return false, "", "", fmt.Errorf("inspect parse failed: %w", err)
	}

	// Extract manifest digest from RepoDigests e.g. "piklz/prestoback@sha256:abc..."
	localDigest := ""
	for _, rd := range arr[0].RepoDigests {
		if idx := strings.Index(rd, "@"); idx >= 0 {
			localDigest = rd[idx+1:] // "sha256:abc..."
			break
		}
	}
	if localDigest == "" {
		// Image was built locally and never pulled — no remote digest to compare.
		// Treat as up-to-date to avoid false positives.
		log.Printf("[updater] no RepoDigests for %s (locally built?) — skipping check", image)
		return false, "local-build", "", nil
	}

	// ── Step 2: remote digest via registry HEAD (no download) ─────────────────
	remoteDigest, err := headRegistryDigest(image)
	if err != nil {
		return false, localDigest, "", fmt.Errorf("registry check failed: %w", err)
	}

	return localDigest != remoteDigest, localDigest, remoteDigest, nil
}

// headRegistryDigest fetches the manifest digest from the registry using a
// single HEAD request — no image layers are transferred.
//
// Works for Docker Hub public images and any OCI-compliant registry.
// Returns the Docker-Content-Digest header value.
func headRegistryDigest(image string) (string, error) {
	registry, repository, tag := parseImageRef(image)
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)

	// Must request manifest list type first — this is what docker pull stores
	// in RepoDigests on multi-arch images. Without this the registry may return
	// a platform-specific manifest digest which won't match RepoDigests.
	accept := strings.Join([]string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", ")

	// Always fetch a Bearer token first — Docker Hub's anonymous endpoint can
	// return a platform-specific manifest digest instead of the list digest,
	// which won't match RepoDigests and causes false "up to date" results.
	token, err := fetchBearerToken(registry, repository)
	if err != nil {
		// If token fetch fails, fall back to anonymous — better than nothing.
		log.Printf("[updater] bearer token fetch failed (%v), trying anonymous", err)
		return doHeadManifest(manifestURL, "", accept)
	}
	if token == "" {
		// Registry doesn't require auth (non-Hub registry) — anonymous is fine.
		return doHeadManifest(manifestURL, "", accept)
	}
	return doHeadManifest(manifestURL, token, accept)
}

func doHeadManifest(url, token, accept string) (string, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("auth required (%d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header in response")
	}
	return digest, nil
}

func fetchBearerToken(registry, repository string) (string, error) {
	probeURL := fmt.Sprintf("https://%s/v2/", registry)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(probeURL)
	if err != nil {
		return "", fmt.Errorf("registry probe: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		return "", nil // no auth needed
	}

	// Parse: Www-Authenticate: Bearer realm="...",service="...",scope="..."
	authHeader := resp.Header.Get("Www-Authenticate")
	realm, service := parseWwwAuthenticate(authHeader)
	if realm == "" {
		return "", fmt.Errorf("could not parse Www-Authenticate: %q", authHeader)
	}

	tokenURL := fmt.Sprintf("%s?service=%s&scope=repository:%s:pull", realm, service, repository)
	tresp, err := client.Get(tokenURL)
	if err != nil {
		return "", fmt.Errorf("token fetch: %w", err)
	}
	defer tresp.Body.Close()

	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tresp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	if payload.Token != "" {
		return payload.Token, nil
	}
	return payload.AccessToken, nil
}

// parseImageRef splits "piklz/prestoback:dev" into
// ("registry-1.docker.io", "piklz/prestoback", "dev")
func parseImageRef(image string) (registry, repository, tag string) {
	ref := image
	tag = "latest"
	if idx := strings.LastIndex(ref, ":"); idx > strings.LastIndex(ref, "/") {
		tag = ref[idx+1:]
		ref = ref[:idx]
	}
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry = parts[0]
		repository = parts[1]
	} else {
		registry = "registry-1.docker.io"
		if len(parts) == 1 {
			repository = "library/" + parts[0]
		} else {
			repository = ref
		}
	}
	return
}

func parseWwwAuthenticate(header string) (realm, service string) {
	header = strings.TrimPrefix(header, "Bearer ")
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "realm=") {
			realm = strings.Trim(strings.TrimPrefix(part, "realm="), `"`)
		} else if strings.HasPrefix(part, "service=") {
			service = strings.Trim(strings.TrimPrefix(part, "service="), `"`)
		}
	}
	return
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
