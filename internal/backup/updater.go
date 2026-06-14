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

// composeInfo holds Compose metadata from container labels.
// Set only when the container was started by Docker Compose.
type composeInfo struct {
	Project string // com.docker.compose.project
	Service string // com.docker.compose.service
	WorkDir string // com.docker.compose.project.working_dir
}

// getComposeInfo returns Compose metadata when the container carries Compose
// labels, or nil for standalone containers.
func getComposeInfo(c containerInspect) *composeInfo {
	labels := c.Config.Labels
	project := labels["com.docker.compose.project"]
	service := labels["com.docker.compose.service"]
	workDir := labels["com.docker.compose.project.working_dir"]
	if project == "" || service == "" || workDir == "" {
		return nil
	}
	return &composeInfo{Project: project, Service: service, WorkDir: workDir}
}

// SelfUpdate performs a safe in-place update of the prestoback container.
//
// Approach:
//  1. Pull the new image
//  2. Drain active jobs (max 60s)
//  3. Inspect the current container — detect Compose vs standalone
//  4. Spawn a detached helper (via Docker socket) that restarts correctly:
//     - Compose-managed: docker compose up -d --no-deps --pull never <service>
//     Hands control back to Compose, avoiding the "container name already in
//     use" conflict caused by Compose's restart policy recreating the container
//     between our docker rm and docker run.
//     - Standalone: docker stop → docker rm → docker run (original behaviour)
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

	// ── Step 3: inspect current container ───────────────────────────────────────
	raw, err := exec.Command("docker", "container", "inspect", selfName).Output()
	if err != nil {
		return fmt.Errorf("could not inspect current container: %w", err)
	}
	var arr []containerInspect
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return fmt.Errorf("could not parse container inspect output: %w", err)
	}
	ci := arr[0]

	// ── Step 4: spawn helper that does stop → rm → run ────────────────────────
	//
	// We use docker stop/rm/run for BOTH compose-managed and standalone containers.
	// Why not "docker compose up" inside the helper?
	//   docker:cli does not ship the compose plugin — compose commands fail silently.
	//
	// Why does stop/rm/run work for compose-managed containers?
	//   "restart: unless-stopped" means Docker will NOT auto-restart after a manual
	//   docker stop. There is no compose daemon running between deployments.
	//   The brief gap between rm and run is safe.
	//
	// We preserve ALL original labels (including com.docker.compose.*) in the
	// reconstructed docker run command — exactly as Watchtower does. This means
	// compose still recognises and manages the container on the next
	// "docker compose up -d".
	runArgs, err := buildDockerRunArgs(ci, selfName, image)
	if err != nil {
		return fmt.Errorf("could not reconstruct docker run args: %w", err)
	}
	if info := getComposeInfo(ci); info != nil {
		emit(UpdateResult{Stage: "stopping", Message: fmt.Sprintf(
			"Compose project detected (%s / %s) — preserving compose labels in restart",
			info.Project, info.Service,
		)})
	}
	log.Printf("[updater] run args: %v", runArgs)

	// stop -t 30: give the app 30s to shut down cleanly.
	// Each arg must be shell-escaped because it goes through sh -c.
	// Without escaping, env vars like FOO=bar baz or label values with spaces
	// get word-split by the shell into extra arguments, breaking docker run.
	quotedArgs := make([]string, len(runArgs))
	for i, a := range runArgs {
		quotedArgs[i] = shellEscape(a)
	}
	// docker rm -f atomically force-stops and removes in one operation.
	// This avoids a race condition with restart:always policies where the
	// container restarts between a docker stop and docker rm.
	stopScript := fmt.Sprintf(
		"sleep 5 && docker rm -f %s && docker run %s",
		shellEscape(selfName), strings.Join(quotedArgs, " "),
	)
	log.Printf("[updater] helper script: %s", stopScript)
	emit(UpdateResult{Stage: "stopping", Message: "Spawning update helper…"})
	_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()

	helperArgs := []string{
		"run", "-d", "--name", "prestoback-updater",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"docker:cli", "sh", "-c", stopScript,
	}

	helperOut, err := exec.Command("docker", helperArgs...).CombinedOutput()
	if err != nil {
		log.Printf("[updater] docker:cli failed (%v: %s), trying docker:latest", err, helperOut)
		_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()
		// Swap docker:cli → docker:latest and retry.
		for i, a := range helperArgs {
			if a == "docker:cli" {
				helperArgs[i] = "docker:latest"
				break
			}
		}
		helperOut, err = exec.Command("docker", helperArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start update helper: %w\n%s", err, helperOut)
		}
	}

	helperID := strings.TrimSpace(string(helperOut))
	if len(helperID) > 12 {
		helperID = helperID[:12]
	}
	log.Printf("[updater] helper container started: %s", helperID)
	InvalidateUpdateCache(image)

	emit(UpdateResult{
		Stage: "done",
		Message: "Helper started (" + helperID + ") — PrestoBack restarting in ~10s. " +
			"If it doesn't return, run: docker logs prestoback-updater",
	})
	return nil
}

// buildDockerRunArgs inspects the running container and returns the exact
// []string args needed to recreate it with a new image.
//
// Each arg is a separate string — no shell involved, no quoting issues.
// Labels are preserved (including com.docker.compose.*) so compose still
// recognises the container after the update, exactly as Watchtower does.
func buildDockerRunArgs(c containerInspect, containerName, newImage string) ([]string, error) {
	args := []string{"-d", "--name", containerName}

	// Restart policy
	if rp := c.HostConfig.RestartPolicy.Name; rp != "" && rp != "no" {
		args = append(args, "--restart", rp)
	}

	// Port bindings
	for portProto, bindings := range c.HostConfig.PortBindings {
		containerPort := strings.TrimSuffix(portProto, "/tcp")
		for _, b := range bindings {
			if b.HostPort != "" {
				args = append(args, "-p", b.HostPort+":"+containerPort)
			}
		}
	}

	// Networks — skip "bridge" (Docker adds it automatically)
	for netName := range c.NetworkSettings.Networks {
		if netName != "bridge" {
			args = append(args, "--network", netName)
		}
	}

	// Volume binds
	for _, bind := range c.HostConfig.Binds {
		args = append(args, "-v", bind)
	}

	// Environment variables — skip Docker-internal ones
	skipEnv := map[string]bool{
		"PATH": true, "HOSTNAME": true, "HOME": true, "GOPATH": true,
	}
	for _, env := range c.Config.Env {
		key := strings.SplitN(env, "=", 2)[0]
		if !skipEnv[key] {
			args = append(args, "-e", env)
		}
	}

	// Labels — preserve ALL labels including com.docker.compose.* so compose
	// continues to own and recognise this container after the update.
	// Skip Docker-internal desktop and buildkit labels.
	// Preserve ALL compose labels including config-hash.
	// Without config-hash, compose treats the container as a foreign orphan and
	// tries to CREATE a new one rather than stop+rm+recreate → name conflict.
	// With a stale config-hash, compose sees "owned, config changed" → correctly
	// stops the existing container then recreates with a fresh hash.
	skipLabelPrefixes := []string{
		"com.docker.desktop.",
		"org.opencontainers.image.",
	}
	for k, v := range c.Config.Labels {
		skip := false
		for _, prefix := range skipLabelPrefixes {
			if strings.HasPrefix(k, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			args = append(args, "--label", k+"="+v)
		}
	}

	args = append(args, newImage)
	return args, nil
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

// shellEscape wraps s in single quotes, escaping any embedded single quotes.
// Required when building sh -c scripts from []string args.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
