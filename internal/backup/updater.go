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
// Approach (same pattern as Watchtower/Dockge):
//  1. Pull the new image
//  2. Drain active jobs (max 60s)
//  3. Inspect the current container to get its exact run flags
//  4. Spawn a detached helper container (via Docker socket) that:
//     - Sleeps 5s so prestoback can flush the SSE response
//     - Stops + removes the current prestoback container
//     - docker run with the same flags but new image
//
// Why helper and not compose? The helper uses plain docker CLI which is always
// available via docker:cli. Compose adds dependency on plugin availability
// inside the helper and requires the compose file to be accessible.
// Plain docker stop/rm/run is simpler and more reliable.
//
// On restart, Docker's --restart=unless-stopped ensures prestoback comes back up.
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

	// ── Step 3: build the docker run command from current container inspect ────
	// We reconstruct the exact flags used to start the current container so the
	// new one is identical except for the image digest.
	runArgs, err := buildDockerRunArgs(selfName, image)
	if err != nil {
		return fmt.Errorf("could not inspect current container: %w", err)
	}
	log.Printf("[updater] reconstructed run args: %v", runArgs)
	emit(UpdateResult{Stage: "stopping", Message: fmt.Sprintf("Container config read (%d flags)", len(runArgs))})

	// ── Step 4: spawn detached helper via docker:cli ───────────────────────────
	// docker:cli is a minimal image with just the Docker CLI binary.
	// It does NOT need compose — we use plain docker stop/rm/run.
	//
	// The helper is NOT --rm so it persists after exit for log inspection:
	//   docker logs prestoback-updater
	_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()

	// Build the stop+rm+run command. Each step is separate so failures are visible.
	// We pass the docker run args as individual arguments to avoid shell quoting issues.
	stopScript := fmt.Sprintf(
		"sleep 5 && docker stop -t 30 %s ; docker rm -f %s ; docker run %s",
		selfName, selfName, strings.Join(runArgs, " "),
	)
	log.Printf("[updater] helper script: %s", stopScript)
	emit(UpdateResult{Stage: "stopping", Message: "Spawning update helper…"})

	helperOut, err := exec.Command("docker", "run", "-d",
		"--name", "prestoback-updater",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"docker:cli",
		"sh", "-c", stopScript,
	).CombinedOutput()

	if err != nil {
		log.Printf("[updater] docker:cli failed (%v: %s), trying docker:latest", err, helperOut)
		_ = exec.Command("docker", "rm", "-f", "prestoback-updater").Run()
		helperOut, err = exec.Command("docker", "run", "-d",
			"--name", "prestoback-updater",
			"-v", "/var/run/docker.sock:/var/run/docker.sock",
			"docker:latest",
			"sh", "-c", stopScript,
		).CombinedOutput()
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
// []string args needed to recreate it with a new image, suitable for passing
// directly to exec.Command("docker", args...).
// Using a []string avoids all shell quoting and word-splitting issues.
func buildDockerRunArgs(containerName, newImage string) ([]string, error) {
	raw, err := exec.Command("docker", "container", "inspect", containerName).Output()
	if err != nil {
		return nil, fmt.Errorf("docker container inspect: %w", err)
	}
	var arr []containerInspect
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return nil, fmt.Errorf("parse inspect output: %w", err)
	}
	c := arr[0]

	args := []string{"-d"}
	args = append(args, "--name", containerName)

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

	// Networks — skip "bridge" (added automatically by Docker)
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
			args = append(args, "-e", env) // pass as separate arg — no quoting needed
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
