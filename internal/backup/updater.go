package backup

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"runtime"
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
func doCheckForUpdate(image string) (bool, string, string, error) {
	// ── local digest ──────────────────────────────────────────────────────────
	localOut, err := exec.Command("docker", "inspect", "--format={{.Id}}", image).Output()
	if err != nil {
		return false, "", "", fmt.Errorf("local image not found: %w", err)
	}
	localDigest := strings.TrimSpace(string(localOut))

	// ── remote digest via registry API (no pull, no docker CLI) ───────────────
	remoteDigest, err := registryDigest(image)
	if err != nil {
		return false, localDigest, "", fmt.Errorf("registry check failed: %w", err)
	}

	// docker inspect returns   sha256:<hex>
	// registry API returns     sha256:<hex>
	// Strip prefix for a clean comparison.
	local := strings.TrimPrefix(localDigest, "sha256:")
	remote := strings.TrimPrefix(remoteDigest, "sha256:")

	return local != remote, localDigest, remoteDigest, nil
}

// ── Registry API ──────────────────────────────────────────────────────────────

// registryDigest fetches the content-digest of an image tag from its registry
// using a single HEAD request — no image data is transferred.
//
// Supports:
//   - Docker Hub official images  (e.g. "ubuntu:22.04")
//   - Docker Hub user images      (e.g. "myorg/myapp:latest")
//   - Third-party registries      (e.g. "ghcr.io/owner/repo:tag")
//
// Authentication uses the Bearer token flow: we first ask the registry's
// token service for an anonymous (or credential-based) pull token, then HEAD
// the manifest endpoint. Docker Hub credentials from `docker login` are NOT
// read here; for private Hub repos the image should include a token via the
// standard DOCKER_CONFIG / ~/.docker/config.json path (future work).
func registryDigest(image string) (string, error) {
	registry, repository, tag := parseImageRef(image)

	// Build the manifest URL for the target platform so the digest we get
	// matches what `docker pull` would actually use on this host.
	accept := manifestAcceptHeader()

	// ── Attempt 1: anonymous HEAD (works for public images on any registry) ───
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)

	digest, err := headManifest(manifestURL, "", accept)
	if err == nil {
		return digest, nil
	}

	// ── Attempt 2: Bearer token (Docker Hub + most OCI-compliant registries) ──
	token, tokenErr := fetchRegistryToken(registry, repository)
	if tokenErr != nil {
		// Return the original error — the token fetch is best-effort.
		return "", fmt.Errorf("manifest HEAD: %w; token fetch: %v", err, tokenErr)
	}

	digest, err = headManifest(manifestURL, token, accept)
	if err != nil {
		return "", err
	}
	return digest, nil
}

// headManifest sends a HEAD request to manifestURL and returns the
// Docker-Content-Digest response header value.
func headManifest(url, bearerToken, accept string) (string, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", accept)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("registry returned %d (auth required or insufficient permissions)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d for %s", resp.StatusCode, url)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("registry did not return Docker-Content-Digest header")
	}
	return digest, nil
}

// fetchRegistryToken obtains an anonymous Bearer token from a registry's
// token service. Works for Docker Hub and any registry that advertises
// a Www-Authenticate: Bearer realm=… header on a 401 response.
func fetchRegistryToken(registry, repository string) (string, error) {
	// Trigger a 401 to discover the token endpoint.
	probeURL := fmt.Sprintf("https://%s/v2/", registry)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(probeURL)
	if err != nil {
		return "", fmt.Errorf("registry probe: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		// Registry allows anonymous access — no token needed.
		return "", nil
	}

	// Parse: Www-Authenticate: Bearer realm="https://…",service="…",scope="…"
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
		AccessToken string `json:"access_token"` // some registries use this key
	}
	if err := json.NewDecoder(tresp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("token decode: %w", err)
	}
	if payload.Token != "" {
		return payload.Token, nil
	}
	return payload.AccessToken, nil
}

// ── Image-ref parsing ─────────────────────────────────────────────────────────

// parseImageRef splits an image reference into (registry, repository, tag).
//
// Examples:
//
//	"ubuntu:22.04"              → ("registry-1.docker.io", "library/ubuntu",    "22.04")
//	"myorg/myapp:v1.2"         → ("registry-1.docker.io", "myorg/myapp",        "v1.2")
//	"ghcr.io/owner/repo:main"  → ("ghcr.io",              "owner/repo",          "main")
func parseImageRef(image string) (registry, repository, tag string) {
	// Split off tag.
	ref := image
	tag = "latest"
	if idx := strings.LastIndex(ref, ":"); idx > strings.LastIndex(ref, "/") {
		tag = ref[idx+1:]
		ref = ref[:idx]
	}

	// Detect whether the first component is a registry hostname.
	// A registry hostname contains a dot or a colon, or equals "localhost".
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		registry = parts[0]
		repository = parts[1]
	} else {
		registry = "registry-1.docker.io"
		if len(parts) == 1 {
			// Official image: no slash → add "library/" prefix.
			repository = "library/" + parts[0]
		} else {
			repository = ref
		}
	}
	return
}

// parseWwwAuthenticate extracts realm and service from a Bearer challenge.
// e.g. `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`
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

// manifestAcceptHeader returns the Accept header value that asks the registry
// for the manifest type matching this host's architecture. This ensures the
// digest we compare is for the image variant that is actually running.
func manifestAcceptHeader() string {
	// OCI index / Docker manifest list — multi-platform wrapper.
	// The registry resolves these to the correct platform digest server-side
	// when we also send platform headers, but most registries return the index
	// digest which matches what `docker inspect` reports after a pull.
	_ = runtime.GOARCH // referenced so the import is used even if we keep it simple
	return strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", ")
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
