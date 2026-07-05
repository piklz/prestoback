package backup

// imagemeta.go — per-container update-check reporting for Telegram/UI.
//
// This is a thin layer on top of updater.go's CheckForUpdate/ForceCheckForUpdate,
// which already does the real work correctly: a single HEAD request against
// the registry's manifest endpoint, compared against the image's local
// RepoDigests — no `docker pull`, no image layers transferred. See updater.go's
// doCheckForUpdate for why that comparison is reliable for multi-arch images
// (both sides are the manifest LIST digest, not a platform-specific one).
//
// What this file adds on top, ONLY when an update is actually available (to
// keep the common "nothing changed" case as cheap as a single HEAD):
//   - which underlying container an image belongs to (for grouping/reporting)
//   - a best-effort download size (sum of the platform-specific manifest's
//     layer sizes)
//   - a best-effort remote build date (from the image config blob)
//   - a best-effort "latest semver tag" lookup via the registry's tags/list,
//     plus the current tag itself when it's already a semver tag — this is
//     how a rolling tag like ":release" can still be reported as e.g.
//     "2.7.5 → 3.0.1" without needing to pin a specific version tag.
//
// None of this downloads image layers; the size/date lookups are small JSON
// manifest/config-blob fetches (a few KB), not the layers themselves.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ImageMeta is the per-container update-check result used for Telegram/UI
// reporting. Unlike the older ImageUpdateStatus (docker.go, pull-based — no
// longer used by the default check path), this is built entirely from
// registry API metadata.
type ImageMeta struct {
	ContainerName   string `json:"container_name"`
	Image           string `json:"image"` // full ref as configured, e.g. ghcr.io/immich-app/immich-server:release
	CurrentTag      string `json:"current_tag"`
	UpdateAvailable bool   `json:"update_available"`
	LocalDigest     string `json:"local_digest"`
	RemoteDigest    string `json:"remote_digest"`
	CurrentVersion  string `json:"current_version"`   // e.g. "2.7.5" — only set if CurrentTag itself is a semver tag
	LatestVersion   string `json:"latest_version"`    // e.g. "3.0.1" — highest semver tag found in the registry, best-effort
	SizeBytes       int64  `json:"size_bytes"`        // best-effort compressed download size of the new image, 0 if not determined
	CreatedDate     string `json:"created_date"`      // best-effort remote image build date "YYYY-MM-DD", "" if not determined
	Err             string `json:"err,omitempty"`     // non-empty if the check itself failed OR was skipped for a benign reason (see Skipped)
	Skipped         bool   `json:"skipped,omitempty"` // true when Err is set for a benign, non-actionable reason — pinned-by-digest or a locally-built image — rather than a genuine check failure (registry unreachable, bad tag, etc.). Reporting layers should render these as informational, not warnings.
}

// CheckImageMeta checks c's image against its registry using the same
// HEAD-based digest comparison as the self-updater — never pulls or
// downloads layers just to check. cache dedupes repeated checks of the same
// image within one check cycle (e.g. several containers sharing a base
// image), the same pattern the old pull-based CheckImageUpdate used.
func CheckImageMeta(c ContainerInfo, force bool, cache map[string]ImageMeta) ImageMeta {
	out, err := exec.Command("docker", "inspect", "--format={{.Config.Image}}", c.ID).Output()
	if err != nil {
		return ImageMeta{ContainerName: c.Name, Err: "inspect failed: " + err.Error()}
	}
	image := strings.TrimSpace(string(out))
	if image == "" {
		return ImageMeta{ContainerName: c.Name, Err: "could not determine image name"}
	}

	if cached, ok := cache[image]; ok {
		cached.ContainerName = c.Name
		return cached
	}

	res := ImageMeta{ContainerName: c.Name, Image: image}

	if strings.Contains(image, "@sha256:") {
		res.Err = "image is pinned by digest, not a tag — nothing to compare against"
		res.Skipped = true
		cache[image] = res
		return res
	}

	registry, repository, tag := parseImageRef(image)
	res.CurrentTag = tag
	if sv, ok := parseSemverTag(tag); ok {
		res.CurrentVersion = sv.raw
	}

	var hasUpdate bool
	var localDigest, remoteDigest string
	if force {
		hasUpdate, localDigest, remoteDigest, err = ForceCheckForUpdate(image)
	} else {
		hasUpdate, localDigest, remoteDigest, err = CheckForUpdate(image)
	}
	if err != nil {
		res.Err = err.Error()
		cache[image] = res
		return res
	}
	if localDigest == "local-build" {
		res.Err = "locally built image — no registry digest to track"
		res.Skipped = true
		cache[image] = res
		return res
	}
	res.LocalDigest = localDigest
	res.RemoteDigest = remoteDigest
	res.UpdateAvailable = hasUpdate

	if hasUpdate {
		if size, created, err2 := fetchImageDetails(registry, repository, remoteDigest); err2 == nil {
			res.SizeBytes = size
			res.CreatedDate = created
		} else {
			log.Printf("[imagemeta] size/date lookup failed for %s: %v", image, err2)
		}
		if lv, err2 := latestSemverTag(registry, repository); err2 == nil {
			res.LatestVersion = lv
		}
	}

	cache[image] = res
	return res
}

// ── Size / created-date lookup ────────────────────────────────────────────────
//
// remoteDigest here is the manifest LIST digest (see doCheckForUpdate). For a
// multi-arch image that's a list of per-platform entries, not the thing that
// actually has layers/size — so if the fetched content turns out to be a
// list, we resolve it to this host's actual platform and fetch THAT specific
// manifest for its layer sizes and config digest.

const registryFetchTimeout = 15 * time.Second

var manifestAccept = strings.Join([]string{
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
}, ", ")

func fetchImageDetails(registry, repository, digest string) (sizeBytes int64, createdDate string, err error) {
	token, _ := fetchBearerToken(registry, repository) // best-effort; "" is fine for no-auth registries

	body, _, err := getRegistryJSON(fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, digest), token, manifestAccept)
	if err != nil {
		return 0, "", err
	}

	var probe struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
				Variant      string `json:"variant,omitempty"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	_ = json.Unmarshal(body, &probe)

	if strings.Contains(probe.MediaType, "manifest.list") || strings.Contains(probe.MediaType, "image.index") {
		arch, variant := hostPlatform()
		var platDigest string
		for _, m := range probe.Manifests {
			if m.Platform.OS != "linux" || m.Platform.Architecture != arch {
				continue
			}
			if variant != "" && m.Platform.Variant != "" && m.Platform.Variant != variant {
				continue
			}
			platDigest = m.Digest
			break
		}
		if platDigest == "" {
			return 0, "", fmt.Errorf("no manifest for platform linux/%s in list", arch)
		}
		body, _, err = getRegistryJSON(fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, platDigest), token, manifestAccept)
		if err != nil {
			return 0, "", err
		}
	}

	var single struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &single); err != nil {
		return 0, "", err
	}
	for _, l := range single.Layers {
		sizeBytes += l.Size
	}

	if single.Config.Digest != "" {
		if cbody, _, err2 := getRegistryJSON(fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, single.Config.Digest), token, ""); err2 == nil {
			var cfg struct {
				Created string `json:"created"`
			}
			if json.Unmarshal(cbody, &cfg) == nil && cfg.Created != "" {
				if t, perr := time.Parse(time.RFC3339, cfg.Created); perr == nil {
					createdDate = t.Format("2006-01-02")
				} else {
					createdDate = cfg.Created
				}
			}
		}
	}
	return sizeBytes, createdDate, nil
}

func getRegistryJSON(url, token, accept string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: registryFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp, fmt.Errorf("GET %s: registry returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}
	return body, resp, nil
}

// ── Host platform detection ───────────────────────────────────────────────────

var (
	platformOnce    sync.Once
	platformArch    string
	platformVariant string
)

// hostPlatform returns this host's OCI platform arch/variant (e.g. "arm64",
// "" or "arm"/"v7"), used to pick the right entry out of a multi-arch
// manifest list. Cached — this never changes at runtime.
func hostPlatform() (arch, variant string) {
	platformOnce.Do(func() {
		out, err := exec.Command("docker", "info", "--format={{.Architecture}}").Output()
		raw := strings.TrimSpace(string(out))
		if err != nil || raw == "" {
			raw = runtime.GOARCH
		}
		switch raw {
		case "x86_64", "amd64":
			platformArch = "amd64"
		case "aarch64", "arm64":
			platformArch = "arm64"
		case "armv7l", "armv7", "arm":
			platformArch = "arm"
			platformVariant = "v7"
		case "armv6l":
			platformArch = "arm"
			platformVariant = "v6"
		default:
			platformArch = raw
		}
	})
	return platformArch, platformVariant
}

// ── Version tag lookup ────────────────────────────────────────────────────────

var semverTagRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

type semver struct {
	major, minor, patch int
	raw                 string
}

func parseSemverTag(tag string) (semver, bool) {
	m := semverTagRe.FindStringSubmatch(tag)
	if m == nil {
		return semver{}, false
	}
	maj, _ := strconv.Atoi(m[1])
	minV, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	return semver{maj, minV, pat, tag}, true
}

func (a semver) less(b semver) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// latestSemverTag finds the highest semver-looking tag in the repository's
// tag list (e.g. "v3.0.1" among "release", "latest", "v2.7.5", "v3.0.1").
// Best-effort — a repo with no semver tags (rolling-tag-only) just returns
// an error, which callers treat as "no version info available", not a
// failed check.
func latestSemverTag(registry, repository string) (string, error) {
	tags, err := listTags(registry, repository)
	if err != nil {
		return "", err
	}
	var best semver
	found := false
	for _, t := range tags {
		sv, ok := parseSemverTag(t)
		if !ok {
			continue
		}
		if !found || best.less(sv) {
			best = sv
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("no semver-looking tags found")
	}
	return best.raw, nil
}

// listTags fetches the repository's full tag list, following pagination via
// the Link header. Capped at 5 pages (500 tags) so a huge/misbehaving
// registry can't turn a single check into an unbounded loop.
func listTags(registry, repository string) ([]string, error) {
	token, _ := fetchBearerToken(registry, repository)
	var all []string
	next := fmt.Sprintf("https://%s/v2/%s/tags/list?n=100", registry, repository)
	for page := 0; page < 5 && next != ""; page++ {
		body, resp, err := getRegistryJSON(next, token, "")
		if err != nil {
			return all, err
		}
		var tr struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &tr); err != nil {
			return all, err
		}
		all = append(all, tr.Tags...)
		next = nextPageURL(registry, resp.Header.Get("Link"))
	}
	return all, nil
}

// nextPageURL parses a standard pagination Link header, e.g.
// `</v2/repo/tags/list?n=100&last=xyz>; rel="next"`, into an absolute URL.
func nextPageURL(registry, link string) string {
	if link == "" {
		return ""
	}
	parts := strings.SplitN(link, ";", 2)
	if len(parts) != 2 || !strings.Contains(parts[1], `rel="next"`) {
		return ""
	}
	raw := strings.Trim(strings.TrimSpace(parts[0]), "<>")
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.HasPrefix(raw, "/") {
		return "https://" + registry + raw
	}
	return "https://" + registry + "/" + raw
}
