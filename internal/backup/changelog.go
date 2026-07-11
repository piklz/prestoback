package backup

// changelog.go — fetches release notes from GitHub for PrestoBack's own
// self-update flow (/changelog and the gated /selfupdate confirm-before-
// applying flow in internal/api).
//
// Deliberately uses the GitHub REST API (api.github.com/repos/.../releases)
// rather than parsing a CHANGELOG.md out of the repo tree — releases are
// already structured JSON with a tag, a body, and a publish date, so no
// markdown-section-slicing is needed, and it's one GET request with no
// repo-layout assumptions (a moved or renamed CHANGELOG.md would silently
// break a file-based approach; the releases endpoint doesn't care).
//
// The GitHub repo is deliberately NOT inferred from the Docker image
// reference — Docker Hub namespace and GitHub owner are not guaranteed to
// match (plenty of published images live under a different GitHub org/user
// than their Docker Hub namespace). It's read from PRESTOBACK_GITHUB_REPO
// (e.g. "amayer1983/prestoback"), the same env-var-configured pattern
// PRESTOBACK_IMAGE/PRESTOBACK_CONTAINER already use for self-update.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const githubAPITimeout = 15 * time.Second

// GithubRelease is the subset of GitHub's release object this feature needs.
type GithubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
}

// FetchReleasesSince returns every published (non-draft, non-prerelease)
// release newer than currentVersion, newest first — GitHub's releases
// endpoint already returns them in that order, so this just walks the list
// and stops at the first tag matching currentVersion (that release, and
// everything older, is already running).
//
// currentVersion is compared against TagName both as-is and with a leading
// "v" stripped, since config.Version and git tags don't always agree on
// that prefix (e.g. running version "1.41.0" vs tag "v1.41.0").
//
// If currentVersion isn't found within the fetched page at all (e.g. it's
// old enough to have scrolled past GitHub's default page size, or this is
// a dev build with no matching tag), every fetched release is returned —
// better to show a few extra entries than none.
func FetchReleasesSince(repo, currentVersion string) ([]GithubRelease, error) {
	if repo == "" {
		return nil, fmt.Errorf("no GitHub repo configured (set PRESTOBACK_GITHUB_REPO)")
	}
	releases, err := fetchReleases(repo)
	if err != nil {
		return nil, err
	}

	sort.Slice(releases, func(i, j int) bool { return releases[i].PublishedAt.After(releases[j].PublishedAt) })

	want := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	var out []GithubRelease
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		if strings.TrimPrefix(r.TagName, "v") == want {
			break
		}
		out = append(out, r)
	}
	return out, nil
}

// FetchLatestRelease returns just the newest published release — used when
// only "what's the latest version" is needed, not the full gap list.
func FetchLatestRelease(repo string) (GithubRelease, error) {
	releases, err := fetchReleases(repo)
	if err != nil {
		return GithubRelease{}, err
	}
	for _, r := range releases {
		if !r.Draft && !r.Prerelease {
			return r, nil
		}
	}
	return GithubRelease{}, fmt.Errorf("no published releases found for %s", repo)
}

func fetchReleases(repo string) ([]GithubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// GitHub's API rejects requests with no User-Agent.
	req.Header.Set("User-Agent", "PrestoBack-selfupdate")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: githubAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch releases for %s: %w", repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("repo %q not found (check PRESTOBACK_GITHUB_REPO)", repo)
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub API rate-limited — try again shortly")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("GitHub API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var releases []GithubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("parse releases response: %w", err)
	}
	return releases, nil
}
