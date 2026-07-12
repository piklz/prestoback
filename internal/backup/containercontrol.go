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
	"os"
	"regexp"
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

// ── Branch-aware changelog (dev/CI builds vs tagged releases) ─────────────────
//
// FetchReleasesSince (above) only makes sense for the main/release track:
// GitHub Releases in this repo's own workflow are cut from tagged commits
// on main, so a dev-tag image (built by CI on every push to a feature/dev
// branch, versioned as e.g. "vdev-252ee28e" — see docker-build.yml) never
// has a matching release tag. Previously that meant FetchReleasesSince's
// "current version not found in the page" fallback fired and it returned
// every release for the WHOLE page — i.e. main's changelog — even though
// the running image has nothing to do with main. DevTrackInfo +
// FetchCommitsSince give the dev track its own comparison: actual commits
// on the branch it was built from, since the commit it was built at.

var (
	semverTagRe      = regexp.MustCompile(`^v?\d+(\.\d+){0,2}$`)
	devVersionSHARe  = regexp.MustCompile(`(?i)-([0-9a-f]{6,40})$`)
	shaTagRe         = regexp.MustCompile(`^(sha-)?[0-9a-f]{7,40}$`)
	mainTrackTagsSet = map[string]bool{"": true, "latest": true, "stable": true, "main": true, "master": true}
)

// DevTrackInfo inspects the running image's tag (and, as a fallback, an
// explicit PRESTOBACK_GITHUB_BRANCH override) to decide whether this build
// tracks a non-release branch rather than a tagged version.
//
//   - isDev is false for an untagged/`latest`/`stable`/`main`/`master` tag,
//     or a semver-looking tag (e.g. "v1.0.2") — the normal release track.
//   - isDev is true for anything else (e.g. "dev", "staging", "nightly"),
//     treating the tag itself as the GitHub branch name to compare commits
//     against, unless PRESTOBACK_GITHUB_BRANCH overrides that guess.
//   - A tag that's a bare or "sha-"-prefixed commit hash (e.g. the
//     `type=sha` tag docker/metadata-action also pushes on every build,
//     "sha-252ee28e") is NOT a valid git ref on its own — using it as a
//     branch name would send a bogus "compare to branch sha-252ee28e" call
//     to GitHub. Treated as isDev=true with an empty branch instead, so
//     FetchCommitsSince fails with a clear "set PRESTOBACK_GITHUB_BRANCH"
//     error rather than a confusing "not found".
//   - Caveat: for any branch name Docker tags can't represent as-is (a
//     slash, uppercase letters, etc. — docker/metadata-action sanitizes
//     these into the tag, e.g. branch "Feature/Foo" becomes tag
//     "feature-foo"), the original branch name generally can't be
//     reconstructed from the tag. PRESTOBACK_GITHUB_BRANCH is the escape
//     hatch for that case; "dev" itself needs no sanitizing so this
//     doesn't affect the common case.
//   - baseSHA is the short commit SHA this build was made from, parsed off
//     the tail of currentVersion (e.g. "dev-252ee28e" -> "252ee28e").
//     Empty if the version string doesn't carry one, in which case
//     FetchCommitsSince falls back to "most recent commits on the branch"
//     instead of a precise since-comparison.
func DevTrackInfo(image, currentVersion string) (branch, baseSHA string, isDev bool) {
	baseSHA = extractShortSHA(currentVersion)

	if override := strings.TrimSpace(os.Getenv("PRESTOBACK_GITHUB_BRANCH")); override != "" {
		return override, baseSHA, true
	}

	_, _, tag := parseImageRef(image)
	tag = strings.ToLower(strings.TrimSpace(tag))
	if mainTrackTagsSet[tag] || semverTagRe.MatchString(tag) {
		return "", baseSHA, false
	}
	if shaTagRe.MatchString(tag) {
		return "", baseSHA, true // dev track, but no usable branch name — see FetchCommitsSince's error
	}
	return tag, baseSHA, true
}

func extractShortSHA(version string) string {
	m := devVersionSHARe.FindStringSubmatch(strings.TrimSpace(version))
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// FetchCommitsSince returns commits on `branch` newer than baseSHA, newest
// first, reshaped as GithubRelease entries — TagName/Name carry the short
// SHA and commit headline, Body carries the full commit message. Reusing
// GithubRelease's shape (rather than a separate type) means the existing
// rendering pipeline — Telegram, Discord, and index.html's changelog modal
// — needs no changes to display commit-based changelogs; it's already
// generic over "a list of things with a tag, a name, a body, and a date".
//
// If baseSHA is unknown (couldn't be parsed from the running version), or
// the compare call fails (e.g. baseSHA no longer reachable after a
// force-push/rebase on the branch), falls back to the most recent commits
// on the branch rather than erroring out — a few extra/irrelevant entries
// beats no changelog at all.
func FetchCommitsSince(repo, branch, baseSHA string) ([]GithubRelease, error) {
	if repo == "" {
		return nil, fmt.Errorf("no GitHub repo configured (set PRESTOBACK_GITHUB_REPO)")
	}
	if branch == "" {
		return nil, fmt.Errorf("no branch to compare against (set PRESTOBACK_GITHUB_BRANCH)")
	}

	var entries []githubCommitEntry
	var err error
	if baseSHA != "" {
		entries, err = fetchCompareCommits(repo, baseSHA, branch)
		if err != nil {
			entries, err = fetchBranchCommits(repo, branch, 10)
		}
	} else {
		entries, err = fetchBranchCommits(repo, branch, 10)
	}
	if err != nil {
		return nil, err
	}

	out := make([]GithubRelease, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- { // API returns oldest-first; want newest-first, same as FetchReleasesSince
		c := entries[i]
		headline := c.Commit.Message
		if idx := strings.IndexByte(headline, '\n'); idx >= 0 {
			headline = headline[:idx]
		}
		short := c.SHA
		if len(short) > 8 {
			short = short[:8]
		}
		out = append(out, GithubRelease{
			TagName:     short,
			Name:        headline,
			Body:        c.Commit.Message,
			PublishedAt: c.Commit.Author.Date,
			HTMLURL:     c.HTMLURL,
		})
	}
	return out, nil
}

type githubCommitEntry struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	HTMLURL string `json:"html_url"`
}

// fetchCompareCommits lists commits reachable from `head` but not `base` —
// exactly "what's new since the commit this build was made from", via
// GitHub's compare API (oldest-first in the response, same as the commits
// API below).
func fetchCompareCommits(repo, base, head string) ([]githubCommitEntry, error) {
	var resp struct {
		Commits []githubCommitEntry `json:"commits"`
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/compare/%s...%s", repo, base, head)
	if err := githubAPIGet(url, &resp); err != nil {
		return nil, fmt.Errorf("compare %s...%s: %w", base, head, err)
	}
	return resp.Commits, nil
}

// fetchBranchCommits lists the most recent commits on a branch, with no
// "since" comparison — the fallback when there's no baseSHA to compare
// from, or the compare call itself failed.
func fetchBranchCommits(repo, branch string, perPage int) ([]githubCommitEntry, error) {
	var entries []githubCommitEntry
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?sha=%s&per_page=%d", repo, branch, perPage)
	if err := githubAPIGet(url, &entries); err != nil {
		return nil, fmt.Errorf("list commits on %s: %w", branch, err)
	}
	return entries, nil
}

func fetchReleases(repo string) ([]GithubRelease, error) {
	var releases []GithubRelease
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=10", repo)
	if err := githubAPIGet(url, &releases); err != nil {
		return nil, fmt.Errorf("fetch releases for %s: %w", repo, err)
	}
	return releases, nil
}

// githubAPIGet is the shared HTTP-GET-and-decode helper for every GitHub
// REST call this file makes (releases, compare, commits) — same auth
// header, same timeout, same error shaping, so a rate-limit or a typo'd
// PRESTOBACK_GITHUB_REPO reads identically no matter which endpoint hit it.
func githubAPIGet(url string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// GitHub's API rejects requests with no User-Agent.
	req.Header.Set("User-Agent", "PrestoBack-selfupdate")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: githubAPITimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found (check PRESTOBACK_GITHUB_REPO and, for a branch, PRESTOBACK_GITHUB_BRANCH)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("GitHub API rate-limited — try again shortly")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("GitHub API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	return nil
}
