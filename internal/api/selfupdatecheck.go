package api

// selfupdatecheck.go — /changelog, and the gated /selfupdate flow: checking
// no longer immediately applies an update. Instead it fetches the GitHub
// changelog for whatever new versions are available, stores that as
// "pending", surfaces it on the dashboard (via /api/status) and in
// Telegram with an explicit "🔄 Update now" button, and only calls
// backup.SelfUpdate once that button is pressed (or the dashboard's
// equivalent endpoint is hit). This mirrors the existing app-update flow
// in updatecheck.go (checkForUpdates / buildUpdateReportMessage) closely
// on purpose — same debounce-on-first-alert, same dismiss-and-re-alert
// pattern — so the two update flows feel consistent instead of one being
// gated and the other not.

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/config"
	"github.com/pi/prestoback/internal/notify"
)

const selfUpdateCheckInterval = 6 * time.Hour

// PendingSelfUpdate is what's shown on the dashboard banner and re-sent to
// Telegram until applied or dismissed.
type PendingSelfUpdate struct {
	LocalDigest  string          `json:"local_digest"`
	RemoteDigest string          `json:"remote_digest"`
	Releases     []GithubRelease `json:"releases,omitempty"` // newest first; may be empty if changelog fetch failed
	ChangelogErr string          `json:"changelog_err,omitempty"`
	CheckedAt    time.Time       `json:"checked_at"`
}

// GithubRelease mirrors backup.GithubRelease for the JSON the frontend sees
// (same shape — kept as a distinct type only so this package doesn't need
// to import backup's type into every handler signature).
type GithubRelease = backup.GithubRelease

// githubRepo returns the configured GitHub "owner/repo" for changelog
// fetches, e.g. "amayer1983/prestoback". Deliberately a plain env var,
// same pattern as PRESTOBACK_IMAGE/PRESTOBACK_CONTAINER — not inferred
// from the Docker image reference, since a Docker Hub namespace and a
// GitHub owner are not guaranteed to match.
func githubRepo() string {
	return strings.TrimSpace(os.Getenv("PRESTOBACK_GITHUB_REPO"))
}

// selfUpdateCheckLoop periodically checks for a new PrestoBack image and,
// if one is available, alerts once (debounced) — same shape as
// updateCheckLoop for app images.
func (s *Server) selfUpdateCheckLoop() {
	time.Sleep(3 * time.Minute) // stagger from updateCheckLoop's own startup delay
	for {
		if s.image != "" && s.selfName != "" {
			s.checkSelfUpdate(true, false) // return values unused here — pendingSelfUpdate is read from state by anything that needs it
		}
		time.Sleep(selfUpdateCheckInterval)
	}
}

// checkSelfUpdate checks PrestoBack's own image against its registry and
// updates s.pendingSelfUpdate accordingly.
//
//   - notifyUser: if true and this is a newly-detected update (not already
//     alerted — unless force), send a Telegram message with the changelog
//     and an "Update now" button.
//   - force: bypass the alert debounce — used by the /selfupdate command so
//     an explicit user request always gets a reply, even if the background
//     loop already alerted about this same update earlier.
//
// Returns (pending, localDigest, remoteDigest, err). pending is nil when
// already up to date — but localDigest/remoteDigest are still populated in
// that case. This distinction matters: BUG FIXED HERE — the previous
// version only surfaced the digests on PendingSelfUpdate, which is nil on
// the up-to-date path, so handleUpdateCheck's "up to date" branch had
// nothing to show and fell back to empty strings, which the dashboard then
// rendered as "local build (no registry digest)" — visually identical to
// the genuine no-RepoDigests case, even though the real check succeeded
// with real matching digests (confirmed via container logs: "local digest"
// and "remote digest" both logged correctly, hasUpdate=false). Callers
// that just want "what did the digest comparison find" should read the
// digest return values directly, not pending.LocalDigest/RemoteDigest.
func (s *Server) checkSelfUpdate(notifyUser, force bool) (pending *PendingSelfUpdate, localDigest, remoteDigest string, err error) {
	hasUpdate, local, remote, err := backup.ForceCheckForUpdate(s.image)
	if err != nil {
		return nil, "", "", err
	}

	if !hasUpdate {
		s.stateMu.Lock()
		s.pendingSelfUpdate = nil
		s.selfUpdateAlertSent = false
		s.stateMu.Unlock()
		return nil, local, remote, nil
	}

	p := &PendingSelfUpdate{
		LocalDigest:  local,
		RemoteDigest: remote,
		CheckedAt:    time.Now(),
	}
	if repo := githubRepo(); repo != "" {
		releases, cerr := backup.FetchReleasesSince(repo, config.Version)
		if cerr != nil {
			p.ChangelogErr = cerr.Error()
			log.Printf("[selfupdate] changelog fetch failed: %v", cerr)
		} else {
			for i := range releases {
				releases[i].Body = stripReleaseBoilerplate(releases[i].Body)
			}
			p.Releases = releases
		}
	} else {
		p.ChangelogErr = "PRESTOBACK_GITHUB_REPO not configured — set it to show release notes here"
	}

	s.stateMu.Lock()
	s.pendingSelfUpdate = p
	alreadyAlerted := s.selfUpdateAlertSent
	if !alreadyAlerted || force {
		s.selfUpdateAlertSent = true
	}
	s.stateMu.Unlock()

	if notifyUser && (!alreadyAlerted || force) {
		nc := s.cfg.GetNotify()
		if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
			tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
			text := buildSelfUpdateMessage(p)
			btns := []notify.ButtonAction{
				{Label: "🔄 Update now", Data: "selfupdate:apply"},
				{Label: "📋 Full changelog", Data: "selfupdate:changelog"},
				{Label: "👀 Remind me later", Data: "selfupdate:dismiss"},
			}
			if err := notify.SendRawWithButtons(tgCfg, text, btns); err != nil {
				log.Printf("[selfupdate] notify failed: %v", err)
			}
		}
	}

	return p, local, remote, nil
}

// buildSelfUpdateMessage renders a short "update available" summary —
// version delta plus the first release's headline notes, trimmed. Full
// per-version notes are available via the "📋 Full changelog" button
// (handleTelegramCallback → "selfupdate:changelog") rather than crammed in
// here, since a multi-version gap can be long.
func buildSelfUpdateMessage(p *PendingSelfUpdate) string {
	var sb strings.Builder
	sb.WriteString("⬆️ *PrestoBack update available*\n\n")
	if len(p.Releases) == 1 {
		r := p.Releases[0]
		sb.WriteString(fmt.Sprintf("*%s*\n", notify.EscapeMD(displayVersion(r))))
		sb.WriteString(renderReleaseBodyTelegram(truncateRaw(r.Body, 500)))
	} else if len(p.Releases) > 1 {
		sb.WriteString(fmt.Sprintf("*%d new version\\(s\\)* since `%s`:\n\n", len(p.Releases), notify.EscapeMD(config.Version)))
		for _, r := range p.Releases {
			sb.WriteString(fmt.Sprintf("• *%s*\n", notify.EscapeMD(displayVersion(r))))
		}
		sb.WriteString("\nTap 📋 for full release notes\\.")
	} else {
		sb.WriteString("A new image is available\\. \\(Release notes unavailable")
		if p.ChangelogErr != "" {
			sb.WriteString(": " + notify.EscapeMD(p.ChangelogErr))
		}
		sb.WriteString("\\)")
	}
	return sb.String()
}

// buildFullChangelogMessage renders every pending release's full notes —
// what the "📋 Full changelog" button and the /changelog command both show.
func buildFullChangelogMessage(p *PendingSelfUpdate) string {
	if p == nil || len(p.Releases) == 0 {
		if p != nil && p.ChangelogErr != "" {
			return fmt.Sprintf("⚠️ Couldn't load release notes: %s", notify.EscapeMD(p.ChangelogErr))
		}
		return "✅ No pending PrestoBack update\\."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📋 *%d new version\\(s\\) since `%s`*\n\n", len(p.Releases), notify.EscapeMD(config.Version)))
	for _, r := range p.Releases {
		sb.WriteString(fmt.Sprintf("*%s* — %s\n", notify.EscapeMD(displayVersion(r)), notify.EscapeMD(r.PublishedAt.Format("2006-01-02"))))
		sb.WriteString(renderReleaseBodyTelegram(truncateRaw(r.Body, 800)))
		sb.WriteString("\n\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func displayVersion(r GithubRelease) string {
	if r.Name != "" && r.Name != r.TagName {
		return fmt.Sprintf("%s (%s)", r.TagName, r.Name)
	}
	return r.TagName
}

// ── Release body cleanup + Telegram markdown rendering ────────────────────────
//
// GitHub's auto-generated release notes (generate_release_notes: true, as
// used by this repo's own docker-build.yml) come back as real markdown —
// headings, **bold**, [links](url), "* item" bullets — plus boilerplate
// that's useful on the GitHub releases page but just noise in a push
// notification: an HTML comment GitHub embeds at the top, a "New
// Contributors" section, and a trailing "**Full Changelog**: <compare-url>"
// line. Both the Telegram message and the dashboard's changelog view (see
// index.html's mdLite()) start from the same stripReleaseBoilerplate output,
// so the two surfaces show consistent, cleaned-up content.

var (
	htmlCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	mdHeadingRe   = regexp.MustCompile(`(?m)^#{1,6}\s*(.+?)\s*$`)
	mdBulletRe    = regexp.MustCompile(`^[*\-]\s+`)
	mdLinkRe      = regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)\s]+)\)`)
	mdBoldRe      = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

// stripReleaseBoilerplate removes GitHub's auto-generated filler, leaving
// just the actual "What's Changed" bullets (and any other real content the
// release body has) as markdown for renderReleaseBodyTelegram / mdLite to
// format.
func stripReleaseBoilerplate(body string) string {
	body = htmlCommentRe.ReplaceAllString(body, "")

	lines := strings.Split(body, "\n")
	var out []string
	skippingSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := mdHeadingRe.FindStringSubmatch(trimmed); m != nil {
			skippingSection = strings.Contains(strings.ToLower(m[1]), "new contributors")
			if skippingSection {
				continue
			}
		}
		if skippingSection {
			continue
		}
		if strings.HasPrefix(trimmed, "**Full Changelog**") || strings.HasPrefix(trimmed, "Full Changelog:") {
			continue
		}
		out = append(out, line)
	}
	// Collapse 3+ blank lines left behind by the section removal down to one,
	// so stripping "New Contributors" doesn't leave a visible gap.
	cleaned := strings.Join(out, "\n")
	for strings.Contains(cleaned, "\n\n\n") {
		cleaned = strings.ReplaceAll(cleaned, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(cleaned)
}

// truncateRaw hard-truncates the RAW markdown (before rendering), not the
// rendered MarkdownV2 output — cutting after rendering risks slicing a
// message mid-escape-sequence or mid-link and corrupting Telegram's
// formatting. Truncating the source text first, then rendering the
// (shorter) result, is always safe.
func truncateRaw(body string, max int) (out string) {
	body = strings.TrimSpace(body)
	if len(body) <= max {
		return body
	}
	return strings.TrimSpace(body[:max]) + "…"
}

// renderReleaseBodyTelegram converts cleaned release markdown into real
// Telegram MarkdownV2 formatting: headings become bold lines, "* "/"- "
// bullets become "• ", **bold** becomes Telegram's bold, and [text](url)
// links stay tappable — instead of running the whole body through
// EscapeMD, which previously left every one of those as literal
// backslash-escaped punctuation (e.g. "\*\*bold\*\*") rather than actual
// formatting.
func renderReleaseBodyTelegram(body string) string {
	if body == "" {
		return ""
	}
	lines := strings.Split(body, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			out = append(out, "")
			continue
		}
		if m := mdHeadingRe.FindStringSubmatch(trimmed); m != nil {
			out = append(out, "*"+notify.EscapeMD(m[1])+"*")
			continue
		}
		isBullet := mdBulletRe.MatchString(trimmed)
		text := mdBulletRe.ReplaceAllString(trimmed, "")
		text = renderInlineMDToTelegram(text)
		if isBullet {
			out = append(out, "• "+text)
		} else {
			out = append(out, text)
		}
	}
	return strings.Trim(strings.Join(out, "\n"), "\n")
}

// renderInlineMDToTelegram escapes a single line of text for MarkdownV2
// while preserving [text](url) links and **bold** spans as real formatting
// rather than escaping every character indiscriminately. Links are
// extracted to placeholders before EscapeMD runs (their URLs would
// otherwise collide with EscapeMD's own reserved-character escaping), then
// substituted back in as proper Telegram link syntax afterward.
func renderInlineMDToTelegram(text string) string {
	type link struct{ label, url string }
	var links []link
	text = mdLinkRe.ReplaceAllStringFunc(text, func(m string) string {
		sub := mdLinkRe.FindStringSubmatch(m)
		links = append(links, link{label: sub[1], url: sub[2]})
		return fmt.Sprintf("\x00LINK%d\x00", len(links)-1)
	})

	// Bold markers get non-reserved placeholder bytes so EscapeMD passes
	// them through untouched, then get swapped back to literal "*" after —
	// simpler than teaching EscapeMD to skip a matched span.
	text = mdBoldRe.ReplaceAllString(text, "\x01$1\x02")

	escaped := notify.EscapeMD(text)
	escaped = strings.ReplaceAll(escaped, "\x01", "*")
	escaped = strings.ReplaceAll(escaped, "\x02", "*")

	for i, l := range links {
		placeholder := fmt.Sprintf("\x00LINK%d\x00", i) // no reserved chars — EscapeMD left it untouched
		md := fmt.Sprintf("[%s](%s)", notify.EscapeMD(l.label), escapeMDURL(l.url))
		escaped = strings.ReplaceAll(escaped, placeholder, md)
	}
	return escaped
}
