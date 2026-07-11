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
	LocalDigest  string           `json:"local_digest"`
	RemoteDigest string           `json:"remote_digest"`
	Releases     []GithubRelease  `json:"releases,omitempty"` // newest first; may be empty if changelog fetch failed
	ChangelogErr string           `json:"changelog_err,omitempty"`
	CheckedAt    time.Time        `json:"checked_at"`
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
			s.checkSelfUpdate(true, false)
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
func (s *Server) checkSelfUpdate(notifyUser, force bool) (*PendingSelfUpdate, error) {
	hasUpdate, local, remote, err := backup.ForceCheckForUpdate(s.image)
	if err != nil {
		return nil, err
	}

	if !hasUpdate {
		s.stateMu.Lock()
		s.pendingSelfUpdate = nil
		s.selfUpdateAlertSent = false
		s.stateMu.Unlock()
		return nil, nil
	}

	pending := &PendingSelfUpdate{
		LocalDigest:  local,
		RemoteDigest: remote,
		CheckedAt:    time.Now(),
	}
	if repo := githubRepo(); repo != "" {
		releases, cerr := backup.FetchReleasesSince(repo, config.Version)
		if cerr != nil {
			pending.ChangelogErr = cerr.Error()
			log.Printf("[selfupdate] changelog fetch failed: %v", cerr)
		} else {
			pending.Releases = releases
		}
	} else {
		pending.ChangelogErr = "PRESTOBACK_GITHUB_REPO not configured — set it to show release notes here"
	}

	s.stateMu.Lock()
	s.pendingSelfUpdate = pending
	alreadyAlerted := s.selfUpdateAlertSent
	if !alreadyAlerted || force {
		s.selfUpdateAlertSent = true
	}
	s.stateMu.Unlock()

	if notifyUser && (!alreadyAlerted || force) {
		nc := s.cfg.GetNotify()
		if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
			tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
			text := buildSelfUpdateMessage(pending)
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

	return pending, nil
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
		sb.WriteString(trimmedBody(r.Body, 500))
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
		sb.WriteString(trimmedBody(r.Body, 800))
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func displayVersion(r GithubRelease) string {
	if r.Name != "" && r.Name != r.TagName {
		return fmt.Sprintf("%s (%s)", r.TagName, r.Name)
	}
	return r.TagName
}

// trimmedBody escapes and hard-truncates a release body for MarkdownV2 —
// Telegram messages are capped at 4096 chars, and release notes can run
// long, especially summed across several versions.
func trimmedBody(body string, max int) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	truncated := len(body) > max
	if truncated {
		body = body[:max]
	}
	out := notify.EscapeMD(body) + "\n"
	if truncated {
		out += "…\n"
	}
	return out
}
