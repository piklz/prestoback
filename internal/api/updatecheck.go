package api

// updatecheck.go — the /check and background update-check flow.
//
// Replaces the old pull-based approach (docker.go's CheckImageUpdate, no
// longer called from here) with the registry HEAD-digest comparison already
// proven by the self-updater (backup.CheckForUpdate / ForceCheckForUpdate,
// see updater.go). No image layers are ever downloaded just to check —
// checking 7 apps now costs 7 small HEAD requests instead of 7 real pulls,
// and large images (1GB+) no longer time out mid-check.
//
// It also fixes a reporting bug: FindContainers(app.ID) does a fuzzy
// substring match, which is correct and intentional for backup/stop-start
// orchestration (over-including sibling containers is safe there), but the
// same fuzzy match was being reused for update *reporting*, causing a
// container that both has its own dedicated app AND is fuzzy-matched by a
// parent app (e.g. "immich_power_tools" is its own "Power-tools" app, and
// also matches the parent "immich" app's FindContainers("immich")) to be
// checked and reported twice, under two different app names. ownedContainers
// resolves each running container to exactly one owning app, preferring
// exact matches (ContainerName / LinkedContainers) over fuzzy ones.

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/config"
	"github.com/pi/prestoback/internal/notify"
)

// AppUpdateReport groups per-image update findings under the app that owns
// them, for a Docksentry-style /check report. Only images with an update
// available or a check error are included — up-to-date images are omitted
// to keep the report focused.
type AppUpdateReport struct {
	AppID   string             `json:"app_id"`
	AppName string             `json:"app_name"`
	Images  []backup.ImageMeta `json:"images"`
	// Pinned mirrors config.AppConfig.Pinned at the time this report was
	// built. A pinned app (e.g. a Compose service with a hand-managed
	// upgrade path — Immich's Postgres, for instance) still gets checked
	// and reported on, but buildUpdateReportMessage must not offer an
	// "Update" action button for it: tapping Auto-Update on a pinned app
	// would bypass exactly the manual intervention pinning exists to
	// force.
	Pinned bool `json:"pinned"`
	// BatchAnchor groups this app with others that share a Compose
	// depends_on relationship (see containercontrol.go's
	// ListContainerControlGroups, the same grouping the Container Control
	// page already uses — deliberately reused rather than inventing a
	// second "what belongs together" heuristic). An app with no
	// depends_on relationships is its own anchor — a batch of one.
	BatchAnchor string `json:"batch_anchor"`
	// BatchSize is how many OTHER apps in this same report currently have
	// a pending update and share BatchAnchor — i.e. how large "Update
	// batch" would be if clicked right now. Intentionally scoped to apps
	// that actually have a pending update, not every app in the compose
	// group: a batch action should only touch what the user was just
	// shown, never silently reach into a sibling with nothing pending.
	BatchSize int `json:"batch_size"`
	// Unmanaged is true for a container discovered by the host-wide
	// RunningContainers() scan (see checkForUpdates) that isn't backed by
	// any registered config.AppConfig — e.g. a container running on the
	// host that was never added as a PrestoBack app. It's still checked
	// and reported on for parity with a dedicated update-checker like
	// Docksentry, which has no "registered app" concept to filter
	// through — but buildUpdateReportMessage must not offer an "Update"
	// action button for it: the Telegram "update:<id>" callback resolves
	// AppID via s.cfg.GetApp, which only knows about real AppConfig
	// entries, so a button here would silently do nothing when tapped.
	Unmanaged bool `json:"unmanaged,omitempty"`
}

// ownedContainers assigns each running container discoverable from apps to
// exactly one owning app. Exact matches (app.ContainerName, app.LinkedContainers)
// always outrank fuzzy FindContainers(app.ID) substring matches; among fuzzy
// matches, the longer (more specific) app.ID wins — e.g. "power_tools" beats
// "immich" for a container named "immich_power_tools".
//
// This is purely a reporting-layer helper. It does not change and must not
// be used for backup quiescing or update-apply container selection — those
// deliberately keep the maximal-inclusion FindContainers/LinkedContainers
// behavior as-is (see the updateMu comment in server.go).
func ownedContainers(apps []config.AppConfig) map[string][]backup.ContainerInfo {
	type claim struct {
		appID       string
		specificity int
	}
	const exactSpecificity = 1 << 20 // always outranks any fuzzy substring match

	owner := map[string]claim{}               // container ID -> current best claim
	byID := map[string]backup.ContainerInfo{} // container ID -> the container itself

	for _, app := range apps {
		var exact []backup.ContainerInfo
		if app.ContainerName != "" {
			exact = append(exact, backup.ContainersByName([]string{app.ContainerName})...)
		}
		exact = append(exact, backup.ContainersByName(app.LinkedContainers)...)
		for _, c := range backup.DedupeContainers(exact) {
			byID[c.ID] = c
			if cur, ok := owner[c.ID]; !ok || exactSpecificity >= cur.specificity {
				owner[c.ID] = claim{appID: app.ID, specificity: exactSpecificity}
			}
		}

		specificity := len(app.ID)
		for _, c := range backup.DedupeContainers(backup.FindContainers(app.ID)) {
			byID[c.ID] = c
			if cur, ok := owner[c.ID]; !ok || specificity > cur.specificity {
				owner[c.ID] = claim{appID: app.ID, specificity: specificity}
			}
		}
	}

	result := map[string][]backup.ContainerInfo{}
	for id, cl := range owner {
		result[cl.appID] = append(result[cl.appID], byID[id])
	}
	return result
}

// checkForUpdates checks every running container's image against its
// registry (see the package comment above) and returns one AppUpdateReport
// per app that has at least one image with an update available or a check
// error — up-to-date apps are omitted. Also updates s.pendingUpdates (app
// names, unchanged shape — still read by the dashboard) and, if notify is
// true, sends a Telegram alert for any newly-pending app (subject to the
// existing per-app debounce in updateAlertSent).
//
// The second return value is false if Docker itself was unreachable and
// nothing could be checked at all — callers must not report that as "up to
// date" (an empty report list on its own can't tell those two cases apart).
func (s *Server) checkForUpdates(notifyUser bool) ([]AppUpdateReport, bool) {
	apps := s.cfg.ListApps()

	if ok, errMsg := backup.DockerReachable(); !ok {
		log.Printf("[updatecheck] aborting — Docker daemon unreachable: %s", errMsg)
		return nil, false
	}

	owned := ownedContainers(apps)
	cache := map[string]backup.ImageMeta{}

	// containerAnchor maps a running container's name to its
	// ListContainerControlGroups anchor — reusing that page's existing
	// depends_on-derived grouping rather than a second parser. A failure
	// here (e.g. Docker inspect hiccup on one container) just means every
	// app falls back to being its own anchor below — never fatal to the
	// update check itself.
	containerAnchor := map[string]string{}
	if groups, err := backup.ListContainerControlGroups(); err == nil {
		for _, g := range groups {
			for _, c := range g.Containers {
				containerAnchor[c.Name] = g.Anchor
			}
		}
	}

	var reports []AppUpdateReport
	var pending []string

	for _, app := range apps {
		var images []backup.ImageMeta
		appHasUpdate := false
		anchor := app.Name // fallback: no known compose relationships — a batch of one
		for _, c := range owned[app.ID] {
			if a, ok := containerAnchor[c.Name]; ok {
				anchor = a
				break
			}
		}
		for _, c := range owned[app.ID] {
			// No running-only filter here: this is a registry-vs-local-digest
			// comparison (backup.CheckImageMeta → docker inspect + a registry
			// HEAD), which works identically for a stopped or paused container
			// — the image reference doesn't go anywhere when a container is
			// stopped. Portainer, Diun, and Docksentry all check regardless of
			// running state for the same reason; skipping non-running
			// containers here just meant a temporarily-stopped app silently
			// dropped out of every future check.
			meta := backup.CheckImageMeta(c, true, cache) // true: /check and the daily loop both want a fresh answer, not a stale hourly cache
			if meta.Err != "" {
				log.Printf("[updatecheck] %s/%s: %s", app.Name, c.Name, meta.Err)
				images = append(images, meta) // surfaced to the user, not swallowed
				continue
			}
			if meta.UpdateAvailable {
				appHasUpdate = true
				images = append(images, meta)
			}
		}
		if len(images) > 0 {
			reports = append(reports, AppUpdateReport{AppID: app.ID, AppName: app.Name, Images: images, Pinned: app.Pinned, BatchAnchor: anchor})
		}
		if appHasUpdate {
			pending = append(pending, app.Name)
		}
	}

	// ── Host-wide scan: containers that aren't backed by any registered
	// app ──────────────────────────────────────────────────────────────────
	//
	// Everything above only ever looks at containers reachable from
	// s.cfg.ListApps() (via ownedContainers). A container running on the
	// host that was never added as a PrestoBack app — e.g. a dashboard or
	// utility container nobody bothered to set up backups for — is
	// invisible to that path by construction, which meant it silently
	// never appeared in /check even though a dedicated update-checker
	// like Docksentry (no "registered app" concept, just `docker ps`)
	// would report it. RunningContainers() plus a diff against ownedIDs
	// closes that gap: every currently-running container not already
	// claimed by an app gets checked and reported the same way, just
	// flagged Unmanaged so no "Update" button is offered for it (see
	// AppUpdateReport.Unmanaged's doc comment for why).
	ownedIDs := map[string]bool{}
	for _, cs := range owned {
		for _, c := range cs {
			ownedIDs[c.ID] = true
		}
	}
	for _, c := range backup.RunningContainers() {
		if ownedIDs[c.ID] {
			continue
		}
		anchor := c.Name
		if a, ok := containerAnchor[c.Name]; ok {
			anchor = a
		}
		meta := backup.CheckImageMeta(c, true, cache)
		if meta.Err == "" && !meta.UpdateAvailable {
			continue // up to date — omitted from the report, same as any other image
		}
		if meta.Err != "" {
			log.Printf("[updatecheck] (unmanaged) %s: %s", c.Name, meta.Err)
		}
		reports = append(reports, AppUpdateReport{
			AppID:       "container:" + c.Name,
			AppName:     c.Name,
			Images:      []backup.ImageMeta{meta},
			BatchAnchor: anchor,
			Unmanaged:   true,
		})
		if meta.UpdateAvailable {
			pending = append(pending, c.Name)
		}
	}

	// BatchSize: how many reports share the same anchor — see its doc
	// comment on AppUpdateReport for why this is scoped to reports
	// (apps with an actual pending update) rather than every app in the
	// compose group. Unmanaged reports are excluded from the count itself
	// (though they remain in `reports` and are still displayed): they have
	// no config.AppConfig, so handleUpdateBatch's s.cfg.GetApp(rep.AppID)
	// silently drops them from `targets` without adding them to `skipped`
	// either — counting them here would inflate a registered sibling's
	// "Update batch (N)" button beyond what the batch action actually
	// updates, with no accounting for the gap the way a pinned member gets
	// (skipped_pinned).
	batchCounts := map[string]int{}
	for _, r := range reports {
		if r.Unmanaged {
			continue
		}
		batchCounts[r.BatchAnchor]++
	}
	for i := range reports {
		reports[i].BatchSize = batchCounts[reports[i].BatchAnchor]
	}

	sort.Strings(pending)
	sort.Slice(reports, func(i, j int) bool { return reports[i].AppName < reports[j].AppName })

	s.stateMu.Lock()
	s.pendingUpdates = pending
	s.pendingUpdateDetails = reports
	pendingSet := map[string]bool{}
	for _, n := range pending {
		pendingSet[n] = true
	}
	// Clear debounce for apps that no longer have a pending update (e.g. user
	// already ran /update) so a future re-appearance alerts again.
	for name := range s.updateAlertSent {
		if !pendingSet[name] {
			delete(s.updateAlertSent, name)
		}
	}
	var toAlertNames []string
	for _, name := range pending {
		if !s.updateAlertSent[name] {
			s.updateAlertSent[name] = true
			toAlertNames = append(toAlertNames, name)
		}
	}
	s.stateMu.Unlock()

	if !notifyUser || len(toAlertNames) == 0 {
		return reports, true
	}

	nc := s.cfg.GetNotify()
	telegramReady := nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != ""
	discordReady := nc.DiscordEnabled && nc.DiscordURL != ""
	if !telegramReady && !discordReady {
		log.Printf("[updatecheck] %d app(s) have updates available but no notify channel is configured: %v", len(toAlertNames), toAlertNames)
		return reports, true
	}

	alertSet := map[string]bool{}
	for _, n := range toAlertNames {
		alertSet[n] = true
	}
	var toAlertReports []AppUpdateReport
	for _, r := range reports {
		if alertSet[r.AppName] {
			toAlertReports = append(toAlertReports, r)
		}
	}

	if telegramReady {
		tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
		text, btns := buildUpdateReportMessage(toAlertReports)
		s.stateMu.Lock()
		s.dismissSeq++
		batchID := fmt.Sprintf("%d", s.dismissSeq)
		s.dismissBatches[batchID] = toAlertNames
		s.stateMu.Unlock()
		btns = append(btns, notify.ButtonAction{Label: "👀 Remind me later", Data: "updatecheck:dismiss:" + batchID})
		if err := notify.SendRawWithButtons(tgCfg, text, btns); err != nil {
			log.Printf("[updatecheck] notify failed: %v", err)
		}
	}

	if discordReady {
		title, desc := buildUpdateReportDiscordMessage(toAlertReports)
		if err := notify.SendDiscordEmbed(nc.DiscordURL, title, desc, 0xf5a524); err != nil {
			log.Printf("[updatecheck] discord notify failed: %v", err)
		}
	}

	return reports, true
}

// buildUpdateReportDiscordMessage is the Discord-embed equivalent of
// buildUpdateReportMessage — same per-app/per-image content, rendered with
// Discord's own lightweight markdown instead of Telegram's MarkdownV2 (no
// EscapeMD needed) and no per-app buttons, since Discord embeds don't
// support inline actions the way Telegram messages do.
func buildUpdateReportDiscordMessage(reports []AppUpdateReport) (title, description string) {
	var updatableApps []string
	for _, r := range reports {
		for _, img := range r.Images {
			if img.UpdateAvailable {
				updatableApps = append(updatableApps, r.AppName)
				break
			}
		}
	}
	switch {
	case len(updatableApps) == 1:
		title = "⬆️ Update available — " + updatableApps[0]
	case len(updatableApps) > 1:
		title = fmt.Sprintf("⬆️ %d app(s) have updates", len(updatableApps))
	default:
		title = "ℹ️ Update check complete"
	}

	var sb strings.Builder
	for _, r := range reports {
		name := r.AppName
		if r.Pinned {
			name = "🔒 " + name
		} else if r.Unmanaged {
			name = "🧩 " + name
		}
		sb.WriteString(fmt.Sprintf("**%s**\n", name))
		for _, img := range r.Images {
			label := fmt.Sprintf("`%s`", img.ContainerName)
			if img.WebURL != "" {
				label = fmt.Sprintf("[%s](%s)", img.ContainerName, img.WebURL)
			}
			switch {
			case img.Err != "" && img.Skipped:
				line := fmt.Sprintf("ℹ️ %s — %s (tracked manually)", label, img.Err)
				if img.LocalCreatedDate != "" {
					line += fmt.Sprintf(" 🗓️ Current: %s", img.LocalCreatedDate)
				}
				sb.WriteString(line + "\n")
			case img.Err != "":
				sb.WriteString(fmt.Sprintf("⚠️ %s — %s\n", label, img.Err))
			default:
				line := fmt.Sprintf("• %s (%s) 🐳", label, img.Image)
				if img.CurrentVersion != "" && img.LatestVersion != "" && img.CurrentVersion != img.LatestVersion {
					line += fmt.Sprintf(" 🔖 %s → %s", img.CurrentVersion, img.LatestVersion)
				}
				sb.WriteString(line + "\n")
				var detail []string
				if img.SizeBytes > 0 {
					detail = append(detail, "📦 "+humanBytes(img.SizeBytes))
				}
				if img.LocalCreatedDate != "" {
					detail = append(detail, "🗓️ Current: "+img.LocalCreatedDate)
				}
				if len(detail) > 0 {
					sb.WriteString("  " + strings.Join(detail, " | ") + "\n")
				}
			}
		}
		if r.Pinned {
			sb.WriteString("   _pinned — update manually, no Auto-Update button offered_\n")
		} else if r.Unmanaged {
			sb.WriteString("   _not tracked as a PrestoBack app yet — add it under Applications for one-tap backup_\n")
		}
		sb.WriteString("\n")
	}
	return title, strings.TrimSpace(sb.String())
}

// buildUpdateReportMessage renders a Docksentry-style Telegram report: a
// headline, then each app with its underlying image(s) — version delta and
// size where known, or the check error if one occurred. Shared by the
// on-demand /check command and the debounced background alert so the two
// stay visually consistent.
func buildUpdateReportMessage(reports []AppUpdateReport) (string, []notify.ButtonAction) {
	var updatableApps []string
	hasRealIssue := false
	hasSkip := false
	for _, r := range reports {
		for _, img := range r.Images {
			if img.UpdateAvailable {
				updatableApps = append(updatableApps, r.AppName)
				break // count each app once, even if several of its images have updates
			}
		}
	}
	for _, r := range reports {
		for _, img := range r.Images {
			if img.Err == "" {
				continue
			}
			if img.Skipped {
				hasSkip = true
			} else {
				hasRealIssue = true
			}
		}
	}

	var sb strings.Builder
	switch {
	case len(updatableApps) == 1:
		sb.WriteString(fmt.Sprintf("⬆️ *Update available* — `%s`\n\n", notify.EscapeMD(updatableApps[0])))
	case len(updatableApps) > 1:
		sb.WriteString(fmt.Sprintf("⬆️ *%d app\\(s\\) have updates*\n\n", len(updatableApps)))
	case hasRealIssue:
		sb.WriteString("⚠️ *Update check had issues* — see below\\.\n\n")
	case hasSkip:
		sb.WriteString("ℹ️ *Update check complete* — some images couldn't be checked \\(pinned by digest or locally built\\) and are tracked manually\\.\n\n")
	default:
		sb.WriteString("✅ *Update check complete* — everything up to date\\.\n\n")
	}

	for _, r := range reports {
		name := notify.EscapeMD(r.AppName)
		if r.Pinned {
			name = "🔒 " + name
		} else if r.Unmanaged {
			name = "🧩 " + name
		}
		sb.WriteString(fmt.Sprintf("*%s*\n", name))
		for _, img := range r.Images {
			cname := notify.EscapeMD(img.ContainerName)
			// Link the name to its registry/package page when recognized
			// (Docker Hub, GHCR, Quay — see registryWebURL in imagemeta.go).
			// A markdown link and inline code can't nest in Telegram's
			// MarkdownV2, so this replaces the old plain backtick styling
			// rather than layering on top of it.
			label := fmt.Sprintf("`%s`", cname)
			if img.WebURL != "" {
				label = fmt.Sprintf("[%s](%s)", cname, escapeMDURL(img.WebURL))
			}
			switch {
			case img.Err != "" && img.Skipped:
				// One line, not a separate date line below — a pinned/
				// unresolvable image has nothing actionable to show, so a
				// second line just for its current-build date is noise
				// this format deliberately drops (matches the user's own
				// "much cleaner" reference format, which condenses these).
				line := fmt.Sprintf("ℹ️ %s — %s \\(tracked manually\\)", label, notify.EscapeMD(img.Err))
				if img.LocalCreatedDate != "" {
					line += fmt.Sprintf(" 🗓️ Current: %s", notify.EscapeMD(img.LocalCreatedDate))
				}
				sb.WriteString(line + "\n")
			case img.Err != "":
				sb.WriteString(fmt.Sprintf("⚠️ %s — %s\n", label, notify.EscapeMD(img.Err)))
			default:
				line := fmt.Sprintf("• %s \\(%s\\) 🐳", label, notify.EscapeMD(img.Image))
				// 🔖 version arrow only when both ends are known and
				// actually differ — CurrentVersion now resolves even for a
				// moving tag like :latest/:release (see
				// resolveCurrentVersionByDigest in imagemeta.go), not just
				// when the configured tag is itself a version string.
				if img.CurrentVersion != "" && img.LatestVersion != "" && img.CurrentVersion != img.LatestVersion {
					line += fmt.Sprintf(" 🔖 %s → %s", notify.EscapeMD(img.CurrentVersion), notify.EscapeMD(img.LatestVersion))
				}
				sb.WriteString(line + "\n")
				var detail []string
				if img.SizeBytes > 0 {
					detail = append(detail, "📦 "+notify.EscapeMD(humanBytes(img.SizeBytes)))
				}
				if img.LocalCreatedDate != "" {
					detail = append(detail, "🗓️ Current: "+notify.EscapeMD(img.LocalCreatedDate))
				}
				if len(detail) > 0 {
					sb.WriteString("  " + strings.Join(detail, " \\| ") + "\n")
				}
			}
		}
		if r.Pinned {
			sb.WriteString("   _pinned — update manually, no Auto\\-Update button offered_\n")
		} else if r.Unmanaged {
			sb.WriteString("   _not tracked as a PrestoBack app yet — add it under Applications for one\\-tap backup_\n")
		}
		sb.WriteString("\n")
	}

	// One button per updatable app so each can be applied independently,
	// plus (when there's more than one) a combined "update all" button —
	// mirrors the reference notification pattern: individual per-app
	// buttons for granular control, with a single "update all" shortcut
	// added on top when a batch update is convenient instead.
	var btns []notify.ButtonAction
	updatableCount := 0
	for _, r := range reports {
		if r.Pinned {
			// No per-app button for a pinned app — see AppUpdateReport.Pinned's
			// doc comment. It's still listed above with a 🔒 marker and the
			// "pinned" note so the update isn't silently hidden, just not
			// offered as a one-tap action.
			continue
		}
		if r.Unmanaged {
			// Own callback prefix ("qupdate:") rather than "update:<id>" —
			// that path looks the AppID up via s.cfg.GetApp, which has
			// nothing to find for an unmanaged container (AppID here is
			// "container:<name>", not a real app). qupdate: instead calls
			// the same quick-update endpoint the UI's Container Control
			// badge already uses for exactly this case (see
			// handleContainerQuickUpdate/runQuickContainerUpdate,
			// server.go) — no pre-update backup, since there's no app to
			// back up, just a direct pull + recreate by container name.
			hasRealUpdate := false
			for _, im := range r.Images {
				if im.UpdateAvailable {
					hasRealUpdate = true
					break
				}
			}
			if hasRealUpdate {
				btns = append(btns, notify.ButtonAction{Label: "🔄 Update " + r.AppName, Data: "qupdate:" + r.AppName})
			}
			continue
		}
		// A report can exist purely because one of its images is
		// pinned-by-digest/skipped (e.g. Immich-postgres, or immich's
		// immich_redis linked container) with nothing else in the app
		// actually needing an update — that's what put it in `reports` at
		// all (updatecheck's len(images) > 0 check counts Skipped/errored
		// images, not just real ones). r.Pinned/r.Unmanaged don't catch
		// this case: the app itself is a real, non-pinned config.AppConfig,
		// it just has no actionable image right now. Offering "Update" here
		// would try to act on an app with nothing to pull against.
		hasRealUpdate := false
		for _, im := range r.Images {
			if im.UpdateAvailable {
				hasRealUpdate = true
				break
			}
		}
		if !hasRealUpdate {
			continue
		}
		updatableCount++
		btns = append(btns, notify.ButtonAction{Label: "🔄 Update " + r.AppName, Data: "update:" + r.AppID})
	}
	if updatableCount > 1 {
		btns = append(btns, notify.ButtonAction{Label: fmt.Sprintf("🔄 Update all %d", updatableCount), Data: "update:all"})
	}

	return strings.TrimRight(sb.String(), "\n"), btns
}

// escapeMDURL escapes only the two characters MarkdownV2 requires escaping
// inside a link's URL segment — "\" and ")" — per Telegram's spec. Deliberately
// NOT notify.EscapeMD, which is for display text and would mangle the URL
// itself here (e.g. it escapes "." , which would corrupt "github.com").
func escapeMDURL(url string) string {
	r := strings.NewReplacer(`\`, `\\`, `)`, `\)`)
	return r.Replace(url)
}
