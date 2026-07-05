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
	AppID   string
	AppName string
	Images  []backup.ImageMeta
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

	var reports []AppUpdateReport
	var pending []string

	for _, app := range apps {
		var images []backup.ImageMeta
		appHasUpdate := false
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
			reports = append(reports, AppUpdateReport{AppID: app.ID, AppName: app.Name, Images: images})
		}
		if appHasUpdate {
			pending = append(pending, app.Name)
		}
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
	if !nc.TelegramEnabled || nc.TelegramToken == "" || nc.TelegramChatID == "" {
		log.Printf("[updatecheck] %d app(s) have updates available but Telegram is not configured: %v", len(toAlertNames), toAlertNames)
		return reports, true
	}
	tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}

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

	text, btns := buildUpdateReportMessage(toAlertReports)
	btns = append(btns, notify.ButtonAction{Label: "👀 Remind me later", Data: "updatecheck:dismiss"})
	if err := notify.SendRawWithButtons(tgCfg, text, btns); err != nil {
		log.Printf("[updatecheck] notify failed: %v", err)
	}
	return reports, true
}

// buildUpdateReportMessage renders a Docksentry-style Telegram report: a
// headline, then each app with its underlying image(s) — version delta and
// size where known, or the check error if one occurred. Shared by the
// on-demand /check command and the debounced background alert so the two
// stay visually consistent.
func buildUpdateReportMessage(reports []AppUpdateReport) (string, []notify.ButtonAction) {
	var updatableApps []string
	for _, r := range reports {
		for _, img := range r.Images {
			if img.UpdateAvailable {
				updatableApps = append(updatableApps, r.AppName)
				break
			}
		}
	}

	var sb strings.Builder
	switch len(updatableApps) {
	case 0:
		sb.WriteString("⚠️ *Update check had issues* — see below\\.\n\n")
	case 1:
		sb.WriteString(fmt.Sprintf("⬆️ *Update available* — `%s`\n\n", notify.EscapeMD(updatableApps[0])))
	default:
		sb.WriteString(fmt.Sprintf("⬆️ *%d app\\(s\\) have updates*\n\n", len(updatableApps)))
	}

	for _, r := range reports {
		sb.WriteString(fmt.Sprintf("*%s*\n", notify.EscapeMD(r.AppName)))
		for _, img := range r.Images {
			name := notify.EscapeMD(img.ContainerName)
			switch {
			case img.Err != "":
				sb.WriteString(fmt.Sprintf("⚠️ `%s` — %s\n", name, notify.EscapeMD(img.Err)))
			case img.CurrentVersion != "" && img.LatestVersion != "" && img.CurrentVersion != img.LatestVersion:
				sb.WriteString(fmt.Sprintf("• `%s` %s → %s", name, notify.EscapeMD(img.CurrentVersion), notify.EscapeMD(img.LatestVersion)))
				appendSizeSuffix(&sb, img.SizeBytes)
				sb.WriteString("\n")
			default:
				sb.WriteString(fmt.Sprintf("• `%s` update available \\(tag: %s\\)", name, notify.EscapeMD(img.CurrentTag)))
				appendSizeSuffix(&sb, img.SizeBytes)
				sb.WriteString("\n")
			}
			if img.CreatedDate != "" {
				sb.WriteString(fmt.Sprintf("   📦 %s\n", notify.EscapeMD(img.CreatedDate)))
			}
		}
		sb.WriteString("\n")
	}

	var btns []notify.ButtonAction
	switch len(reports) {
	case 0:
		// nothing to act on
	case 1:
		btns = append(btns, notify.ButtonAction{Label: "🔄 Update now", Data: "update:" + reports[0].AppID})
	default:
		btns = append(btns, notify.ButtonAction{Label: fmt.Sprintf("🔄 Update all %d", len(reports)), Data: "update:all"})
	}

	return strings.TrimRight(sb.String(), "\n"), btns
}

func appendSizeSuffix(sb *strings.Builder, sizeBytes int64) {
	if sizeBytes <= 0 {
		return
	}
	sb.WriteString(fmt.Sprintf(" \\(%s\\)", notify.EscapeMD(humanBytes(sizeBytes))))
}
