package api

// healthmonitor.go — host-wide container health-transition alerting.
// Independent of the backup-app registry entirely: this watches EVERY
// container Docker knows about (running or not, registered as a
// PrestoBack app or not), the same host-wide scope RunningContainers'
// own doc comment already models on a dedicated watchdog like Docksentry
// — because a healthcheck failure is exactly the kind of thing that
// matters for a container PrestoBack was never asked to back up too.
//
// Design goals, in priority order:
//  1. Alert on TRANSITIONS only, never on "still unhealthy." A container
//     stuck unhealthy for six hours should produce ONE alert, not 720 of
//     them at a 30s poll interval — this is the single most important
//     property a health-alerting feature has to get right, or it trains
//     the user to ignore the channel entirely.
//  2. Attach the "why," not just the "what." HealthAndExitFromStatus
//     (docker.go) already gives every routine poll the bare "unhealthy"
//     string for free out of `docker ps` — but that alone tells you
//     nothing you didn't already suspect. InspectContainerHealth's
//     probe output and ContainerLogTail's recent log lines are what
//     actually let you diagnose from your phone without reaching for a
//     terminal, which is the whole point of a "cool telegram feature"
//     over a bare state-change ping.
//  3. Don't spam during a flap. A container bouncing
//     unhealthy→healthy→unhealthy repeatedly (a flaky dependency, a
//     healthcheck with too tight a timeout) is worse for alert fatigue
//     than one that's cleanly down — collapseFlapping turns a burst of
//     these into one "flapping, muting for a while" message instead of
//     one alert per bounce.
//  4. Act from the alert, not just read it. Every unhealthy alert carries
//     Restart / more-logs / mute buttons — reusing the exact
//     inline-keyboard mechanism already built for update alerts
//     (SendRawWithButtons, handleTelegramCallback), not a new pattern.

import (
	"fmt"
	"strings"
	"time"

	"github.com/pi/prestoback/internal/backup"
	"github.com/pi/prestoback/internal/history"
	"github.com/pi/prestoback/internal/notify"
)

const (
	healthPollInterval = 30 * time.Second // matches diskMonitorLoop's order of magnitude — frequent enough to catch a real outage promptly, cheap enough (one `docker ps` snapshot) to run forever
	healthLogTailLines = 50               // "head 50 type log" from the brief — last N lines of `docker logs`, attached to every unhealthy alert
	healthMoreLogLines = 200              // the 📄 More logs button's deeper look
	healthMuteDuration = 30 * time.Minute // fixed rather than user-configurable — keeps callback_data (and the button label) simple; /health or the next natural alert both still work while muted

	// Flap detection: healthFlapWindow is the lookback window,
	// healthFlapThreshold is how many unhealthy EDGES (not polls) inside
	// that window count as "flapping" rather than "just unlucky twice."
	healthFlapWindow    = 10 * time.Minute
	healthFlapThreshold = 3
	healthFlapMuteFor   = 30 * time.Minute
)

// containerHealthState is per-container, in-memory only (like every other
// poll-loop debounce map on *Server — see updateAlertSent) — a restart of
// PrestoBack itself just means "re-learn everyone's current state on the
// next poll, alert on nothing until an actual edge happens after that,"
// which is the right behavior anyway (never alert on your own startup).
type containerHealthState struct {
	lastHealth     string      // "" | "starting" | "healthy" | "unhealthy" — "" also covers "no healthcheck configured"
	unhealthySince time.Time   // zero when lastHealth != "unhealthy"
	recentEdges    []time.Time // unhealthy-transition timestamps within healthFlapWindow, oldest first — for flap detection
	mutedUntil     time.Time   // alerts suppressed for this container until this time (manual mute button, or auto-mute after a detected flap)
	flapAlertSent  bool        // true once the "flapping, muting" message has gone out for the CURRENT flap streak — reset when the streak ages out of the window
}

func (s *Server) containerHealthMonitorLoop() {
	ticker := time.NewTicker(healthPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.pollContainerHealth()
	}
}

// pollContainerHealth does one `docker ps -a`-scale pass (via
// RunningContainers — stopped containers have no live healthcheck to
// poll, so they're correctly out of scope here) and reacts only to
// containers whose health STATE actually changed since the last poll.
func (s *Server) pollContainerHealth() {
	containers := backup.RunningContainers()
	now := time.Now()

	for _, c := range containers {
		health, _ := backup.HealthAndExitFromStatus(c.RawStatus)

		s.stateMu.Lock()
		st, seen := s.containerHealth[c.Name]
		if !seen {
			st = &containerHealthState{}
			s.containerHealth[c.Name] = st
		}
		prev := st.lastHealth
		st.lastHealth = health
		if health == "unhealthy" && prev != "unhealthy" {
			if st.unhealthySince.IsZero() {
				st.unhealthySince = now
			}
			st.recentEdges = append(st.recentEdges, now)
			cutoff := now.Add(-healthFlapWindow)
			trimmed := st.recentEdges[:0]
			for _, t := range st.recentEdges {
				if t.After(cutoff) {
					trimmed = append(trimmed, t)
				}
			}
			st.recentEdges = trimmed
		}
		flapping := len(st.recentEdges) >= healthFlapThreshold
		alreadyFlapAlerted := st.flapAlertSent
		if flapping && !alreadyFlapAlerted {
			st.flapAlertSent = true
			st.mutedUntil = now.Add(healthFlapMuteFor)
		}
		if !flapping {
			st.flapAlertSent = false // streak aged out — a future burst gets its own flap alert
		}
		muted := now.Before(st.mutedUntil)
		downFor := ""
		if prev == "unhealthy" && health != "unhealthy" && !st.unhealthySince.IsZero() {
			downFor = formatDuration(now.Sub(st.unhealthySince))
			st.unhealthySince = time.Time{}
		}
		s.stateMu.Unlock()

		// Only the seen&&!first-observation case below ever fires an
		// alert — !seen (this container's very first poll since
		// PrestoBack started) deliberately updates state above and then
		// falls through to here doing nothing further, so a restart of
		// PrestoBack itself never manufactures a false transition alert
		// for whatever state everything already happened to be in.
		if !seen {
			continue
		}

		switch {
		case flapping && !alreadyFlapAlerted:
			s.sendContainerFlappingAlert(c.Name, len(st.recentEdges))
		case health == "unhealthy" && prev != "unhealthy" && !muted:
			s.sendContainerUnhealthyAlert(c.Name)
		case prev == "unhealthy" && health != "unhealthy" && health != "":
			// Recovery is reported even if the container was muted while
			// down — muting silences repeated unhealthy noise, not the
			// one-line "it's back" that actually matters most.
			s.sendContainerHealthyAgain(c.Name, downFor)
		}
	}
}

func (s *Server) sendContainerUnhealthyAlert(name string) {
	detail, _ := backup.InspectContainerHealth(name)
	logs, _ := backup.ContainerLogTail(name, healthLogTailLines)

	// Logged to History unconditionally — independent of the
	// OnContainerHealth notify toggle below, which only governs outbound
	// Telegram/Discord/etc alerts. The History page (and anything else
	// reading /api/history) should show these transitions regardless of
	// whether the user has chat notifications turned on for them.
	s.hist.Append(history.Entry{Event: history.EventContainerUnhealthy, AppID: name, AppName: name, Detail: detail.LastOutput})

	nc := s.cfg.GetNotify()
	if !nc.OnContainerHealth {
		return
	}
	text := formatHealthAlertText(name, detail.LastOutput, logs)

	if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
		tgCfg := notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}
		var err error
		// Telegram caps callback_data at 64 bytes total. "health:restart:"
		// is the longest prefix here at 15 bytes, leaving 49 for the name
		// — comfortably enough for every container name in a normal
		// compose setup, but Compose allows names well past that (a long
		// project prefix + service name + replica index adds up fast).
		// Rather than risk the WHOLE alert failing to send over a button
		// array Telegram rejects, buttons are simply left off for a name
		// that doesn't fit — the alert itself (the part that actually
		// matters) still goes out either way.
		if len(name) <= 45 {
			btns := []notify.ButtonAction{
				{Label: "🔄 Restart " + truncateForTelegram(name, 20), Data: "health:restart:" + name},
				{Label: "📄 More logs", Data: "health:logs:" + name},
				{Label: "🔇 Mute 30m", Data: "health:mute:" + name},
			}
			err = notify.SendRawWithButtons(tgCfg, text, btns)
		} else {
			err = notify.SendRaw(tgCfg, text)
		}
		if err != nil {
			// MarkdownV2 can choke on unescaped content inside raw docker
			// log/healthcheck output despite EscapeMD — same fallback
			// posture the update-check/self-update paths already use for
			// this exact failure mode.
			_ = notify.SendRawPlain(tgCfg, stripMDEscapes(text))
		}
	}
	if nc.DiscordEnabled && nc.DiscordURL != "" {
		desc := detail.LastOutput
		if logs != "" {
			desc += "\n\n**Last logs:**\n```\n" + truncateForDiscord(logs) + "\n```"
		}
		_ = notify.SendDiscordEmbed(nc.DiscordURL, "🩺 "+name+" turned UNHEALTHY", desc, 0xe74c3c)
	}
	if nc.NtfyEnabled && nc.NtfyURL != "" {
		_ = notify.SendNtfyWebhook(nc.NtfyURL, notify.Event{Kind: "container_unhealthy", AppName: name, Detail: detail.LastOutput, IsError: true})
	}
	if nc.WebhookEnabled && nc.WebhookURL != "" {
		_ = notify.SendGenericWebhook(nc.WebhookURL, notify.Event{Kind: "container_unhealthy", AppName: name, Detail: detail.LastOutput, IsError: true})
	}
}

func (s *Server) sendContainerFlappingAlert(name string, edgeCount int) {
	s.hist.Append(history.Entry{
		Event: history.EventContainerFlapping, AppID: name, AppName: name,
		Detail: fmt.Sprintf("unhealthy %d times in the last %s", edgeCount, formatDuration(healthFlapWindow)),
	})

	nc := s.cfg.GetNotify()
	if !nc.OnContainerHealth {
		return
	}
	msg := fmt.Sprintf("⚠️ *%s is flapping* — unhealthy %d times in the last %s\\. Muting further alerts for this container for %s\\.",
		notify.EscapeMD(name), edgeCount, notify.EscapeMD(formatDuration(healthFlapWindow)), notify.EscapeMD(formatDuration(healthFlapMuteFor)))
	if nc.TelegramEnabled && nc.TelegramToken != "" && nc.TelegramChatID != "" {
		_ = notify.SendRaw(notify.TelegramConfig{Token: nc.TelegramToken, ChatID: nc.TelegramChatID}, msg)
	}
	if nc.DiscordEnabled && nc.DiscordURL != "" {
		_ = notify.SendDiscordEmbed(nc.DiscordURL, "⚠️ "+name+" is flapping",
			fmt.Sprintf("Unhealthy %d times in the last %s — muting further alerts for %s.", edgeCount, formatDuration(healthFlapWindow), formatDuration(healthFlapMuteFor)), 0xf5a524)
	}
}

func (s *Server) sendContainerHealthyAgain(name, downFor string) {
	detail := name + " is healthy again"
	if downFor != "" {
		detail = fmt.Sprintf("%s is healthy again — was down for %s", name, downFor)
	}
	s.hist.Append(history.Entry{Event: history.EventContainerHealthy, AppID: name, AppName: name, Detail: detail})
	s.dispatchNotify(notify.Event{Kind: "container_healthy", AppName: name, Detail: detail})
}

// formatHealthAlertText builds the docksentry-style single-block message:
// a 🩺-prefixed headline, the healthcheck's own last-probe output (if
// Docker recorded one), and a fenced code block of recent logs. All
// user/container-controlled content (name, probe output, log lines) goes
// through EscapeMD — this is externally-produced text (an app's own
// error output), never something to trust as pre-safe.
func formatHealthAlertText(name, healthcheckOutput, logs string) string {
	var b strings.Builder
	b.WriteString("🩺 *")
	b.WriteString(notify.EscapeMD(name))
	b.WriteString(" turned UNHEALTHY*\n")
	if healthcheckOutput != "" {
		b.WriteString("Healthcheck:\n```\n")
		b.WriteString(notify.EscapeMD(truncateForTelegram(healthcheckOutput, 500)))
		b.WriteString("\n```\n")
	}
	if logs != "" {
		b.WriteString("Last logs:\n```\n")
		b.WriteString(notify.EscapeMD(truncateForTelegram(logs, 2500)))
		b.WriteString("\n```")
	}
	return b.String()
}

func truncateForTelegram(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-max:] // keep the TAIL — the most recent lines are the ones that explain "why unhealthy right now", same reasoning ContainerLogTail's --tail already applies at the docker-logs level
}

func truncateForDiscord(s string) string { return truncateForTelegram(s, 1800) }

// stripMDEscapes is the same "strip backslash-escapes and retry plain"
// fallback shape used elsewhere for a MarkdownV2 send that Telegram
// rejected — good enough for a fallback path that only exists to
// guarantee the alert arrives AT ALL, not to preserve formatting.
func stripMDEscapes(s string) string {
	return strings.NewReplacer(
		"\\_", "_", "\\*", "*", "\\[", "[", "\\]", "]", "\\(", "(", "\\)", ")",
		"\\~", "~", "\\`", "`", "\\>", ">", "\\#", "#", "\\+", "+", "\\-", "-",
		"\\=", "=", "\\|", "|", "\\{", "{", "\\}", "}", "\\.", ".", "\\!", "!",
	).Replace(s)
}

// ── /health command ──────────────────────────────────────────────────────

func (s *Server) handleHealthCommand(tgCfg notify.TelegramConfig) {
	containers := backup.RunningContainers()
	var unhealthy, starting []backup.ContainerInfo
	for _, c := range containers {
		health, _ := backup.HealthAndExitFromStatus(c.RawStatus)
		switch health {
		case "unhealthy":
			unhealthy = append(unhealthy, c)
		case "starting":
			starting = append(starting, c)
		}
	}
	if len(unhealthy) == 0 && len(starting) == 0 {
		_ = notify.SendRaw(tgCfg, "💚 Everything with a healthcheck is currently healthy\\.")
		return
	}
	var b strings.Builder
	b.WriteString("🩺 *Container health*\n\n")
	for _, c := range unhealthy {
		s.stateMu.Lock()
		st := s.containerHealth[c.Name]
		s.stateMu.Unlock()
		muted := ""
		if st != nil && time.Now().Before(st.mutedUntil) {
			muted = " 🔇"
		}
		b.WriteString(fmt.Sprintf("❌ `%s` — unhealthy%s\n", notify.EscapeMD(c.Name), muted))
	}
	for _, c := range starting {
		b.WriteString(fmt.Sprintf("⏳ `%s` — still starting\n", notify.EscapeMD(c.Name)))
	}
	_ = notify.SendRaw(tgCfg, b.String())
}

// ── Telegram callback actions (Restart / More logs / Mute) ─────────────────

// handleHealthCallback dispatches "health:<action>:<containerName>"
// callback_data — see handleTelegramCallback's "case \"health\":" branch.
// The caller has already answered the callback query (spinner) and
// verified the request came from the configured chat, same as every
// other callback branch.
func (s *Server) handleHealthCallback(tgCfg notify.TelegramConfig, parts []string) {
	if len(parts) < 3 {
		return
	}
	action, name := parts[1], parts[2]
	switch action {
	case "restart":
		containers := backup.ContainersByName([]string{name})
		if len(containers) == 0 {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Container not found: `%s`", notify.EscapeMD(name)))
			return
		}
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("🔄 Restarting `%s`\\.\\.\\.", notify.EscapeMD(name)))
		go func() {
			emit := func(string) {}
			if err := backup.RestartOneContainer(containers[0], emit); err != nil {
				_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Restart failed for `%s`: `%s`", notify.EscapeMD(name), notify.EscapeMD(err.Error())))
				return
			}
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("✅ `%s` restarted", notify.EscapeMD(name)))
		}()

	case "logs":
		logs, err := backup.ContainerLogTail(name, healthMoreLogLines)
		if err != nil && logs == "" {
			_ = notify.SendRaw(tgCfg, fmt.Sprintf("❌ Could not read logs for `%s`: `%s`", notify.EscapeMD(name), notify.EscapeMD(err.Error())))
			return
		}
		text := fmt.Sprintf("📄 *Last %d lines — %s*\n```\n%s\n```", healthMoreLogLines, notify.EscapeMD(name), notify.EscapeMD(truncateForTelegram(logs, 3500)))
		if err := notify.SendRaw(tgCfg, text); err != nil {
			_ = notify.SendRawPlain(tgCfg, stripMDEscapes(text))
		}

	case "mute":
		s.stateMu.Lock()
		st, ok := s.containerHealth[name]
		if !ok {
			st = &containerHealthState{}
			s.containerHealth[name] = st
		}
		st.mutedUntil = time.Now().Add(healthMuteDuration)
		s.stateMu.Unlock()
		_ = notify.SendRaw(tgCfg, fmt.Sprintf("🔇 Muted alerts for `%s` for %s\\. Recovery \\(\"healthy again\"\\) still gets reported\\.",
			notify.EscapeMD(name), notify.EscapeMD(formatDuration(healthMuteDuration))))
	}
}
