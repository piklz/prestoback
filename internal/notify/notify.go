package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Event describes what happened — passed to all notifiers.
type Event struct {
	Kind    string // "backup_success", "backup_fail", "restore_success", etc.
	AppName string
	Detail  string // backup ID, error message, archive size, etc.
	IsError bool
	// Force bypasses the per-event on_backup_success/fail-style toggle below
	// (channel-enabled checks — TelegramEnabled, DiscordEnabled, etc. — still
	// apply; Force isn't "ignore whether the user configured Telegram at
	// all"). Set by callers for "large operation" runs: the user shouldn't
	// have to keep the toggle on for every routine backup just to hear about
	// the rare one that took long enough that they probably walked away.
	Force bool
}

func (e Event) Emoji() string {
	if e.IsError {
		return "❌"
	}
	return "✅"
}

func (e Event) Title() string {
	switch e.Kind {
	case "backup_success":
		return "Backup complete"
	case "backup_fail":
		return "Backup failed"
	case "restore_success":
		return "Restore complete"
	case "restore_fail":
		return "Restore failed"
	case "push_success":
		return "Remote push complete"
	case "push_fail":
		return "Remote push failed"
	default:
		return "PrestoBack event"
	}
}

// ── MarkdownV2 helpers ────────────────────────────────────────────────────────

// EscapeMD escapes all characters reserved in Telegram's MarkdownV2 format.
// Exported so bot command handlers in other packages can build safe messages.
// MUST be applied to every user-supplied string (app names, error messages,
// file paths, cron expressions) before embedding in a message. Without it,
// characters like _ * [ ] ( ) ~ ` > # + - = | { } . ! are misinterpreted
// as formatting and cause HTTP 400 from the Telegram API.
func EscapeMD(s string) string {
	reserved := `\_*[]()~` + "`" + `>#+-=|{}.!`
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if strings.ContainsRune(reserved, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeMD is the unexported alias used internally within this package.
func escapeMD(s string) string { return EscapeMD(s) }

// fmtEvent formats a notification event as a safe MarkdownV2 message.
func fmtEvent(ev Event) string {
	return fmt.Sprintf("%s *%s*\n🐳 App: `%s`\n📋 %s",
		ev.Emoji(),
		escapeMD(ev.Title()),
		escapeMD(ev.AppName),
		escapeMD(ev.Detail),
	)
}

// SendRaw sends a pre-formatted MarkdownV2 string directly. Used by bot
// command handlers that build their own message layout.
func SendRaw(cfg TelegramConfig, text string) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	return telegramPost(cfg.Token, "sendMessage", map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     text,
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
	})
}

// SendRawPlain sends a plain text message with no parse_mode. Used as a
// fallback when a MarkdownV2-formatted message fails to send — Docker error
// output can contain Unicode spinner frames and other chars that trip
// Telegram's parser even after EscapeMD.
func SendRawPlain(cfg TelegramConfig, text string) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	return telegramPost(cfg.Token, "sendMessage", map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     text,
		"disable_web_page_preview": true,
	})
}

// ── Telegram ─────────────────────────────────────────────────────────────────

type TelegramConfig struct {
	Token  string
	ChatID string
}

func SendTelegram(cfg TelegramConfig, ev Event) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	return telegramPost(cfg.Token, "sendMessage", map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     fmtEvent(ev),
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
	})
}

// SendTelegramWithButtons sends a message with inline action buttons.
// actions: map of button label -> callback_data
func SendTelegramWithButtons(cfg TelegramConfig, ev Event, actions map[string]string) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	var buttons []map[string]string
	for label, data := range actions {
		buttons = append(buttons, map[string]string{
			"text":          label,
			"callback_data": data,
		})
	}
	return telegramPost(cfg.Token, "sendMessage", map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     fmtEvent(ev),
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{buttons},
		},
	})
}

func telegramPost(token, method string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	resp, err := httpPost(url, "application/json", data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API %d: %s", resp.StatusCode, body)
	}
	return nil
}

// AnswerCallbackQuery clears the spinner on Telegram inline button press.
func AnswerCallbackQuery(token, callbackQueryID, text string) error {
	return telegramPost(token, "answerCallbackQuery", map[string]any{
		"callback_query_id": callbackQueryID,
		"text":              text,
		"show_alert":        false,
	})
}

// ── Webhook (Ntfy, Gotify, Discord, generic) ──────────────────────────────────

func SendWebhook(webhookURL string, ev Event) error {
	if webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}
	if strings.Contains(webhookURL, "discord.com/api/webhooks") {
		return sendDiscord(webhookURL, ev)
	}
	if strings.Contains(webhookURL, "ntfy.sh") || isNtfyURL(webhookURL) {
		return sendNtfy(webhookURL, ev)
	}
	return sendGeneric(webhookURL, ev)
}

// SendDiscordEmbed posts a title + long-form description embed — used for
// update/changelog notifications (release notes or, for a dev-track build,
// commit history — see backup.FetchCommitsSince) where the generic
// Event-based sendDiscord below (one fixed-shape line, built for backup/
// restore results) isn't expressive enough. Exported so internal/api can
// call it directly for self-update and app-update alerts, which aren't
// modeled as Event values.
func SendDiscordEmbed(webhookURL, title, description string, color int) error {
	if webhookURL == "" {
		return fmt.Errorf("discord webhook URL not configured")
	}
	// Discord's embed description hard limit is 4096 chars; leave headroom.
	if len(description) > 4000 {
		description = description[:4000] + "…"
	}
	data, err := json.Marshal(map[string]any{
		"embeds": []map[string]any{{
			"title":       title,
			"description": description,
			"color":       color,
			"footer":      map[string]string{"text": "PrestoBack"},
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		return err
	}
	resp, err := httpPost(webhookURL, "application/json", data)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func sendDiscord(url string, ev Event) error {
	color := 0x3dd68c
	if ev.IsError {
		color = 0xf05f5f
	}
	data, err := json.Marshal(map[string]any{
		"embeds": []map[string]any{{
			"title":       ev.Emoji() + " " + ev.Title(),
			"description": fmt.Sprintf("**%s** — %s", ev.AppName, ev.Detail),
			"color":       color,
			"footer":      map[string]string{"text": "PrestoBack"},
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		return err
	}
	resp, err := httpPost(url, "application/json", data)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func sendNtfy(url string, ev Event) error {
	return sendNtfyWithToken(url, "", ev)
}

func sendNtfyWithToken(url, token string, ev Event) error {
	priority := "default"
	if ev.IsError {
		priority = "high"
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(ev.AppName+": "+ev.Detail))
	if err != nil {
		return err
	}
	req.Header.Set("Title", ev.Emoji()+" "+ev.Title())
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", "whale")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func sendGeneric(url string, ev Event) error {
	data, err := json.Marshal(map[string]any{
		"event":    ev.Kind,
		"app":      ev.AppName,
		"title":    ev.Title(),
		"detail":   ev.Detail,
		"is_error": ev.IsError,
		"time":     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	resp, err := httpPost(url, "application/json", data)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

type Config struct {
	TelegramToken   string
	TelegramChatID  string
	TelegramEnabled bool

	DiscordURL     string
	DiscordEnabled bool

	NtfyURL     string
	NtfyToken   string
	NtfyEnabled bool

	WebhookURL     string
	WebhookEnabled bool

	OnBackupSuccess  bool
	OnBackupFail     bool
	OnRestoreSuccess bool
	OnRestoreFail    bool
}

// Dispatch fires all enabled notification channels for the given event.
// Runs in a single goroutine per event — never blocks the caller.
// A 30-second context deadline covers the whole dispatch to prevent
// a slow/dead remote endpoint from holding the goroutine open indefinitely.
func Dispatch(cfg Config, ev Event) {
	go func() {
		wantsNotify := false
		switch ev.Kind {
		case "backup_success":
			wantsNotify = cfg.OnBackupSuccess
		case "backup_fail":
			wantsNotify = cfg.OnBackupFail
		case "restore_success":
			wantsNotify = cfg.OnRestoreSuccess
		case "restore_fail":
			wantsNotify = cfg.OnRestoreFail
		default:
			wantsNotify = true
		}
		if !ev.Force && !wantsNotify {
			return
		}
		if cfg.TelegramEnabled && cfg.TelegramToken != "" {
			if err := SendTelegram(TelegramConfig{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID}, ev); err != nil {
				log.Printf("[notify] telegram: %v", err)
			}
		}
		if cfg.DiscordEnabled && cfg.DiscordURL != "" {
			if err := sendDiscord(cfg.DiscordURL, ev); err != nil {
				log.Printf("[notify] discord: %v", err)
			}
		}
		if cfg.NtfyEnabled && cfg.NtfyURL != "" {
			if err := sendNtfyWithToken(cfg.NtfyURL, cfg.NtfyToken, ev); err != nil {
				log.Printf("[notify] ntfy: %v", err)
			}
		}
		if cfg.WebhookEnabled && cfg.WebhookURL != "" {
			if err := sendGeneric(cfg.WebhookURL, ev); err != nil {
				log.Printf("[notify] webhook: %v", err)
			}
		}
	}()
}

// ── Telegram bot update polling ───────────────────────────────────────────────

type TelegramUpdate struct {
	UpdateID      int                    `json:"update_id"`
	Message       *TelegramMessage       `json:"message,omitempty"`
	CallbackQuery *TelegramCallbackQuery `json:"callback_query,omitempty"`
}

type TelegramMessage struct {
	MessageID int          `json:"message_id"`
	From      TelegramUser `json:"from"`
	Chat      TelegramChat `json:"chat"`
	Text      string       `json:"text"`
}

type TelegramCallbackQuery struct {
	ID      string          `json:"id"`
	From    TelegramUser    `json:"from"`
	Message TelegramMessage `json:"message"`
	Data    string          `json:"data"`
}

type TelegramUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}
type TelegramChat struct {
	ID int64 `json:"id"`
}

type BotUpdates struct {
	OK     bool             `json:"ok"`
	Result []TelegramUpdate `json:"result"`
}

// BotCommand describes a bot command for Telegram's autocomplete picker.
// Command must be lowercase, no leading slash (Telegram adds it).
// Description is shown in the picker; max 256 characters.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// ButtonAction is one inline keyboard button: a display label and callback payload.
// Used with SendRawWithButtons for ordered, readable button menus.
type ButtonAction struct {
	Label string // text shown on the button
	Data  string // callback_data sent when tapped
}

// SendRawWithButtons sends a pre-formatted MarkdownV2 message with inline buttons.
// Each ButtonAction is placed on its own row so full names are always visible —
// this avoids the truncation that occurs when all buttons share a single row.
func SendRawWithButtons(cfg TelegramConfig, text string, actions []ButtonAction) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	rows := make([][]map[string]string, len(actions))
	for i, a := range actions {
		rows[i] = []map[string]string{{"text": a.Label, "callback_data": a.Data}}
	}
	return telegramPost(cfg.Token, "sendMessage", map[string]any{
		"chat_id":                  cfg.ChatID,
		"text":                     text,
		"parse_mode":               "MarkdownV2",
		"disable_web_page_preview": true,
		"reply_markup": map[string]any{
			"inline_keyboard": rows,
		},
	})
}

// SetMyCommands registers the bot's full command list with Telegram so the
// "/" autocomplete picker displays all available commands with descriptions.
// Call once on startup after confirming the token is valid.
func SetMyCommands(token string, commands []BotCommand) error {
	if token == "" {
		return fmt.Errorf("telegram token not configured")
	}
	return telegramPost(token, "setMyCommands", map[string]any{
		"commands": commands,
	})
}

func GetUpdates(token string, offset int) ([]TelegramUpdate, error) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=10", token, offset)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r BotUpdates
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Result, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func httpPost(url, contentType string, body []byte) (*http.Response, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Post(url, contentType, bytes.NewReader(body))
}

func isNtfyURL(url string) bool {
	return !strings.Contains(url, "discord") && !strings.Contains(url, "webhook")
}
