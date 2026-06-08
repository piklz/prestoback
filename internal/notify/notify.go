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

// ── Telegram ─────────────────────────────────────────────────────────────────

type TelegramConfig struct {
	Token  string
	ChatID string
}

func SendTelegram(cfg TelegramConfig, ev Event) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	text := fmt.Sprintf("%s *%s*\n🐳 App: `%s`\n📋 %s",
		ev.Emoji(), ev.Title(), ev.AppName, ev.Detail)

	payload := map[string]any{
		"chat_id":    cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	return telegramPost(cfg.Token, "sendMessage", payload)
}

// SendTelegramWithButtons sends a message with inline action buttons.
// actions: map of button label -> callback_data
func SendTelegramWithButtons(cfg TelegramConfig, ev Event, actions map[string]string) error {
	if cfg.Token == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	text := fmt.Sprintf("%s *%s*\n🐳 App: `%s`\n📋 %s",
		ev.Emoji(), ev.Title(), ev.AppName, ev.Detail)

	var buttons []map[string]string
	for label, data := range actions {
		buttons = append(buttons, map[string]string{
			"text":          label,
			"callback_data": data,
		})
	}

	payload := map[string]any{
		"chat_id":    cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{buttons},
		},
	}
	return telegramPost(cfg.Token, "sendMessage", payload)
}

func telegramPost(token, method string, payload any) error {
	data, _ := json.Marshal(payload)
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

	// Auto-detect Discord by URL shape
	if strings.Contains(webhookURL, "discord.com/api/webhooks") {
		return sendDiscord(webhookURL, ev)
	}
	// Auto-detect Ntfy (no /message path, just domain/topic)
	if strings.Contains(webhookURL, "ntfy.sh") || isNtfyURL(webhookURL) {
		return sendNtfy(webhookURL, ev)
	}
	// Generic JSON POST
	return sendGeneric(webhookURL, ev)
}

func sendDiscord(url string, ev Event) error {
	color := 0x3dd68c // green
	if ev.IsError {
		color = 0xf05f5f // red
	}
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       ev.Emoji() + " " + ev.Title(),
			"description": fmt.Sprintf("**%s** — %s", ev.AppName, ev.Detail),
			"color":       color,
			"footer":      map[string]string{"text": "PrestoBack"},
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}},
	}
	data, _ := json.Marshal(payload)
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
	payload := map[string]any{
		"event":    ev.Kind,
		"app":      ev.AppName,
		"title":    ev.Title(),
		"detail":   ev.Detail,
		"is_error": ev.IsError,
		"time":     time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)
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
// Runs in a goroutine — never blocks the caller.
func Dispatch(cfg Config, ev Event) {
	go func() {
		// Check if this event type is enabled
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
		if !wantsNotify {
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
// Handles incoming commands from the Telegram bot (/status, /backup, /restore, /history)

type TelegramUpdate struct {
	UpdateID      int                    `json:"update_id"`
	Message       *TelegramMessage       `json:"message,omitempty"`
	CallbackQuery *TelegramCallbackQuery `json:"callback_query,omitempty"`
}

type TelegramMessage struct {
	MessageID int            `json:"message_id"`
	From      TelegramUser   `json:"from"`
	Chat      TelegramChat   `json:"chat"`
	Text      string         `json:"text"`
}

type TelegramCallbackQuery struct {
	ID      string         `json:"id"`
	From    TelegramUser   `json:"from"`
	Message TelegramMessage `json:"message"`
	Data    string         `json:"data"`
}

type TelegramUser struct { ID int64 `json:"id"`; Username string `json:"username"` }
type TelegramChat struct { ID int64 `json:"id"` }

type BotUpdates struct {
	OK     bool             `json:"ok"`
	Result []TelegramUpdate `json:"result"`
}

func GetUpdates(token string, offset int) ([]TelegramUpdate, error) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=10", token, offset)
	resp, err := http.Get(url)
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
	// Simple heuristic — no /api/webhooks or /discord in path
	return !strings.Contains(url, "discord") && !strings.Contains(url, "webhook")
}
