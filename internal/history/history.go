package history

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type EventType string

const (
	EventBackupSuccess  EventType = "backup_success"
	EventBackupFail     EventType = "backup_fail"
	EventRestoreSuccess EventType = "restore_success"
	EventRestoreFail    EventType = "restore_fail"
	EventPushSuccess    EventType = "push_success"
	EventPushFail       EventType = "push_fail"
)

type Entry struct {
	Time      time.Time `json:"time"`
	Event     EventType `json:"event"`
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	Detail    string    `json:"detail"`   // backup ID, error message, etc.
	SizeBytes int64     `json:"size_bytes,omitempty"`
	DurationMs int64   `json:"duration_ms,omitempty"`
}

type Log struct {
	path string
	mu   sync.Mutex
	entries []Entry
}

const maxEntries = 500

func Load(path string) (*Log, error) {
	l := &Log{path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(data, &l.entries)
	return l, nil
}

func (l *Log) Append(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.entries = append([]Entry{e}, l.entries...) // newest first
	if len(l.entries) > maxEntries {
		l.entries = l.entries[:maxEntries]
	}
	data, _ := json.MarshalIndent(l.entries, "", "  ")
	_ = os.WriteFile(l.path, data, 0644)
}

func (l *Log) List(limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.entries) {
		limit = len(l.entries)
	}
	out := make([]Entry, limit)
	copy(out, l.entries[:limit])
	return out
}
