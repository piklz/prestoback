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
	Time       time.Time `json:"time"`
	Event      EventType `json:"event"`
	AppID      string    `json:"app_id"`
	AppName    string    `json:"app_name"`
	Detail     string    `json:"detail"` // backup ID, error message, etc.
	SizeBytes  int64     `json:"size_bytes,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
}

type Log struct {
	path    string
	mu      sync.Mutex
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

// AverageThroughput estimates bytes-per-millisecond for a given app and
// event kind (e.g. EventBackupSuccess), averaged across every past entry
// that recorded both SizeBytes and DurationMs. Used to turn a plain byte
// count into a real duration estimate for the large-operation confirm modal
// — a slow remote push and a fast local copy naturally end up with
// different estimates for the same number of bytes, without hardcoding a
// transport-specific constant. ok is false when there's no usable history
// yet (first-ever run) — callers should fall back to a conservative default
// rather than divide by zero.
func (l *Log) AverageThroughput(appID string, kind EventType) (bytesPerMs float64, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var totalBytes, totalMs int64
	for _, e := range l.entries {
		if e.AppID != appID || e.Event != kind {
			continue
		}
		if e.SizeBytes <= 0 || e.DurationMs <= 0 {
			continue
		}
		totalBytes += e.SizeBytes
		totalMs += e.DurationMs
	}
	if totalMs == 0 {
		return 0, false
	}
	return float64(totalBytes) / float64(totalMs), true
}
