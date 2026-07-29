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
	EventPullSuccess    EventType = "pull_success"
	EventPullFail       EventType = "pull_fail"
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

// maxEntries bounds history.json by entry count. maxBytesOnDisk is a second,
// defensive bound by serialized size: 500 short entries is small (well
// under 200KB), but a pathological Detail string (a very long error
// message, for instance) repeated across entries could in principle bloat
// the file well past what the entry count alone suggests. Append enforces
// both — count first (the normal case), then trims further by size if
// still over budget — so history.json can't meaningfully outgrow the data
// directory even in that edge case.
const (
	maxEntries     = 500
	maxBytesOnDisk = 2 * 1024 * 1024 // 2MB — generous for 500 entries of normal size, a hard backstop for abnormal ones
)

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
	// Byte-size backstop: keep dropping the oldest entry until under
	// budget. Only ever engages if entries are running unusually large
	// (long Detail strings) — for normal-sized entries maxEntries alone
	// keeps this well under maxBytesOnDisk and this loop never executes.
	for len(data) > maxBytesOnDisk && len(l.entries) > 1 {
		l.entries = l.entries[:len(l.entries)-1]
		data, _ = json.MarshalIndent(l.entries, "", "  ")
	}
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

// ListPage is List's paginated, filterable sibling — for the History page,
// which was dumping up to 100 entries into the DOM in one unbroken block
// with no way to see more or narrow it down (reported as the panel
// "getting long and large"). Kept separate from List rather than changing
// its signature, since three existing call sites (the dashboard's recent-
// activity widget, and two Telegram commands) depend on its current
// (limit int) shape and have no use for pagination or filtering.
//
// eventFilter is an exact EventType match, or "" for all events. offset/
// limit page through the filtered set, newest-first (entries is already
// stored newest-first). total is the filtered count before pagination, so
// the caller can render "showing X of Y" / decide whether a "load more"
// affordance is still warranted.
func (l *Log) ListPage(limit, offset int, eventFilter string) (out []Entry, total int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var filtered []Entry
	if eventFilter == "" {
		filtered = l.entries
	} else {
		for _, e := range l.entries {
			if string(e.Event) == eventFilter {
				filtered = append(filtered, e)
			}
		}
	}
	total = len(filtered)

	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []Entry{}, total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	out = make([]Entry, end-offset)
	copy(out, filtered[offset:end])
	return out, total
}

// Count returns the total number of stored entries (unfiltered) — the
// History page's "X events" label reads this instead of the length of
// whatever page happened to load, since those aren't the same number once
// pagination is involved.
func (l *Log) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
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
