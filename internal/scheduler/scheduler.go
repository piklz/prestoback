package scheduler

// scheduler.go — minimal cron scheduler for PrestoBack.
// Each job has an ID, a cron expression, and a function to run.
// Jobs are upserted (add-or-replace) so syncing app schedules is idempotent.

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Job is a scheduled task.
type Job struct {
	ID       string
	CronExpr string
	Fn       func()
}

// entry is an internal job with its next run time.
type entry struct {
	Job
	next time.Time
}

// NextRunInfo is returned by NextRuns for display in the UI.
type NextRunInfo struct {
	AppID   string    `json:"app_id"`
	NextRun time.Time `json:"next_run"`
}

// Scheduler runs jobs on cron schedules.
type Scheduler struct {
	mu      sync.Mutex
	jobs    map[string]*entry
	stop    chan struct{}
	running bool
}

// New creates and starts a Scheduler.
func New() *Scheduler {
	s := &Scheduler{
		jobs: make(map[string]*entry),
		stop: make(chan struct{}),
	}
	go s.loop()
	return s
}

// Upsert adds or replaces a job. The next run time is calculated immediately.
func (s *Scheduler) Upsert(j Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := nextAfter(j.CronExpr, time.Now())
	s.jobs[j.ID] = &entry{Job: j, next: next}
	log.Printf("[scheduler] upserted %s — next run: %s", j.ID, next.Format(time.RFC3339))
}

// Remove cancels a job.
func (s *Scheduler) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, id)
}

// NextRuns returns the next scheduled run time for every active job.
func (s *Scheduler) NextRuns() []NextRunInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]NextRunInfo, 0, len(s.jobs))
	for _, e := range s.jobs {
		out = append(out, NextRunInfo{AppID: e.ID, NextRun: e.next})
	}
	return out
}

// Stop shuts down the scheduler loop.
func (s *Scheduler) Stop() {
	close(s.stop)
}

func (s *Scheduler) loop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			var toRun []*entry
			for _, e := range s.jobs {
				if now.After(e.next) || now.Equal(e.next) {
					toRun = append(toRun, e)
					e.next = nextAfter(e.CronExpr, now)
				}
			}
			s.mu.Unlock()
			for _, e := range toRun {
				log.Printf("[scheduler] firing %s", e.ID)
				go e.Fn()
			}
		}
	}
}

// ── Cron parser ───────────────────────────────────────────────────────────────
// Supports standard 5-field cron: minute hour day month weekday
// Fields support: * (any), N (exact), */N (step), N-M (range), N,M (list)

func nextAfter(expr string, from time.Time) time.Time {
	fields := parseCron(expr)
	if fields == nil {
		return from.Add(24 * time.Hour) // fallback: daily
	}
	// Start from next minute
	t := from.Truncate(time.Minute).Add(time.Minute)
	// Search up to 4 years ahead to avoid infinite loops on bad expressions
	limit := from.Add(4 * 365 * 24 * time.Hour)
	for t.Before(limit) {
		if !fields.month.match(int(t.Month())) {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !fields.weekday.match(int(t.Weekday())) || !fields.day.match(t.Day()) {
			t = t.Add(24 * time.Hour).Truncate(24 * time.Hour)
			continue
		}
		if !fields.hour.match(t.Hour()) {
			t = t.Add(time.Hour).Truncate(time.Hour)
			continue
		}
		if !fields.minute.match(t.Minute()) {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return from.Add(24 * time.Hour)
}

type cronFields struct {
	minute, hour, day, month, weekday cronField
}

type cronField struct {
	values []int
}

func (f cronField) match(v int) bool {
	for _, n := range f.values {
		if n == v {
			return true
		}
	}
	return false
}

func parseCron(expr string) *cronFields {
	parts := splitFields(expr)
	if len(parts) != 5 {
		return nil
	}
	minute := parseField(parts[0], 0, 59)
	hour := parseField(parts[1], 0, 23)
	day := parseField(parts[2], 1, 31)
	month := parseField(parts[3], 1, 12)
	weekday := parseField(parts[4], 0, 6)
	if minute == nil || hour == nil || day == nil || month == nil || weekday == nil {
		return nil
	}
	return &cronFields{*minute, *hour, *day, *month, *weekday}
}

func splitFields(s string) []string {
	var fields []string
	cur := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if cur != "" {
				fields = append(fields, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		fields = append(fields, cur)
	}
	return fields
}

func parseField(s string, min, max int) *cronField {
	if s == "*" {
		vals := make([]int, max-min+1)
		for i := range vals {
			vals[i] = min + i
		}
		return &cronField{vals}
	}
	// */N
	if len(s) > 2 && s[:2] == "*/" {
		step := atoi(s[2:])
		if step <= 0 {
			return nil
		}
		var vals []int
		for i := min; i <= max; i += step {
			vals = append(vals, i)
		}
		return &cronField{vals}
	}
	// Comma-separated list
	var vals []int
	for _, part := range splitComma(s) {
		// Range N-M
		if idx := indexByte(part, '-'); idx >= 0 {
			lo := atoi(part[:idx])
			hi := atoi(part[idx+1:])
			for i := lo; i <= hi; i++ {
				vals = append(vals, clamp(i, min, max))
			}
		} else {
			n := atoi(part)
			vals = append(vals, clamp(n, min, max))
		}
	}
	if len(vals) == 0 {
		return nil
	}
	return &cronField{vals}
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// DescribeCron returns a human-readable description of a cron expression.
// Example: "0 3 * * *" → "Every day at 3:00 AM"
func DescribeCron(expr string) string {
	fields := parseCron(expr)
	if fields == nil {
		return "Invalid cron expression"
	}

	minute := formatCronField(fields.minute, 0, 59)
	hour := formatCronField(fields.hour, 0, 23)
	day := formatCronField(fields.day, 1, 31)
	month := formatCronField(fields.month, 1, 12)
	weekday := formatCronField(fields.weekday, 0, 6)

	// Simple heuristics for common patterns
	isDaily := len(fields.day.values) == 31 && len(fields.month.values) == 12 && len(fields.weekday.values) == 7
	isWeekly := len(fields.weekday.values) < 7
	isMonthly := len(fields.day.values) == 1 && len(fields.month.values) == 12

	if isDaily && len(fields.hour.values) == 1 {
		return fmt.Sprintf("Every day at %s", formatTime(fields.hour.values[0], fields.minute.values[0]))
	}
	if isMonthly && len(fields.hour.values) == 1 {
		return fmt.Sprintf("On day %d every month at %s", fields.day.values[0], formatTime(fields.hour.values[0], fields.minute.values[0]))
	}
	if isWeekly && len(fields.hour.values) == 1 {
		days := formatWeekdays(fields.weekday.values)
		return fmt.Sprintf("%s at %s", days, formatTime(fields.hour.values[0], fields.minute.values[0]))
	}

	// Fallback: show all fields
	return fmt.Sprintf("minute=%s hour=%s day=%s month=%s weekday=%s", minute, hour, day, month, weekday)
}

func formatWeekdays(values []int) string {
	var names []string
	dayNames := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
	for _, v := range values {
		if v >= 0 && v < 7 {
			names = append(names, dayNames[v])
		}
	}
	if len(names) == 7 {
		return "Every day"
	}
	if len(names) == 5 {
		hasWeekend := false
		for _, v := range values {
			if v == 0 || v == 6 {
				hasWeekend = true
				break
			}
		}
		if !hasWeekend {
			return "Every weekday"
		}
	}
	if len(names) <= 2 {
		return "On " + strings.Join(names, " and ")
	}
	return "On " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func formatTime(hour, minute int) string {
	return fmt.Sprintf("%02d:%02d", hour, minute)
}

func formatCronField(f cronField, min, max int) string {
	if len(f.values) == (max - min + 1) {
		return "*"
	}
	if len(f.values) == 1 {
		return fmt.Sprintf("%d", f.values[0])
	}
	return fmt.Sprintf("%d values", len(f.values))
}

// NextRunsForExpr returns the next N run times for a cron expression.
func NextRunsForExpr(expr string, count int, from time.Time) []time.Time {
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100 // safety limit
	}

	var runs []time.Time
	next := from
	for i := 0; i < count; i++ {
		next = nextAfter(expr, next)
		runs = append(runs, next)
	}
	return runs
}
