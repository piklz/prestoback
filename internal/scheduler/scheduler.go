package scheduler

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Job is a function to run on a schedule.
type Job struct {
	ID       string
	CronExpr string
	Fn       func()
}

// Scheduler runs cron jobs. Supports the standard 5-field cron format:
// minute hour day-of-month month day-of-week
// e.g. "0 3 * * *" = 3:00 AM daily
type Scheduler struct {
	mu   sync.Mutex
	jobs map[string]*jobState
	quit chan struct{}
}

type jobState struct {
	Job
	next time.Time
}

func New() *Scheduler {
	return &Scheduler{
		jobs: make(map[string]*jobState),
		quit: make(chan struct{}),
	}
}

func (s *Scheduler) Upsert(j Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := nextTime(j.CronExpr, time.Now())
	s.jobs[j.ID] = &jobState{Job: j, next: next}
	log.Printf("[scheduler] job %s scheduled next at %s", j.ID, next.Format(time.RFC3339))
}

func (s *Scheduler) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, id)
}

func (s *Scheduler) Start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.quit:
				return
			case now := <-ticker.C:
				s.mu.Lock()
				var toRun []*jobState
				for _, js := range s.jobs {
					if !now.Before(js.next) {
						toRun = append(toRun, js)
					}
				}
				// Advance next times before unlocking
				for _, js := range toRun {
					js.next = nextTime(js.CronExpr, now.Add(time.Minute))
				}
				s.mu.Unlock()

				for _, js := range toRun {
					log.Printf("[scheduler] running job %s", js.ID)
					go js.Fn()
				}
			}
		}
	}()
}

func (s *Scheduler) Stop() { close(s.quit) }

// ── Cron parser ───────────────────────────────────────────────────────────────
// Minimal 5-field cron: minute hour dom month dow

func nextTime(expr string, from time.Time) time.Time {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		// Invalid — default to daily at 3am
		return nextTime("0 3 * * *", from)
	}
	// Truncate to minute
	t := from.Truncate(time.Minute).Add(time.Minute)
	// Search up to 1 year ahead
	for i := 0; i < 525960; i++ {
		if matchCron(fields, t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return from.Add(24 * time.Hour) // fallback
}

func matchCron(fields []string, t time.Time) bool {
	return matchField(fields[0], t.Minute(), 0, 59) &&
		matchField(fields[1], t.Hour(), 0, 23) &&
		matchField(fields[2], t.Day(), 1, 31) &&
		matchField(fields[3], int(t.Month()), 1, 12) &&
		matchField(fields[4], int(t.Weekday()), 0, 6)
}

func matchField(field string, val, min, max int) bool {
	if field == "*" {
		return true
	}
	// Handle */n step
	if strings.HasPrefix(field, "*/") {
		n, err := strconv.Atoi(field[2:])
		if err != nil || n <= 0 {
			return false
		}
		return (val-min)%n == 0
	}
	// Handle ranges a-b
	if strings.Contains(field, "-") {
		parts := strings.SplitN(field, "-", 2)
		lo, e1 := strconv.Atoi(parts[0])
		hi, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil {
			return false
		}
		return val >= lo && val <= hi
	}
	// Handle lists a,b,c
	if strings.Contains(field, ",") {
		for _, part := range strings.Split(field, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err == nil && n == val {
				return true
			}
		}
		return false
	}
	// Single value
	n, err := strconv.Atoi(field)
	_ = min; _ = max
	return err == nil && n == val
}
