package oauthserver

import (
	"sync"
	"time"
)

// rateWindow counts events per key in a fixed window. It is in-process: with
// several replicas each one allows the full budget.
type rateWindow struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	start  time.Time
	counts map[string]int
}

func newRateWindow(limit int, window time.Duration, now func() time.Time) *rateWindow {
	return &rateWindow{limit: limit, window: window, now: now, counts: map[string]int{}}
}

// allow records an event for key and reports whether it is within the limit.
func (w *rateWindow) allow(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if now := w.now(); now.Sub(w.start) >= w.window {
		w.start = now
		clear(w.counts)
	}

	if w.counts[key] >= w.limit {
		return false
	}

	w.counts[key]++

	return true
}
