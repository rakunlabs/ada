package ratelimit

import (
	"testing"
	"time"
)

func TestComputeBackoffSaturatesDurationOverflow(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	cfg := Config{
		SoftThreshold: 1,
		BackoffBase:   time.Duration(1 << 62),
	}
	if got := computeBackoff(cfg, 2); got != maxDuration {
		t.Fatalf("overflowed backoff = %v, want saturation %v", got, maxDuration)
	}

	cfg.BackoffMax = 30 * time.Second
	if got := computeBackoff(cfg, 1_000); got != cfg.BackoffMax {
		t.Fatalf("large capped backoff = %v, want %v", got, cfg.BackoffMax)
	}
}

func TestReservationLeaseDurationSaturatesOverflow(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	cfg := Config{
		Window:                maxDuration,
		StoreOperationTimeout: maxDuration,
	}
	if got := reservationLeaseDuration(cfg); got != maxDuration {
		t.Fatalf("reservation lease duration = %v, want saturation %v", got, maxDuration)
	}
}

func TestFormatRetryAfterRoundsUp(t *testing.T) {
	for delay, want := range map[time.Duration]string{
		0:                             "1",
		time.Nanosecond:               "1",
		time.Second:                   "1",
		time.Second + time.Nanosecond: "2",
	} {
		if got := formatRetryAfter(delay); got != want {
			t.Errorf("formatRetryAfter(%v) = %q, want %q", delay, got, want)
		}
	}
}
