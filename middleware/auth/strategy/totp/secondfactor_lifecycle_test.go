package totp

import "testing"

func TestSecondFactorCloseIsIdempotentAndStopsDefaultStore(t *testing.T) {
	sf := NewSecondFactor(Config{}, nil)
	used := sf.used

	if err := sf.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-used.done:
	default:
		t.Fatal("replay-cache janitor did not stop before Close returned")
	}
	if err := sf.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
