package issuer_test

import (
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
)

func TestTokenExpiryBoundary(t *testing.T) {
	now := time.Now()
	for _, tt := range []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"zero", time.Time{}, false}, {"before", now.Add(-time.Nanosecond), true},
		{"equal", now, true}, {"after", now.Add(time.Nanosecond), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := (issuer.Token{ExpiresAt: tt.expiry}).ExpiredAt(now); got != tt.want {
				t.Fatalf("expired=%v want=%v", got, tt.want)
			}
		})
	}
}
