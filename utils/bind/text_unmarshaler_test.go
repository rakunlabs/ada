package bind

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

var errInvalidColor = errors.New("invalid color")

type color string

func (c *color) UnmarshalText(text []byte) error {
	switch string(text) {
	case "red", "green":
		*c = color(text)
		return nil
	}
	return errInvalidColor
}

type level int

func (l *level) UnmarshalText(text []byte) error {
	switch string(text) {
	case "low":
		*l = 1
	case "high":
		*l = 2
	default:
		return errors.New("invalid level")
	}
	return nil
}

func TestBindTextUnmarshalerTakesPrecedenceOverKind(t *testing.T) {
	type target struct {
		Color  color    `query:"color"`
		Level  level    `query:"level"`
		Colors []color  `query:"colors"`
		Ptr    *color   `query:"ptr"`
		IP     net.IP   `query:"ip"`
		IPs    []net.IP `query:"ips"`
		HIP    net.IP   `header:"X-IP"`
		PIP    net.IP   `uri:"ip"`
	}

	req, _ := http.NewRequest(http.MethodGet, "/?color=red&level=high&colors=red,green&ptr=green&ip=10.0.0.1&ips=10.0.0.2&ips=::1", nil)
	req.Header.Set("X-IP", "192.168.1.1")
	req.SetPathValue("ip", "127.0.0.1")

	var got target
	if err := Bind(req, &got, WithQuerySeparator(",")); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	if got.Color != "red" || got.Level != 2 || got.Ptr == nil || *got.Ptr != "green" {
		t.Fatalf("unexpected scalar values: %+v", got)
	}
	if len(got.Colors) != 2 || got.Colors[0] != "red" || got.Colors[1] != "green" {
		t.Fatalf("Colors = %v", got.Colors)
	}
	if !got.IP.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("IP = %v", got.IP)
	}
	if len(got.IPs) != 2 || !got.IPs[0].Equal(net.ParseIP("10.0.0.2")) || !got.IPs[1].Equal(net.ParseIP("::1")) {
		t.Fatalf("IPs = %v", got.IPs)
	}
	if !got.HIP.Equal(net.ParseIP("192.168.1.1")) || !got.PIP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("HIP = %v, PIP = %v", got.HIP, got.PIP)
	}
}

func TestBindTextUnmarshalerValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "named string", query: "color=blue"},
		{name: "named int", query: "level=7"},
		{name: "slice element", query: "colors=red&colors=blue"},
		{name: "net.IP", query: "ip=not-an-ip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target struct {
				Color  color   `query:"color"`
				Level  level   `query:"level"`
				Colors []color `query:"colors"`
				IP     net.IP  `query:"ip"`
			}
			req, _ := http.NewRequest(http.MethodGet, "/?"+tt.query, nil)
			if err := Bind(req, &target); err == nil {
				t.Fatalf("Bind accepted invalid value: %+v", target)
			}
		})
	}
}

func TestBindFormTextUnmarshaler(t *testing.T) {
	form := url.Values{"color": {"blue"}}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var target struct {
		Color color `form:"color"`
	}
	if err := Bind(req, &target); !errors.Is(err, errInvalidColor) {
		t.Fatalf("Bind error = %v, want %v", err, errInvalidColor)
	}

	form = url.Values{"ip": {"10.1.2.3"}}
	req, _ = http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var ipTarget struct {
		IP net.IP `form:"ip"`
	}
	if err := Bind(req, &ipTarget); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !ipTarget.IP.Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("IP = %v", ipTarget.IP)
	}
}

type rangedPage int

func (p *rangedPage) UnmarshalText(text []byte) error {
	n, err := strconv.Atoi(string(text))
	if err != nil || n < 1 || n > 100 {
		return fmt.Errorf("page must be 1..100, got %q", text)
	}
	*p = rangedPage(n)
	return nil
}

// TestBindTextUnmarshalerHasNoNumericFallback pins that UnmarshalText is the
// only parser for a type that implements it. Before v0.5.4 int-kinded types
// were parsed with strconv and their UnmarshalText never ran, so range checks
// were skipped and slog.Level accepted numbers but not its own names. Falling
// back to strconv when UnmarshalText fails would bring the skipped validation
// back, so a rejected value must stay an error.
func TestBindTextUnmarshalerHasNoNumericFallback(t *testing.T) {
	type target struct {
		Page  rangedPage `query:"page"`
		Level slog.Level `query:"level"`
	}

	for _, tc := range []struct {
		query   string
		wantErr bool
		check   func(target) bool
	}{
		{"page=5", false, func(g target) bool { return g.Page == 5 }},
		{"page=5000", true, nil},
		{"page=-1", true, nil},
		{"level=WARN", false, func(g target) bool { return g.Level == slog.LevelWarn }},
		{"level=WARN%2B2", false, func(g target) bool { return g.Level == slog.LevelWarn+2 }},
		{"level=4", true, nil},
	} {
		t.Run(tc.query, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/?"+tc.query, nil)

			var got target
			err := Bind(req, &got)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Bind accepted %q: %+v", tc.query, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if !tc.check(got) {
				t.Fatalf("unexpected value: %+v", got)
			}
		})
	}
}
