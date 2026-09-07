package bind

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type listItem struct {
	Name string `json:"name" query:"name" header:"X-Name" uri:"name"`
}

func TestBindJSONSlice(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []listItem
	}{
		{`[{"name":"one"},{"name":"two"}]`, []listItem{{"one"}, {"two"}}},
		{`[]`, []listItem{}},
		{`null`, nil},
	} {
		t.Run(tc.body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?name=query", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			req.Header.Set("X-Name", "header")
			req.SetPathValue("name", "path")
			got := []listItem{{"old"}}
			if err := Bind(req, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestBindJSONSliceRejectsInvalidInput(t *testing.T) {
	for _, body := range []string{`{"name":"one"}`, `true`, `42`, `"one"`, ``, `[{`, `[] {}`, `[] garbage`} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			var got []listItem
			if err := Bind(req, &got); !errors.Is(err, ErrBinding) {
				t.Fatalf("expected binding error, got %v", err)
			}
		})
	}
}

func TestBindJSONSingleAsSlice(t *testing.T) {
	for _, tc := range []struct {
		body string
		want []listItem
		fail bool
	}{
		{`{"name":"one"}`, []listItem{{"one"}}, false},
		{" \t\r\n{\"name\":\"one\"} \n", []listItem{{"one"}}, false},
		{`[{"name":"one"}]`, []listItem{{"one"}}, false},
		{`[]`, []listItem{}, false},
		{`null`, nil, false},
		{`{} {}`, nil, true},
		{`{} junk`, nil, true},
		{`{"name":42}`, nil, true},
		{`[{`, nil, true},
		{`true`, nil, true},
		{`"one"`, nil, true},
		{``, nil, true},
		{" \n", nil, true},
	} {
		t.Run(tc.body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			got := []listItem{{"old"}}
			err := Bind(req, &got, WithJSONSingleAsSlice(true))
			if tc.fail {
				if !errors.Is(err, ErrBinding) {
					t.Fatalf("expected binding error, got %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
}

func TestBindJSONSliceTypes(t *testing.T) {
	for _, target := range []any{new([]*listItem), new([]map[string]any), new([]any), new([]json.RawMessage)} {
		t.Run(reflect.TypeOf(target).String(), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"one","number":9007199254740993}`))
			req.Header.Set("Content-Type", "application/json")
			if err := Bind(req, target, WithJSONSingleAsSlice(true)); err != nil {
				t.Fatal(err)
			}
			list := reflect.ValueOf(target).Elem()
			if list.Len() != 1 {
				t.Fatalf("expected one element, got %v", target)
			}
			if values, ok := list.Index(0).Interface().(map[string]any); ok {
				if values["number"] != json.Number("9007199254740993") {
					t.Fatalf("number lost precision: %#v", values["number"])
				}
			}
		})
	}
}

func TestBindJSONSliceBodyLimit(t *testing.T) {
	for _, single := range []bool{false, true} {
		for _, unknownLength := range []bool{false, true} {
			for _, body := range []string{`[{"name":"one"}]`, `{"name":"one"}`, strings.Repeat(" ", 32) + `[]`, `[]` + strings.Repeat(" ", 32)} {
				req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if unknownLength {
					req.ContentLength = -1
				}
				var got []listItem
				err := Bind(req, &got, WithJSONSingleAsSlice(single), WithBodyLimit(4))
				if !errors.Is(err, ErrBodyTooLarge) || !errors.Is(err, ErrBinding) {
					t.Fatalf("single=%t unknownLength=%t body=%q: %v", single, unknownLength, body, err)
				}
			}
		}
	}
}

func TestBindJSONSliceContentType(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/xml", "application/x-www-form-urlencoded", "multipart/form-data"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`[]`))
		req.Header.Set("Content-Type", contentType)
		var got []listItem
		if err := Bind(req, &got, WithJSONSingleAsSlice(true)); !errors.Is(err, ErrBinding) {
			t.Fatalf("Content-Type=%q: expected binding error, got %v", contentType, err)
		}
	}
}

func TestBindJSONSingleAsSliceOption(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/?name=query", strings.NewReader(`{"name":"body"}`))
	req.Header.Set("Content-Type", "application/json")
	var item listItem
	if err := Bind(req, &item, WithJSONSingleAsSlice(true)); err != nil || item.Name != "query" {
		t.Fatalf("struct binding changed: %#v, %v", item, err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	var items []listItem
	if err := Bind(req, &items, WithJSONSingleAsSlice(true), WithJSONSingleAsSlice(false)); !errors.Is(err, ErrBinding) {
		t.Fatalf("expected object rejection with option disabled, got %v", err)
	}
}
