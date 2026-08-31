package bind

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ExampleUser demonstrates various struct tags for HTTP request binding
type ExampleUser struct {
	// JSON binding - from request body when Content-Type is application/json
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`

	// Form binding - from form data when Content-Type is application/x-www-form-urlencoded
	FirstName string `form:"first_name"`
	LastName  string `form:"last_name"`
	Age       int    `form:"age"`

	// Query parameter binding - from URL query parameters
	Page     int      `query:"page"`
	PageSize int      `query:"page_size"`
	Tags     []string `query:"tags"` // Supports multiple values: ?tags=go&tags=web
	Active   bool     `query:"active"`

	// Header binding - from HTTP headers
	UserAgent     string `header:"User-Agent"`
	Authorization string `header:"Authorization"`
	ContentType   string `header:"Content-Type"`

	// URI parameter binding - from URL path parameters (depends on router)
	UserID     string `uri:"user_id"`    // e.g., /users/{user_id}
	CategoryID string `param:"category"` // alternative tag name

	// File upload binding - for multipart/form-data
	Avatar    *multipart.FileHeader   `file:"avatar"`
	Documents []*multipart.FileHeader `file:"documents"`

	// Time binding with custom format
	CreatedAt time.Time  `json:"created_at" time_format:"2006-01-02T15:04:05Z07:00"`
	UpdatedAt *time.Time `form:"updated_at" time_format:"2006-01-02"`

	// Pointer fields for optional values
	Bio        *string  `json:"bio,omitempty"`
	ProfilePic *string  `form:"profile_pic"`
	Score      *float64 `query:"score"`

	// Mixed bindings - a field can have multiple tags
	Name string `json:"name" form:"name" query:"name"`

	// Nested struct (for JSON/XML binding)
	Address Address `json:"address" xml:"address"`

	// Slice of primitives
	Hobbies     []string `json:"hobbies" form:"hobbies"`
	LuckyNums   []int    `query:"lucky_nums"`
	Preferences []bool   `form:"preferences"`

	Duration   time.Duration `query:"duration"`
	HugeNumber json.Number   `query:"huge_number"`

	// Custom type with TextUnmarshaler
	CustomField CustomType `query:"custom_field"`
}

func TestBindRejectsNonStructTarget(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/?value=1", nil)
	target := 0

	if err := Bind(req, &target); err == nil {
		t.Fatal("Bind accepted a pointer to a non-struct target")
	}
}

func TestBindRejectsNarrowIntegerOverflow(t *testing.T) {
	tests := []struct {
		name  string
		query string
		bind  func(*http.Request) error
	}{
		{
			name:  "int8 overflow",
			query: "value=128",
			bind: func(req *http.Request) error {
				var target struct {
					Value int8 `query:"value"`
				}
				return Bind(req, &target)
			},
		},
		{
			name:  "int8 underflow",
			query: "value=-129",
			bind: func(req *http.Request) error {
				var target struct {
					Value int8 `query:"value"`
				}
				return Bind(req, &target)
			},
		},
		{
			name:  "uint8 overflow",
			query: "value=256",
			bind: func(req *http.Request) error {
				var target struct {
					Value uint8 `query:"value"`
				}
				return Bind(req, &target)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/?"+tt.query, nil)
			if err := tt.bind(req); err == nil {
				t.Fatal("Bind accepted an out-of-range integer")
			}
		})
	}
}

type CustomType struct {
	Value string
}

type closeTrackingBody struct {
	*strings.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func (c *CustomType) UnmarshalText(text []byte) error {
	c.Value = strings.ToUpper(string(text))
	return nil
}

// Address represents a nested struct
type Address struct {
	Street  string `json:"street" xml:"street"`
	City    string `json:"city" xml:"city"`
	Country string `json:"country" xml:"country"`
	ZipCode string `json:"zip_code" xml:"zip_code"`
}

// SimpleForm demonstrates form-only binding
type SimpleForm struct {
	Name      string `form:"name"`
	Email     string `form:"email"`
	Message   string `form:"message"`
	Subscribe bool   `form:"subscribe"`
}

// APIRequest demonstrates API-style binding with query params and headers
type APIRequest struct {
	// Path parameters
	ResourceID string `uri:"id"`

	// Query parameters
	Filter   string   `query:"filter"`
	Sort     string   `query:"sort"`
	Fields   []string `query:"fields"`
	Page     int      `query:"page"`
	PageSize int      `query:"page_size"`

	// Headers
	APIKey      string `header:"X-API-Key"`
	RequestID   string `header:"X-Request-ID"`
	ContentType string `header:"Content-Type"`
	AcceptLang  string `header:"Accept-Language"`

	// Body (JSON)
	Data map[string]any `json:"data"`
}

// FileUploadRequest demonstrates file upload binding
type FileUploadRequest struct {
	// Regular form fields
	Title       string   `form:"title"`
	Description string   `form:"description"`
	Public      bool     `form:"public"`
	Tags        []string `form:"tags"`

	// File uploads
	MainFile    *multipart.FileHeader   `file:"main_file"`
	Attachments []*multipart.FileHeader `file:"attachments"`

	// Mixed
	UserID string `uri:"user_id" form:"user_id"`
}

// XMLRequest demonstrates XML binding
type XMLRequest struct {
	XMLName xml.Name `xml:"request"`
	Action  string   `xml:"action,attr"`
	Data    XMLData  `xml:"data"`
}

type XMLData struct {
	Title   string `xml:"title"`
	Content string `xml:"content"`
	Author  string `xml:"author"`
}

func TestDefaultBinder_BindJSON(t *testing.T) {
	// Test JSON binding
	jsonData := `{
		"id": 123,
		"username": "johndoe",
		"email": "john@example.com",
		"address": {
			"street": "123 Main St",
			"city": "Anytown",
			"country": "USA",
			"zip_code": "12345"
		},
		"hobbies": ["reading", "gaming"]
	}`

	req, _ := http.NewRequest("POST", "/users", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.ID != 123 {
		t.Errorf("Expected ID 123, got %d", user.ID)
	}

	if user.Username != "johndoe" {
		t.Errorf("Expected username 'johndoe', got %s", user.Username)
	}

	if user.Address.City != "Anytown" {
		t.Errorf("Expected city 'Anytown', got %s", user.Address.City)
	}

	if len(user.Hobbies) != 2 || user.Hobbies[0] != "reading" {
		t.Errorf("Expected hobbies [reading, gaming], got %v", user.Hobbies)
	}
}

func TestDefaultBinder_BindForm(t *testing.T) {
	// Test form binding
	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("age", "30")
	form.Add("hobbies", "reading")
	form.Add("hobbies", "gaming")

	req, _ := http.NewRequest("POST", "/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.FirstName != "John" {
		t.Errorf("Expected first name 'John', got %s", user.FirstName)
	}

	if user.Age != 30 {
		t.Errorf("Expected age 30, got %d", user.Age)
	}

	if len(user.Hobbies) != 2 {
		t.Errorf("Expected 2 hobbies, got %d", len(user.Hobbies))
	}
}

func TestDefaultBinder_BindQuery(t *testing.T) {
	// Test query parameter binding
	req, _ := http.NewRequest("GET", "/users?lucky_nums=10,60&lucky_nums=1,2,3&lucky_nums=99&page=2&page_size=10&tags=go&tags=web&active=true&score=95.5&duration=10s&huge_number=19.94324&custom_field=custom", nil)

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.Page != 2 {
		t.Errorf("Expected page 2, got %d", user.Page)
	}

	if user.PageSize != 10 {
		t.Errorf("Expected page size 10, got %d", user.PageSize)
	}

	if len(user.Tags) != 2 || user.Tags[0] != "go" || user.Tags[1] != "web" {
		t.Errorf("Expected tags [go, web], got %v", user.Tags)
	}

	if len(user.LuckyNums) != 6 || user.LuckyNums[0] != 10 || user.LuckyNums[1] != 60 || user.LuckyNums[2] != 1 || user.LuckyNums[3] != 2 || user.LuckyNums[4] != 3 || user.LuckyNums[5] != 99 {
		t.Errorf("Expected lucky numbers [10, 60, 1, 2, 3, 99], got %v", user.LuckyNums)
	}

	if user.Duration != 10*time.Second {
		t.Errorf("Expected duration 10s, got %v", user.Duration)
	}

	if user.HugeNumber != "19.94324" {
		t.Errorf("Expected huge number '19.94324', got %v", user.HugeNumber)
	}

	if !user.Active {
		t.Errorf("Expected active to be true")
	}

	if user.Score == nil || *user.Score != 95.5 {
		t.Errorf("Expected score 95.5, got %v", user.Score)
	}

	if user.CustomField.Value != "CUSTOM" {
		t.Errorf("Expected custom field 'CUSTOM', got %s", user.CustomField.Value)
	}
}

func TestDefaultBinder_BindHeaders(t *testing.T) {
	// Test header binding
	req, _ := http.NewRequest("GET", "/users", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Content-Type", "application/json")

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.UserAgent != "TestAgent/1.0" {
		t.Errorf("Expected User-Agent 'TestAgent/1.0', got %s", user.UserAgent)
	}

	if user.Authorization != "Bearer token123" {
		t.Errorf("Expected Authorization 'Bearer token123', got %s", user.Authorization)
	}
}

func TestDefaultBinder_BindMultipartForm(t *testing.T) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add form fields
	if err := writer.WriteField("title", "Test Upload"); err != nil {
		t.Fatalf("write title field: %v", err)
	}
	if err := writer.WriteField("description", "Test file upload"); err != nil {
		t.Fatalf("write description field: %v", err)
	}
	if err := writer.WriteField("public", "true"); err != nil {
		t.Fatalf("write public field: %v", err)
	}
	if err := writer.WriteField("tags", "test"); err != nil {
		t.Fatalf("write first tag field: %v", err)
	}
	if err := writer.WriteField("tags", "upload"); err != nil {
		t.Fatalf("write second tag field: %v", err)
	}

	// Add file
	fileWriter, err := writer.CreateFormFile("main_file", "test.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fileWriter.Write([]byte("test file content")); err != nil {
		t.Fatalf("write form file: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, _ := http.NewRequest("POST", "/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	var upload FileUploadRequest
	err = Bind(req, &upload)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if upload.Title != "Test Upload" {
		t.Errorf("Expected title 'Test Upload', got %s", upload.Title)
	}

	if !upload.Public {
		t.Errorf("Expected public to be true")
	}

	if len(upload.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(upload.Tags))
	}

	if upload.MainFile == nil {
		t.Errorf("Expected main file to be uploaded")
	} else if upload.MainFile.Filename != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got %s", upload.MainFile.Filename)
	}
}

func TestDefaultBinder_BindXML(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
	<request action="create">
		<data>
			<title>Test Title</title>
			<content>Test Content</content>
			<author>Test Author</author>
		</data>
	</request>`

	req, _ := http.NewRequest("POST", "/xml", strings.NewReader(xmlData))
	req.Header.Set("Content-Type", "application/xml")

	var xmlReq XMLRequest
	err := Bind(req, &xmlReq)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if xmlReq.Action != "create" {
		t.Errorf("Expected action 'create', got %s", xmlReq.Action)
	}

	if xmlReq.Data.Title != "Test Title" {
		t.Errorf("Expected title 'Test Title', got %s", xmlReq.Data.Title)
	}
}

func TestDefaultBinder_BindTimeFields(t *testing.T) {
	// Test time binding with custom format
	form := url.Values{}
	form.Add("updated_at", "2023-12-25")

	req, _ := http.NewRequest("POST", "/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expected := time.Date(2023, 12, 25, 0, 0, 0, 0, time.UTC)
	if user.UpdatedAt == nil {
		t.Fatalf("Expected updated_at to be set")
	}
	if !user.UpdatedAt.Equal(expected) {
		t.Errorf("Expected updated_at %v, got %v", expected, user.UpdatedAt)
	}
}

func TestDefaultBinder_MixedBinding(t *testing.T) {
	// Test mixed binding: JSON body + query params + headers
	jsonData := `{"id": 123, "username": "johndoe"}`

	req, _ := http.NewRequest("POST", "/users?page=1&active=true", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent/1.0")

	var user ExampleUser
	err := Bind(req, &user)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check JSON binding
	if user.ID != 123 {
		t.Errorf("Expected ID 123, got %d", user.ID)
	}

	// Check query binding
	if user.Page != 1 {
		t.Errorf("Expected page 1, got %d", user.Page)
	}

	if !user.Active {
		t.Errorf("Expected active to be true")
	}

	// Check header binding
	if user.UserAgent != "TestAgent/1.0" {
		t.Errorf("Expected User-Agent 'TestAgent/1.0', got %s", user.UserAgent)
	}
}

func TestDefaultBinder_ErrorCases(t *testing.T) {
	// Test nil request
	var user ExampleUser
	err := Bind(nil, &user)
	if err == nil {
		t.Error("Expected error for nil request")
	}

	// Test nil target
	req, _ := http.NewRequest("GET", "/", nil)
	err = Bind(req, nil)
	if err == nil {
		t.Error("Expected error for nil target")
	}

	// Test non-pointer target
	err = Bind(req, user)
	if err == nil {
		t.Error("Expected error for non-pointer target")
	}

	// Test invalid JSON
	req, _ = http.NewRequest("POST", "/", strings.NewReader(`{"invalid": json`))
	req.Header.Set("Content-Type", "application/json")
	err = Bind(req, &user)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}

	// Test invalid form data parsing
	req, _ = http.NewRequest("POST", "/", strings.NewReader("age=notanumber"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = Bind(req, &user)
	if err == nil {
		t.Error("Expected error for invalid form data")
	}
}

func TestBindContentTypeParsing(t *testing.T) {
	type payload struct {
		Value string `json:"value" xml:"value"`
	}

	t.Run("parameters", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"bound"}`))
		req.Header.Set("Content-Type", "Application/JSON; Charset=UTF-8")

		var target payload
		if err := Bind(req, &target); err != nil {
			t.Fatalf("Bind returned an error: %v", err)
		}
		if target.Value != "bound" {
			t.Fatalf("expected parsed media type to bind JSON, got %q", target.Value)
		}
	})

	for _, contentType := range []string{"application/json-evil", "application/xml-evil", "text/xml-evil"} {
		t.Run("deceptive "+contentType, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"body"}`))
			req.Header.Set("Content-Type", contentType)

			target := payload{Value: "unchanged"}
			if err := Bind(req, &target); err != nil {
				t.Fatalf("Bind returned an error: %v", err)
			}
			if target.Value != "unchanged" {
				t.Fatalf("deceptive media type %q was treated as supported", contentType)
			}
		})
	}

	t.Run("malformed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"body"}`))
		req.Header.Set("Content-Type", "application/json; charset")

		var target payload
		err := Bind(req, &target)
		if !errors.Is(err, ErrBinding) {
			t.Fatalf("expected malformed media type to wrap ErrBinding, got %v", err)
		}
	})
}

func TestBindRejectsTrailingBodyData(t *testing.T) {
	type payload struct {
		Value string `json:"value" xml:"value"`
	}

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "multiple JSON values", contentType: "application/json", body: `{"value":"first"} {"value":"second"}`},
		{name: "trailing JSON data", contentType: "application/json", body: `{"value":"first"} trailing`},
		{name: "multiple XML values", contentType: "application/xml", body: `<payload><value>first</value></payload><payload><value>second</value></payload>`},
		{name: "trailing XML data", contentType: "application/xml", body: `<payload><value>first</value></payload>trailing`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.ContentLength = -1

			var target payload
			err := Bind(req, &target)
			if !errors.Is(err, ErrBinding) {
				t.Fatalf("expected trailing body data to wrap ErrBinding, got %v", err)
			}
		})
	}

	for _, tt := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "JSON whitespace", contentType: "application/json", body: "{\"value\":\"bound\"}\n\t "},
		{name: "XML whitespace", contentType: "application/xml", body: "<payload><value>bound</value></payload>\n\t "},
		{name: "XML comment", contentType: "application/xml", body: "<payload><value>bound</value></payload><!-- trailing comment -->"},
		{name: "XML processing instruction", contentType: "application/xml", body: "<payload><value>bound</value></payload><?audit complete?>"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			var target payload
			if err := Bind(req, &target); err != nil {
				t.Fatalf("expected trailing whitespace to be accepted, got %v", err)
			}
			if target.Value != "bound" {
				t.Fatalf("expected body to bind, got %q", target.Value)
			}
		})
	}
}

func TestBindBodyLimit(t *testing.T) {
	type payload struct {
		Value string `json:"value" xml:"value"`
	}

	for _, tt := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "JSON", contentType: "application/json", body: `{"value":"too long"}`},
		{name: "XML", contentType: "application/xml", body: `<payload><value>too long</value></payload>`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.ContentLength = -1

			var target payload
			err := Bind(req, &target, WithBodyLimit(int64(len(tt.body)-1)))
			if !errors.Is(err, ErrBinding) {
				t.Fatalf("expected oversized body to wrap ErrBinding, got %v", err)
			}
		})
	}

	t.Run("custom exact limit", func(t *testing.T) {
		body := `{"value":"accepted"}`
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1

		var target payload
		if err := Bind(req, &target, WithBodyLimit(int64(len(body)))); err != nil {
			t.Fatalf("expected a body at the custom limit to be accepted, got %v", err)
		}
		if target.Value != "accepted" {
			t.Fatalf("expected custom-limit body to bind, got %q", target.Value)
		}
	})

	t.Run("trailing whitespace counts toward limit", func(t *testing.T) {
		value := `{"value":"bound"}`
		body := value + strings.Repeat(" ", 10)
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1

		var target payload
		err := Bind(req, &target, WithBodyLimit(int64(len(value))))
		if !errors.Is(err, ErrBinding) {
			t.Fatalf("expected trailing whitespace to count toward the body limit, got %v", err)
		}
	})

	largeValue := strings.Repeat("x", 4<<20)
	largeBody := `{"value":"` + largeValue + `"}`

	// DefaultBodyLimit is 0: a limit that only covered Bind was a trap, so the
	// limit now comes from the bodylimit middleware and Bind has none of its
	// own unless a caller asks for one.
	t.Run("no limit by default", func(t *testing.T) {
		if DefaultBodyLimit != 0 {
			t.Fatalf("DefaultBodyLimit = %d, want 0 (disabled)", DefaultBodyLimit)
		}

		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")

		var target payload
		if err := Bind(req, &target); err != nil {
			t.Fatalf("expected the default to accept a %d byte body, got %v", len(largeBody), err)
		}
		if target.Value != largeValue {
			t.Fatalf("default-limit body did not bind completely: got %d bytes, want %d", len(target.Value), len(largeValue))
		}
	})

	t.Run("disabled limit", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")

		var target payload
		if err := Bind(req, &target, WithBodyLimit(0)); err != nil {
			t.Fatalf("expected disabled body limit to accept the body, got %v", err)
		}
		if target.Value != largeValue {
			t.Fatalf("disabled-limit body did not bind completely: got %d bytes", len(target.Value))
		}
	})
}

func TestBindBodyLimitForm(t *testing.T) {
	body := url.Values{"value": {strings.Repeat("x", 128)}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1

	var target struct {
		Value string `form:"value"`
	}
	err := Bind(req, &target, WithBodyLimit(int64(len(body)-1)))
	if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
		t.Fatalf("expected oversized form to return the body-limit binding error, got %v", err)
	}
}

func TestBindBodyLimitMultipartAfterParseForm(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("value", "bound"); err != nil {
		t.Fatalf("write multipart field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	contentType := writer.FormDataContentType()

	for _, tt := range []struct {
		name    string
		limit   int64
		wantErr bool
	}{
		{name: "exact limit succeeds", limit: int64(body.Len())},
		{name: "oversized body is measured", limit: int64(body.Len() - 1), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
			req.Header.Set("Content-Type", contentType)
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			if err := req.ParseForm(); err != nil {
				t.Fatalf("pre-parse form: %v", err)
			}
			if req.Form == nil || req.PostForm == nil {
				t.Fatal("ParseForm did not initialize Form and PostForm")
			}
			if req.MultipartForm != nil {
				t.Fatal("ParseForm unexpectedly parsed the multipart body")
			}
			t.Cleanup(func() {
				if req.MultipartForm != nil {
					if err := req.MultipartForm.RemoveAll(); err != nil {
						t.Errorf("remove multipart form: %v", err)
					}
				}
			})

			var target struct {
				Value string `form:"value"`
			}
			err := Bind(req, &target, WithBodyLimit(tt.limit))
			if tt.wantErr {
				if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
					t.Fatalf("expected measured multipart body to exceed the limit, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bind returned an error: %v", err)
			}
			if target.Value != "bound" {
				t.Fatalf("multipart value = %q, want bound", target.Value)
			}
		})
	}
}

// TestBindBodyLimitRejectsPreParsedUnknownLengthForms pins that an explicit
// WithBodyLimit fails closed when the body was already consumed by ParseForm
// and its encoded size can no longer be established. The limit is generous
// enough for the body, so a rejection can only come from the unmeasurable
// framing.
func TestBindBodyLimitRejectsPreParsedUnknownLengthForms(t *testing.T) {
	const bodyLimit = 1 << 20

	largeValue := strings.Repeat("x", 1024)

	t.Run("ParseForm", func(t *testing.T) {
		body := url.Values{"value": {largeValue}}.Encode()
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		if err := req.ParseForm(); err != nil {
			t.Fatalf("pre-parse form: %v", err)
		}

		var target struct {
			Value string `form:"value"`
		}
		err := Bind(req, &target, WithBodyLimit(bodyLimit))
		if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
			t.Fatalf("expected pre-parsed form with unknown length to fail closed, got %v", err)
		}
	})

	t.Run("FormValue", func(t *testing.T) {
		body := url.Values{"value": {largeValue}}.Encode()
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		if got := req.FormValue("value"); got != largeValue {
			t.Fatalf("pre-parse form value length = %d, want %d", len(got), len(largeValue))
		}

		var target struct {
			Value string `form:"value"`
		}
		err := Bind(req, &target, WithBodyLimit(bodyLimit))
		if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
			t.Fatalf("expected FormValue-parsed form with unknown length to fail closed, got %v", err)
		}
	})

	t.Run("ParseMultipartForm", func(t *testing.T) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("value", largeValue); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		if err := req.ParseMultipartForm(DefaultMultipartFormMaxMemory); err != nil {
			t.Fatalf("pre-parse multipart form: %v", err)
		}
		t.Cleanup(func() {
			if err := req.MultipartForm.RemoveAll(); err != nil {
				t.Errorf("remove multipart form: %v", err)
			}
		})

		var target struct {
			Value string `form:"value"`
		}
		err := Bind(req, &target, WithBodyLimit(bodyLimit))
		if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
			t.Fatalf("expected pre-parsed multipart form with unknown length to fail closed, got %v", err)
		}
	})
}

func TestBindBodyLimitAcceptsPreParsedKnownLengthForms(t *testing.T) {
	t.Run("url encoded", func(t *testing.T) {
		body := url.Values{"value": {"bound"}}.Encode()
		req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			t.Fatalf("pre-parse form: %v", err)
		}

		var target struct {
			Value string `form:"value"`
		}
		if err := Bind(req, &target); err != nil {
			t.Fatalf("Bind returned an error: %v", err)
		}
		if target.Value != "bound" {
			t.Fatalf("pre-parsed form value = %q, want bound", target.Value)
		}
	})

	t.Run("multipart", func(t *testing.T) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("value", "bound"); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
		req.Header.Set("Content-Type", writer.FormDataContentType())
		if err := req.ParseMultipartForm(DefaultMultipartFormMaxMemory); err != nil {
			t.Fatalf("pre-parse multipart form: %v", err)
		}
		t.Cleanup(func() {
			if err := req.MultipartForm.RemoveAll(); err != nil {
				t.Errorf("remove multipart form: %v", err)
			}
		})

		var target struct {
			Value string `form:"value"`
		}
		if err := Bind(req, &target); err != nil {
			t.Fatalf("Bind returned an error: %v", err)
		}
		if target.Value != "bound" {
			t.Fatalf("pre-parsed multipart value = %q, want bound", target.Value)
		}
	})
}

func TestBindBodyLimitMultipart(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("upload", "large.bin")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	bodyLimit := body.Len()
	if _, err := body.Write(bytes.Repeat([]byte("epilogue"), 512)); err != nil {
		t.Fatalf("write multipart epilogue: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.ContentLength = -1

	var target struct {
		Upload *multipart.FileHeader `file:"upload"`
	}
	err = Bind(req, &target, WithBodyLimit(int64(bodyLimit)), WithMultipartFormMaxMemory(1))
	if !errors.Is(err, ErrBinding) || !strings.Contains(err.Error(), "request body exceeds limit") {
		t.Fatalf("expected oversized multipart form to return the body-limit binding error, got %v", err)
	}
	entries, readErr := os.ReadDir(tempDir)
	if readErr != nil {
		t.Fatalf("read multipart temp directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("multipart parsing leaked temporary files: %v", entries)
	}
}

func TestBindCleansMultipartFilesAfterBindingError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("count", "invalid"); err != nil {
		t.Fatalf("write multipart field: %v", err)
	}
	file, err := writer.CreateFormFile("upload", "large.bin")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	var target struct {
		Count  int                   `form:"count"`
		Upload *multipart.FileHeader `file:"upload"`
	}
	err = Bind(req, &target, WithBodyLimit(int64(body.Len())), WithMultipartFormMaxMemory(1))
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("expected invalid multipart field to return a binding error, got %v", err)
	}
	entries, readErr := os.ReadDir(tempDir)
	if readErr != nil {
		t.Fatalf("read multipart temp directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("binding error leaked multipart temporary files: %v", entries)
	}
}

func TestBindBodyLimitPreservesClose(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("value=bound")}
	req, _ := http.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var target struct {
		Value string `form:"value"`
	}
	// The limit is explicit: without one Bind does not wrap the body at all
	// and there is no wrapper whose Close could be checked.
	if err := Bind(req, &target, WithBodyLimit(1<<20)); err != nil {
		t.Fatalf("Bind returned an error: %v", err)
	}
	if body.closed {
		t.Fatal("Bind unexpectedly closed the request body")
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("close wrapped request body: %v", err)
	}
	if !body.closed {
		t.Fatal("wrapped request body did not close the original body")
	}
}

// TestBindMultipartDefaultAllowsLargeUpload is the contradiction the retired
// default encoded: DefaultMultipartFormMaxMemory is 32 MiB, but every byte past
// the first mebibyte was rejected by DefaultBodyLimit before the multipart
// parser ever saw it, so the documented 32 MiB was unreachable.
func TestBindMultipartDefaultAllowsLargeUpload(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	const uploadSize = (2 << 20) + 1 // comfortably past the retired 1 MiB cap

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("upload", "large.bin")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("x"), uploadSize)); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	var target struct {
		Upload *multipart.FileHeader `file:"upload"`
	}
	if err := Bind(req, &target); err != nil {
		t.Fatalf("default Bind rejected a %d byte multipart upload: %v", body.Len(), err)
	}
	t.Cleanup(func() {
		if req.MultipartForm != nil {
			if err := req.MultipartForm.RemoveAll(); err != nil {
				t.Errorf("remove multipart form: %v", err)
			}
		}
	})

	if target.Upload == nil {
		t.Fatal("multipart upload did not bind")
	}
	if target.Upload.Size != uploadSize {
		t.Fatalf("upload size = %d, want %d", target.Upload.Size, uploadSize)
	}
}

// TestBindBodyLimitErrorIsRecognisable pins the contract the ada error handler
// depends on to answer 413: every body-limit failure, whichever code path
// produced it, is reachable with errors.Is and carries the limit. Matching on
// the message instead was what left these failures indistinguishable from any
// other binding error, and therefore reported as 500.
func TestBindBodyLimitErrorIsRecognisable(t *testing.T) {
	const limit = 8

	jsonBody := `{"value":"` + strings.Repeat("x", 64) + `"}`

	multipartBody := func(t *testing.T) (*bytes.Buffer, string) {
		t.Helper()

		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("value", strings.Repeat("x", 64)); err != nil {
			t.Fatalf("write multipart field: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		return &body, writer.FormDataContentType()
	}

	for _, tt := range []struct {
		name    string
		request func(t *testing.T) *http.Request
	}{
		{
			// Rejected up front on Content-Length.
			name: "declared length",
			request: func(*testing.T) *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
				req.Header.Set("Content-Type", "application/json")

				return req
			},
		},
		{
			// Rejected while streaming, by the wrapped body.
			name: "streamed",
			request: func(*testing.T) *http.Request {
				req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(jsonBody))
				req.Header.Set("Content-Type", "application/json")
				req.ContentLength = -1

				return req
			},
		},
		{
			// Rejected because a pre-parsed body of unknown length cannot be
			// measured, so the limit fails closed.
			name: "pre-parsed unmeasurable",
			request: func(t *testing.T) *http.Request {
				body, contentType := multipartBody(t)

				req, _ := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body.Bytes()))
				req.Header.Set("Content-Type", contentType)
				req.ContentLength = -1
				req.TransferEncoding = []string{"chunked"}
				if err := req.ParseMultipartForm(DefaultMultipartFormMaxMemory); err != nil {
					t.Fatalf("pre-parse multipart form: %v", err)
				}
				t.Cleanup(func() {
					if err := req.MultipartForm.RemoveAll(); err != nil {
						t.Errorf("remove multipart form: %v", err)
					}
				})

				return req
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var target struct {
				Value string `json:"value" form:"value"`
			}

			err := Bind(tt.request(t), &target, WithBodyLimit(limit))
			if err == nil {
				t.Fatal("Bind accepted a body over the limit")
			}
			if !errors.Is(err, ErrBinding) {
				t.Errorf("error %v does not wrap ErrBinding", err)
			}
			if !errors.Is(err, ErrBodyTooLarge) {
				t.Errorf("error %v does not wrap ErrBodyTooLarge", err)
			}

			var tooLarge *BodyTooLargeError
			if !errors.As(err, &tooLarge) {
				t.Fatalf("error %v is not a *BodyTooLargeError", err)
			}
			if tooLarge.Limit != limit {
				t.Errorf("Limit = %d, want %d", tooLarge.Limit, limit)
			}

			// The byte count is not sensitive and is the only thing that tells
			// a client what to send instead.
			if want := "request body exceeds limit of 8 bytes"; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		})
	}
}

// TestBindPreservesCauseInChain guards the wrapping that
// TestBindBodyLimitErrorIsRecognisable relies on. Bind reported every failure
// as "binding: <text>" with the cause flattened to a string, so no caller could
// inspect any error Bind produced.
func TestBindPreservesCauseInChain(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":`))
	req.Header.Set("Content-Type", "application/json")

	var target struct {
		Value string `json:"value"`
	}

	err := Bind(req, &target)
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("error %v does not wrap ErrBinding", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error %v does not keep the decode cause reachable", err)
	}
}

func TestBindJSONUsesNumber(t *testing.T) {
	var target struct {
		Value any `json:"value"`
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":9007199254740993}`))
	req.Header.Set("Content-Type", "application/json")

	if err := Bind(req, &target); err != nil {
		t.Fatalf("Bind returned an error: %v", err)
	}
	value, ok := target.Value.(json.Number)
	if !ok || value != "9007199254740993" {
		t.Fatalf("expected json.Number without precision loss, got %T(%v)", target.Value, target.Value)
	}
}

func TestBindSliceValuesReplaceExistingData(t *testing.T) {
	type payload struct {
		FormValues  []string `form:"form_values"`
		QueryValues []int    `query:"query_values"`
	}

	form := url.Values{"form_values": {"new", "values"}}
	req, _ := http.NewRequest(http.MethodPost, "/?query_values=1,2&query_values=3,4", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	target := payload{
		FormValues:  []string{"old-form"},
		QueryValues: []int{99},
	}
	if err := Bind(req, &target); err != nil {
		t.Fatalf("Bind returned an error: %v", err)
	}
	if !reflect.DeepEqual(target.FormValues, []string{"new", "values"}) {
		t.Fatalf("form values were appended instead of replaced: %v", target.FormValues)
	}
	if !reflect.DeepEqual(target.QueryValues, []int{1, 2, 3, 4}) {
		t.Fatalf("query values were not expanded and replaced deterministically: %v", target.QueryValues)
	}
}

func TestBindRejectsInvalidOptions(t *testing.T) {
	for _, tt := range []struct {
		name string
		opt  Option
	}{
		{name: "negative body limit", opt: WithBodyLimit(-1)},
		{name: "negative multipart memory", opt: WithMultipartFormMaxMemory(-1)},
		{name: "nil option", opt: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			var target struct{}
			err := Bind(req, &target, tt.opt)
			if !errors.Is(err, ErrBinding) {
				t.Fatalf("expected invalid option to wrap ErrBinding, got %v", err)
			}
		})
	}
}

func TestGetFieldCacheConcurrent(t *testing.T) {
	const (
		goroutines = 32
		iterations = 100
	)

	stringType := reflect.TypeOf("")
	byteType := reflect.TypeOf(byte(0))
	errs := make(chan string, goroutines)

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range iterations {
				rt := reflect.StructOf([]reflect.StructField{
					{Name: "Name", Type: stringType, Tag: `query:"name"`},
					{Name: "Pad", Type: reflect.ArrayOf(g*iterations+i+1, byteType)},
				})

				cache := getFieldCache(rt)
				if len(cache.queryFields) != 1 || cache.queryFields[0].tagValue != "name" {
					errs <- "unexpected query field cache"
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// Benchmark tests
func BenchmarkBinder_JSON(b *testing.B) {
	jsonData := `{"id": 123, "username": "johndoe", "email": "john@example.com"}`

	for b.Loop() {
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		var user ExampleUser
		if err := Bind(req, &user); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBinder_Form(b *testing.B) {
	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("age", "30")

	// Pre-encode form data to avoid encoding overhead in benchmark
	encodedForm := form.Encode()

	b.ResetTimer() // Reset timer after setup

	for b.Loop() {
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(encodedForm))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var user ExampleUser
		if err := Bind(req, &user); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBinder_Form_Parsed(b *testing.B) {
	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("age", "30")

	// Pre-create and parse request to isolate binding performance
	req, _ := http.NewRequest("POST", "/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil { // Pre-parse the form
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		var user ExampleUser
		// Test only the binding logic, not request parsing
		if err := bindForm(req, reflect.ValueOf(&user).Elem(), getFieldCache(reflect.TypeOf(user))); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDefaultBinder_BindJSONRawMessage(t *testing.T) {
	type RequestWithRawMessage struct {
		Name  string            `query:"name"`
		Data  json.RawMessage   `query:"data"`
		Items []json.RawMessage `query:"items"`
	}

	// Test single json.RawMessage and []json.RawMessage via query params
	req, _ := http.NewRequest("GET", `/test?name=test&data={"key":"value"}&items={"id":1}&items={"id":2}`, nil)

	var result RequestWithRawMessage
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Name != "test" {
		t.Errorf("Expected name 'test', got %s", result.Name)
	}

	// Check single RawMessage
	expectedData := `{"key":"value"}`
	if string(result.Data) != expectedData {
		t.Errorf("Expected data '%s', got '%s'", expectedData, string(result.Data))
	}

	// Check slice of RawMessage
	if len(result.Items) != 2 {
		t.Fatalf("Expected 2 items, got %d", len(result.Items))
	}

	expectedItem1 := `{"id":1}`
	expectedItem2 := `{"id":2}`
	if string(result.Items[0]) != expectedItem1 {
		t.Errorf("Expected items[0] '%s', got '%s'", expectedItem1, string(result.Items[0]))
	}
	if string(result.Items[1]) != expectedItem2 {
		t.Errorf("Expected items[1] '%s', got '%s'", expectedItem2, string(result.Items[1]))
	}
}

func TestDefaultBinder_BindJSONRawMessageForm(t *testing.T) {
	type RequestWithRawMessage struct {
		Data  json.RawMessage   `form:"data"`
		Items []json.RawMessage `form:"items"`
	}

	form := url.Values{}
	form.Add("data", `{"nested":"object"}`)
	form.Add("items", `{"id":1}`)
	form.Add("items", `{"id":2}`)
	form.Add("items", `[1,2,3]`)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result RequestWithRawMessage
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check single RawMessage
	expectedData := `{"nested":"object"}`
	if string(result.Data) != expectedData {
		t.Errorf("Expected data '%s', got '%s'", expectedData, string(result.Data))
	}

	// Check slice of RawMessage
	if len(result.Items) != 3 {
		t.Fatalf("Expected 3 items, got %d", len(result.Items))
	}

	if string(result.Items[0]) != `{"id":1}` {
		t.Errorf("Expected items[0] '{\"id\":1}', got '%s'", string(result.Items[0]))
	}
	if string(result.Items[1]) != `{"id":2}` {
		t.Errorf("Expected items[1] '{\"id\":2}', got '%s'", string(result.Items[1]))
	}
	if string(result.Items[2]) != `[1,2,3]` {
		t.Errorf("Expected items[2] '[1,2,3]', got '%s'", string(result.Items[2]))
	}
}

func TestDefaultBinder_BindNestedStructFromForm(t *testing.T) {
	type NestedObject struct {
		Key   string `json:"key"`
		Items []int  `json:"items"`
	}

	type Request struct {
		Name   string       `form:"name"`
		Nested NestedObject `form:"nested"`
	}

	form := url.Values{}
	form.Add("name", "test")
	form.Add("nested", `{"key":"value","items":[1,2,3]}`)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Name != "test" {
		t.Errorf("Expected name 'test', got %s", result.Name)
	}

	if result.Nested.Key != "value" {
		t.Errorf("Expected nested.key 'value', got %s", result.Nested.Key)
	}

	if len(result.Nested.Items) != 3 || result.Nested.Items[0] != 1 || result.Nested.Items[1] != 2 || result.Nested.Items[2] != 3 {
		t.Errorf("Expected nested.items [1,2,3], got %v", result.Nested.Items)
	}
}

func TestDefaultBinder_BindNestedStructPointerFromForm(t *testing.T) {
	type NestedObject struct {
		Key   string `json:"key"`
		Value int    `json:"value"`
	}

	type Request struct {
		Nested *NestedObject `form:"nested"`
	}

	form := url.Values{}
	form.Add("nested", `{"key":"test","value":42}`)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Nested == nil {
		t.Fatal("Expected nested to be non-nil")
	}

	if result.Nested.Key != "test" {
		t.Errorf("Expected nested.key 'test', got %s", result.Nested.Key)
	}

	if result.Nested.Value != 42 {
		t.Errorf("Expected nested.value 42, got %d", result.Nested.Value)
	}
}

func TestDefaultBinder_BindMapFromForm(t *testing.T) {
	type Request struct {
		Data map[string]any `form:"data"`
	}

	form := url.Values{}
	form.Add("data", `{"key":"value","number":123}`)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Data["key"] != "value" {
		t.Errorf("Expected data.key 'value', got %v", result.Data["key"])
	}

	if result.Data["number"] != float64(123) {
		t.Errorf("Expected data.number 123, got %v", result.Data["number"])
	}
}

func TestDefaultBinder_BindSliceOfStructsFromForm(t *testing.T) {
	type Item struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	type Request struct {
		Items []Item `form:"items"`
	}

	form := url.Values{}
	form.Add("items", `{"id":1,"name":"first"}`)
	form.Add("items", `{"id":2,"name":"second"}`)

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(result.Items) != 2 {
		t.Fatalf("Expected 2 items, got %d", len(result.Items))
	}

	if result.Items[0].ID != 1 || result.Items[0].Name != "first" {
		t.Errorf("Expected items[0] {1, first}, got %+v", result.Items[0])
	}

	if result.Items[1].ID != 2 || result.Items[1].Name != "second" {
		t.Errorf("Expected items[1] {2, second}, got %+v", result.Items[1])
	}
}

func TestDefaultBinder_BindNestedStructFromMultipartForm(t *testing.T) {
	type NestedObject struct {
		Key   string `json:"key"`
		Items []int  `json:"items"`
	}

	type Request struct {
		Title  string       `form:"title"`
		Nested NestedObject `form:"nested"`
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	if err := writer.WriteField("title", "Test Title"); err != nil {
		t.Fatalf("write title field: %v", err)
	}
	if err := writer.WriteField("nested", `{"key":"value","items":[1,2,3]}`); err != nil {
		t.Fatalf("write nested field: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, _ := http.NewRequest("POST", "/test", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Title != "Test Title" {
		t.Errorf("Expected title 'Test Title', got %s", result.Title)
	}

	if result.Nested.Key != "value" {
		t.Errorf("Expected nested.key 'value', got %s", result.Nested.Key)
	}

	if len(result.Nested.Items) != 3 {
		t.Errorf("Expected 3 items, got %d", len(result.Nested.Items))
	}
}

func TestDefaultBinder_HeaderOverridesJSONAndForm(t *testing.T) {
	// Test that header binding overrides JSON and form values for the same field
	type Request struct {
		Token string `json:"token" form:"token" header:"X-Token"`
	}

	// Send JSON body with token, form with token, and header with token
	// Header should win since it's bound last
	jsonData := `{"token": "json-token"}`

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token", "header-token")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Header should override JSON value
	if result.Token != "header-token" {
		t.Errorf("Expected token 'header-token' (header should override JSON), got '%s'", result.Token)
	}
}

func TestDefaultBinder_HeaderOverridesForm(t *testing.T) {
	type Request struct {
		Token string `form:"-" header:"X-Token"`
	}

	form := url.Values{}
	form.Add("token", "form-token")

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Header should override form value
	if result.Token != "" {
		t.Errorf("Expected token '' (header should override form), got '%s'", result.Token)
	}
}

func TestDefaultBinder_HeaderOnly(t *testing.T) {
	type Request struct {
		Token string `json:"-" form:"" header:"X-Token"`
	}

	jsonData := `{"token": "json-token"}`

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Header should override form value
	if result.Token != "" {
		t.Errorf("Expected token '' (header should override form), got '%s'", result.Token)
	}
}

func TestDefaultBinder_BindingPriorityOrder(t *testing.T) {
	// Test the full priority order: JSON/Form -> Query -> Header -> URI
	// Later bindings should override earlier ones
	type Request struct {
		Value string `json:"value" query:"value" header:"X-Value"`
	}

	jsonData := `{"value": "json-value"}`

	req, _ := http.NewRequest("POST", "/test?value=query-value", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Value", "header-value")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Header should be the final value (bound after JSON and query)
	if result.Value != "header-value" {
		t.Errorf("Expected value 'header-value' (header should override all), got '%s'", result.Value)
	}
}

func TestDefaultBinder_IndependentBindingSources(t *testing.T) {
	type Request struct {
		// Only from JSON body
		FromJSON string `json:"from_json" form:"-" query:"-" header:"-"`

		// Only from form data
		FromForm string `json:"-" form:"from_form" query:"-" header:"-"`

		// Only from query params
		FromQuery string `json:"-" form:"-" query:"from_query" header:"-"`

		// Only from header
		FromHeader string `json:"-" form:"-" query:"-" header:"X-From-Header"`
	}

	// Send all sources with values - each field should only bind from its designated source
	jsonData := `{"from_json":"json-value","from_form":"should-ignore","from_query":"should-ignore","from_header":"should-ignore"}`

	req, _ := http.NewRequest("POST", "/test?from_query=query-value&from_json=should-ignore", strings.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-From-Header", "header-value")

	var result Request
	err := Bind(req, &result)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Each field should only get value from its designated source
	if result.FromJSON != "json-value" {
		t.Errorf("Expected FromJSON 'json-value', got '%s'", result.FromJSON)
	}

	if result.FromForm != "" {
		t.Errorf("Expected FromForm '' (no form data sent), got '%s'", result.FromForm)
	}

	if result.FromQuery != "query-value" {
		t.Errorf("Expected FromQuery 'query-value', got '%s'", result.FromQuery)
	}

	if result.FromHeader != "header-value" {
		t.Errorf("Expected FromHeader 'header-value', got '%s'", result.FromHeader)
	}
}

func TestBindQuerySeparatorOnlyAppliesToSlices(t *testing.T) {
	type request struct {
		Name string   `query:"name"`
		Tags []string `query:"tags"`
	}

	tests := []struct {
		name     string
		rawQuery string
		opts     []Option
		wantName string
		wantTags []string
	}{
		{
			name:     "comma in a scalar string is kept",
			rawQuery: "name=Doe,%20John",
			wantName: "Doe, John",
		},
		{
			name:     "comma in a slice still splits",
			rawQuery: "tags=a,b,c",
			wantTags: []string{"a", "b", "c"},
		},
		{
			name:     "separator disabled leaves both raw",
			rawQuery: "name=Doe,%20John&tags=a,b,c",
			opts:     []Option{WithQuerySeparator("")},
			wantName: "Doe, John",
			wantTags: []string{"a,b,c"},
		},
		{
			name:     "custom separator splits slices and spares scalars",
			rawQuery: "name=Doe|John&tags=a|b|c",
			opts:     []Option{WithQuerySeparator("|")},
			wantName: "Doe|John",
			wantTags: []string{"a", "b", "c"},
		},
		{
			name:     "repeated and separated values combine",
			rawQuery: "tags=a,b&tags=c",
			wantTags: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/?"+tt.rawQuery, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}

			var got request
			if err := Bind(req, &got, tt.opts...); err != nil {
				t.Fatalf("Bind(?%s): %v", tt.rawQuery, err)
			}

			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if !reflect.DeepEqual(got.Tags, tt.wantTags) {
				t.Errorf("Tags = %#v, want %#v", got.Tags, tt.wantTags)
			}
		})
	}
}

func TestBindQuerySeparatorSparesJSONScalars(t *testing.T) {
	type nested struct {
		Street string `json:"street"`
		City   string `json:"city"`
	}
	type request struct {
		Address nested            `query:"address"`
		Meta    map[string]string `query:"meta"`
		Raw     json.RawMessage   `query:"raw"`
	}

	values := url.Values{}
	values.Set("address", `{"street":"123 Main St","city":"NYC"}`)
	values.Set("meta", `{"a":"1","b":"2"}`)
	values.Set("raw", `{"x":1,"y":2}`)

	req, err := http.NewRequest(http.MethodGet, "/?"+values.Encode(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	var got request
	if err := Bind(req, &got); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	if got.Address.Street != "123 Main St" || got.Address.City != "NYC" {
		t.Errorf("Address = %+v, want {123 Main St NYC}", got.Address)
	}
	if !reflect.DeepEqual(got.Meta, map[string]string{"a": "1", "b": "2"}) {
		t.Errorf("Meta = %#v, want map[a:1 b:2]", got.Meta)
	}
	if string(got.Raw) != `{"x":1,"y":2}` {
		t.Errorf("Raw = %s, want {\"x\":1,\"y\":2}", got.Raw)
	}
}

func TestBindQuerySeparatorSparesJSONSlices(t *testing.T) {
	type item struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	type request struct {
		Raw        []json.RawMessage    `query:"raw"`
		RawPtrs    []*json.RawMessage   `query:"raw_ptrs"`
		Structs    []item               `query:"structs"`
		StructPtrs []*item              `query:"struct_ptrs"`
		Maps       []map[string]string  `query:"maps"`
		MapPtrs    []*map[string]string `query:"map_ptrs"`
	}

	values := url.Values{
		"raw":         {`{"a":1,"b":2}`},
		"raw_ptrs":    {`[1,2]`},
		"structs":     {`{"id":1,"name":"one"}`},
		"struct_ptrs": {`{"id":2,"name":"two"}`},
		"maps":        {`{"a":"1","b":"2"}`},
		"map_ptrs":    {`{"c":"3","d":"4"}`},
	}
	req, err := http.NewRequest(http.MethodGet, "/?"+values.Encode(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	var got request
	if err := Bind(req, &got); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	if len(got.Raw) != 1 || string(got.Raw[0]) != `{"a":1,"b":2}` {
		t.Errorf("Raw = %q", got.Raw)
	}
	if len(got.RawPtrs) != 1 || got.RawPtrs[0] == nil || string(*got.RawPtrs[0]) != `[1,2]` {
		t.Errorf("RawPtrs = %v", got.RawPtrs)
	}
	if want := []item{{ID: 1, Name: "one"}}; !reflect.DeepEqual(got.Structs, want) {
		t.Errorf("Structs = %#v, want %#v", got.Structs, want)
	}
	if len(got.StructPtrs) != 1 || got.StructPtrs[0] == nil || *got.StructPtrs[0] != (item{ID: 2, Name: "two"}) {
		t.Errorf("StructPtrs = %#v", got.StructPtrs)
	}
	if want := []map[string]string{{"a": "1", "b": "2"}}; !reflect.DeepEqual(got.Maps, want) {
		t.Errorf("Maps = %#v, want %#v", got.Maps, want)
	}
	if len(got.MapPtrs) != 1 || got.MapPtrs[0] == nil || !reflect.DeepEqual(*got.MapPtrs[0], map[string]string{"c": "3", "d": "4"}) {
		t.Errorf("MapPtrs = %#v", got.MapPtrs)
	}
}

func TestBindRepeatedParameterFirstValueWinsForScalars(t *testing.T) {
	type request struct {
		Scalar string   `query:"v"`
		Slice  []string `query:"v2"`
	}

	req, err := http.NewRequest(http.MethodGet, "/?v=bir&v=iki&v2=bir&v2=iki", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	var got request
	if err := Bind(req, &got); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	if got.Scalar != "bir" {
		t.Errorf("Scalar = %q, want %q (first value wins)", got.Scalar, "bir")
	}
	if want := []string{"bir", "iki"}; !reflect.DeepEqual(got.Slice, want) {
		t.Errorf("Slice = %#v, want %#v", got.Slice, want)
	}
}

func TestBindReportsMalformedQuery(t *testing.T) {
	type request struct {
		Name string `query:"name"`
	}

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.URL.RawQuery = "bad=%zz&name=ok"

	var got request
	err = Bind(req, &got)
	if err == nil {
		t.Fatalf("Bind accepted a malformed query and bound %+v", got)
	}
	if !errors.Is(err, ErrBinding) {
		t.Errorf("error %v does not wrap ErrBinding", err)
	}
	if !strings.Contains(err.Error(), "failed to parse query") {
		t.Errorf("error %v does not name the query as the cause", err)
	}

}
