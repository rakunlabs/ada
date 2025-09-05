package bind

import (
	"bytes"
	"encoding/xml"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
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
	CreatedAt time.Time `json:"created_at" time_format:"2006-01-02T15:04:05Z07:00"`
	UpdatedAt time.Time `form:"updated_at" time_format:"2006-01-02"`

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
	Data map[string]interface{} `json:"data"`
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
	req, _ := http.NewRequest("GET", "/users?page=2&page_size=10&tags=go&tags=web&active=true&score=95.5", nil)

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

	if !user.Active {
		t.Errorf("Expected active to be true")
	}

	if user.Score == nil || *user.Score != 95.5 {
		t.Errorf("Expected score 95.5, got %v", user.Score)
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
	writer.WriteField("title", "Test Upload")
	writer.WriteField("description", "Test file upload")
	writer.WriteField("public", "true")
	writer.WriteField("tags", "test")
	writer.WriteField("tags", "upload")

	// Add file
	fileWriter, _ := writer.CreateFormFile("main_file", "test.txt")
	fileWriter.Write([]byte("test file content"))

	writer.Close()

	req, _ := http.NewRequest("POST", "/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	var upload FileUploadRequest
	err := Bind(req, &upload)

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

// Benchmark tests
func BenchmarkBinder_JSON(b *testing.B) {
	jsonData := `{"id": 123, "username": "johndoe", "email": "john@example.com"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")

		var user ExampleUser
		Bind(req, &user)
	}
}

func BenchmarkBinder_Form(b *testing.B) {
	form := url.Values{}
	form.Add("first_name", "John")
	form.Add("last_name", "Doe")
	form.Add("age", "30")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var user ExampleUser
		Bind(req, &user)
	}
}

// Helper function to create a request with body that can be read multiple times
func createRequestWithBody(method, url string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, url, body)
	return req
}
