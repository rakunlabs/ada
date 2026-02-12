package bind

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
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

type CustomType struct {
	Value string
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

// Benchmark tests
func BenchmarkBinder_JSON(b *testing.B) {
	jsonData := `{"id": 123, "username": "johndoe", "email": "john@example.com"}`

	for b.Loop() {
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

	// Pre-encode form data to avoid encoding overhead in benchmark
	encodedForm := form.Encode()

	b.ResetTimer() // Reset timer after setup

	for b.Loop() {
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(encodedForm))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		var user ExampleUser
		Bind(req, &user)
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
	req.ParseForm() // Pre-parse the form

	b.ResetTimer()

	for b.Loop() {
		var user ExampleUser
		// Test only the binding logic, not request parsing
		bindForm(req, reflect.ValueOf(&user).Elem(), getFieldCache(reflect.TypeOf(user)))
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

	writer.WriteField("title", "Test Title")
	writer.WriteField("nested", `{"key":"value","items":[1,2,3]}`)

	writer.Close()

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
