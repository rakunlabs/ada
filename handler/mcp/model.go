package mcp

import (
	"encoding/json"
	"sync"
)

// JSON-RPC 2.0 structures
// See: https://www.jsonrpc.org/specification

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Common types

// Icon represents an icon for display in user interfaces.
type Icon struct {
	Src      string   `json:"src"`
	MimeType string   `json:"mimeType,omitempty"`
	Sizes    []string `json:"sizes,omitempty"`
}

// Annotations provide hints to clients about how to use or display content.
type Annotations struct {
	Audience     []string `json:"audience,omitempty"`
	Priority     *float64 `json:"priority,omitempty"`
	LastModified string   `json:"lastModified,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Content types

// TextContent represents plain text content.
type TextContent struct {
	Type        string       `json:"type"` // "text"
	Text        string       `json:"text"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// NewTextContent creates a new TextContent with the type field set.
func NewTextContent(text string) TextContent {
	return TextContent{
		Type: "text",
		Text: text,
	}
}

// ImageContent represents base64-encoded image content.
type ImageContent struct {
	Type        string       `json:"type"` // "image"
	Data        string       `json:"data"`
	MimeType    string       `json:"mimeType"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// NewImageContent creates a new ImageContent with the type field set.
func NewImageContent(data string, mimeType string) ImageContent {
	return ImageContent{
		Type:     "image",
		Data:     data,
		MimeType: mimeType,
	}
}

// AudioContent represents base64-encoded audio content.
type AudioContent struct {
	Type        string       `json:"type"` // "audio"
	Data        string       `json:"data"`
	MimeType    string       `json:"mimeType"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// NewAudioContent creates a new AudioContent with the type field set.
func NewAudioContent(data string, mimeType string) AudioContent {
	return AudioContent{
		Type:     "audio",
		Data:     data,
		MimeType: mimeType,
	}
}

// ResourceLinkContent represents a link to a resource.
type ResourceLinkContent struct {
	Type        string       `json:"type"` // "resource_link"
	URI         string       `json:"uri"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// NewResourceLinkContent creates a new ResourceLinkContent with the type field set.
func NewResourceLinkContent(uri string) ResourceLinkContent {
	return ResourceLinkContent{
		Type: "resource_link",
		URI:  uri,
	}
}

// EmbeddedResourceContent represents an embedded resource in content.
type EmbeddedResourceContent struct {
	Type        string          `json:"type"` // "resource"
	Resource    ResourceContent `json:"resource"`
	Annotations *Annotations    `json:"annotations,omitempty"`
}

// NewEmbeddedResourceContent creates a new EmbeddedResourceContent with the type field set.
func NewEmbeddedResourceContent(resource ResourceContent) EmbeddedResourceContent {
	return EmbeddedResourceContent{
		Type:     "resource",
		Resource: resource,
	}
}

// ResourceContent represents the contents of a resource (text or binary).
type ResourceContent struct {
	URI         string       `json:"uri"`
	MimeType    string       `json:"mimeType,omitempty"`
	Text        string       `json:"text,omitempty"`
	Blob        string       `json:"blob,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Implementation info

type ClientInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Icons       []Icon `json:"icons,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
}

type ServerInfo struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	Icons       []Icon `json:"icons,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Initialize

type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

type Capabilities struct {
	Tools       *ToolsCapability       `json:"tools,omitempty"`
	Resources   *ResourcesCapability   `json:"resources,omitempty"`
	Prompts     *PromptsCapability     `json:"prompts,omitempty"`
	Logging     *LoggingCapability     `json:"logging,omitempty"`
	Completions *CompletionsCapability `json:"completions,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type LoggingCapability struct{}

type CompletionsCapability struct{}

// /////////////////////////////////////////////////////////////
// Tools

type Tool struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description"`
	Icons        []Icon         `json:"icons,omitempty"`
	InputSchema  map[string]any `json:"inputSchema"`
	OutputSchema map[string]any `json:"outputSchema,omitempty"`
	Annotations  *Annotations   `json:"annotations,omitempty"`
}

type Tools struct {
	list     []Tool
	handlers map[string]ToolHandler
	m        sync.RWMutex
}

func (t *Tools) Add(tool Tool, handler ToolHandler) {
	t.m.Lock()
	defer t.m.Unlock()

	t.list = append(t.list, tool)
	if handler != nil {
		t.handlers[tool.Name] = handler
	}
}

func (t *Tools) GetHandler(name string) ToolHandler {
	t.m.RLock()
	defer t.m.RUnlock()
	return t.handlers[name]
}

func (t *Tools) List() []Tool {
	t.m.RLock()
	defer t.m.RUnlock()
	return append([]Tool(nil), t.list...)
}

// ToolCallParams represents the parameters for a tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolsListResult is the result of a tools/list request.
type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ToolCallResult is the result of a tools/call request.
type ToolCallResult struct {
	Content           []any `json:"content,omitempty"`
	StructuredContent any   `json:"structuredContent,omitempty"`
	IsError           bool  `json:"isError,omitempty"`
}

// NewToolCallResult creates a ToolCallResult with a single text content.
func NewToolCallResult(text string) ToolCallResult {
	return ToolCallResult{
		Content: []any{NewTextContent(text)},
	}
}

// NewToolCallErrorResult creates a ToolCallResult with isError set to true.
func NewToolCallErrorResult(text string) ToolCallResult {
	return ToolCallResult{
		Content: []any{NewTextContent(text)},
		IsError: true,
	}
}

// /////////////////////////////////////////////////////////////
// Resources

type Resource struct {
	URI         string       `json:"uri"`
	Name        string       `json:"name"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Icons       []Icon       `json:"icons,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Size        *int64       `json:"size,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

type Resources struct {
	list     []Resource
	handlers map[string]ResourceHandler
	m        sync.RWMutex
}

func (r *Resources) Add(resource Resource, handler ResourceHandler) {
	r.m.Lock()
	defer r.m.Unlock()

	r.list = append(r.list, resource)
	if handler != nil {
		r.handlers[resource.URI] = handler
	}
}

func (r *Resources) GetHandler(uri string) ResourceHandler {
	r.m.RLock()
	defer r.m.RUnlock()
	return r.handlers[uri]
}

func (r *Resources) List() []Resource {
	r.m.RLock()
	defer r.m.RUnlock()
	return append([]Resource(nil), r.list...)
}

// ResourcesListResult is the result of a resources/list request.
type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// ResourcesReadResult is the result of a resources/read request.
type ResourcesReadResult struct {
	Contents []ResourceContent `json:"contents"`
}

// ResourcesReadParams represents the parameters for a resources/read request.
type ResourcesReadParams struct {
	URI string `json:"uri"`
}

// /////////////////////////////////////////////////////////////
// Resource Templates

type ResourceTemplate struct {
	URITemplate string       `json:"uriTemplate"`
	Name        string       `json:"name"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Icons       []Icon       `json:"icons,omitempty"`
	MimeType    string       `json:"mimeType,omitempty"`
	Annotations *Annotations `json:"annotations,omitempty"`
}

type ResourceTemplates struct {
	list []ResourceTemplate
	m    sync.RWMutex
}

func (rt *ResourceTemplates) Add(template ResourceTemplate) {
	rt.m.Lock()
	defer rt.m.Unlock()

	rt.list = append(rt.list, template)
}

func (rt *ResourceTemplates) List() []ResourceTemplate {
	rt.m.RLock()
	defer rt.m.RUnlock()
	return append([]ResourceTemplate(nil), rt.list...)
}

// ResourceTemplatesListResult is the result of a resources/templates/list request.
type ResourceTemplatesListResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
	NextCursor        string             `json:"nextCursor,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Prompts

type Prompt struct {
	Name        string      `json:"name"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
	Icons       []Icon      `json:"icons,omitempty"`
	Arguments   []PromptArg `json:"arguments,omitempty"`
}

type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptMessage struct {
	Role    string        `json:"role"`
	Content PromptContent `json:"content"`
}

type PromptContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type Prompts struct {
	list     []Prompt
	handlers map[string]PromptHandler
	m        sync.RWMutex
}

func (p *Prompts) Add(prompt Prompt, handler PromptHandler) {
	p.m.Lock()
	defer p.m.Unlock()

	p.list = append(p.list, prompt)
	if handler != nil {
		p.handlers[prompt.Name] = handler
	}
}

func (p *Prompts) GetHandler(name string) PromptHandler {
	p.m.RLock()
	defer p.m.RUnlock()
	return p.handlers[name]
}

func (p *Prompts) List() []Prompt {
	p.m.RLock()
	defer p.m.RUnlock()
	return append([]Prompt(nil), p.list...)
}

// PromptsListResult is the result of a prompts/list request.
type PromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// PromptsGetParams represents the parameters for a prompts/get request.
type PromptsGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Completion

type CompleteRequest struct {
	Ref      CompletionRef    `json:"ref"`
	Argument CompleteArgument `json:"argument"`
	Context  *CompleteContext `json:"context,omitempty"`
}

type CompletionRef struct {
	Type string `json:"type"` // "ref/prompt" or "ref/resource"
	Name string `json:"name,omitempty"`
	URI  string `json:"uri,omitempty"`
}

type CompleteArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CompleteContext struct {
	Arguments map[string]string `json:"arguments,omitempty"`
}

type CompleteResult struct {
	Completion CompletionValues `json:"completion"`
}

type CompletionValues struct {
	Values  []string `json:"values"`
	Total   int      `json:"total,omitempty"`
	HasMore bool     `json:"hasMore,omitempty"`
}

// CompletionHandlers holds registered completion handlers.
type CompletionHandlers struct {
	handlers map[string]CompletionHandler
	m        sync.RWMutex
}

func (ch *CompletionHandlers) Add(refKey string, handler CompletionHandler) {
	ch.m.Lock()
	defer ch.m.Unlock()

	ch.handlers[refKey] = handler
}

func (ch *CompletionHandlers) GetHandler(refKey string) CompletionHandler {
	ch.m.RLock()
	defer ch.m.RUnlock()
	return ch.handlers[refKey]
}

// /////////////////////////////////////////////////////////////
// Logging

type SetLevelRequest struct {
	Level string `json:"level"`
}

type LogMessageParams struct {
	Level  string `json:"level"`
	Logger string `json:"logger,omitempty"`
	Data   any    `json:"data"`
}

// /////////////////////////////////////////////////////////////
// Subscriptions

type SubscribeRequest struct {
	URI string `json:"uri"`
}

type UnsubscribeRequest struct {
	URI string `json:"uri"`
}

type ResourceUpdatedNotification struct {
	URI   string `json:"uri"`
	Title string `json:"title,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Cancellation

// CancelledParams represents the parameters for a notifications/cancelled notification.
type CancelledParams struct {
	RequestID any    `json:"requestId"`
	Reason    string `json:"reason,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Tasks (notification only, full task support is separate)

// TaskStatusNotification represents the parameters for a notifications/tasks/status notification.
type TaskStatusNotification struct {
	TaskID        string `json:"taskId"`
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage,omitempty"`
	CreatedAt     string `json:"createdAt"`
	LastUpdatedAt string `json:"lastUpdatedAt,omitempty"`
	TTL           *int64 `json:"ttl,omitempty"`
	PollInterval  *int64 `json:"pollInterval,omitempty"`
}

// /////////////////////////////////////////////////////////////
// Empty result

// EmptyResult represents an empty JSON-RPC result {}.
type EmptyResult struct{}

// /////////////////////////////////////////////////////////////
// Health check

type HealthCheckResponse struct {
	Status  string `json:"status"`
	Server  string `json:"server"`
	Version string `json:"version"`
}
