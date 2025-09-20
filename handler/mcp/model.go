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
// MCP specific structures

type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
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

// Resources collection
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

// Prompts collection
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

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Prompts structures
type Prompt struct {
	Name        string      `json:"name"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
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

// Completion structures
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

// Logging structures
type SetLevelRequest struct {
	Level string `json:"level"`
}

type LogMessageParams struct {
	Level  string `json:"level"`
	Logger string `json:"logger,omitempty"`
	Data   any    `json:"data"`
}

// Resource templates
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Subscription structures
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
