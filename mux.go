package ada

import (
	"net/http"
	"path"
	"strings"
)

type typeNode int

const (
	typeNodeSelf     typeNode = iota // Self node, e.g., /
	typeNodeStatic                   // Static node, e.g., /users
	typeNodeWildcard                 // Wildcard node, e.g., /users/*
	typeNodeParam                    // Parameterized node, e.g., /users/{id}
)

type node struct {
	Segment  *node
	Possible bool

	TypeStatic   *nodeStatic
	TypeWildcard *nodeWildcard
	TypeParam    *nodeParam

	MethodHandler map[string]http.HandlerFunc
	Handler       http.HandlerFunc

	// Path of the node, used for telemetry.
	Path string
}

type nodeStatic struct {
	Key      string
	Children map[byte]*node
}

func (n *nodeStatic) SetChild(char byte, child *node) {
	if n.Children == nil {
		n.Children = make(map[byte]*node)
	}

	n.Children[char] = child
}

type nodeParam struct {
	// Name of the parameter, ex "id"
	Name     string
	Children *node
}

type nodeWildcard struct {
	// Children nodes for wildcard
	Children *node
}

func (n *node) IsHandlerExists() bool {
	if n.Handler != nil || len(n.MethodHandler) > 0 {
		return true
	}

	return false
}

func (n *node) FindNode(path string, r *http.Request) (*node, typeNode) {
	if path == "" {
		if n.IsHandlerExists() {
			return n, 0
		}

		return nil, 0
	}

	if n.TypeStatic != nil {
		current := n
		isFound := true

		for i := 0; i < len(path); {
			char := path[i]
			child, ok := current.TypeStatic.Children[char]
			if !ok {
				isFound = false

				break
			}

			remaining := path[i:]
			if !strings.HasPrefix(remaining, child.TypeStatic.Key) {
				isFound = false

				break
			}

			i += len(child.TypeStatic.Key)
			current = child
		}

		if isFound {
			return current, typeNodeStatic
		}
	}

	// Check for parameter nodes - they match any segment and capture the value
	if n.TypeParam != nil && path != "" {
		return n.TypeParam.Children, typeNodeParam
	}

	// Check for wildcard nodes - they match any remaining path
	if n.TypeWildcard != nil {
		return n.TypeWildcard.Children, typeNodeWildcard
	}

	return nil, 0
}

func (n *node) SetHandler(method, path string, handler http.HandlerFunc) {
	handlerAssign := func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = path // Set the pattern
		handler(w, r)
	}

	if method == "" {
		n.Handler = handlerAssign

		return
	}

	if n.MethodHandler == nil {
		n.MethodHandler = make(map[string]http.HandlerFunc)
	}

	n.MethodHandler[method] = handlerAssign
}

func (n *node) Insert(method, path string, handler http.HandlerFunc) {
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	var typeNodeSegment typeNode
	current := n
	for i, segment := range pathSegments {
		if segment == "" {
			continue // skip empty segments
		}

		typeNodeSegment = findTypeNode(segment)
		switch typeNodeSegment {
		case typeNodeStatic:
			current = current.insertNodeTypeStatic(segment)
		case typeNodeWildcard:
			current = current.insertNodeTypeWildcard()
		case typeNodeParam:
			current = current.insertNodeTypeParam(segment)
		default:
			panic("unknown node type") // should never happen
		}

		if i != len(pathSegments)-1 {
			if current.Segment != nil {
				current = current.Segment
			} else {
				current.Segment = &node{}
				current = current.Segment
			}
		}
	}

	current.SetHandler(method, path, handler)
	if typeNodeSegment == typeNodeWildcard {
		current.Possible = true
	}
}

func (n *node) insertNodeTypeStatic(path string) *node {
	current := n
	// place every segment in a node or sub-node
	for byteIndex := 0; byteIndex < len(path); {
		char := path[byteIndex]
		// find the type of the node
		if current.TypeStatic == nil {
			current.TypeStatic = &nodeStatic{}
		}

		if child, exists := current.TypeStatic.Children[char]; exists {
			commonLen := 0
			// find remaining on path
			remaining := path[byteIndex:]
			for commonLen < len(child.TypeStatic.Key) && commonLen < len(remaining) {
				if child.TypeStatic.Key[commonLen] == remaining[commonLen] {
					commonLen += 1
				} else {
					break
				}
			}

			// if it is inside of this node than switch to it and try to continue to find
			if commonLen == len(child.TypeStatic.Key) {
				// continue to look inside the child node
				current = child
				byteIndex += commonLen
			} else {
				// Need to split the node
				splitNode := &node{
					TypeStatic: &nodeStatic{
						Key:      child.TypeStatic.Key[:commonLen],
						Children: make(map[byte]*node),
					},
				}

				// Update existing child
				child.TypeStatic.Key = child.TypeStatic.Key[commonLen:]
				splitNode.TypeStatic.SetChild(child.TypeStatic.Key[0], child)

				// Add new path if needed
				if commonLen < len(remaining) {
					newSuffix := remaining[commonLen:]
					newNode := &node{
						TypeStatic: &nodeStatic{
							Key:      newSuffix,
							Children: make(map[byte]*node),
						},
					}

					splitNode.TypeStatic.SetChild(newSuffix[0], newNode)
					current.TypeStatic.SetChild(char, splitNode)

					return newNode
				}
				current.TypeStatic.SetChild(char, splitNode)

				return splitNode
			}
		} else {
			// Create new node with remaining characters
			newNode := &node{
				TypeStatic: &nodeStatic{
					Key:      path[byteIndex:],
					Children: make(map[byte]*node),
				},
			}
			current.TypeStatic.SetChild(char, newNode)

			return newNode
		}
	}

	return current
}

func (n *node) insertNodeTypeWildcard() *node {
	// For wildcard nodes, we create a single node that can match any segment
	if n.TypeWildcard == nil {
		n.TypeWildcard = &nodeWildcard{}
	}

	// If there are no children yet, create a new child node
	if n.TypeWildcard.Children == nil {
		n.TypeWildcard.Children = &node{}
	}

	return n.TypeWildcard.Children
}

func (n *node) insertNodeTypeParam(path string) *node {
	// Extract parameter name from {paramName} format
	paramName := strings.Trim(path, "{}")

	// Create parameter node if it doesn't exist
	if n.TypeParam == nil {
		n.TypeParam = &nodeParam{
			Name: paramName,
		}
	}

	// If there are no children yet, create a new child node
	if n.TypeParam.Children == nil {
		n.TypeParam.Children = &node{}
	}

	return n.TypeParam.Children
}

func findTypeNode(part string) typeNode {
	switch {
	case part == "*":
		return typeNodeWildcard
	case strings.Contains(part, "{"):
		return typeNodeParam
	default:
		return typeNodeStatic
	}
}

// //////////////////////////////////////////////////////////

type Mux struct {
	root *node

	errHandler  func(c *Context, err error)
	notFound    http.HandlerFunc
	middlewares []func(next http.Handler) http.Handler
	prefix      string
}

func NewMux() *Mux {
	return &Mux{
		root: &node{},
	}
}

func (m *Mux) HandleWithMethod(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	handlerFunc := Chain(append(m.middlewares, middlewares...)...)(handler)
	path = m.prefix + "/" + strings.TrimPrefix(path, "/")
	m.root.Insert(method, path, handlerFunc.ServeHTTP)
}

func (m *Mux) GET(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodGet, path, handler, middlewares...)
}

func (m *Mux) POST(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPost, path, handler, middlewares...)
}

func (m *Mux) PUT(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPut, path, handler, middlewares...)
}

func (m *Mux) PATCH(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPatch, path, handler, middlewares...)
}

func (m *Mux) DELETE(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodDelete, path, handler, middlewares...)
}

func (m *Mux) HEAD(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodHead, path, handler, middlewares...)
}

func (m *Mux) OPTIONS(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodOptions, path, handler, middlewares...)
}

func (m *Mux) TRACE(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodTrace, path, handler, middlewares...)
}

func (m *Mux) CONNECT(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodConnect, path, handler, middlewares...)
}

func (m *Mux) HandleFunc(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod("", path, handler, middlewares...)
}

// HandleFuncWildcard is registering all paths under the given path.
func (m *Mux) HandleFuncWildcard(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	if path[len(path)-1] == '/' {
		path += "*"
	}

	m.HandleFunc(path, handler, middlewares...)
}

func (m *Mux) Handle(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(path, handler.ServeHTTP, middlewares...)
}

// HandleWildcard is registering all paths under the given path.
func (m *Mux) HandleWildcard(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFuncWildcard(path, handler.ServeHTTP, middlewares...)
}

func (m *Mux) Use(middlewares ...func(next http.Handler) http.Handler) {
	if len(middlewares) == 0 {
		return
	}

	m.middlewares = append(m.middlewares, middlewares...)
}

func (m Mux) Group(pathGroup string, middlewares ...func(next http.Handler) http.Handler) *Mux {
	m.prefix = path.Join("/", m.prefix, pathGroup)
	m.middlewares = append(m.middlewares, middlewares...)

	return &m
}

// NotFound sets the handler for 404 Not Found responses.
//   - If not set, it defaults to http.NotFound.
func (m *Mux) NotFound(handler http.HandlerFunc) {
	m.notFound = handler
}

// ErrorHandler sets the handler for 500 Internal Server Error responses.
//   - If not set, it defaults to a generic error handler.
//   - Only usable for ada.HandlerFunc handlers.
func (m *Mux) ErrorHandler(handler func(c *Context, err error)) {
	m.errHandler = handler
}

// ServeHTTP implements the http.Handler interface for Mux.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	notFound := m.notFound
	if notFound == nil {
		notFound = http.NotFound
	}

	path := r.URL.Path
	current := m.root
	var possible *node
	var possibleIndex int

	pathPattern := make([]indexValue, 0)

	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, segment := range segments {
		if current.TypeWildcard != nil && current.TypeWildcard.Children.Possible {
			possible = current.TypeWildcard.Children
			possibleIndex = i
		}
		// find the type of the node
		node, nodeType := current.FindNode(segment, r)
		if node == nil {
			current = possible
			break
		}

		if nodeType == typeNodeParam {
			pathPattern = append(pathPattern, indexValue{
				index: i,
				name:  current.TypeParam.Name,
				value: segment,
			})
		}

		if i != len(segments)-1 {
			if node.Possible {
				possible = node
			}

			if node.Segment == nil {
				current = possible
				possibleIndex = i
				break
			}
			current = node.Segment

			continue
		}

		if node.IsHandlerExists() {
			current = node
		} else {
			current = possible
		}
	}

	if current == nil {
		notFound(w, r)
		return
	}

	handler := current.MethodHandler[strings.ToUpper(r.Method)]
	if handler == nil {
		handler = current.Handler
	}

	if handler == nil {
		notFound(w, r)
		return
	}

	if current.Possible {
		r.SetPathValue("*", strings.Join(segments[possibleIndex:], "/"))
	}

	if len(pathPattern) > 0 {
		for _, v := range pathPattern {
			if current.Possible && possibleIndex <= v.index {
				continue
			}

			r.SetPathValue(v.name, v.value)
		}
	}

	handler.ServeHTTP(w, r)
}

// ////////////////////////////////////////////

// Chain is a utility function to chain multiple middleware functions together.
func Chain(middlewares ...func(next http.Handler) http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}

		return next
	}
}

// ////////////////////////////////////////////

type indexValue struct {
	index int
	name  string
	value string
}
