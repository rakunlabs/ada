package ada

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

type typeNode int

const (
	typeNodeStatic   typeNode = iota // Static node, e.g., /users
	typeNodeWildcard                 // Wildcard node, e.g., /users/*
	typeNodeParam                    // Parameterized node, e.g., /users/{id}
)

type node struct {
	Segment *node

	TypeStatic   *nodeStatic
	TypeWildcard *nodeWildcard
	TypeParam    *nodeParam

	MethodHandler map[string]http.HandlerFunc
	Handler       http.HandlerFunc
}

type nodeStatic struct {
	Key      string
	Children map[rune]*node
}

func (n *nodeStatic) SetChild(char rune, child *node) {
	if n.Children == nil {
		n.Children = make(map[rune]*node)
	}

	n.Children[char] = child
}

type nodeParam struct {
	Name     string // Name of the parameter, e.g., "id"
	Children *node
}

type nodeWildcard struct {
	Children *node // Children nodes for wildcard
}

func (n *node) FindNode(path string, r *http.Request) *node {
	if n.TypeStatic != nil {
		current := n
		isFound := true
		// for i, char := range path {
		for i := 0; i < len(path); {
			char, size := utf8.DecodeRuneInString(path[i:])
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

			i += len(child.TypeStatic.Key) + size - 1
			current = child
		}

		if isFound {
			return current
		}
	}

	// Check for parameter nodes - they match any segment and capture the value
	if n.TypeParam != nil {
		r.SetPathValue(n.TypeParam.Name, path)
		return n.TypeParam.Children
	}

	// Check for wildcard nodes - they match any segment
	if n.TypeWildcard != nil {
		return n.TypeWildcard.Children
	}

	return nil
}

func (n *node) SetHandler(method string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	handlerWithMiddlewares := Chain(middlewares...)(handler)

	if method == "" {
		n.Handler = handlerWithMiddlewares.ServeHTTP

		return
	}

	if n.MethodHandler == nil {
		n.MethodHandler = make(map[string]http.HandlerFunc)
	}

	n.MethodHandler[method] = handlerWithMiddlewares.ServeHTTP
}

func (n *node) Insert(method, path string, handler http.HandlerFunc) {
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	current := n
	for i, segment := range pathSegments {
		if segment == "" {
			continue // skip empty segments
		}

		switch findTypeNode(segment) {
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

	current.SetHandler(method, handler)
}

func (n *node) insertNodeTypeStatic(path string) *node {
	current := n
	// place every segment in a node or sub-node
	for byteIndex := 0; byteIndex < len(path); {
		char, charSize := utf8.DecodeRuneInString(path[byteIndex:])
		// find the type of the node
		if current.TypeStatic == nil {
			current.TypeStatic = &nodeStatic{}
		}

		if child, exists := current.TypeStatic.Children[char]; exists {
			commonLen := 0
			// find remaining on path
			remaining := path[byteIndex:]
			for commonLen < len(child.TypeStatic.Key) && commonLen < len(remaining) {
				charCommon, size := utf8.DecodeRuneInString(child.TypeStatic.Key[commonLen:])
				charRemaining, _ := utf8.DecodeRuneInString(remaining[commonLen:])
				if charCommon == charRemaining {
					commonLen += size
				} else {
					break
				}
			}

			// if it is inside of this node than switch to it and try to continue to find
			if commonLen == len(child.TypeStatic.Key) {
				// continue to look inside the child node
				current = child
				byteIndex += commonLen + charSize - 1
			} else {
				// Need to split the node
				splitNode := &node{
					TypeStatic: &nodeStatic{
						Key:      child.TypeStatic.Key[:commonLen],
						Children: make(map[rune]*node),
					},
				}

				// Update existing child
				child.TypeStatic.Key = child.TypeStatic.Key[commonLen:]
				childChar, _ := utf8.DecodeRuneInString(child.TypeStatic.Key[0:])
				splitNode.TypeStatic.SetChild(childChar, child)

				// Add new path if needed
				if commonLen < len(remaining) {
					newSuffix := remaining[commonLen:]
					newNode := &node{
						TypeStatic: &nodeStatic{
							Key:      newSuffix,
							Children: make(map[rune]*node),
						},
					}

					childChar, _ := utf8.DecodeRuneInString(newSuffix[0:])
					splitNode.TypeStatic.SetChild(childChar, newNode)
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
					Children: make(map[rune]*node),
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

	notFound    http.HandlerFunc
	middlewares []func(next http.Handler) http.Handler
}

func NewMux() *Mux {
	return &Mux{
		root: &node{},
	}
}

func (m *Mux) addHandler(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	handlerFunc := Chain(middlewares...)(handler)
	m.root.Insert(method, path, handlerFunc.ServeHTTP)
}

func (m *Mux) GET(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler(http.MethodGet, path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) POST(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler(http.MethodPost, path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) PUT(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler(http.MethodPut, path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) PATCH(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler(http.MethodPatch, path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) DELETE(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler(http.MethodDelete, path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) HandleFunc(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler("", path, handler, append(m.middlewares, middlewares...)...)
}

func (m *Mux) Handle(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.addHandler("", path, handler.ServeHTTP, append(m.middlewares, middlewares...)...)
}

func (m *Mux) Use(middlewares ...func(next http.Handler) http.Handler) {
	if len(middlewares) == 0 {
		return
	}

	m.middlewares = append(m.middlewares, middlewares...)
}

// func (m Mux) Group(path string, middlewares ...func(next http.Handler) http.Handler) *Mux {

// }

// Notfound sets the handler for 404 Not Found responses.
func (m *Mux) Notfound(handler http.HandlerFunc) {
	m.notFound = handler
}

// ServeHTTP implements the http.Handler interface for Mux.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	notFound := m.notFound
	if notFound == nil {
		notFound = http.NotFound
	}

	path := r.URL.Path
	current := m.root

	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, segment := range segments {
		// find the type of the node
		node := current.FindNode(segment, r)
		if node == nil {
			notFound(w, r)

			return
		}

		if i != len(segments)-1 {
			if node.Segment == nil {
				notFound(w, r)

				return
			}
			current = node.Segment
		} else {
			current = node
		}
	}

	handler := current.MethodHandler[strings.ToUpper(r.Method)]
	if handler == nil {
		handler = current.Handler
	}

	if handler == nil {
		notFound(w, r)

		return
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
