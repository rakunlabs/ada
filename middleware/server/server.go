package server

import "net/http"

const (
	HeaderServer = "Server"
)

type Server struct {
	Value string
}

func New(server string) *Server {
	return &Server{
		Value: server,
	}
}

func Middleware(server string) func(next http.Handler) http.Handler {
	return New(server).Middleware
}

func (m *Server) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the server name in the response header
		w.Header().Set(HeaderServer, m.Value)

		next.ServeHTTP(w, r)
	})
}
