// Package provider supplies deterministic local HTTP servers for vendor
// adapter tests. It never makes outbound requests and records every request
// before invoking the configured handler.
package provider

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

type Request struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

type Handler func(Request) Response

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func JSONResponse(status int, value any) Response {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return Response{Status: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}
}

type Mock struct {
	Server *httptest.Server

	mu       sync.Mutex
	handlers map[string]Handler
	requests []Request
}

// New starts a loopback-only mock server. A default 404 response makes
// unconfigured vendor endpoints fail loudly in tests.
func New(t *testing.T) *Mock {
	t.Helper()
	m := &Mock{handlers: make(map[string]Handler)}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serveHTTP))
	t.Cleanup(m.Server.Close)
	return m
}

func (m *Mock) Handle(method, path string, handler Handler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[method+" "+path] = handler
}

func (m *Mock) Requests() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *Mock) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	req := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: append([]byte(nil), body...)}
	m.mu.Lock()
	m.requests = append(m.requests, req)
	handler := m.handlers[r.Method+" "+r.URL.Path]
	m.mu.Unlock()
	if handler == nil {
		http.NotFound(w, r)
		return
	}
	response := handler(req)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := response.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(response.Body)
}
